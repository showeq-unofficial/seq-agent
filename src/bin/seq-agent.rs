//! seq-agent — a dumb EverQuest packet-capture forwarder.
//!
//! Opens a pcap device (or reads a `.pcap` file), applies a BPF filter, and
//! streams timestamped raw frames over TCP using the SEQA protocol. No decode,
//! no state, no protocol knowledge — so it never needs updating on patch day.
//!
//! The agent is the TCP *listener*: it binds a port and waits for a daemon to
//! dial in, so it needs zero config about where the daemon lives — all the
//! topology sits in the daemon. It's an on-demand tap: on a live device the
//! capture starts *when a daemon connects*, using the BPF filter that daemon
//! asks for in its `ClientHello` (or the agent's `--filter` default if none
//! arrives before a short timeout), and stops when it disconnects. Each session
//! runs two threads: capture (this thread) fills a bounded ring; a sender thread
//! sends the agent `Hello` and drains the ring to the socket. Live capture drops
//! the oldest frame when the ring is full (never stalls the NIC); file input
//! backpressures instead (faithful replay) and ignores the ClientHello.

use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use pcap::{Activated, Capture, Device};
use seq_agent::proto::{ClientHello, FrameHeader, Hello};

/// How long the agent waits for a daemon's `ClientHello` before falling back to
/// its own `--filter` default (matches scry's 2 s hello timeout).
const HELLO_TIMEOUT: Duration = Duration::from_millis(2000);

struct Frame {
    header: FrameHeader,
    data: Vec<u8>,
}

// ---- bounded ring between the capture thread and the serve thread ----

struct Ring {
    m: Mutex<Inner>,
    not_empty: Condvar,
    not_full: Condvar,
    cap: usize,
    lossless: bool,
}
struct Inner {
    q: VecDeque<Frame>,
    closed: bool,
    dropped: u64,
}

impl Ring {
    fn new(cap: usize, lossless: bool) -> Self {
        Ring {
            m: Mutex::new(Inner {
                q: VecDeque::new(),
                closed: false,
                dropped: 0,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            cap: cap.max(1),
            lossless,
        }
    }

    /// Producer. Lossless mode blocks when full (faithful file replay); live
    /// mode drops the oldest frame so the capture never stalls.
    fn push(&self, f: Frame) {
        let mut g = self.m.lock().unwrap();
        if self.lossless {
            while g.q.len() >= self.cap && !g.closed {
                g = self.not_full.wait(g).unwrap();
            }
            if g.closed {
                return;
            }
        } else if g.q.len() >= self.cap {
            g.q.pop_front();
            g.dropped += 1;
        }
        g.q.push_back(f);
        drop(g);
        self.not_empty.notify_one();
    }

    fn try_pop(&self) -> Option<Frame> {
        let mut g = self.m.lock().unwrap();
        let f = g.q.pop_front();
        if f.is_some() {
            drop(g);
            self.not_full.notify_one();
        }
        f
    }

    /// Consumer. Returns None only once the ring is closed AND drained.
    fn pop_blocking(&self) -> Option<Frame> {
        let mut g = self.m.lock().unwrap();
        loop {
            if let Some(f) = g.q.pop_front() {
                drop(g);
                self.not_full.notify_one();
                return Some(f);
            }
            if g.closed {
                return None;
            }
            g = self.not_empty.wait(g).unwrap();
        }
    }

    fn close(&self) {
        let mut g = self.m.lock().unwrap();
        g.closed = true;
        drop(g);
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    /// True once closed — the producer (capture loop) uses this to stop when the
    /// sender tears the session down after a daemon disconnect.
    fn closed(&self) -> bool {
        self.m.lock().unwrap().closed
    }

    fn dropped(&self) -> u64 {
        self.m.lock().unwrap().dropped
    }
}

// ---- per-connection handshake + sender ----

/// Read the daemon's optional `ClientHello` for the BPF filter it wants, waiting
/// up to `timeout`. Any timeout / EOF / malformed hello falls back to `default`
/// (the agent's `--filter`). Only ever reads this one message — after it, the
/// daemon channel is write-only (frames flow agent → daemon).
fn read_client_hello(sock: &TcpStream, default: &str, timeout: Duration) -> String {
    let _ = sock.set_read_timeout(Some(timeout));
    let mut r: &TcpStream = sock;
    let filter = match ClientHello::read_from(&mut r) {
        Ok(ch) => ch.filter,
        Err(_) => default.to_string(),
    };
    let _ = sock.set_read_timeout(None);
    filter
}

/// Sender thread: write the agent `Hello`, then drain the ring to the socket. On
/// any socket error (daemon gone) close the ring so the capture loop stops.
fn send_session(sock: TcpStream, hello: Hello, ring: &Ring) {
    let mut w = BufWriter::new(sock);
    let res = hello
        .write_to(&mut w)
        .and_then(|_| w.flush())
        .and_then(|_| pump(&mut w, ring));
    match res {
        // pump returns Ok only once the ring is closed and drained — a file
        // replay that ran to completion.
        Ok(()) => eprintln!("[seq-agent] all frames delivered"),
        Err(e) => eprintln!("[seq-agent] daemon disconnected: {e}"),
    }
    ring.close();
}

fn pump<W: Write>(w: &mut W, ring: &Ring) -> io::Result<()> {
    loop {
        match ring.pop_blocking() {
            None => {
                w.flush()?;
                return Ok(());
            }
            Some(f) => {
                // Batch everything queued right now, then flush once.
                write_frame(w, &f)?;
                while let Some(f2) = ring.try_pop() {
                    write_frame(w, &f2)?;
                }
                w.flush()?;
            }
        }
    }
}

fn write_frame<W: Write>(w: &mut W, f: &Frame) -> io::Result<()> {
    f.header.write_to(w)?;
    w.write_all(&f.data)
}

// ---- one session: capture (this thread) fills the ring, sender drains it ----

/// Serve a single daemon: spawn the sender (agent `Hello` + frame stream), then
/// pump captured frames into the ring until the file ends or the daemon leaves.
/// `lossless` = faithful file replay (backpressure); otherwise live drop-oldest.
fn serve_session<T: Activated>(
    mut cap: Capture<T>,
    sock: TcpStream,
    hello: Hello,
    lossless: bool,
    ring_cap: usize,
) {
    let ring = Arc::new(Ring::new(ring_cap, lossless));
    let sender = {
        let r = ring.clone();
        thread::spawn(move || send_session(sock, hello, &r))
    };

    let mut pushed: u64 = 0;
    loop {
        // The sender closes the ring when the daemon drops — stop capturing.
        if ring.closed() {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let h = pkt.header;
                let ts = (h.ts.tv_sec as u64)
                    .wrapping_mul(1_000_000)
                    .wrapping_add(h.ts.tv_usec as u64);
                ring.push(Frame {
                    header: FrameHeader {
                        ts_micros: ts,
                        caplen: h.caplen,
                        origlen: h.len,
                    },
                    data: pkt.data.to_vec(),
                });
                pushed += 1;
                if pushed % 5000 == 0 {
                    eprintln!("[seq-agent] captured {pushed} (dropped {})", ring.dropped());
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                eprintln!("[seq-agent] capture error: {e}");
                break;
            }
        }
    }
    ring.close();
    let _ = sender.join();
    eprintln!(
        "[seq-agent] session done: {pushed} captured, {} dropped",
        ring.dropped()
    );
}

// ---- capture drivers ----

/// File replay (fixed source): serve one daemon a faithful replay, then exit.
/// Ignores any ClientHello — the file is already the capture the daemon wants
/// (the agent's `--filter`, if given, still narrows it). Mirrors scry's `:fixed`.
fn run_file(
    listener: &TcpListener,
    file: &str,
    opts: &Opts,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sock, _) = listener.accept()?;
    let _ = sock.set_nodelay(true);
    let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    eprintln!("[seq-agent] daemon connected from {peer}; replaying {file}");

    let mut cap = Capture::from_file(file)?;
    if !opts.filter.is_empty() {
        cap.filter(&opts.filter, true)?;
    }
    let hello = Hello {
        link_type: cap.get_datalink().0,
        snaplen: opts.snaplen,
        filter: opts.filter.clone(),
    };
    serve_session(cap, sock, hello, true, opts.ring);
    Ok(())
}

/// Live device (on-demand tap): each daemon that connects gets a fresh capture
/// with the filter it asks for in its ClientHello (or `--filter` default). A bad
/// filter / device error fails just that session; the agent keeps listening.
fn run_device(listener: &TcpListener, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let dev = opts.device.as_deref().unwrap();
    for conn in listener.incoming() {
        let sock = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[seq-agent] accept error: {e}");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let peer = sock.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        eprintln!("[seq-agent] daemon connected from {peer}");
        if let Err(e) = tap_once(sock, dev, opts) {
            eprintln!("[seq-agent] session error: {e}");
        }
    }
    Ok(())
}

/// Open a live capture with the daemon-requested (or default) filter and serve it.
fn tap_once(sock: TcpStream, dev: &str, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let filter = read_client_hello(&sock, &opts.filter, HELLO_TIMEOUT);
    eprintln!(
        "[seq-agent] capturing {dev} with filter {}",
        if filter.is_empty() { "<none>" } else { &filter }
    );
    let mut cap = Capture::from_device(dev)?
        .promisc(opts.promisc)
        .snaplen(opts.snaplen as i32)
        .immediate_mode(true)
        .timeout(1000)
        .open()?;
    if !filter.is_empty() {
        cap.filter(&filter, true)?;
    }
    let hello = Hello {
        link_type: cap.get_datalink().0,
        snaplen: opts.snaplen,
        filter,
    };
    serve_session(cap, sock, hello, false, opts.ring);
    Ok(())
}

// ---- CLI ----

struct Opts {
    device: Option<String>,
    input: Option<String>,
    filter: String,
    snaplen: u32,
    listen: String,
    ring: usize,
    promisc: bool,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("[seq-agent] error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut device = None;
    let mut input = None;
    let mut filter = String::new();
    let mut snaplen: u32 = 65535;
    let mut listen = "0.0.0.0:9099".to_string();
    let mut ring: usize = 8192;
    let mut promisc = true;

    while let Some(a) = args.next() {
        match a.as_str() {
            "-i" | "--device" => device = Some(next(&mut args, &a)?),
            "--input" => input = Some(next(&mut args, &a)?),
            "-f" | "--filter" => filter = next(&mut args, &a)?,
            "-s" | "--snaplen" => snaplen = next(&mut args, &a)?.parse()?,
            "-l" | "--listen" => listen = next(&mut args, &a)?,
            "--ring" => ring = next(&mut args, &a)?.parse()?,
            "--no-promisc" => promisc = false,
            "--list-devices" => {
                for d in Device::list()? {
                    println!("{:<16} {}", d.name, d.desc.unwrap_or_default());
                }
                return Ok(());
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    if device.is_some() == input.is_some() {
        return Err("specify exactly one of --device <name> or --input <file.pcap>".into());
    }
    let opts = Opts {
        device,
        input,
        filter,
        snaplen,
        listen,
        ring,
        promisc,
    };

    let listener = TcpListener::bind(&opts.listen)?;
    eprintln!(
        "[seq-agent] listening on {} (waiting for daemon)",
        opts.listen
    );
    match &opts.input {
        Some(file) => run_file(&listener, file, &opts),
        None => run_device(&listener, &opts),
    }
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn print_usage() {
    eprint!(
        "seq-agent — capture forwarder (SEQA protocol)\n\n\
         The agent listens; the daemon dials in, names a BPF filter in its hello,\n\
         and drains the frame stream. Live capture starts on connect.\n\n\
         USAGE:\n  \
           seq-agent (-i DEVICE | --input FILE.pcap) [--listen HOST:PORT] [options]\n\n\
         OPTIONS:\n  \
           -i, --device NAME     capture from a live device\n      \
               --input FILE      read frames from a .pcap file instead\n  \
           -f, --filter BPF      default BPF filter if the daemon's hello omits one\n  \
           -s, --snaplen N       capture length (default 65535)\n  \
           -l, --listen HOST:PORT  address to accept a daemon on (default 0.0.0.0:9099)\n      \
               --ring N          per-session frame buffer depth (default 8192)\n      \
               --no-promisc      disable promiscuous mode\n      \
               --list-devices    list capture devices and exit\n  \
           -h, --help            show this help\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Connect a loopback pair, run `client_fn` on the dialing side while the
    /// agent side reads its hello, and return the resolved filter.
    fn resolve_filter(
        client_fn: impl FnOnce(TcpStream) + Send + 'static,
        default: &str,
        timeout: Duration,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = thread::spawn(move || client_fn(TcpStream::connect(addr).unwrap()));
        let (server, _) = listener.accept().unwrap();
        let filter = read_client_hello(&server, default, timeout);
        h.join().unwrap();
        filter
    }

    #[test]
    fn uses_daemon_supplied_filter() {
        let got = resolve_filter(
            |mut c| {
                ClientHello {
                    filter: "udp and port 9000".into(),
                }
                .write_to(&mut c)
                .unwrap();
                c.flush().unwrap();
            },
            "default",
            Duration::from_secs(2),
        );
        assert_eq!(got, "udp and port 9000");
    }

    #[test]
    fn falls_back_to_default_when_daemon_sends_no_hello() {
        // Daemon connects but stays silent past the timeout: agent uses --filter.
        let got = resolve_filter(
            |c| {
                thread::sleep(Duration::from_millis(200));
                drop(c);
            },
            "default",
            Duration::from_millis(50),
        );
        assert_eq!(got, "default");
    }
}
