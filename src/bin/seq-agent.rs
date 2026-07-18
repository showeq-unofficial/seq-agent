//! seq-agent — a dumb EverQuest packet-capture forwarder.
//!
//! Opens a pcap device (or reads a `.pcap` file), applies a BPF filter, and
//! streams timestamped raw frames over TCP using the SEQA protocol. No decode,
//! no state, no protocol knowledge — so it never needs updating on patch day.
//!
//! The agent is the TCP *listener*: it binds a port and waits for a daemon to
//! dial in, so the agent needs zero config about where the daemon lives — all
//! the topology sits in the daemon. Two threads: capture (this thread) fills a
//! bounded ring; a serve thread accepts a daemon connection and drains the ring
//! to it, waiting for the next daemon on disconnect. Live capture drops the
//! oldest frame when the ring is full (never stalls the NIC); file input
//! backpressures instead (faithful replay).

use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use pcap::{Activated, Capture, Device};
use seq_agent::proto::{FrameHeader, Hello};

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

    fn is_done(&self) -> bool {
        let g = self.m.lock().unwrap();
        g.closed && g.q.is_empty()
    }

    fn dropped(&self) -> u64 {
        self.m.lock().unwrap().dropped
    }
}

// ---- serve thread: accept a daemon, send hello, pump frames ----

fn serve_loop(ring: &Ring, hello: Hello, listener: TcpListener) {
    for conn in listener.incoming() {
        if ring.is_done() {
            return;
        }
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[seq-agent] accept error: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!("[seq-agent] daemon connected from {peer}");
        let mut w = BufWriter::new(stream);
        let res = hello
            .write_to(&mut w)
            .and_then(|_| w.flush())
            .and_then(|_| pump(&mut w, ring));
        match res {
            // pump returns Ok only when the ring is closed and drained, i.e. a
            // file replay finished — nothing left to serve, so we're done.
            Ok(()) => {
                eprintln!("[seq-agent] all frames delivered");
                return;
            }
            // Live capture keeps filling the ring across the gap (drop-oldest);
            // wait for the next daemon to dial in.
            Err(e) => eprintln!("[seq-agent] daemon disconnected: {e}; waiting for next"),
        }
    }
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

// ---- capture loop (runs on the main thread) ----

fn run<T: Activated>(mut cap: Capture<T>, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    if !opts.filter.is_empty() {
        cap.filter(&opts.filter, true)?;
    }
    let link_type = cap.get_datalink().0;
    let hello = Hello {
        link_type,
        snaplen: opts.snaplen,
        filter: opts.filter.clone(),
    };
    let listener = TcpListener::bind(&opts.listen)?;
    eprintln!(
        "[seq-agent] link_type={link_type} snaplen={} filter={} listening on {} (waiting for daemon)",
        opts.snaplen,
        if opts.filter.is_empty() {
            "<none>"
        } else {
            &opts.filter
        },
        opts.listen
    );

    let ring = Arc::new(Ring::new(opts.ring, opts.input.is_some()));
    let server = {
        let r = ring.clone();
        let hello = hello.clone();
        thread::spawn(move || serve_loop(&r, hello, listener))
    };

    let mut pushed: u64 = 0;
    loop {
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
    let _ = server.join();
    eprintln!(
        "[seq-agent] done: {pushed} captured, {} dropped",
        ring.dropped()
    );
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

    match &opts.input {
        Some(file) => run(Capture::from_file(file)?, &opts),
        None => {
            let dev = opts.device.as_deref().unwrap();
            let cap = Capture::from_device(dev)?
                .promisc(opts.promisc)
                .snaplen(opts.snaplen as i32)
                .immediate_mode(true)
                .timeout(1000)
                .open()?;
            run(cap, &opts)
        }
    }
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn print_usage() {
    eprint!(
        "seq-agent — capture forwarder (SEQA protocol)\n\n\
         The agent listens; the daemon dials in and drains the frame stream.\n\n\
         USAGE:\n  \
           seq-agent (-i DEVICE | --input FILE.pcap) [--listen HOST:PORT] [options]\n\n\
         OPTIONS:\n  \
           -i, --device NAME     capture from a live device\n      \
               --input FILE      read frames from a .pcap file instead\n  \
           -f, --filter BPF      BPF capture filter (e.g. 'udp')\n  \
           -s, --snaplen N       capture length (default 65535)\n  \
           -l, --listen HOST:PORT  address to accept a daemon on (default 0.0.0.0:9099)\n      \
               --ring N          frames buffered while no daemon is connected (default 8192)\n      \
               --no-promisc      disable promiscuous mode\n      \
               --list-devices    list capture devices and exit\n  \
           -h, --help            show this help\n"
    );
}
