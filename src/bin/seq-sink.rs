//! seq-sink — a tiny SEQA consumer for testing seq-agent end to end.
//!
//! Dials a seq-agent (which listens), parses the SEQA hello + frame stream,
//! prints per-connection stats, and can reconstruct the captured frames into a
//! `.pcap` file (`--write-pcap`) to prove the round-trip is byte-faithful.
//! It is also the seed of the eventual daemon-side frame reader — the daemon is
//! the party that dials the agent.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use seq_agent::proto::{FrameHeader, Hello, MAX_CAPLEN};

struct Opts {
    connect: String,
    write_pcap: Option<String>,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("[seq-sink] error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut connect = "127.0.0.1:9099".to_string();
    let mut write_pcap = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--connect" => connect = args.next().ok_or("--connect needs a value")?,
            "--write-pcap" => write_pcap = Some(args.next().ok_or("--write-pcap needs a value")?),
            "-h" | "--help" => {
                eprintln!("seq-sink --connect HOST:PORT [--write-pcap FILE]");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let opts = Opts {
        connect,
        write_pcap,
    };

    // Dial the agent, retrying so it doesn't matter which side starts first.
    println!("[seq-sink] connecting to {}", opts.connect);
    let stream = connect_with_retry(&opts.connect);
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    println!("[seq-sink] connected to {peer}");
    if let Err(e) = handle(stream, &opts) {
        eprintln!("[seq-sink] connection ended: {e}");
    }
    Ok(())
}

/// Connect to the agent, retrying with backoff until it accepts. Blocks forever
/// (Ctrl-C to give up) — mirrors the agent's willingness to wait for a daemon.
fn connect_with_retry(addr: &str) -> TcpStream {
    let mut backoff = Duration::from_millis(200);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return s;
            }
            Err(_) => {
                thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
}

fn handle(stream: TcpStream, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let mut r = BufReader::new(stream);
    let hello = Hello::read_from(&mut r)?;
    println!(
        "[seq-sink] hello: link_type={} snaplen={} filter={}",
        hello.link_type,
        hello.snaplen,
        if hello.filter.is_empty() {
            "<none>".into()
        } else {
            format!("{:?}", hello.filter)
        }
    );

    let mut pcap = match &opts.write_pcap {
        Some(path) => Some(PcapWriter::create(path, hello.link_type, hello.snaplen)?),
        None => None,
    };

    let start = Instant::now();
    let mut frames: u64 = 0;
    let mut bytes: u64 = 0;
    loop {
        let fh = match FrameHeader::read_from(&mut r) {
            Ok(fh) => fh,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        if fh.caplen > MAX_CAPLEN {
            return Err(format!("frame caplen {} exceeds max {}", fh.caplen, MAX_CAPLEN).into());
        }
        let mut data = vec![0u8; fh.caplen as usize];
        r.read_exact(&mut data)?;
        frames += 1;
        bytes += fh.caplen as u64;
        if let Some(w) = &mut pcap {
            w.write(&fh, &data)?;
        }
        if frames % 500 == 0 {
            println!("[seq-sink] {frames} frames, {bytes} bytes");
        }
    }
    if let Some(w) = &mut pcap {
        w.flush()?;
    }
    let dur = start.elapsed();
    println!(
        "[seq-sink] summary: {frames} frames, {bytes} bytes in {:.3}s",
        dur.as_secs_f64()
    );
    Ok(())
}

// ---- minimal libpcap-format writer (pure std, no pcap dependency) ----

struct PcapWriter {
    f: BufWriter<File>,
}

impl PcapWriter {
    fn create(path: &str, link_type: i32, snaplen: u32) -> io::Result<Self> {
        let mut f = BufWriter::new(File::create(path)?);
        f.write_all(&0xa1b2_c3d4u32.to_le_bytes())?; // magic (usec resolution)
        f.write_all(&2u16.to_le_bytes())?; // version major
        f.write_all(&4u16.to_le_bytes())?; // version minor
        f.write_all(&0i32.to_le_bytes())?; // thiszone
        f.write_all(&0u32.to_le_bytes())?; // sigfigs
        f.write_all(&snaplen.to_le_bytes())?; // snaplen
        f.write_all(&(link_type as u32).to_le_bytes())?; // network / DLT
        Ok(PcapWriter { f })
    }

    fn write(&mut self, h: &FrameHeader, data: &[u8]) -> io::Result<()> {
        let sec = (h.ts_micros / 1_000_000) as u32;
        let usec = (h.ts_micros % 1_000_000) as u32;
        self.f.write_all(&sec.to_le_bytes())?;
        self.f.write_all(&usec.to_le_bytes())?;
        self.f.write_all(&h.caplen.to_le_bytes())?;
        self.f.write_all(&h.origlen.to_le_bytes())?;
        self.f.write_all(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}
