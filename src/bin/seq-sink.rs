//! seq-sink — a tiny SEQA consumer for testing seq-agent end to end.
//!
//! Listens for a seq-agent connection, parses the SEQA hello + frame stream,
//! prints per-connection stats, and can reconstruct the captured frames into a
//! `.pcap` file (`--write-pcap`) to prove the round-trip is byte-faithful.
//! It is also the seed of the eventual daemon-side frame reader.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use seq_agent::proto::{FrameHeader, Hello, MAX_CAPLEN};

struct Opts {
    listen: String,
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
    let mut listen = "127.0.0.1:9099".to_string();
    let mut write_pcap = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-l" | "--listen" => listen = args.next().ok_or("--listen needs a value")?,
            "--write-pcap" => write_pcap = Some(args.next().ok_or("--write-pcap needs a value")?),
            "-h" | "--help" => {
                eprintln!("seq-sink --listen HOST:PORT [--write-pcap FILE]");
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let opts = Opts { listen, write_pcap };

    let listener = TcpListener::bind(&opts.listen)?;
    println!("[seq-sink] listening on {}", opts.listen);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                println!("[seq-sink] connection from {peer}");
                if let Err(e) = handle(s, &opts) {
                    eprintln!("[seq-sink] connection ended: {e}");
                }
            }
            Err(e) => eprintln!("[seq-sink] accept error: {e}"),
        }
    }
    Ok(())
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
