//! SEQA wire protocol — the framing between `seq-agent` (capture forwarder)
//! and any consumer (`seq-sink` today, the daemon later).
//!
//! Deliberately pcap-shaped so a captured stream converts to/from a `.pcap`
//! file with no transformation. All integers little-endian.
//!
//! ```text
//! Hello (once, on connect):
//!   magic     [u8;4]  "SEQA"
//!   version   u8      = 1
//!   flags     u8      reserved, 0
//!   link_type i32     pcap DLT (EN10MB=1, LINUX_SLL=113, ...)
//!   snaplen   u32
//!   filt_len  u16
//!   filter    [u8; filt_len]   BPF string (UTF-8), may be empty
//!
//! Frame (repeated until EOF):
//!   ts_micros u64     unix time, microseconds
//!   caplen    u32     captured bytes (== data length)
//!   origlen   u32     original on-wire length
//!   data      [u8; caplen]
//! ```

use std::io::{self, Read, Write};

pub const MAGIC: [u8; 4] = *b"SEQA";
pub const VERSION: u8 = 1;

/// Reject absurd frame lengths from a corrupt/hostile stream before allocating.
pub const MAX_CAPLEN: u32 = 262_144;

#[derive(Debug, Clone)]
pub struct Hello {
    pub link_type: i32,
    pub snaplen: u32,
    pub filter: String,
}

impl Hello {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&[VERSION, 0])?;
        w.write_all(&self.link_type.to_le_bytes())?;
        w.write_all(&self.snaplen.to_le_bytes())?;
        let fb = self.filter.as_bytes();
        let flen = u16::try_from(fb.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filter too long"))?;
        w.write_all(&flen.to_le_bytes())?;
        w.write_all(fb)
    }

    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Hello> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SEQA magic"));
        }
        let mut vf = [0u8; 2];
        r.read_exact(&mut vf)?;
        if vf[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SEQA version {}", vf[0]),
            ));
        }
        let link_type = read_i32(r)?;
        let snaplen = read_u32(r)?;
        let flen = read_u16(r)? as usize;
        let mut fbuf = vec![0u8; flen];
        r.read_exact(&mut fbuf)?;
        let filter = String::from_utf8(fbuf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "filter not UTF-8"))?;
        Ok(Hello {
            link_type,
            snaplen,
            filter,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub ts_micros: u64,
    pub caplen: u32,
    pub origlen: u32,
}

impl FrameHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.ts_micros.to_le_bytes())?;
        w.write_all(&self.caplen.to_le_bytes())?;
        w.write_all(&self.origlen.to_le_bytes())
    }

    pub fn read_from<R: Read>(r: &mut R) -> io::Result<FrameHeader> {
        let ts_micros = read_u64(r)?;
        let caplen = read_u32(r)?;
        let origlen = read_u32(r)?;
        Ok(FrameHeader {
            ts_micros,
            caplen,
            origlen,
        })
    }
}

fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_i32<R: Read>(r: &mut R) -> io::Result<i32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
