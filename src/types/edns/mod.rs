pub mod edns0;

use std::fmt;
use std::fmt::Formatter;
use std::fmt::Display;
use std::fmt::Write;
use std::io::{Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use crate::msg::{RecourseRecordHdr, RR};
use crate::types::RecourseRecord;
use crate::{Result, util};
pub use edns0::{IEdns0, EDNS0};

/// EDNS0
/// RFC 6891.
#[derive(Debug, Clone)]
pub struct Opt {
    pub hdr: RecourseRecordHdr,
    pub option: Vec<EDNS0>,
}

impl Into<RecourseRecord> for Opt {
    fn into(self) -> RecourseRecord {
        RecourseRecord::Opt(self)
    }
}

impl RR for Opt {
    type Item = Opt;

    fn pack(&self, bs: &mut BytesMut) -> Result<()> {
        for el in &self.option {
            bs.put_u16(el.option());
            bs.put_u16(0);
            let start = bs.len();
            el.pack(bs)?;
            let count = bs.len() - start;
            util::set_value_offset(bs.as_mut(), start - 2, count as u16);
        }
        Ok(())
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        let mut options = Vec::new();
        let mut off: usize = cur.position() as usize;

        loop {
            let code = cur.read_u16::<BigEndian>()?;
            let opt_len = cur.read_u16::<BigEndian>()?;
            off += 4;
            let data = &cur.get_ref()[off..off + opt_len as usize];
            let e0 = EDNS0::unpack(code, data)?;
            options.push(e0);
            off += opt_len as usize;
            if off >= cur.get_ref().len() {
                break;
            }
        }

        Ok(Self {
            hdr: h,
            option: options,
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        &self.hdr
    }
}

impl Opt {
    pub fn is_do(&self) -> bool {
        (self.hdr.ttl & edns0::_DO as u32) == edns0::_DO as u32
    }

    pub fn version(&self) -> u8 {
        (self.hdr.ttl & 0x00FF0000 >> 16) as u8
    }

    /// UDP buffer size.
    pub fn udp_size(&self) -> u16 {
        self.hdr.class
    }

    pub fn set_udp_size(&mut self, size: u16) {
        self.hdr.class = size;
    }

    pub fn extended_r_code(&self) -> u16 {
        ((self.hdr.ttl & 0xFF000000 >> 24) << 4) as u16
    }

    pub fn set_extended_r_code(&mut self, v: u16) {
        self.hdr.ttl = self.op_extended_r_code(v)
    }

    pub fn op_extended_r_code(&self, v: u16) -> u32 {
        return self.hdr.ttl & 0x00FFFFFF | ((v >> 4) as u32) << 24
    }

    pub fn set_do(&mut self, d: &[bool]) {
        if d.len() == 1 {
            if d[0] {
                self.hdr.ttl |= edns0::_DO as u32;
            } else {
                self.hdr.ttl ^= edns0::_DO as u32;
                self.hdr.ttl &= edns0::_DO as u32;
            }
        } else {
            self.hdr.ttl |= edns0::_DO as u32
        }
    }
}

impl Display for Opt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("\n;; OPT PSEUDOSECTION:\n; EDNS: version ")?;
        fmt::Display::fmt(&self.version(), f)?;
        f.write_str("; ")?;

        if self.is_do() {
            f.write_str("flags: do; ")?;
        } else {
            f.write_str("flags:; ")?;
        }

        if self.hdr.ttl & 0x7FFF != 0 {
            f.write_str("MBZ: 0x")?;
            f.write_str(&hex::encode(&(self.hdr.ttl & 0x7FFF).to_be_bytes()))?;
        }
        f.write_str("udp: ")?;
        fmt::Display::fmt(&self.udp_size(), f)?;

        for o in &self.option {
            match o {
                EDNS0::Nid(val) => {
                    f.write_str("\n; NSID: ")?;
                    let mut buf = BytesMut::new();
                    if let Ok(_) = val.pack(&mut buf) {
                        f.write_str("(")?;
                        for a in buf.as_ref() {
                            f.write_char((*a) as char)?;
                        }
                        f.write_str(")")?;
                    }
                }
                EDNS0::SubNet(val) => {
                    f.write_str("\n; SUBNET: ")?;
                    val.fmt(f)?;
                }
                EDNS0::Local(val) => {
                    f.write_str("\n; LOCAL OPT: ")?;
                    val.fmt(f)?;
                }
            }
        }
        Ok(())
    }
}

