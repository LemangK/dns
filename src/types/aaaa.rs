use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use std::net::Ipv6Addr;
use bytes::{BytesMut};
use crate::msg::{RR, RecourseRecordHdr};
use crate::types::RecourseRecord;
use crate::{Result, util};

/// RFC 3596.
#[derive(Debug, Clone)]
pub struct AAAA {
    pub hdr: RecourseRecordHdr,
    pub aaaa: Ipv6Addr,
}

impl AAAA {
    pub fn new(h: RecourseRecordHdr, aaaa: Ipv6Addr) -> Self {
        Self {
            hdr: RecourseRecordHdr {
                rd_length: 16,
                ..h
            },
            aaaa,
        }
    }
}

impl Display for AAAA {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.hdr.fmt(f)?;
        std::fmt::Display::fmt(&self.aaaa, f)
    }
}

impl Into<RecourseRecord> for AAAA {
    fn into(self) -> RecourseRecord {
        RecourseRecord::AAAA(self)
    }
}

impl RR for AAAA {
    type Item = AAAA;

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        util::set_rd(buf, &self.aaaa.octets());
        Ok(())
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        let mut s = [0u8; 16];
        cur.read_exact(&mut s[..])?;
        Ok(Self {
            hdr: h,
            aaaa: Ipv6Addr::from(s),
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        &self.hdr
    }
}