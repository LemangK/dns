use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use std::net::Ipv6Addr;
use bytes::{BytesMut};
use crate::msg::{RR, RecourseRecordHdr};
use crate::types::{RecourseRecord, TYPE_AAAA};
use crate::{DomainString, Result, util};

/// RFC 3596.
#[derive(Debug, Clone)]
pub struct AAAA {
    pub hdr: RecourseRecordHdr,
    pub aaaa: Ipv6Addr,
}

impl AAAA {
    pub fn new(name: DomainString, class: u16, ttl: u32, aaaa: Ipv6Addr) -> Self {
        Self {
            hdr: RecourseRecordHdr {
                name,
                typ: TYPE_AAAA,
                class,
                ttl,
                rd_length: 16,
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
        if h.rd_length == 0 {
            return Ok(AAAA {
                hdr: h,
                aaaa: Ipv6Addr::UNSPECIFIED,
            })
        }
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