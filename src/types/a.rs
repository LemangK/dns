use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use std::net::Ipv4Addr;
use bytes::{BytesMut};
use crate::msg::{RR, RecourseRecordHdr};
use crate::types::RecourseRecord;
use crate::{DomainString, Result, types, util};

/// RFC 1035.
#[derive(Debug, Clone)]
pub struct A {
    pub hdr: RecourseRecordHdr,
    pub a: Ipv4Addr,
}

impl A {
    pub fn new(name: DomainString, class: u16, ttl: u32, a: Ipv4Addr) -> Self {
        Self {
            hdr: RecourseRecordHdr {
                name,
                typ: types::TYPE_A,
                class,
                ttl,
                rd_length: a.octets().len() as u16,
            },
            a,
        }
    }
}

impl Into<RecourseRecord> for A {
    fn into(self) -> RecourseRecord {
        RecourseRecord::A(self)
    }
}

impl Display for A {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.hdr.fmt(f)?;
        std::fmt::Display::fmt(&self.a, f)
    }
}

impl RR for A {
    type Item = A;

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        util::set_rd(buf, &self.a.octets());
        Ok(())
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        let mut s = [0u8; 4];
        cur.read_exact(&mut s[..])?;
        Ok(A {
            hdr: h,
            a: Ipv4Addr::from(s),
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        &self.hdr
    }
}
