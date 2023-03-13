use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor};
use bytes::{BytesMut};
use crate::{DomainString, util};
use crate::msg::{RecourseRecordHdr, RR};
use crate::types::RecourseRecord;
use crate::Result;
use crate::types::TYPE_CNAME;

/// CNAME
/// RFC 6891.
#[derive(Debug, Clone)]
pub struct CNAME {
    pub hdr: RecourseRecordHdr,
    pub target: DomainString,
}

impl CNAME {
    pub fn new(name: DomainString, class: u16, ttl: u32, target: DomainString) -> Self {
        Self {
            hdr: RecourseRecordHdr {
                name,
                typ: TYPE_CNAME,
                class,
                ttl,
                rd_length: util::cal_domain_name_len(&target) as u16,
            },
            target,
        }
    }
}

impl Into<RecourseRecord> for CNAME {
    fn into(self) -> RecourseRecord {
        RecourseRecord::CNAME(self)
    }
}

impl Display for CNAME {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.hdr, f)?;
        f.write_str(&self.target)
    }
}

impl RR for CNAME {
    type Item = CNAME;

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        let start = buf.len();
        util::pack_domain_name(&self.target, buf)?;
        let count = buf.len() - start;
        util::set_value_offset(buf.as_mut(), start - 2, count as u16);
        Ok(())
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        if h.rd_length == 0 {
            return Ok(Self {
                hdr: h,
                target: "".into(),
            })
        }
        let name = util::unpack_domain_name_cur(cur)?;
        Ok(Self {
            hdr: h,
            target: name,
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        &self.hdr
    }
}