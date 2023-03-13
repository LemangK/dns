use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use bytes::{BytesMut};
use crate::util::ResizeMut;
use crate::Result;
use crate::msg::{RecourseRecordHdr, RR};
use crate::types::RecourseRecord;

/// RFC3597 represents an unknown/generic RR. See RFC 3597.
#[derive(Debug, Clone)]
pub struct RFC3597 {
    pub hdr: RecourseRecordHdr,
    pub data: String,
}

impl Into<RecourseRecord> for RFC3597 {
    fn into(self) -> RecourseRecord {
        RecourseRecord::Unknown(self)
    }
}

impl Display for RFC3597 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.hdr.fmt(f)?;
        f.write_str(&self.data)
    }
}

impl RR for RFC3597 {
    type Item = RFC3597;

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        let add = buf.extend_split(self.data.len()/2);
        hex::decode_to_slice(&self.data, add)?;
        Ok(())
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        let mut data = vec![0u8; h.rd_length as usize];
        cur.read_exact(&mut data[..])?;
        Ok(Self {
            hdr: h,
            data: hex::encode(data),
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        &self.hdr
    }
}