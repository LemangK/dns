// use std::fmt::{Display, Formatter};
// use std::io::Cursor;
// use bytes::{BytesMut};
// use crate::msg::{RecourseRecordHdr, RR};
//
// pub struct SVCB {
//     pub hdr: RecourseRecordHdr,
//     pub priority: u16,
//     pub target: String,
//     pub value: Vec<SVCBKeyValue>,
// }
//
// impl Display for SVCB {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }
//
// pub struct HTTPS(SVCB);
//
// impl Display for HTTPS {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         self.0.fmt(f)
//     }
// }
//
// impl RR for HTTPS {
//     type Item = HTTPS;
//
//     fn pack(&self, buf: &mut BytesMut) -> crate::Result<()> {
//         todo!()
//     }
//
//     fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> crate::Result<Self::Item> {
//         todo!()
//     }
//
//     fn header(&self) -> &RecourseRecordHdr {
//         &self.0.hdr
//     }
// }
//
// pub struct SVCBKeyValue {}