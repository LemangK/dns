mod label;
pub use label::Labels;

use std::{fmt, io};
use std::fmt::{Display, Formatter, Write};
use std::io::Cursor;
use std::net::IpAddr;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};
use rand::Rng;
use crate::{DomainString, util};
use crate::{Result, Error};
use crate::types;
use crate::types::RecourseRecord;

fn id() -> u16 {
    rand::thread_rng().gen()
}

#[inline]
fn error<E>(msg: E) -> io::Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, msg)
}


#[derive(Default, Copy, Clone)]
pub struct PktMsgHeader {
    pub id: u16,
    pub bits: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl PktMsgHeader {
    pub fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16(self.id);
        buf.put_u16(self.bits);
        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_count);
        buf.put_u16(self.authority_count);
        buf.put_u16(self.additional_count);
        Ok(())
    }

    pub fn unpack(cur: &mut Cursor<&[u8]>) -> io::Result<PktMsgHeader> {
        let mut ret: PktMsgHeader = PktMsgHeader::default();
        ret.id = cur.read_u16::<BigEndian>()?;
        ret.bits = cur.read_u16::<BigEndian>()?;
        ret.question_count = cur.read_u16::<BigEndian>()?;
        ret.answer_count = cur.read_u16::<BigEndian>()?;
        ret.authority_count = cur.read_u16::<BigEndian>()?;
        ret.additional_count = cur.read_u16::<BigEndian>()?;
        Ok(ret)
    }
}

pub trait RR: Display {
    type Item;
    fn pack(&self, buf: &mut BytesMut) -> Result<()>;
    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item>;
    fn header(&self) -> &RecourseRecordHdr;
}

/// DNS Message Header
#[derive(Copy, Clone, Default)]
pub struct MsgHdr {
    pub id: u16,
    pub response: bool,
    pub op_code: u16,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub zero: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    // response code
    pub response_code: u16,
}

impl Display for MsgHdr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(";; opcode: ")?;
        f.write_str(util::opcode_string(self.op_code))?;
        f.write_str(", status: ")?;
        f.write_str(util::rcode_string(self.response_code))?;
        f.write_str(", id: ")?;
        fmt::Display::fmt(&self.id, f)?;
        f.write_str("\n;; flags:")?;

        if self.response {
            f.write_str(" qr")?;
        }
        if self.authoritative {
            f.write_str(" aa")?;
        }
        if self.truncated {
            f.write_str(" tc")?;
        }
        if self.recursion_desired {
            f.write_str(" rd")?;
        }
        if self.recursion_available {
            f.write_str(" ra")?;
        }
        if self.zero {
            f.write_str(" z")?;
        }
        if self.authenticated_data {
            f.write_str(" ad")?;
        }
        if self.checking_disabled {
            f.write_str(" cd")?;
        }

        Ok(())
    }
}

impl Into<PktMsgHeader> for MsgHdr {
    fn into(self) -> PktMsgHeader {
        // Header.Bits
        const _QR: u16 = 1 << 15; // query/response (response=1)
        const _AA: u16 = 1 << 10; // authoritative
        const _TC: u16 = 1 << 9; // truncated
        const _RD: u16 = 1 << 8; // recursion desired
        const _RA: u16 = 1 << 7; // recursion available
        const _Z: u16 = 1 << 6; // Z
        const _AD: u16 = 1 << 5; // authenticated data
        const _CD: u16 = 1 << 4; // checking disabled

        let mut ret = PktMsgHeader::default();
        ret.id = self.id;
        ret.bits = self.op_code << 11 | (self.response_code & 0xF) as u16;
        if self.response {
            ret.bits |= _QR;
        }
        if self.authoritative {
            ret.bits |= _AA;
        }
        if self.truncated {
            ret.bits |= _TC;
        }
        if self.recursion_desired {
            ret.bits |= _RD;
        }
        if self.recursion_available {
            ret.bits |= _RA;
        }
        if self.zero {
            ret.bits |= _Z;
        }
        if self.authenticated_data {
            ret.bits |= _AD;
        }
        if self.checking_disabled {
            ret.bits |= _CD;
        }
        ret
    }
}


impl From<PktMsgHeader> for MsgHdr {
    fn from(value: PktMsgHeader) -> Self {
        // Header.Bits
        const _QR: u16 = 1 << 15; // query/response (response=1)
        const _AA: u16 = 1 << 10; // authoritative
        const _TC: u16 = 1 << 9; // truncated
        const _RD: u16 = 1 << 8; // recursion desired
        const _RA: u16 = 1 << 7; // recursion available
        const _Z: u16 = 1 << 6; // Z
        const _AD: u16 = 1 << 5; // authenticated data
        const _CD: u16 = 1 << 4; // checking disabled

        let mut msg = MsgHdr::default();
        msg.id = value.id;
        msg.response = value.bits & _QR != 0;
        msg.op_code = (value.bits >> 11) & 0xF;
        msg.authoritative = value.bits & _AA != 0;
        msg.truncated = value.bits & _TC != 0;
        msg.recursion_desired = value.bits & _RD != 0;
        msg.recursion_available = value.bits & _RA != 0;
        msg.zero = value.bits & _Z != 0;
        msg.authenticated_data = value.bits & _AD != 0;
        msg.checking_disabled = value.bits & _CD != 0;
        msg.response_code = value.bits & 0xF;
        msg
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: DomainString,
    pub q_type: u16,
    pub q_class: u16,
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(";")?;

        util::name_string(&self.name, f)?;
        f.write_str("\t")?;

        util::qclass_string(self.q_class, f)?;
        f.write_str("\t ")?;

        util::qtype_string(self.q_type, f)?;

        Ok(())
    }
}

impl Question {
    pub fn is_a(&self) -> bool {
        self.q_type == types::TYPE_A
    }

    pub fn is_aaaa(&self) -> bool {
        self.q_type == types::TYPE_AAAA
    }

    pub fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        util::pack_domain_name(&self.name, buf)?;
        buf.put_u16(self.q_type);
        buf.put_u16(self.q_class);
        Ok(())
    }

    pub fn unpack(cur: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let name = util::unpack_domain_name_cur(cur)?;
        let q_type = cur.read_u16::<BigEndian>()?;
        let q_class = cur.read_u16::<BigEndian>()?;
        Ok(Self {
            name,
            q_type,
            q_class,
        })
    }

    pub fn skip(cur: &mut Cursor<&[u8]>) -> io::Result<()> {
        if util::skip_domain_name(cur) {
            let _ = cur.read_u16::<BigEndian>()?;
            let _ = cur.read_u16::<BigEndian>()?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, " skip failed"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecourseRecordHdr {
    pub name: DomainString,
    pub typ: u16,
    pub class: u16,
    pub ttl: u32,
    pub rd_length: u16,// body length
}

impl RecourseRecordHdr {
    pub fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        util::pack_domain_name(&self.name, buf)?;
        buf.put_u16(self.typ);
        buf.put_u16(self.class);
        buf.put_u32(self.ttl);
        buf.put_u16(self.rd_length);
        Ok(())
    }

    pub fn unpack(cur: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let name = util::unpack_domain_name_cur(cur)?;
        let r_type = cur.read_u16::<BigEndian>()?;
        let class = cur.read_u16::<BigEndian>()?;
        let ttl = cur.read_u32::<BigEndian>()?;
        let rd_length = cur.read_u16::<BigEndian>()?;
        Ok(RecourseRecordHdr {
            name,
            typ: r_type,
            class,
            ttl,
            rd_length,
        })
    }
}

impl Display for RecourseRecordHdr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.typ == types::TYPE_OPT {
            f.write_str(";")?;
        }

        util::name_string(&self.name, f)?;
        f.write_char('\t')?;

        fmt::Display::fmt(&self.ttl, f)?;
        f.write_char('\t')?;

        util::qclass_string(self.class, f)?;
        f.write_char('\t')?;

        util::qtype_string(self.typ, f)?;
        f.write_char('\t')?;

        Ok(())
    }
}
//
// pub struct RRs<T>(Vec<T>);
//
// impl<T> Default for RRs<T> {
//     fn default() -> Self {
//         RRs(Vec::default())
//     }
// }
//
// impl<T> RRs<T>
// {
//     pub fn into_inner(self) -> Vec<T> {
//         self.0
//     }
//
//     pub fn add<I: Into<T>>(&mut self, rr: I) {
//         self.0.push(rr.into())
//     }
//
//     #[inline]
//     pub fn iter(&self) -> std::slice::Iter<'_, T> {
//         self.0.iter()
//     }
//
//     #[inline]
//     pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
//         self.0.iter_mut()
//     }
// }

#[derive(Debug, Clone)]
pub struct RRs(Vec<RecourseRecord>);

impl RRs {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn into_inner(self) -> Vec<RecourseRecord> {
        self.0
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        let mut ret = Vec::with_capacity(self.0.len());
        for item in &self.0 {
            match item {
                RecourseRecord::A(val) => ret.push(IpAddr::V4(val.a)),
                RecourseRecord::AAAA(val) => ret.push(IpAddr::V6(val.aaaa)),
                _ => {}
            }
        }
        ret
    }
}

/// DNS Message
#[derive(Default, Clone)]
pub struct Msg {
    pub hdr: MsgHdr,
    pub question: Vec<Question>,
    pub answer: Vec<RecourseRecord>,
    pub authority: Vec<RecourseRecord>,
    pub additional: Vec<RecourseRecord>,
    // compress: bool,
}

impl Msg {
    pub fn new() -> Self {
        Msg {
            ..Default::default()
        }
    }

    pub fn set_question<S: Into<DomainString>>(&mut self, name: S, q_type: u16) -> &mut Self {
        self.hdr.id = id();
        self.hdr.recursion_desired = true;
        self.question.clear();
        self.question.push(Question {
            name: name.into(),
            q_type,
            q_class: types::CLASS_INET,
        });
        self
    }

    pub fn set_response_code(&mut self, request: &Msg, response_code: u16) -> &mut Self {
        self.set_reply(request);
        self.hdr.response_code = response_code;
        self
    }

    pub fn as_reply(&mut self) -> &mut Self {
        self.hdr.response = true;
        self.hdr.response_code = types::RCODE_SUCCESS;
        self
    }

    pub fn set_reply(&mut self, request: &Msg) -> &mut Self {
        self.hdr.id = request.hdr.id;
        self.hdr.response = true;
        self.hdr.op_code = request.hdr.op_code;
        if self.hdr.op_code == types::OPCODE_QUERY {
            self.hdr.recursion_desired = request.hdr.recursion_desired;
            self.hdr.checking_disabled = request.hdr.checking_disabled;
        }
        self.hdr.response_code = types::RCODE_SUCCESS;
        if request.question.len() > 0 {
            self.question.clear();
            self.question.push(request.question[0].clone());
        }
        self
    }

    pub fn is_edns0(&self) -> Option<&types::Opt> {
        for extra in &self.additional {
            if let RecourseRecord::Opt(val) = &extra {
                return Some(val);
            }
        }
        None
    }

    pub fn get_edns0_mut(&mut self) -> Option<&mut types::Opt> {
        for extra in &mut self.additional {
            if let RecourseRecord::Opt(val) = extra {
                return Some(val);
            }
        }
        None
    }

    pub fn set_hdr(&mut self, h: PktMsgHeader) -> &mut Self {
        self.hdr = h.into();
        self
    }

    pub fn is_compressible(&self) -> bool {
        self.question.len() > 1 || self.answer.len() > 0 || self.authority.len() > 0 || self.additional.len() > 0
    }

    pub fn has_ipv6_question(&self) -> bool {
        for q in &self.question {
            if q.q_type == types::TYPE_AAAA {
                return true;
            }
        }
        false
    }

    pub fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        // if self.compress && self.is_compressible() {
        //     // todo: compress
        // }
        if self.hdr.response_code > 0xFFF {
            return Err(Error::BadResponseCode);
        }

        let r_code = self.hdr.response_code;
        if let Some(_) = self.is_edns0() {} else if r_code > 0xF {
            return Err(Error::BadExtendedResponseCode);
        }

        // Header
        {
            let mut hdr: PktMsgHeader = self.hdr.into();
            hdr.question_count = self.question.len() as u16;
            hdr.answer_count = self.answer.len() as u16;
            hdr.additional_count = self.authority.len() as u16;
            hdr.authority_count = self.additional.len() as u16;
            hdr.pack(buf)?;
        }

        for item in &self.question {
            item.pack(buf)?;
        }
        for item in &self.answer {
            item.header().pack(buf)?;
            item.pack(buf)?;
        }
        for item in &self.authority {
            item.header().pack(buf)?;
            item.pack(buf)?;
        }
        for item in &self.additional {
            if let RecourseRecord::Opt(opt) = &item {
                let mut new_opt = opt.hdr.clone();
                new_opt.ttl = opt.op_extended_r_code(r_code);
                new_opt.pack(buf)?;
            } else {
                item.header().pack(buf)?;
            }
            item.pack(buf)?;
        }

        Ok(())
    }

    pub fn unpack(msg: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(msg);
        let pkt_msg_hdr = PktMsgHeader::unpack(&mut cur)?;
        let mut msg = Msg {
            hdr: pkt_msg_hdr.into(),
            ..Default::default()
        };
        msg.__unpack(pkt_msg_hdr, &mut cur)?;
        Ok(msg)
    }

    pub fn unpack_answer(msg: &[u8]) -> Option<RRs> {
        let mut cur = Cursor::new(msg);
        if let Some(hdr) = Self::skip_questions(&mut cur) {
            let mut ret = RRs::new();
            if hdr.answer_count > 0 {
                if let Ok(_) = unpack_slice(hdr.answer_count as usize, &mut ret.0, &mut cur) {
                    return Some(ret);
                }
            } else {
                return Some(ret);
            }
        }
        return None;
    }

    pub fn pick_question(msg: &[u8]) -> Option<DomainString> {
        if let Some(mut o) = Self::unpack_questions(msg) {
            if !o.is_empty() {
                Some(o.remove(0).name)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn unpack_questions(msg: &[u8]) -> Option<Vec<Question>> {
        let mut cur = Cursor::new(msg);
        if let Ok(val) = PktMsgHeader::unpack(&mut cur) {
            let mut question = Vec::with_capacity(val.question_count as usize);
            if val.question_count > 0 {
                for _ in 0..val.question_count {
                    if let Ok(q) = Question::unpack(&mut cur) {
                        question.push(q);
                    }
                }
            }
            return Some(question);
        }
        return None;
    }

    pub fn skip_questions(cur: &mut Cursor<&[u8]>) -> Option<PktMsgHeader> {
        if let Ok(val) = PktMsgHeader::unpack(cur) {
            if val.question_count > 0 {
                for _ in 0..val.question_count {
                    if let Err(_) = Question::skip(cur) {
                        return None;
                    }
                }
            }
            return Some(val);
        }
        return None;
    }

    pub fn to_buf(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::new();
        self.pack(&mut buf)?;
        Ok(buf)
    }

    pub fn to_buf_with(&self, buf: &mut BytesMut) -> Result<()> {
        self.pack(buf)?;
        Ok(())
    }

    fn __unpack(&mut self, hdr: PktMsgHeader, cur: &mut Cursor<&[u8]>) -> Result<()> {
        if cur.get_ref().len() == cur.position() as usize {
            self.question = vec![];
            self.answer = vec![];
            self.authority = vec![];
            self.additional = vec![];
            return Ok(());
        }
        self.question.clear();
        for _ in 0..hdr.question_count {
            self.question.push(Question::unpack(cur)?);
        }
        unpack_slice(hdr.answer_count as usize, self.answer.as_mut(), cur)?;
        unpack_slice(hdr.authority_count as usize, self.authority.as_mut(), cur)?;
        unpack_slice(hdr.additional_count as usize, self.additional.as_mut(), cur)?;

        if let Some(opt) = self.is_edns0() {
            self.hdr.response_code |= opt.extended_r_code();
        }

        return Ok(());
    }
}

impl Display for Msg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.hdr.fmt(f)?;
        f.write_str("; ")?;
        f.write_str("QUERY: ")?;
        fmt::Display::fmt(&self.question.len(), f)?;
        f.write_str(", ANSWER: ")?;
        fmt::Display::fmt(&self.answer.len(), f)?;
        f.write_str(", AUTHORITY: ")?;
        fmt::Display::fmt(&self.authority.len(), f)?;
        f.write_str(", ADDITIONAL: ")?;
        fmt::Display::fmt(&self.additional.len(), f)?;
        f.write_str("\n")?;

        if !self.question.is_empty() {
            f.write_str("\n;; QUESTION SECTION:\n")?;
            for item in &self.question {
                item.fmt(f)?;
                f.write_str("\n")?;
            }
        }

        if !self.answer.is_empty() {
            f.write_str("\n;; ANSWER SECTION:\n")?;
            for item in &self.answer {
                item.fmt(f)?;
                f.write_str("\n")?;
            }
        }

        if !self.authority.is_empty() {
            f.write_str("\n;; AUTHORITY SECTION:\n")?;
            for item in &self.authority {
                item.fmt(f)?;
                f.write_str("\n")?;
            }
        }

        if !self.additional.is_empty() {
            f.write_str("\n;; ADDITIONAL SECTION:\n")?;
            for item in &self.additional {
                item.fmt(f)?;
                f.write_str("\n")?;
            }
        }

        Ok(())
    }
}

fn unpack_slice(l: usize, slice: &mut Vec<RecourseRecord>, cur: &mut Cursor<&[u8]>) -> Result<()> {
    slice.clear();
    for _ in 0..l {
        let h = RecourseRecordHdr::unpack(cur)?;
        let l = cur.get_ref().len();
        if h.rd_length as usize + cur.position() as usize > l {
            return Err(error("overflow header").into());
        }
        if cur.position() as usize + h.rd_length as usize > l {
            return Err(error("bad rdlength").into());
        }
        slice.push(RecourseRecord::unpack(h, cur)?);
    }
    Ok(())
}