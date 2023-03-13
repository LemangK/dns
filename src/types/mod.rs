pub mod a;
pub mod aaaa;
pub mod cname;
pub mod edns;
pub mod rfc3597;
// pub mod svcb;

use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::net::IpAddr;
use bytes::BytesMut;
pub use a::A;
pub use aaaa::AAAA;
pub use cname::CNAME;
pub use edns::{EDNS0, Opt};
pub use rfc3597::RFC3597;
use crate::msg::{RecourseRecordHdr, RR};
use crate::{DomainString, Result};

#[derive(Debug, Clone)]
pub enum RecourseRecord {
    A(A),
    AAAA(AAAA),
    CNAME(CNAME),
    Opt(Opt),
    Unknown(RFC3597),
}

impl RecourseRecord {
    pub fn new_ip(name: DomainString, class: u16, ttl: u32, ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(val) => A::new(name, class, ttl, val).into(),
            IpAddr::V6(val) => AAAA::new(name, class, ttl, val).into()
        }
    }
}

impl Display for RecourseRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RecourseRecord::A(val) => val.fmt(f),
            RecourseRecord::AAAA(val) => val.fmt(f),
            RecourseRecord::CNAME(val) => val.fmt(f),
            RecourseRecord::Opt(val) => val.fmt(f),
            RecourseRecord::Unknown(val) => val.fmt(f),
        }
    }
}

impl RR for RecourseRecord {
    type Item = RecourseRecord;

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            RecourseRecord::A(val) => val.pack(buf),
            RecourseRecord::AAAA(val) => val.pack(buf),
            RecourseRecord::CNAME(val) => val.pack(buf),
            RecourseRecord::Opt(val) => val.pack(buf),
            RecourseRecord::Unknown(val) => val.pack(buf),
        }
    }

    fn unpack(h: RecourseRecordHdr, cur: &mut Cursor<&[u8]>) -> Result<Self::Item> {
        Ok(match h.typ {
            TYPE_A => A::unpack(h, cur)?.into(),
            TYPE_AAAA => AAAA::unpack(h, cur)?.into(),
            TYPE_CNAME => CNAME::unpack(h, cur)?.into(),
            TYPE_OPT => Opt::unpack(h, cur)?.into(),
            _ => RFC3597::unpack(h, cur)?.into(),
        })
    }

    fn header(&self) -> &RecourseRecordHdr {
        match self {
            RecourseRecord::A(val) => val.header(),
            RecourseRecord::AAAA(val) => val.header(),
            RecourseRecord::CNAME(val) => val.header(),
            RecourseRecord::Opt(val) => val.header(),
            RecourseRecord::Unknown(val) => val.header(),
        }
    }
}

pub const TYPE_NONE: u16 = 0;
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_MD: u16 = 3;
pub const TYPE_MF: u16 = 4;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_MB: u16 = 7;
pub const TYPE_MG: u16 = 8;
pub const TYPE_MR: u16 = 9;
pub const TYPE_NULL: u16 = 10;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_HINFO: u16 = 13;
pub const TYPE_MINFO: u16 = 14;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_RP: u16 = 17;
pub const TYPE_AFSDB: u16 = 18;
pub const TYPE_X25: u16 = 19;
pub const TYPE_ISDN: u16 = 20;
pub const TYPE_RT: u16 = 21;
pub const TYPE_NSAPPTR: u16 = 23;
pub const TYPE_SIG: u16 = 24;
pub const TYPE_KEY: u16 = 25;
pub const TYPE_PX: u16 = 26;
pub const TYPE_GPOS: u16 = 27;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_LOC: u16 = 29;
pub const TYPE_NXT: u16 = 30;
pub const TYPE_EID: u16 = 31;
pub const TYPE_NIMLOC: u16 = 32;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ATMA: u16 = 34;
pub const TYPE_NAPTR: u16 = 35;
pub const TYPE_KX: u16 = 36;
pub const TYPE_CERT: u16 = 37;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;

// EDNS
pub const TYPE_APL: u16 = 42;
pub const TYPE_DS: u16 = 43;
pub const TYPE_SSHFP: u16 = 44;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_DHCID: u16 = 49;
pub const TYPE_NSEC3: u16 = 50;
pub const TYPE_NSEC3PARAM: u16 = 51;
pub const TYPE_TLSA: u16 = 52;
pub const TYPE_SMIMEA: u16 = 53;
pub const TYPE_HIP: u16 = 55;
pub const TYPE_NINFO: u16 = 56;
pub const TYPE_RKEY: u16 = 57;
pub const TYPE_TALINK: u16 = 58;
pub const TYPE_CDS: u16 = 59;
pub const TYPE_CDNSKEY: u16 = 60;
pub const TYPE_OPENPGPKEY: u16 = 61;
pub const TYPE_CSYNC: u16 = 62;
pub const TYPE_ZONEMD: u16 = 63;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_SPF: u16 = 99;
pub const TYPE_UINFO: u16 = 100;
pub const TYPE_UID: u16 = 101;
pub const TYPE_GID: u16 = 102;
pub const TYPE_UNSPEC: u16 = 103;
pub const TYPE_NID: u16 = 104;
pub const TYPE_L32: u16 = 105;
pub const TYPE_L64: u16 = 106;
pub const TYPE_LP: u16 = 107;
pub const TYPE_EUI48: u16 = 108;
pub const TYPE_EUI64: u16 = 109;
pub const TYPE_URI: u16 = 256;
pub const TYPE_CAA: u16 = 257;
pub const TYPE_AVC: u16 = 258;

pub const TYPE_TKEY: u16 = 249;
pub const TYPE_TSIG: u16 = 250;

// valid Question.Qtype only
pub const TYPE_IXFR: u16 = 251;
pub const TYPE_AXFR: u16 = 252;
pub const TYPE_MAILB: u16 = 253;
pub const TYPE_MAILA: u16 = 254;
pub const TYPE_ANY: u16 = 255;

pub const TYPE_TA: u16 = 32768;
pub const TYPE_DLV: u16 = 32769;
pub const TYPE_RESERVED: u16 = 65535;


// CLASS
pub const CLASS_INET: u16 = 1;
pub const CLASS_CSNET: u16 = 2;
pub const CLASS_CHAOS: u16 = 3;
pub const CLASS_HESIOD: u16 = 4;
pub const CLASS_NONE: u16 = 254;
pub const CLASS_ANY: u16 = 255;


// RESPONSE CODE
pub const RCODE_SUCCESS: u16 = 0;
pub const RCODE_FORMAT_ERROR: u16 = 1;
pub const RCODE_SERVER_FAILURE: u16 = 2;
pub const RCODE_NAME_ERROR: u16 = 3;
pub const RCODE_NOT_IMPLEMENTED: u16 = 4;
pub const RCODE_REFUSED: u16 = 5;
pub const RCODE_YXDOMAIN: u16 = 6;
pub const RCODE_YXRRSET: u16 = 7;
pub const RCODE_NXRRSET: u16 = 8;
pub const RCODE_NOT_AUTH: u16 = 9;
pub const RCODE_NOT_ZONE: u16 = 10;
pub const RCODE_BAD_SIG: u16 = 16;
pub const RCODE_BAD_VERS: u16 = 16;
pub const RCODE_BAD_KEY: u16 = 17;
pub const RCODE_BAD_TIME: u16 = 18;
pub const RCODE_BAD_MODE: u16 = 19;
pub const RCODE_BAD_NAME: u16 = 20;
pub const RCODE_BAD_ALG: u16 = 21;
pub const RCODE_BAD_TRUNC: u16 = 22;
pub const RCODE_BAD_COOKIE: u16 = 23;


// Message Opcodes. There is no 3.
pub const OPCODE_QUERY: u16 = 0;
pub const OPCODE_IQUERY: u16 = 1;
pub const OPCODE_STATUS: u16 = 2;
pub const OPCODE_NOTIFY: u16 = 4;
pub const OPCODE_UPDATE: u16 = 5;
