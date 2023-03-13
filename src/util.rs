use std::fmt::{Formatter, Write};
use std::{fmt, io};
use std::io::Cursor;
use bytes::{BufMut, BytesMut};
use crate::DomainString;
use crate::types::*;

const MAX_DOMAIN_NAME_WIRE_OCTETS: usize = 255; // See RFC 1035 section 2.3.4

const ESCAPED_BYTE_SMALL: &str = r#"\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031"#;

const ESCAPED_BYTE_LARGE: &str = r#"\127\128\129\130\131\132\133\134\135\136\137\138\139\140\141\142\143\144\145\146\147\148\149\150\151\152\153\154\155\156\157\158\159\160\161\162\163\164\165\166\167\168\169\170\171\172\173\174\175\176\177\178\179\180\181\182\183\184\185\186\187\188\189\190\191\192\193\194\195\196\197\198\199\200\201\202\203\204\205\206\207\208\209\210\211\212\213\214\215\216\217\218\219\220\221\222\223\224\225\226\227\228\229\230\231\232\233\234\235\236\237\238\239\240\241\242\243\244\245\246\247\248\249\250\251\252\253\254\255"#;

const MAX_COMPRESSION_POINTERS: usize = (MAX_DOMAIN_NAME_WIRE_OCTETS + 1) / 2 - 2;

#[inline]
fn error<E>(msg: E) -> io::Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, msg)
}


#[cfg(feature = "with_idna")]
fn label_to_ascii(label: &str) -> Result<String, unic_idna::Errors> {
    let flags = unic_idna::Flags {
        use_std3_ascii_rules: false,
        transitional_processing: false,
        verify_dns_length: true,
    };
    unic_idna::to_ascii(label, flags)
}

#[cfg(not(feature = "with_idna"))]
fn label_to_ascii(label: &str) -> Result<DomainString, ()> {
    Ok(DomainString::from(label))
}

pub fn set_rd(buf: &mut BytesMut, data: &[u8]) {
    set_rd_length(buf.as_mut(), data.len() as u16);
    buf.put_slice(data);
}

pub fn set_rd_length(buf: &mut [u8], v: u16) {
    set_value_offset(buf, buf.len() - 2, v)
}

pub fn set_value_offset(buf: &mut [u8], start: usize, v: u16) {
    (&mut buf[start..start + 2]).copy_from_slice(&v.to_be_bytes()[..])
}

pub fn cal_domain_name_len(input: &str) -> usize {
    let mut size: usize = 0;
    for label in input.split('.') {
        if label.is_empty() {
            continue;
        }
        if let Ok(label_idn) = label_to_ascii(label) {
            if let Ok(_) = u8::try_from(label_idn.len()) {
                size += 1 + label_idn.as_bytes().len();
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }
    size + 1
}

pub fn pack_domain_name(input: &str, buf: &mut BytesMut) -> io::Result<()> {
    for label in input.split('.') {
        if label.is_empty() {
            continue;
        }

        let label_idn = label_to_ascii(label).map_err(|e| {
            tracing::warn!("Could not encode label {:?}: {:?}", label, e);
            io::Error::new(io::ErrorKind::Other, label)
        })?;

        match u8::try_from(label_idn.len()) {
            Ok(length) => {
                buf.put_u8(length);
                buf.put_slice(label_idn.as_bytes());
            }
            Err(e) => {
                tracing::warn!("Could not encode label {:?}: {}", label, e);
                return Err(io::Error::new(io::ErrorKind::Other, label));
            }
        }
    }
    buf.put_u8(0); // terminate the string
    Ok(())
}

pub fn unpack_domain_name_cur(cur: &mut Cursor<&[u8]>) -> io::Result<DomainString> {
    let (name, pos) = unpack_domain_name(cur.get_ref(), cur.position() as usize)?;
    cur.set_position(pos as u64);
    Ok(name)
}

pub fn skip_domain_name(cur: &mut Cursor<&[u8]>) -> bool {
    if let Some(pos) = __skip_domain_name(cur.get_ref(), cur.position() as usize) {
        cur.set_position(pos as u64);
        true
    } else {
        false
    }
}

fn __skip_domain_name(buf: &[u8], mut off: usize) -> Option<usize> {
    let mut off1 = 0usize;
    let lenmsg = buf.len();
    let mut budget = MAX_DOMAIN_NAME_WIRE_OCTETS as isize;
    let mut ptr = 0usize; // number of pointers followed

    loop {
        if off >= lenmsg {
            return None;
        }
        let c = buf[off];
        off += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0x00 {
                    // end of name
                    break;
                }
                // literal string
                if off + c as usize > lenmsg {
                    return None;
                }
                budget -= c as isize + 1;
                if budget < 0 {
                    return None;
                }
                off += c as usize;
            }
            0xC0 => {
                // pointer to somewhere else in msg.
                // remember location after first ptr,
                // since that's how many bytes we consumed.
                // also, don't follow too many pointers --
                // maybe there's a loop.
                if off >= lenmsg {
                    return None;
                }
                let c1 = buf[off];
                off += 1;
                if ptr == 0 {
                    off1 = off;
                }
                ptr += 1;
                if ptr > MAX_COMPRESSION_POINTERS {
                    return None;
                }
                // pointer should guarantee that it advances and points forwards at least
                // but the condition on previous three lines guarantees that it's
                // at least loop-free
                let x = ((c as usize) ^ 0xc0) << 8;
                off = x | c1 as usize;
            }
            _ => {
                // 0x80 and 0x40 are reserved
                return None;
            }
        }
    }
    if ptr == 0 {
        off1 = off;
    }
    return Some(off1);
}

fn unpack_domain_name(buf: &[u8], mut off: usize) -> io::Result<(DomainString, usize)> {
    // 12 in 32bit is inner
    let mut s = DomainString::with_capacity(12);
    let mut off1 = 0usize;
    let lenmsg = buf.len();
    let mut budget = MAX_DOMAIN_NAME_WIRE_OCTETS as isize;
    let mut ptr = 0usize; // number of pointers followed

    loop {
        if off >= lenmsg {
            return Err(error("buffer size too small"));
        }
        let c = buf[off];
        off += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0x00 {
                    // end of name
                    break;
                }
                // literal string
                if off + c as usize > lenmsg {
                    return Err(error("buffer size too small"));
                }
                budget -= c as isize + 1;
                if budget < 0 {
                    return Err(error(format!(
                        "domain name exceeded {} wire-format octets",
                        MAX_DOMAIN_NAME_WIRE_OCTETS
                    )));
                }
                for &b in &buf[off..off + c as usize] {
                    if is_domain_name_label_special(b) {
                        s.push('\\');
                        s.push(b as char);
                    } else if b < b' ' || b > b'~' {
                        escape_byte(b, &mut s);
                    } else {
                        s.push(b as char);
                    }
                }
                s.push('.');
                off += c as usize;
            }
            0xC0 => {
                // pointer to somewhere else in msg.
                // remember location after first ptr,
                // since that's how many bytes we consumed.
                // also, don't follow too many pointers --
                // maybe there's a loop.
                if off >= lenmsg {
                    return Err(error("buffer size too small"));
                }
                let c1 = buf[off];
                off += 1;
                if ptr == 0 {
                    off1 = off;
                }
                ptr += 1;
                if ptr > MAX_COMPRESSION_POINTERS {
                    return Err(error("too many compression pointers"));
                }
                // pointer should guarantee that it advances and points forwards at least
                // but the condition on previous three lines guarantees that it's
                // at least loop-free
                let x = ((c as usize) ^ 0xc0) << 8;
                off = x | c1 as usize;
            }
            _ => {
                // 0x80 and 0x40 are reserved
                return Err(error("bad rdata"));
            }
        }
    }
    if ptr == 0 {
        off1 = off;
    }
    if s.len() == 0 {
        return Ok((DomainString::from("."), off1));
    }
    return Ok((s, off1));
}

// escape_byte returns the \DDD escaping of b which must
// satisfy b < ' ' || b > '~'.
fn escape_byte(mut b: u8, buf: &mut DomainString) {
    if b < b' ' {
        let data = &ESCAPED_BYTE_SMALL.as_bytes()[b as usize * 4..b as usize * 4 + 4];
        buf.push_str(String::from_utf8_lossy(data).as_ref());
        return;
    }

    b -= b'~' + 1;
    // The cast here is needed as b*4 may overflow byte.
    let data = &ESCAPED_BYTE_LARGE.as_bytes()[b as usize * 4..b as usize * 4 + 4];
    buf.push_str(String::from_utf8_lossy(data).as_ref());
}

// is_domain_name_label_special returns true if
// a domain name label byte should be prefixed
// with an escaping backslash.
fn is_domain_name_label_special(b: u8) -> bool {
    return match b {
        b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\' => true,
        _ => false,
    };
}

#[inline]
fn is_digit(b: char) -> bool { return b >= '0' && b <= '9'; }

#[inline]
fn ddd_string_to_byte(s: &[u8]) -> u8 {
    (s[0] - b'0') * 100 + (s[1] - b'0') * 10 + (s[2] - b'0')
}

fn next_byte(s: &str, offset: usize) -> (u8, usize) {
    if offset >= s.len() {
        return (0, 0);
    }
    let ns = s.as_bytes();
    if ns[offset] != b'\\' {
        return (ns[offset], 1);
    }
    match s.len() - offset {
        1 => {// dangling escape
            return (0, 0);
        }
        2 | 3 => {// too short to be \ddd
        }
        _ => { // maybe \ddd
            if is_digit(ns[offset + 1] as char)
                && is_digit(ns[offset + 2] as char)
                && is_digit(ns[offset + 3] as char) {
                return (ddd_string_to_byte(&ns[offset + 1..]), 4);
            }
        }
    }
    // not \ddd, just an RFC 1035 "quoted" character
    return (ns[offset + 1], 2);
}

pub fn name_string(s: &str, f: &mut Formatter<'_>) -> fmt::Result {
    f.write_str(s)
    // let ns = s.as_bytes();
    // let mut first = true;
    // let mut i: usize = 0;
    // loop {
    //     if i >= ns.len() - 1 {
    //         break;
    //     }
    //     if ns[i] == b'.' {
    //         if first {
    //             f.write_str(".")?;
    //         }
    //         i += 1;
    //         continue;
    //     }
    //     let (b, n) = next_byte(s, i);
    //     if n == 0 {
    //         if first {
    //             if let Ok(s) = std::str::from_utf8(&ns[..i]) {
    //                 f.write_str(s)?;
    //             }
    //         }
    //         break;
    //     }
    //     if is_domain_name_label_special(b) {
    //         if let Ok(s) = std::str::from_utf8(&ns[..i]) {
    //             f.write_str(s)?;
    //         }
    //         f.write_str("\\")?;
    //         f.write_char(b as char)?;
    //     } else if (b as char) < ' ' || (b as char) > '~' {
    //         // pass
    //     } else {
    //         f.write_char(b as char)?;
    //     }
    //     i += n;
    // }
    // Ok(())
}

pub fn rcode_string(code: u16) -> &'static str {
    match code {
        RCODE_SUCCESS => "NOERROR",
        RCODE_FORMAT_ERROR => "FORMERR",
        RCODE_SERVER_FAILURE => "SERVFAIL",
        RCODE_NAME_ERROR => "NXDOMAIN",
        RCODE_NOT_IMPLEMENTED => "NOTIMP",
        RCODE_REFUSED => "REFUSED",
        RCODE_YXDOMAIN => "YXDOMAIN", // See RFC 2136
        RCODE_YXRRSET => "YXRRSET",
        RCODE_NXRRSET => "NXRRSET",
        RCODE_NOT_AUTH => "NOTAUTH",
        RCODE_NOT_ZONE => "NOTZONE",
        RCODE_BAD_SIG => "BADSIG", // Also known as RcodeBadVers, see RFC 6891
        //	RcodeBadVers:        "BADVERS",
        RCODE_BAD_KEY => "BADKEY",
        RCODE_BAD_TIME => "BADTIME",
        RCODE_BAD_MODE => "BADMODE",
        RCODE_BAD_NAME => "BADNAME",
        RCODE_BAD_ALG => "BADALG",
        RCODE_BAD_TRUNC => "BADTRUNC",
        RCODE_BAD_COOKIE => "BADCOOKIE",
        _ => "Unknown"
    }
}

pub fn opcode_string(code: u16) -> &'static str {
    match code {
        OPCODE_QUERY => "QUERY",
        OPCODE_IQUERY => "IQUERY",
        OPCODE_STATUS => "STATUS",
        OPCODE_NOTIFY => "NOTIFY",
        OPCODE_UPDATE => "UPDATE",
        _ => "Unknown"
    }
}

pub fn qtype_string(code: u16, f: &mut Formatter<'_>) -> fmt::Result {
    let s = match code {
        TYPE_A => "A",
        TYPE_AAAA => "AAAA",
        TYPE_AFSDB => "AFSDB",
        TYPE_ANY => "ANY",
        TYPE_APL => "APL",
        TYPE_ATMA => "ATMA",
        TYPE_AVC => "AVC",
        TYPE_AXFR => "AXFR",
        TYPE_CAA => "CAA",
        TYPE_CDNSKEY => "CDNSKEY",
        TYPE_CDS => "CDS",
        TYPE_CERT => "CERT",
        TYPE_CNAME => "CNAME",
        TYPE_CSYNC => "CSYNC",
        TYPE_DHCID => "DHCID",
        TYPE_DLV => "DLV",
        TYPE_DNAME => "DNAME",
        TYPE_DNSKEY => "DNSKEY",
        TYPE_DS => "DS",
        TYPE_EID => "EID",
        TYPE_EUI48 => "EUI48",
        TYPE_EUI64 => "EUI64",
        TYPE_GID => "GID",
        TYPE_GPOS => "GPOS",
        TYPE_HINFO => "HINFO",
        TYPE_HIP => "HIP",
        TYPE_HTTPS => "HTTPS",
        TYPE_ISDN => "ISDN",
        TYPE_IXFR => "IXFR",
        TYPE_KEY => "KEY",
        TYPE_KX => "KX",
        TYPE_L32 => "L32",
        TYPE_L64 => "L64",
        TYPE_LOC => "LOC",
        TYPE_LP => "LP",
        TYPE_MAILA => "MAILA",
        TYPE_MAILB => "MAILB",
        TYPE_MB => "MB",
        TYPE_MD => "MD",
        TYPE_MF => "MF",
        TYPE_MG => "MG",
        TYPE_MINFO => "MINFO",
        TYPE_MR => "MR",
        TYPE_MX => "MX",
        TYPE_NAPTR => "NAPTR",
        TYPE_NID => "NID",
        TYPE_NIMLOC => "NIMLOC",
        TYPE_NINFO => "NINFO",
        TYPE_NS => "NS",
        TYPE_NSEC => "NSEC",
        TYPE_NSEC3 => "NSEC3",
        TYPE_NSEC3PARAM => "NSEC3PARAM",
        TYPE_NULL => "NULL",
        TYPE_NXT => "NXT",
        TYPE_NONE => "None",
        TYPE_OPENPGPKEY => "OPENPGPKEY",
        TYPE_OPT => "OPT",
        TYPE_PTR => "PTR",
        TYPE_PX => "PX",
        TYPE_RKEY => "RKEY",
        TYPE_RP => "RP",
        TYPE_RRSIG => "RRSIG",
        TYPE_RT => "RT",
        TYPE_RESERVED => "Reserved",
        TYPE_SIG => "SIG",
        TYPE_SMIMEA => "SMIMEA",
        TYPE_SOA => "SOA",
        TYPE_SPF => "SPF",
        TYPE_SRV => "SRV",
        TYPE_SSHFP => "SSHFP",
        TYPE_SVCB => "SVCB",
        TYPE_TA => "TA",
        TYPE_TALINK => "TALINK",
        TYPE_TKEY => "TKEY",
        TYPE_TLSA => "TLSA",
        TYPE_TSIG => "TSIG",
        TYPE_TXT => "TXT",
        TYPE_UID => "UID",
        TYPE_UINFO => "UINFO",
        TYPE_UNSPEC => "UNSPEC",
        TYPE_URI => "URI",
        TYPE_X25 => "X25",
        TYPE_ZONEMD => "ZONEMD",
        TYPE_NSAPPTR => "NSAP-PTR",
        _ => return f.write_fmt(format_args!("TYPE{}", code)),
    };
    f.write_str(s)
}

pub fn qclass_string(code: u16, f: &mut Formatter<'_>) -> fmt::Result {
    let s = match code {
        CLASS_INET => "IN",
        CLASS_CSNET => "CS",
        CLASS_CHAOS => "CH",
        CLASS_HESIOD => "HS",
        CLASS_NONE => "NONE",
        CLASS_ANY => "ANY",
        _ => return f.write_fmt(format_args!("CLASS{}", code)),
    };
    f.write_str(s)
}


pub trait ResizeMut {
    fn extend_split(&mut self, additional: usize) -> &mut [u8];
    fn put_front(&mut self, data: &[u8]);
}

impl ResizeMut for BytesMut {
    fn extend_split(&mut self, additional: usize) -> &mut [u8] {
        let l = self.len();
        self.resize(l + additional, 0);
        let (_, add) = self.split_at_mut(l);
        add
    }
    fn put_front(&mut self, _data: &[u8]) {}
}
