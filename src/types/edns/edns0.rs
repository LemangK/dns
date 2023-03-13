use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{BigEndian, ByteOrder};
use crate::{Error, Result};
use bytes::{BufMut, BytesMut};
use crate::util::ResizeMut;

// EDNS0 Option codes.
// long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
pub const EDNS0LLQ: u16 = 0x1;
// update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
pub const EDNS0UL: u16 = 0x2;
// nsid (See RFC 5001)
pub const EDNS0NSID: u16 = 0x3;
// ENUM Source-URI draft: https://datatracker.ietf.org/doc/html/draft-kaplan-enum-source-uri-00
pub const EDNS0ESU: u16 = 0x4;
// DNSSEC Algorithm Understood
pub const EDNS0DAU: u16 = 0x5;
// DS Hash Understood
pub const EDNS0DHU: u16 = 0x6;
// NSEC3 Hash Understood
pub const EDNS0N3U: u16 = 0x7;
// client-subnet (See RFC 7871)
pub const EDNS0SUBNET: u16 = 0x8;
// EDNS0 expire
pub const EDNS0EXPIRE: u16 = 0x9;
// EDNS0 Cookie
pub const EDNS0COOKIE: u16 = 0xa;
// EDNS0 tcp keep alive (See RFC 7828)
pub const EDNS0TCPKEEPALIVE: u16 = 0xb;
// EDNS0 padding (See RFC 7830)
pub const EDNS0PADDING: u16 = 0xc;
// EDNS0 extended DNS errors (See RFC 8914)
pub const EDNS0EDE: u16 = 0xf;
// Beginning of range reserved for local/experimental use (See RFC 6891)
pub const EDNS0LOCALSTART: u16 = 0xFDE9;
// End of range reserved for local/experimental use (See RFC 6891)
pub const EDNS0LOCALEND: u16 = 0xFFFE;
// DNSSEC OK
pub const _DO: u16 = 1 << 15;

pub trait IEdns0: Display {
    type Item;
    fn option(&self) -> u16;
    fn pack(&self, buf: &mut BytesMut) -> Result<()>;
    fn unpack(code: u16, bs: &[u8]) -> Result<Self::Item>;
}

#[derive(Debug, Clone)]
pub enum EDNS0 {
    Nid(NSID),
    SubNet(SubNet),
    Local(LOCAL),
}

impl Display for EDNS0 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EDNS0::Nid(val) => val.fmt(f),
            EDNS0::SubNet(val) => val.fmt(f),
            EDNS0::Local(val) => val.fmt(f),
        }
    }
}

impl IEdns0 for EDNS0 {
    type Item = EDNS0;

    fn option(&self) -> u16 {
        match self {
            EDNS0::Nid(val) => val.option(),
            EDNS0::SubNet(val) => val.option(),
            EDNS0::Local(val) => val.option(),
        }
    }

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            EDNS0::Nid(val) => val.pack(buf),
            EDNS0::SubNet(val) => val.pack(buf),
            EDNS0::Local(val) => val.pack(buf),
        }
    }

    fn unpack(code: u16, bs: &[u8]) -> Result<Self::Item> {
        Ok(match code {
            EDNS0NSID => Self::Nid(NSID::unpack(code, bs)?),
            EDNS0SUBNET => Self::SubNet(SubNet::unpack(code, bs)?),
            _ => Self::Local(LOCAL::unpack(code, bs)?),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NSID {
    pub nsid: String,
}

impl IEdns0 for NSID {
    type Item = NSID;

    fn option(&self) -> u16 {
        EDNS0NSID
    }

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        let add = buf.extend_split(self.nsid.len() / 2);
        hex::decode_to_slice(&self.nsid, add)?;
        Ok(())
    }

    fn unpack(_code: u16, bs: &[u8]) -> Result<Self::Item> {
        Ok(Self {
            nsid: hex::encode(bs)
        })
    }
}

impl Display for NSID {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.nsid)
    }
}

#[derive(Debug, Clone)]
pub struct SubNet {
    pub family: u16,
    pub source_netmask: u8,
    pub source_scope: u8,
    pub address: IpAddr,
}

impl IEdns0 for SubNet {
    type Item = SubNet;

    fn option(&self) -> u16 {
        EDNS0SUBNET
    }

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16(self.family);
        buf.put_u8(self.source_netmask);
        buf.put_u8(self.source_scope);
        match self.family {
            0 => {
                if self.source_netmask != 0 {
                    return Err(Error::new("bad address family"));
                }
            }
            1 => {
                if self.source_netmask > 4/*ipv4*/ * 8 {
                    return Err(Error::new("bad netmask"));
                }
                let address = match self.address {
                    IpAddr::V4(val) => Some(val),
                    IpAddr::V6(val) => val.to_ipv4_mapped(),
                }.ok_or(Error::new("bad address"))?;
                let network = ipnetwork::Ipv4Network::new(address, self.source_netmask)?.network();
                buf.put_slice(&network.octets());
            }
            2 => {
                if self.source_netmask > 16/*ipv6*/ * 8 {
                    return Err(Error::new("bad netmask"));
                }
                let address = match self.address {
                    IpAddr::V4(val) => val.to_ipv6_mapped(),
                    IpAddr::V6(val) => val,
                };
                let network = ipnetwork::Ipv6Network::new(address, self.source_netmask)?.network();
                buf.put_slice(&network.octets());
            }
            _ => {
                return Err(Error::new("bad address family"));
            }
        }
        Ok(())
    }

    fn unpack(_code: u16, bs: &[u8]) -> Result<Self::Item> {
        if bs.len() < 4 {
            return Err(Error::BufTooSmall);
        }
        let family = BigEndian::read_u16(&bs[0..2]);
        let source_netmask = bs[2];
        let source_scope = bs[3];
        let address: IpAddr = match family {
            0 => {
                if source_netmask != 0 {
                    return Err(Error::new("bad address family"));
                }
                Ipv4Addr::UNSPECIFIED.into()
            }
            1 => {
                if source_netmask > 4 * 8 || source_scope > 4 * 8 {
                    return Err(Error::new("bad netmask"));
                }
                Ipv4Addr::from(BigEndian::read_u32(&bs[4..])).into()
            }
            2 => {
                if source_netmask > 16 * 8 || source_scope > 16 * 8 {
                    return Err(Error::new("bad netmask"));
                }
                Ipv6Addr::from(BigEndian::read_u128(&bs[4..])).into()
            }
            _ => {
                return Err(Error::new("bad address family"));
            }
        };
        Ok(Self {
            family,
            source_netmask,
            source_scope,
            address,
        })
    }
}

impl SubNet {
    pub fn new(address: IpAddr, source_netmask: u8, source_scope: u8) -> Self {
        Self {
            family: {
                if address.is_ipv4() {
                    1
                } else {
                    2
                }
            },
            source_netmask,
            source_scope,
            address,
        }
    }
}

impl Display for SubNet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.address, f)?;
        f.write_str("/")?;
        fmt::Display::fmt(&self.source_netmask, f)?;
        f.write_str("/")?;
        fmt::Display::fmt(&self.source_scope, f)
    }
}

#[derive(Debug, Clone)]
pub struct LOCAL {
    pub code: u16,
    pub data: Vec<u8>,
}

impl Display for LOCAL {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("")
    }
}

impl IEdns0 for LOCAL {
    type Item = LOCAL;

    fn option(&self) -> u16 {
        self.code
    }

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_slice(&self.data);
        Ok(())
    }

    fn unpack(code: u16, bs: &[u8]) -> Result<Self::Item> {
        Ok(Self {
            code,
            data: bs.to_vec(),
        })
    }
}

// Cookie option is used to add a DNS Cookie to a message.
pub struct Cookie {
    pub cookie: String, // hex-encoded cookie data
}

impl Display for Cookie {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.cookie)
    }
}

impl IEdns0 for Cookie {
    type Item = Cookie;

    fn option(&self) -> u16 {
        EDNS0COOKIE
    }

    fn pack(&self, buf: &mut BytesMut) -> Result<()> {
        let add = buf.extend_split(self.cookie.len() / 2);
        hex::decode_to_slice(&self.cookie, add)?;
        Ok(())
    }

    fn unpack(_code: u16, bs: &[u8]) -> Result<Self::Item> {
        Ok(Self {
            cookie: hex::encode(bs),
        })
    }
}


