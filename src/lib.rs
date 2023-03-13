use std::io;

pub mod msg;
mod util;
pub mod types;

pub type DomainString = smallstr::SmallString<[u8; 24]>;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    BufTooSmall,
    InvalidSubnet(ipnetwork::IpNetworkError),
    BadExtendedResponseCode,
    BadResponseCode,
    InvalidRdLength,
    HexError(hex::FromHexError),
    UnpackOverflow(String),
    Io(io::Error),
    Error(String),
}

impl Error {
    pub fn new<S: Into<String>>(text: S) -> Self {
        Self::Error(text.into())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(value: hex::FromHexError) -> Self {
        Self::HexError(value)
    }
}

impl From<ipnetwork::IpNetworkError> for Error {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        Self::InvalidSubnet(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn full_domain<S: Into<String>>(s: S) -> DomainString {
    let mut s = s.into();
    if !s.ends_with('.') {
        s.push('.')
    }
    s.into()
}

pub fn clear_full_domain(s: &str) -> &str {
    if s.ends_with('.') {
        &s[..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::time::Instant;
    use bytes::BytesMut;
    use crate::{clear_full_domain, full_domain, types};
    use crate::types::{EDNS0, RecourseRecord};
    use crate::types::edns::edns0;
    use super::msg::*;

    #[test]
    pub fn test_pp() {
        let x = ipnetwork::Ipv4Network::new(Ipv4Addr::new(114, 114, 114, 114), 24).unwrap();
        eprintln!("{:?}", x);
        eprintln!("{:?}", x.network());
    }

    #[test]
    pub fn test_pack() {
        let now = Instant::now();
        let mut msg = Msg::new();
        msg.set_question(full_domain("www.google.com"), types::TYPE_A);
        msg.answer.push(types::A::new(
            full_domain("www.google.com"),
            types::CLASS_INET,
            120,
            Ipv4Addr::new(114, 114, 114, 114),
        ).into());
        msg.answer.push(types::CNAME::new(
            full_domain("www.google.com"),
            types::CLASS_INET,
            120,
            "www.google.com.abc.".into(),
        ).into());

        let mut opt = types::Opt {
            hdr: RecourseRecordHdr {
                name: ".".into(),
                typ: types::TYPE_OPT,
                class: 0,
                ttl: 0,
                rd_length: 0,
            },
            option: vec![],
        };
        opt.set_udp_size(1350);
        opt.set_extended_r_code(0xfe00);
        opt.set_do(&[]);
        opt.option.push(EDNS0::SubNet(edns0::SubNet::new(
            Ipv4Addr::new(114, 114, 114, 114).into(),
            24,
            0,
        )));
        msg.additional.push(opt.into());

        let mut buf = BytesMut::new();
        msg.pack(&mut buf).unwrap();
        eprintln!("{:?}", buf.as_ref());

        {
            let data = buf.as_ref();
            let msg = Msg::unpack(&data[..]).unwrap();
            eprintln!("{}", msg);
        }

        eprintln!("Time {:?}", now.elapsed());
    }

    #[test]
    pub fn test_unpack() {
        let data = [
            // 0x43, 0x1c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            // 0x00, 0x00, 0x00, 0x00, 0x03, 0x73, 0x70, 0x31,
            // 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63,
            // 0x6f, 0x6d, 0x00, 0x00, 0x41, 0x00, 0x01

            // 0xe7, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            // 0x00, 0x00, 0x00, 0x00, 0x03, 0x31, 0x38, 0x34,
            // 0x01, 0x31, 0x01, 0x31, 0x02, 0x31, 0x30, 0x07,
            // 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04,
            // 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00,
            // 0x01


            0u8, 12, 129, 128, 0, 1, 0, 3, 0, 0, 0, 0, 3, 119, 119, 119, 5, 98, 97, 105, 100, 117,
            3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 5, 0, 1, 0, 0, 0, 189, 0, 15, 3, 119, 119,
            119, 1, 97, 6, 115, 104, 105, 102, 101, 110, 192, 22, 192, 43, 0, 1, 0, 1, 0, 0, 0,
            170, 0, 4, 14, 215, 177, 38, 192, 43, 0, 1, 0, 1, 0, 0, 0, 170, 0, 4, 14, 215, 177, 39,
        ];

        let msg = Msg::unpack(&data[..]).unwrap();
        let msg2 = Msg::unpack_questions(&data[..]).unwrap();

        println!("msg: {}", msg);
        println!("msg2: {:?}", msg2);
    }
}
