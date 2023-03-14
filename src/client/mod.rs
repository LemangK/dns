use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use bytes::BytesMut;
use smallvec::SmallVec;
use crate::{full_domain, Msg, types};
use crate::msg::Question;

pub type DnsIpVec = SmallVec<[IpAddr; 5]>;

/// Lookup host
pub async fn lookup_host(
    socket: tokio::net::UdpSocket,
    mut ns: SocketAddr,
    domain: &str,
    ipv4: bool,
    ipv6: bool,
) -> io::Result<DnsIpVec> {
    let mut buf = BytesMut::new();
    let mut ips = DnsIpVec::with_capacity(5);

    if let Ok(addr) = socket.local_addr() {
        match (ns, addr) {
            (SocketAddr::V4(val), SocketAddr::V6(_)) => {
                ns = SocketAddrV6::new(val.ip().to_ipv6_mapped(), val.port(), 0, 0).into();
            }
            _ => {}
        }
    }

    async fn do_request(
        ns: SocketAddr,
        socket: &tokio::net::UdpSocket,
        domain: &str,
        buf: &mut BytesMut,
        typ: u16,
        ips: &mut SmallVec<[IpAddr; 5]>,
    ) -> io::Result<()> {
        const BUF_SIZE: usize = 512; // MinMsgSize = 512, MAX: 65535

        buf.clear();
        {
            let mut msg = Msg::new();
            msg.hdr.recursion_desired = true;
            msg.question.push(Question {
                name: full_domain(domain),
                q_type: typ,
                q_class: types::CLASS_INET,
            });
            msg.to_buf_with(buf)?;
        }

        socket.send_to(buf.as_ref(), ns).await?;
        buf.resize(BUF_SIZE, 0);
        let n = socket.recv(&mut buf[..]).await?;

        let res = Msg::unpack_answer(&buf[..n])?.ips();
        if !res.is_empty() {
            ips.extend(res);
        }
        Ok(())
    }

    if ipv4 {
        do_request(ns, &socket, domain, &mut buf, types::TYPE_A, &mut ips).await?;
    }
    if ipv6 {
        do_request(ns, &socket, domain, &mut buf, types::TYPE_AAAA, &mut ips).await?;
    }

    Ok(ips)
}