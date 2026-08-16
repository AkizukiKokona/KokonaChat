//! 双栈 UDP 套接字：同时监听 IPv6 与 IPv4，优先使用 IPv6。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

/// 绑定结果：UDP 套接字 + 是否为 IPv6 双栈。
pub struct BoundSocket {
    pub sock: UdpSocket,
    pub is_v6: bool,
}

/// 优先绑定 IPv6 双栈（[::]:port，关闭 v6only 以同时收 IPv4），
/// IPv6 不可用时回退 IPv4（0.0.0.0:port）。
pub async fn bind_dual(port: u16) -> Result<BoundSocket> {
    if let Ok(b) = bind_v6(port) {
        return Ok(b);
    }
    bind_v4(port).context("IPv6 与 IPv4 均无法绑定")
}

fn bind_v6(port: u16) -> Result<BoundSocket> {
    let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // 注意：Windows 上不开 SO_REUSEADDR（该语义在 Windows 与 Linux 不同，
    // 开启后可能与其它套接字“假共享”同一端口导致收不到入站包）。
    // 关闭 V6ONLY -> 双栈：IPv4 流量以 v4-mapped (::ffff:a.b.c.d) 形式到达。
    sock.set_only_v6(false)?;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(BoundSocket { sock: UdpSocket::from_std(std_sock)?, is_v6: true })
}

fn bind_v4(port: u16) -> Result<BoundSocket> {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // 见 bind_v6：Windows 上不设 SO_REUSEADDR。
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(BoundSocket { sock: UdpSocket::from_std(std_sock)?, is_v6: false })
}

/// 发送地址规范化：IPv6 双栈套接字无法直接 sendto 纯 IPv4 地址，
/// 需转换为 v4-mapped 形式 `::ffff:a.b.c.d`。
pub fn to_send_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)),
        other => other,
    }
}

/// 接收地址规范化：v4-mapped v6 还原为 v4。
pub fn normalize_recv(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        other => other,
    }
}

/// 将 SocketAddr 格式化为可持久化的 `ip:port` / `[v6]:port` 文本。
/// 端口是关键信息：同一 IP 上的多个用户靠端口区分，必须保留。
pub fn fmt_addr(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

/// 解析 "ip" / "ip:port" / "[v6]:port" / "::v6:port"（无方括号的 IPv6 + 端口），缺省端口用 default_port。
pub fn parse_sockaddr(s: &str, default_port: u16) -> Result<SocketAddr> {
    let text = s.trim();
    if let Ok(a) = text.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    // 无方括号的 IPv6 + 端口，形如 "::1:12222"；在最后一个冒号处拆开。
    if let Some(pos) = text.rfind(':') {
        let head = &text[..pos];
        let port = &text[pos + 1..];
        if let Ok(port) = port.parse::<u16>() {
            if let Ok(ip) = head.parse::<IpAddr>() {
                return Ok(SocketAddr::new(ip, port));
            }
        }
    }
    if let Ok(a) = format!("[{}]:{}", text, default_port).parse::<SocketAddr>() {
        return Ok(a);
    }
    anyhow::bail!("无法解析 IP 地址: {}", s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sockaddr_variants() {
        assert_eq!(parse_sockaddr("1.2.3.4", 1212).unwrap().port(), 1212);
        assert_eq!(parse_sockaddr("1.2.3.4:9999", 1212).unwrap().port(), 9999);
        assert_eq!(parse_sockaddr("2001:db8::1", 1212).unwrap().port(), 1212);
        assert_eq!(parse_sockaddr("[2001:db8::1]:7777", 1212).unwrap().port(), 7777);
        assert_eq!(parse_sockaddr("::1:12222", 1212).unwrap(), "[::1]:12222".parse().unwrap());
    }

    #[test]
    fn mapped_roundtrip() {
        let v4: SocketAddr = "1.2.3.4:1212".parse().unwrap();
        let mapped = to_send_addr(v4);
        assert!(mapped.is_ipv6());
        assert_eq!(normalize_recv(mapped), v4);
    }

    #[test]
    fn fmt_addr_keeps_port() {
        assert_eq!(fmt_addr("1.2.3.4:9999".parse().unwrap()), "1.2.3.4:9999");
        assert_eq!(fmt_addr("[2001:db8::1]:7777".parse().unwrap()), "[2001:db8::1]:7777");
    }
}