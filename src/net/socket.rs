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

/// 地址是否适合对外通告/存储（可达性判断）。
/// 过滤掉不可路由/不可达的地址，保留 loopback（本机多实例联调用）、
/// 公网 v4、全局 v6 及内网 v4（同一局域网内可达）。
pub fn filter_reachable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_multicast() // 224.0.0.0/4
                && !v.is_link_local() // 169.254.0.0/16
        }
        IpAddr::V6(v) => {
            let seg = v.segments();
            let first = seg[0];
            let second = seg[1];
            !v.is_unspecified()
                && !v.is_multicast() // ff00::/8
                // fe80::/10 link-local（无 zone id 不可用）
                && !(first == 0xfe80)
                // fc00::/7 ULA（不可跨路由）
                && !(first == 0xfc00 || first == 0xfd00)
                // 未指派的 0x0000 前缀中非 loopback 的（如 ::ffff 已由 mapped 单独处理）
                && (first != 0x0000 || second != 0x0000 || seg[2] != 0 || seg[3] != 1)
        }
    }
}

/// 判断是否为公网（全局）IPv4 地址。
/// 排除回环 / 链路本地 / 多播 / 未指定 / 内网私有 (RFC1918) / CGNAT (RFC6598)。
pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    let v = u32::from_be_bytes(ip.octets());
    let in_net = |net: u32, prefix: u8| {
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        (v & mask) == (net & mask)
    };
    !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !ip.is_link_local() // 169.254.0.0/16
        && !ip.is_private() // RFC1918: 10/8、172.16/12、192.168/16
        && !in_net(0x6440_0000, 10) // 100.64.0.0/10 CGNAT
}

/// 格式化 `IP:port` / `[v6]:port`（端口为 UDP 监听端口，动态通告必须携带）。
pub fn fmt_ip_port(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
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

    #[test]
    fn filter_reachable_classifies() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // 应过滤
        assert!(!filter_reachable(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))); // link-local
        assert!(!filter_reachable(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)))); // ULA
        assert!(!filter_reachable(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1)))); // 多播
        assert!(!filter_reachable(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)))); // 链路本地
        assert!(!filter_reachable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)))); // 多播
        assert!(!filter_reachable(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))); // 未指定
        assert!(!filter_reachable(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))); // :: 未指定
        // 应保留
        assert!(filter_reachable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))); // loopback（联调）
        assert!(filter_reachable(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)))); // 内网（局域网可达）
        assert!(filter_reachable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(filter_reachable(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(filter_reachable(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))); // ::1
    }

    #[test]
    fn fmt_ip_port_variants() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert_eq!(fmt_ip_port(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1212), "1.2.3.4:1212");
        assert_eq!(fmt_ip_port(IpAddr::V6(Ipv6Addr::new(0x240e, 0, 0, 0, 0, 0, 0, 1)), 1212), "[240e::1]:1212");
    }

    #[test]
    fn public_v4_classification() {
        use std::net::Ipv4Addr;
        // 公网
        assert!(is_public_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_v4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(is_public_v4(Ipv4Addr::new(203, 0, 113, 5)));
        // 内网/保留
        assert!(!is_public_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(!is_public_v4(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(224, 0, 0, 1))); // 多播
    }
}