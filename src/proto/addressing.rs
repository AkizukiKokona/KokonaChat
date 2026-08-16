//! 被动寻址 + 反向探针包结构。
//!
//! ADDR_QUERY 明文内部结构：
//!   q_type(1)=0x01 | target_id(32) | nonce_q(16) | fail_seq(4)
//! ADDR_ANSWER 明文内部结构：
//!   a_type(1)=0x01 命中 / 0x00 未知 | target_id(32) | nonce_q(16) 回显 |
//!   ip_count(2) | [ af(1:4|6) + ip_len(1) + ip ]*
//! IP_CHANGED 明文内部结构（反向探针：告知好友我的新 IP，要求回复）：
//!   p_type(1)=0x01 | probe_id(8) | ip_count(2) | [ af(1) + len(1) + ip ]*
//! IP_CHANGED_ACK 明文内部结构：
//!   probe_id(8) 回显
//! GOSSIP 明文内部结构（向共同好友广播"谁没收到我的新 IP"）：
//!   g_type(1)=0x01 | victim_count(2) | [victim_id(32)]* | ip_count(2) | [af+len+ip]*
//! PUSH_IP 明文内部结构（共同好友代投递某人的新 IP）：
//!   source_id(32) | ip_count(2) | [af+len+ip]*
//!
//! ## 共同好友安全校验（"一手校验，不能乱送"）
//! 所有上述包均满足：
//!   1) Ed25519 签名 + 好友列表校验  ⟹ "发送者是我方好友"；
//!   2) 对直接收件人 E2E 加密、且我方密钥派生绑定双方 ID，解密成功
//!      ⟹ "发送者确实持有我方公钥"，即在其好友列表中（双向确认）。
//! 两条同时满足即构成"确定是共同好友"，才会被转发/回答/接受地址信息。
//! 中继类内容额外要求被转发方（source/victim）也在中继者的好友列表中，
//! 确保任何地址都绝不会交给陌生人。

use anyhow::{bail, Result};

pub struct AddrQuery {
    pub target_id: [u8; 32],
    pub nonce_q: [u8; 16],
    pub fail_seq: u32,
}

pub fn encode_addr_query(target_id: &[u8; 32], nonce_q: &[u8; 16], fail_seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 16 + 4);
    out.push(0x01);
    out.extend_from_slice(target_id);
    out.extend_from_slice(nonce_q);
    out.extend_from_slice(&fail_seq.to_be_bytes());
    out
}

pub fn decode_addr_query(buf: &[u8]) -> Result<AddrQuery> {
    if buf.len() != 1 + 32 + 16 + 4 {
        bail!("寻址请求包体长度错误");
    }
    let mut q = AddrQuery { target_id: [0u8; 32], nonce_q: [0u8; 16], fail_seq: 0 };
    q.target_id.copy_from_slice(&buf[1..33]);
    q.nonce_q.copy_from_slice(&buf[33..49]);
    q.fail_seq = u32::from_be_bytes(buf[49..53].try_into().unwrap());
    Ok(q)
}

pub const ADDR_ANSWER_HIT: u8 = 0x01;
pub const ADDR_ANSWER_MISS: u8 = 0x00;

pub struct AddrAnswer {
    pub hit: bool,
    pub target_id: [u8; 32],
    pub nonce_q: [u8; 16],
    pub ips: Vec<String>,
}

pub fn encode_addr_answer(target_id: &[u8; 32], nonce_q: &[u8; 16], ips: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    if ips.is_empty() {
        out.push(ADDR_ANSWER_MISS);
    } else {
        out.push(ADDR_ANSWER_HIT);
    }
    out.extend_from_slice(target_id);
    out.extend_from_slice(nonce_q);
    let cnt = ips.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&cnt.to_be_bytes());
    for ip in ips.iter().take(cnt as usize) {
        let b = ip.as_bytes();
        let af: u8 = if ip.contains(':') { 6 } else { 4 };
        out.push(af);
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

pub fn decode_addr_answer(buf: &[u8]) -> Result<AddrAnswer> {
    if buf.len() < 1 + 32 + 16 + 2 {
        bail!("寻址应答包体长度错误");
    }
    let hit = buf[0] == ADDR_ANSWER_HIT;
    let mut target_id = [0u8; 32];
    target_id.copy_from_slice(&buf[1..33]);
    let mut nonce_q = [0u8; 16];
    nonce_q.copy_from_slice(&buf[33..49]);
    let cnt = u16::from_be_bytes([buf[49], buf[50]]) as usize;

    let mut ips = Vec::new();
    let mut off = 51;
    for _ in 0..cnt {
        if off + 2 > buf.len() {
            bail!("寻址应答长度不匹配");
        }
        let af = buf[off];
        let len = buf[off + 1] as usize;
        if off + 2 + len > buf.len() {
            bail!("寻址应答长度不匹配");
        }
        let s = String::from_utf8_lossy(&buf[off + 2..off + 2 + len]).into_owned();
        if (af == 4 || af == 6) && s.parse::<std::net::IpAddr>().is_ok() {
            ips.push(s);
        }
        off += 2 + len;
    }
    Ok(AddrAnswer { hit, target_id, nonce_q, ips })
}

// ---------- IP 列表通用编解码 ----------

fn encode_ips(ips: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    let cnt = ips.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&cnt.to_be_bytes());
    for ip in ips.iter().take(cnt as usize) {
        let b = ip.as_bytes();
        let af: u8 = if ip.contains(':') { 6 } else { 4 };
        out.push(af);
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

fn decode_ips(buf: &[u8], off: usize) -> Result<(Vec<String>, usize)> {
    if off + 2 > buf.len() {
        bail!("IP 列表长度不足");
    }
    let cnt = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    let mut ips = Vec::new();
    let mut o = off + 2;
    for _ in 0..cnt {
        if o + 2 > buf.len() {
            bail!("IP 列表长度不匹配");
        }
        let af = buf[o];
        let len = buf[o + 1] as usize;
        if o + 2 + len > buf.len() {
            bail!("IP 列表长度不匹配");
        }
        let s = String::from_utf8_lossy(&buf[o + 2..o + 2 + len]).into_owned();
        if (af == 4 || af == 6) && s.parse::<std::net::IpAddr>().is_ok() {
            ips.push(s);
        }
        o += 2 + len;
    }
    Ok((ips, o))
}

// ---------- 反向探针 ----------

/// IP_CHANGED：告知好友我的新 IP 列表，并请求其回复 ACK。
pub fn encode_ip_changed(probe_id: u64, ips: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x01);
    out.extend_from_slice(&probe_id.to_be_bytes());
    out.extend_from_slice(&encode_ips(ips));
    out
}

pub fn decode_ip_changed(buf: &[u8]) -> Result<(u64, Vec<String>)> {
    if buf.len() < 1 + 8 + 2 {
        bail!("反向探针包体过短");
    }
    if buf[0] != 0x01 {
        bail!("未知探针子类型");
    }
    let probe_id = u64::from_be_bytes(buf[1..9].try_into().unwrap());
    let (ips, _) = decode_ips(buf, 9)?;
    Ok((probe_id, ips))
}

/// IP_CHANGED_ACK：回显 probe_id，表示已收到并更新。
pub fn encode_ip_changed_ack(probe_id: u64) -> Vec<u8> {
    probe_id.to_be_bytes().to_vec()
}

pub fn decode_ip_changed_ack(buf: &[u8]) -> Result<u64> {
    if buf.len() != 8 {
        bail!("探针 ACK 包体长度错误");
    }
    Ok(u64::from_be_bytes(buf.try_into().unwrap()))
}

// ---------- 共同好友代投递 ----------

/// GOSSIP：向共同好友广播"这些好友（victims）没收到我的新 IP，请代转"。
/// source = 签名者（发送方），其新 IP 附带在载荷中。
pub fn encode_gossip(victims: &[[u8; 32]], ips: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x01);
    let vc = victims.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&vc.to_be_bytes());
    for v in victims.iter().take(vc as usize) {
        out.extend_from_slice(v);
    }
    out.extend_from_slice(&encode_ips(ips));
    out
}

pub fn decode_gossip(buf: &[u8]) -> Result<(Vec<[u8; 32]>, Vec<String>)> {
    if buf.len() < 1 + 2 {
        bail!("GOSSIP 包体过短");
    }
    if buf[0] != 0x01 {
        bail!("未知 GOSSIP 子类型");
    }
    let vc = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    if buf.len() < 3 + vc * 32 + 2 {
        bail!("GOSSIP 包体长度不匹配");
    }
    let mut victims = Vec::with_capacity(vc);
    let mut o = 3;
    for _ in 0..vc {
        let mut v = [0u8; 32];
        v.copy_from_slice(&buf[o..o + 32]);
        victims.push(v);
        o += 32;
    }
    let (ips, _) = decode_ips(buf, o)?;
    Ok((victims, ips))
}

/// PUSH_IP：中继者把 source_id 的最新 IP 代投递给收件人。
pub fn encode_push_ip(source_id: &[u8; 32], ips: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(source_id);
    out.extend_from_slice(&encode_ips(ips));
    out
}

pub fn decode_push_ip(buf: &[u8]) -> Result<([u8; 32], Vec<String>)> {
    if buf.len() < 32 + 2 {
        bail!("PUSH_IP 包体过短");
    }
    let mut source_id = [0u8; 32];
    source_id.copy_from_slice(&buf[..32]);
    let (ips, _) = decode_ips(buf, 32)?;
    Ok((source_id, ips))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let target = [3u8; 32];
        let nonce = [7u8; 16];
        let buf = encode_addr_query(&target, &nonce, 42);
        let q = decode_addr_query(&buf).unwrap();
        assert_eq!(q.target_id, target);
        assert_eq!(q.nonce_q, nonce);
        assert_eq!(q.fail_seq, 42);
    }

    #[test]
    fn answer_roundtrip() {
        let target = [4u8; 32];
        let nonce = [8u8; 16];
        let ips = vec!["2001:db8::1".to_string(), "1.2.3.4".to_string()];
        let buf = encode_addr_answer(&target, &nonce, &ips);
        let a = decode_addr_answer(&buf).unwrap();
        assert!(a.hit);
        assert_eq!(a.ips, ips);

        let buf_miss = encode_addr_answer(&target, &nonce, &[]);
        let a = decode_addr_answer(&buf_miss).unwrap();
        assert!(!a.hit);
        assert!(a.ips.is_empty());
    }

    #[test]
    fn ip_changed_roundtrip() {
        let ips = vec!["240e::1".to_string(), "10.0.0.2".to_string()];
        let buf = encode_ip_changed(99123, &ips);
        let (probe_id, got) = decode_ip_changed(&buf).unwrap();
        assert_eq!(probe_id, 99123);
        assert_eq!(got, ips);

        let ack = encode_ip_changed_ack(99123);
        assert_eq!(decode_ip_changed_ack(&ack).unwrap(), 99123);
    }

    #[test]
    fn gossip_push_roundtrip() {
        let victims = vec![[1u8; 32], [2u8; 32]];
        let ips = vec!["240e::2".to_string()];
        let g = encode_gossip(&victims, &ips);
        let (vs, got_ips) = decode_gossip(&g).unwrap();
        assert_eq!(vs, victims);
        assert_eq!(got_ips, ips);

        let p = encode_push_ip(&[3u8; 32], &ips);
        let (src, got) = decode_push_ip(&p).unwrap();
        assert_eq!(src, [3u8; 32]);
        assert_eq!(got, ips);
    }
}