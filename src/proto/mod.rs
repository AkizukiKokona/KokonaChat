//! 协议载荷编解码。
//!
//! MSG 明文内部结构：
//!   msg_type(1)=0x01 text | timestamp(8, unix ms) | content_len(4) | content
//! ACK 明文内部结构：
//!   ack_seq(4)
//! 寻址包内部结构见 `addressing` 子模块（加密信封内）。

pub mod addressing;

use anyhow::{bail, Result};

pub use addressing::*;

pub const MSG_TEXT: u8 = 0x01;

pub fn encode_msg_inner(content: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(MSG_TEXT);
    let ts = crate::util::unix_millis();
    out.extend_from_slice(&ts.to_be_bytes());
    let c = content.as_bytes();
    out.extend_from_slice(&(c.len() as u32).to_be_bytes());
    out.extend_from_slice(c);
    out
}

pub fn decode_msg_inner(buf: &[u8]) -> Result<(u8, u64, String)> {
    if buf.len() < 1 + 8 + 4 {
        bail!("消息体过短");
    }
    let mtype = buf[0];
    let ts = u64::from_be_bytes(buf[1..9].try_into().unwrap());
    let clen = u32::from_be_bytes(buf[9..13].try_into().unwrap()) as usize;
    if buf.len() < 13 + clen {
        bail!("消息体长度不匹配");
    }
    let content = String::from_utf8_lossy(&buf[13..13 + clen]).into_owned();
    Ok((mtype, ts, content))
}

pub fn encode_ack_inner(seq: u32) -> Vec<u8> {
    seq.to_be_bytes().to_vec()
}

pub fn decode_ack_inner(buf: &[u8]) -> Result<u32> {
    if buf.len() != 4 {
        bail!("ACK 包体长度错误");
    }
    Ok(u32::from_be_bytes(buf.try_into().unwrap()))
}