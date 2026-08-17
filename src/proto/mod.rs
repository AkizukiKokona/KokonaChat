//! 协议载荷编解码。
//!
//! MSG 明文内部结构（text）：
//!   msg_type(1)=0x01 | timestamp(8, unix ms) | len(4) | content
//! MSG 明文内部结构（附件分片）：
//!   msg_type(1)=0x02 | timestamp(8, unix ms) | len(4) | attach_body
//!   attach_body: transfer_id(16) | kind(1) | chunk_index(4) | total_chunks(4)
//!                | total_size(8) | name_len(1) | name | data_len(4) | data
//! ACK 明文内部结构：
//!   ack_seq(4)
//! 寻址包内部结构见 `addressing` 子模块（加密信封内）。

pub mod addressing;

use anyhow::{bail, Result};

pub use addressing::*;

pub const MSG_TEXT: u8 = 0x01;
pub const MSG_ATTACH: u8 = 0x02;

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

/// 附件分片。
#[derive(Clone)]
pub struct AttachChunk {
    pub transfer: [u8; 16],
    pub kind: u8,
    pub index: u32,
    pub total: u32,
    pub total_size: u64,
    pub name: String,
    pub data: Vec<u8>,
}

pub fn encode_attach_chunk(c: &AttachChunk, ts: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&c.transfer);
    body.push(c.kind);
    body.extend_from_slice(&c.index.to_be_bytes());
    body.extend_from_slice(&c.total.to_be_bytes());
    body.extend_from_slice(&c.total_size.to_be_bytes());
    let name = c.name.as_bytes();
    body.push(name.len().min(255) as u8);
    body.extend_from_slice(&name[..name.len().min(255)]);
    body.extend_from_slice(&(c.data.len() as u32).to_be_bytes());
    body.extend_from_slice(&c.data);

    let mut out = Vec::with_capacity(13 + body.len());
    out.push(MSG_ATTACH);
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn decode_attach_chunk(buf: &[u8]) -> Result<(u64, AttachChunk)> {
    if buf.len() < 13 {
        bail!("附件分片过短");
    }
    if buf[0] != MSG_ATTACH {
        bail!("不是附件消息");
    }
    let ts = u64::from_be_bytes(buf[1..9].try_into().unwrap());
    let blen = u32::from_be_bytes(buf[9..13].try_into().unwrap()) as usize;
    if buf.len() != 13 + blen {
        bail!("附件分片长度不匹配");
    }
    let b = &buf[13..13 + blen];
    if b.len() < 16 + 1 + 4 + 4 + 8 + 1 + 4 {
        bail!("附件体过短");
    }
    let mut transfer = [0u8; 16];
    transfer.copy_from_slice(&b[..16]);
    let kind = b[16];
    let index = u32::from_be_bytes(b[17..21].try_into().unwrap());
    let total = u32::from_be_bytes(b[21..25].try_into().unwrap());
    let total_size = u64::from_be_bytes(b[25..33].try_into().unwrap());
    let name_len = b[33] as usize;
    if b.len() < 34 + name_len + 4 {
        bail!("附件体长度不足");
    }
    let name = String::from_utf8_lossy(&b[34..34 + name_len]).into_owned();
    let dlen = u32::from_be_bytes(b[34 + name_len..38 + name_len].try_into().unwrap()) as usize;
    if b.len() != 38 + name_len + dlen {
        bail!("附件数据长度不匹配");
    }
    let data = b[38 + name_len..38 + name_len + dlen].to_vec();
    Ok((ts, AttachChunk { transfer, kind, index, total, total_size, name, data }))
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