//! KokonaChat 数据包格式（协议 v1）。
//!
//! 固定头 82 字节：
//!   [0..4)   magic "KOKN"
//!   [4]      version = 0x01
//!   [5]      type
//!   [6]      flags
//!   [7..10)  reserved
//!   [10..14) seq (u32 BE) —— 发送方维护，用于重传/去重
//!   [14..18) payload_len (u32 BE)
//!   [18..50) sender_id（Ed25519 公钥）
//!   [50..82) recipient_id
//!   [82..)   payload
//!   尾部     Ed25519 签名（64 字节，覆盖整个头 + payload）
//!
//! payload 为加密信封时：eph_pub(32) | nonce(12) | AES-GCM 密文+tag。

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::crypto::cipher;

pub const MAGIC: [u8; 4] = *b"KOKN";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 82;
pub const SIG_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PktType {
    Msg = 0x01,
    MsgAck = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    AddrQuery = 0x05,
    AddrAnswer = 0x06,
    IpChanged = 0x07,
    IpChangedAck = 0x08,
    Gossip = 0x09,
    PushIp = 0x0A,
}

impl PktType {
    pub fn from_u8(v: u8) -> Option<PktType> {
        match v {
            0x01 => Some(Self::Msg),
            0x02 => Some(Self::MsgAck),
            0x03 => Some(Self::Ping),
            0x04 => Some(Self::Pong),
            0x05 => Some(Self::AddrQuery),
            0x06 => Some(Self::AddrAnswer),
            0x07 => Some(Self::IpChanged),
            0x08 => Some(Self::IpChangedAck),
            0x09 => Some(Self::Gossip),
            0x0A => Some(Self::PushIp),
            _ => None,
        }
    }
}

/// flags：bit0 = 携带临时密钥（敏感内容密文），bit1 = ACK
pub const FLAG_EPHEMERAL: u8 = 0b0000_0001;
pub const FLAG_ACK: u8 = 0b0000_0010;

#[derive(Clone)]
pub struct Packet {
    pub ptype: PktType,
    pub flags: u8,
    pub seq: u32,
    pub sender_id: [u8; 32],
    pub recipient_id: [u8; 32],
    pub payload: Vec<u8>,
}

pub struct Decoded {
    pub packet: Packet,
    pub signature: [u8; 64],
}

fn get_u32(buf: &[u8]) -> u32 {
    u32::from_be_bytes(buf.try_into().unwrap())
}

impl Packet {
    /// 序列化头 + payload（不含签名）。
    pub fn build_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.ptype as u8);
        out.push(self.flags);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sender_id);
        out.extend_from_slice(&self.recipient_id);
        out.extend_from_slice(&self.payload);
        out
    }

    /// 编码并签名。
    pub fn encode(&self, signer: &SigningKey) -> Vec<u8> {
        let mut out = self.build_unsigned();
        let sig: Signature = signer.sign(&out);
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    /// 解码（含取签名，未验签）。
    pub fn decode(buf: &[u8]) -> Result<Decoded> {
        if buf.len() < HEADER_LEN + SIG_LEN {
            bail!("包过短");
        }
        if &buf[0..4] != &MAGIC {
            bail!("magic 不匹配");
        }
        if buf[4] != VERSION {
            bail!("协议版本不匹配");
        }
        let ptype = PktType::from_u8(buf[5]).with_context(|| format!("未知包类型 {}", buf[5]))?;
        let flags = buf[6];
        let seq = get_u32(&buf[10..14]);
        let plen = get_u32(&buf[14..18]) as usize;
        let expected = HEADER_LEN
            .checked_add(plen)
            .and_then(|v| v.checked_add(SIG_LEN))
            .ok_or_else(|| anyhow::anyhow!("包长度溢出"))?;
        if buf.len() != expected {
            bail!("包长度不匹配");
        }
        let mut sender_id = [0u8; 32];
        let mut recipient_id = [0u8; 32];
        sender_id.copy_from_slice(&buf[18..50]);
        recipient_id.copy_from_slice(&buf[50..82]);
        let payload = buf[82..82 + plen].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[82 + plen..82 + plen + SIG_LEN]);
        Ok(Decoded {
            packet: Packet { ptype, flags, seq, sender_id, recipient_id, payload },
            signature,
        })
    }

    /// 验签（公钥 = 包头中的 sender_id）。
    pub fn verify(dec: &Decoded) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&dec.packet.sender_id)?;
        let covered = dec.packet.build_unsigned();
        let sig = Signature::from_bytes(&dec.signature);
        vk.verify(&covered, &sig).context("签名校验失败")
    }
}

/// 加密信封 -> 字节。
pub fn envelope_close(sealed: &cipher::Sealed) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 12 + sealed.ciphertext.len());
    out.extend_from_slice(&sealed.eph_pub);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    out
}

/// 字节 -> 加密信封。
pub fn envelope_open(buf: &[u8]) -> Result<cipher::Sealed> {
    if buf.len() < 32 + 12 + 16 {
        bail!("信封过短");
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&buf[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[32..44]);
    Ok(cipher::Sealed { eph_pub, nonce, ciphertext: buf[44..].to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn encode_decode_verify() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pkt = Packet {
            ptype: PktType::Msg,
            flags: FLAG_EPHEMERAL,
            seq: 42,
            sender_id: sk.verifying_key().to_bytes(),
            recipient_id: [5u8; 32],
            payload: vec![1, 2, 3, 4],
        };
        let bytes = pkt.encode(&sk);
        let dec = Packet::decode(&bytes).unwrap();
        assert_eq!(dec.packet.ptype, PktType::Msg);
        assert_eq!(dec.packet.seq, 42);
        assert_eq!(dec.packet.payload, vec![1, 2, 3, 4]);
        Packet::verify(&dec).unwrap();

        // 篡改 payload 应验签失败
        let bad = Packet { payload: vec![9, 9], ..dec.packet.clone() };
        let bad_dec = Decoded { packet: bad.clone(), signature: dec.signature };
        assert!(Packet::verify(&bad_dec).is_err());
    }
}