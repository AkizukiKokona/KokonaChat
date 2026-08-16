//! 端到端加密层。
//!
//! 方案：每条消息由发送方生成一次性 X25519 临时密钥（前向保密），
//! 由 `DH(E, recip_static) || DH(sender_static, recip_static)` 经 HKDF-SHA256
//! 派生 AES-256-GCM 消息密钥；KDF 的 info 绑定双方用户 ID。
//! 机密性/完整性由 GCM 提供，消息签名在 packet 层（Ed25519）完成。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 加密信封：临时公钥 | nonce(12) | AES-256-GCM 密文+tag
pub struct Sealed {
    pub eph_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

const KDF_SALT: &[u8] = b"KokonaChat-v1-static-salt";
const KDF_INFO_PREFIX: &[u8] = b"KokonaChat/1.0/";

fn derive_key(shared_a: &[u8; 32], shared_b: &[u8; 32], sender_id: &[u8; 32], recipient_id: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared_a);
    ikm[32..].copy_from_slice(shared_b);
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), &ikm);
    let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(KDF_INFO_PREFIX);
    info.extend_from_slice(sender_id);
    info.extend_from_slice(recipient_id);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("HKDF expand 不应失败");
    okm
}

/// 端到端加密明文到 recipient。
pub fn seal(
    our_static: &StaticSecret,
    recip_xpub: &[u8; 32],
    sender_id: &[u8; 32],
    recipient_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Sealed> {
    let eph_sk = StaticSecret::random_from_rng(&mut OsRng);
    let eph_pub = PublicKey::from(&eph_sk).to_bytes();

    let s1 = eph_sk.diffie_hellman(&PublicKey::from(*recip_xpub)).to_bytes();
    let s2 = our_static.diffie_hellman(&PublicKey::from(*recip_xpub)).to_bytes();
    let key = derive_key(&s1, &s2, sender_id, recipient_id);

    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM 加密失败"))?;

    Ok(Sealed { eph_pub, nonce, ciphertext })
}

/// 解密信封（仅 recipient 可解密）。
pub fn open(
    sealed: &Sealed,
    our_static: &StaticSecret,
    sender_xpub: &[u8; 32],
    sender_id: &[u8; 32],
    recipient_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let s1 = our_static.diffie_hellman(&PublicKey::from(sealed.eph_pub)).to_bytes();
    let s2 = our_static.diffie_hellman(&PublicKey::from(*sender_xpub)).to_bytes();
    let key = derive_key(&s1, &s2, sender_id, recipient_id);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("AES-GCM 解密失败（密钥或密文不匹配）"))
}

/// 由 Ed25519 公钥（用户 ID）推算其 X25519 公钥。
/// 极小概率的弱（twisted）Ed25519 密钥会失败，返回 None。
pub fn ed_pub_to_x25519(ed_pub: &[u8; 32]) -> Option<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let point = CompressedEdwardsY(*ed_pub).decompress()?;
    let mont = point.to_montgomery();
    Some(mont.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey as XPub;

    #[test]
    fn seal_open_roundtrip() {
        let a_seed = [1u8; 32];
        let b_seed = [2u8; 32];
        let a_sk = StaticSecret::from(a_seed);
        let b_sk = StaticSecret::from(b_seed);
        let a_pub: [u8; 32] = XPub::from(&a_sk).to_bytes();
        let b_pub: [u8; 32] = XPub::from(&b_sk).to_bytes();

        let msg = b"hello kokona";
        let sealed = seal(&a_sk, &b_pub, &a_pub, &b_pub, msg).unwrap();
        let pt = open(&sealed, &b_sk, &a_pub, &a_pub, &b_pub).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn tamper_fails() {
        let a_seed = [1u8; 32];
        let b_seed = [2u8; 32];
        let a_sk = StaticSecret::from(a_seed);
        let b_sk = StaticSecret::from(b_seed);
        let a_pub: [u8; 32] = XPub::from(&a_sk).to_bytes();
        let b_pub: [u8; 32] = XPub::from(&b_sk).to_bytes();

        let mut sealed = seal(&a_sk, &b_pub, &a_pub, &b_pub, b"hi").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sealed, &b_sk, &a_pub, &a_pub, &b_pub).is_err());
    }
}