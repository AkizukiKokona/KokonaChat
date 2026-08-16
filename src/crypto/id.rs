/// 用户 ID = Ed25519 公钥的 hex 编码（64 字符）。
use hex;

pub const ID_HEX_LEN: usize = 64;

pub fn encode(pubkey: [u8; 32]) -> String {
    hex::encode(pubkey)
}

pub fn decode(s: &str) -> anyhow::Result<[u8; 32]> {
    let t = s.trim();
    if t.len() != ID_HEX_LEN {
        anyhow::bail!("用户 ID 应为 {} 位 hex（公钥），收到 {} 位", ID_HEX_LEN, t.len());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out)?;
    Ok(out)
}

/// 公钥短形式（前 12 字符），用于 TUI / 打印。
pub fn short(pubkey: &[u8; 32]) -> String {
    short_from_hex(&encode(*pubkey))
}

/// hex 字符串的短形式。
pub fn short_from_hex(s: &str) -> String {
    if s.len() >= 12 {
        s[..12].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let pk = [7u8; 32];
        let s = encode(pk);
        assert_eq!(s.len(), 64);
        assert_eq!(decode(&s).unwrap(), pk);
    }
}