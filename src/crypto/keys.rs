use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::StaticSecret;

/// 身份 = 本地生成的密钥对，公钥（Ed25519 公钥，32 字节）即用户 ID。
/// 加密用 X25519 密钥与签名密钥同源（由同一 32 字节种子派生），
/// 因此从对方 ID（Ed25519 公钥）即可换算其 X25519 公钥，无需额外交互。
pub struct Identity {
    /// 身份种子（32 字节），仅保存在本地，可离线备份
    seed: [u8; 32],
    /// Ed25519 签名密钥对（身份）
    pub signing: SigningKey,
    /// Ed25519 公钥 = 用户 ID
    pub ed_pub: [u8; 32],
    /// X25519 静态加密密钥
    pub x25519_sk: StaticSecret,
}

impl Identity {
    /// 生成本地身份（随机种子）。
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// 由种子重建身份。
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let ed_pub = signing.verifying_key().to_bytes();
        // X25519 静态密钥取自 Ed25519 展开的标量（未 clamp 的那一份，见
        // ed25519-dalek 文档：`to_scalar_bytes` 才是与 `verifying_key().to_montgomery()`
        // 对应的 StaticSecret），从而保证对方由 ID 换算（cipher::ed_pub_to_x25519）
        // 得到的 X25519 公钥与本机一致，跨节点 DH 才能达成一致。
        let scalar_bytes = signing.to_scalar_bytes();
        let x25519_sk = StaticSecret::from(scalar_bytes);
        Identity { seed, signing, ed_pub, x25519_sk }
    }

    /// 用户 ID（公钥的 hex 编码）。
    pub fn user_id(&self) -> String {
        crate::crypto::id::encode(self.ed_pub)
    }

    /// 种子 hex（备份/迁移用）。
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed)
    }

    /// 持久化种子到本地文件（权限 0600）。
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &self.seed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// 从本地文件加载身份。
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            anyhow::bail!("密钥文件长度不正确（应为 32 字节）: {}", path.display());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        Ok(Self::from_seed(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_pub_matches_id_conversion() {
        for seed_byte in 0u8..8 {
            let mut seed = [0u8; 32];
            seed[0] = 0xA5;
            seed[1] = seed_byte;
            let id = Identity::from_seed(seed);
            let from_id = crate::crypto::cipher::ed_pub_to_x25519(&id.ed_pub).unwrap();
            let actual = x25519_dalek::PublicKey::from(&id.x25519_sk).to_bytes();
            assert_eq!(from_id, actual, "seed[1]={seed_byte}");
        }
    }
}
