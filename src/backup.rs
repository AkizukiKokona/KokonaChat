//! 备份与恢复（身份绑定加密）。
//!
//! 内容分两类：
//! - **core**：本地配置（config.toml）+ 好友列表（friends.toml）
//! - **chat**：聊天记录（messages.log）
//!
//! 两者可以**分开备份**（`export-core` / `export-chat`），也可以**合并成一个加密大包**
//! （`export-all`）。无论哪种备份，内容都用本机身份（X25519 静态密钥）**自加密**：
//! 只有同一账户（同一身份种子）才能解密导入；其它身份 / 陌生人即使拿到文件也解不开。
//!
//! 容器格式（二进制）：
//!   `KOKB`(4) | ver(1) | kind(1) | exported_at(u64 BE) | payload_len(u32 BE) | payload(加密)
//!   加密信封 = packet::envelope（eph_pub(32) | nonce(12) | AES-GCM 密文）。明文即下方 JSON。
//!
//! kind：1 = core，2 = chat（聊天记录），3 = all（合并大包）。

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::crypto::cipher;
use crate::crypto::keys::Identity;
use crate::net::packet;

const MAGIC: [u8; 4] = *b"KOKB";
const VERSION: u8 = 1;
const KIND_CORE: u8 = 1;
const KIND_CHAT: u8 = 2;
const KIND_ALL: u8 = 3;

#[derive(Serialize, Deserialize)]
struct CoreSection {
    config: String,
    friends: String,
}

/// 加密前的明文内容。
#[derive(Serialize, Deserialize)]
struct BackupPayload {
    exported_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    core: Option<CoreSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat: Option<String>,
}

pub fn export_core(path: &Path, paths: &Paths, identity: &Identity) -> Result<()> {
    let payload = BackupPayload {
        exported_at: crate::util::unix_millis(),
        core: Some(CoreSection {
            config: std::fs::read_to_string(&paths.config).unwrap_or_default(),
            friends: std::fs::read_to_string(&paths.friends).unwrap_or_default(),
        }),
        chat: None,
    };
    write_backup(path, KIND_CORE, &payload, identity)
}

pub fn export_chat(path: &Path, paths: &Paths, identity: &Identity) -> Result<()> {
    let payload = BackupPayload {
        exported_at: crate::util::unix_millis(),
        core: None,
        chat: Some(std::fs::read_to_string(paths.log_dir.join("messages.log")).unwrap_or_default()),
    };
    write_backup(path, KIND_CHAT, &payload, identity)
}

pub fn export_all(path: &Path, paths: &Paths, identity: &Identity) -> Result<()> {
    let payload = BackupPayload {
        exported_at: crate::util::unix_millis(),
        core: Some(CoreSection {
            config: std::fs::read_to_string(&paths.config).unwrap_or_default(),
            friends: std::fs::read_to_string(&paths.friends).unwrap_or_default(),
        }),
        chat: Some(std::fs::read_to_string(paths.log_dir.join("messages.log")).unwrap_or_default()),
    };
    write_backup(path, KIND_ALL, &payload, identity)
}

pub fn import(path: &Path, paths: &Paths, identity: &Identity) -> Result<()> {
    let raw = std::fs::read(path).with_context(|| format!("读取备份失败: {}", path.display()))?;
    if raw.len() < 4 + 1 + 1 + 8 + 4 {
        bail!("备份文件过短或已损坏");
    }
    if raw[..4] != MAGIC {
        bail!("不是 KokonaChat 备份文件");
    }
    if raw[4] != VERSION {
        bail!("备份版本不受支持: {}", raw[4]);
    }
    let kind = raw[5];
    let exported_at = u64::from_be_bytes(raw[6..14].try_into().unwrap());
    let plen = u32::from_be_bytes(raw[14..18].try_into().unwrap()) as usize;
    if 18 + plen > raw.len() {
        bail!("备份长度不匹配，文件已损坏");
    }
    let sealed = packet::envelope_open(&raw[18..18 + plen])?;

    // 同一账号才能解密：用本机身份的自密钥解开（其它身份解密必失败）。
    let Some(self_xpub) = cipher::ed_pub_to_x25519(&identity.ed_pub) else {
        bail!("无法派生本机加密密钥");
    };
    let pt = cipher::open(&sealed, &identity.x25519_sk, &self_xpub, &identity.ed_pub, &identity.ed_pub)
        .map_err(|_| anyhow::anyhow!("解密失败：备份不属于当前账户，或文件已损坏"))?;
    let payload: BackupPayload = serde_json::from_slice(&pt).context("备份内容解析失败")?;

    let real_kind = if payload.core.is_some() && payload.chat.is_some() {
        KIND_ALL
    } else if payload.core.is_some() {
        KIND_CORE
    } else {
        KIND_CHAT
    };
    if real_kind != kind && !(kind == KIND_ALL && real_kind == KIND_ALL) {
        // 允许容错：以实际内容为准（对旧文件的宽容）
    }

    std::fs::create_dir_all(&paths.root)?;
    if let Some(core) = &payload.core {
        std::fs::create_dir_all(paths.config.parent().unwrap_or(&paths.root))?;
        std::fs::write(&paths.config, &core.config)?;
        std::fs::write(&paths.friends, &core.friends)?;
        println!("已恢复 配置 + 好友列表（{} 字节 / {} 字节）", core.config.len(), core.friends.len());
    }
    if let Some(chat) = &payload.chat {
        // 聊天记录以"追加"方式合并，保留现有历史
        let msg_file = &paths.log_dir.join("messages.log");
        std::fs::create_dir_all(&paths.log_dir)?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(msg_file)?;
        use std::io::Write;
        f.write_all(chat.as_bytes())?;
        if !chat.is_empty() && !chat.ends_with('\n') {
            f.write_all(b"\n")?;
        }
        println!("已追加 聊天记录（{} 字节）到 messages.log", chat.len());
    }

    println!("导入完成（备份时间: {}，本机用户: {}）", crate::util::format_ts(exported_at), identity.user_id());
    Ok(())
}

fn write_backup(path: &Path, kind: u8, payload: &BackupPayload, identity: &Identity) -> Result<()> {
    let Some(self_xpub) = cipher::ed_pub_to_x25519(&identity.ed_pub) else {
        bail!("无法派生本机加密密钥");
    };
    let plain = serde_json::to_vec(payload)?;
    let sealed = cipher::seal(&identity.x25519_sk, &self_xpub, &identity.ed_pub, &identity.ed_pub, &plain)?;
    let env = packet::envelope_close(&sealed);

    let mut out = Vec::with_capacity(18 + env.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&payload.exported_at.to_be_bytes());
    out.extend_from_slice(&(env.len() as u32).to_be_bytes());
    out.extend_from_slice(&env);

    std::fs::write(path, &out).with_context(|| format!("写入备份失败: {}", path.display()))?;
    let kind_name = match kind {
        KIND_CORE => "配置+好友",
        KIND_CHAT => "聊天记录",
        _ => "配置+好友+聊天记录（合并大包）",
    };
    println!(
        "已导出【{}】到 {}（{} 字节，仅本账户可解密）",
        kind_name,
        path.display(),
        out.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn export_import_roundtrip_for_same_identity() {
        let dir = std::env::temp_dir().join(format!("kokona-bak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = config::Paths {
            root: dir.clone(),
            config: dir.join("config.toml"),
            identity: dir.join("identity.key"),
            friends: dir.join("friends.toml"),
            log_dir: dir.join("logs"),
        };
        std::fs::write(&paths.config, "port = 1212\nnickname = \"kokona\"\n").unwrap();
        std::fs::write(&paths.friends, "[[friends]]\nnickname = \"alice\"\npubkey = \"abcd\"\n").unwrap();
        std::fs::create_dir_all(&paths.log_dir).unwrap();
        std::fs::write(paths.log_dir.join("messages.log"), "11:00 > a: hi\n").unwrap();

        let identity = Identity::generate();
        let bak_path = dir.join("backup.kba");

        export_all(&bak_path, &paths, &identity).unwrap();
        // 清空后导入
        std::fs::remove_file(&paths.config).unwrap();
        std::fs::remove_file(&paths.friends).unwrap();
        std::fs::remove_file(paths.log_dir.join("messages.log")).unwrap();

        import(&bak_path, &paths, &identity).unwrap();
        assert_eq!(std::fs::read_to_string(&paths.config).unwrap(), "port = 1212\nnickname = \"kokona\"\n");
        assert!(std::fs::read_to_string(&paths.friends).unwrap().contains("alice"));
        assert!(std::fs::read_to_string(paths.log_dir.join("messages.log")).unwrap().contains("hi"));
    }

    #[test]
    fn different_identity_cannot_decrypt() {
        let dir = std::env::temp_dir().join(format!("kokona-bak2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = config::Paths {
            root: dir.clone(),
            config: dir.join("config.toml"),
            identity: dir.join("identity.key"),
            friends: dir.join("friends.toml"),
            log_dir: dir.join("logs"),
        };
        std::fs::write(&paths.config, "port = 1212\n").unwrap();
        std::fs::write(&paths.friends, "").unwrap();

        let alice = Identity::generate();
        let bob = Identity::generate();
        let bak_path = dir.join("bak.kba");
        export_all(&bak_path, &paths, &alice).unwrap();
        // bob 用于导入（路径不同，构造另一份 paths 语义上即可）
        let paths2 = config::Paths {
            root: dir.join("bob"),
            config: dir.join("bob").join("config.toml"),
            identity: dir.join("bob").join("identity.key"),
            friends: dir.join("bob").join("friends.toml"),
            log_dir: dir.join("bob").join("logs"),
        };
        std::fs::create_dir_all(&paths2.root).unwrap();
        let err = import(&bak_path, &paths2, &bob).unwrap_err();
        assert!(err.to_string().contains("不属于当前账户"), "不同身份应解密失败: {err}");
    }

    #[test]
    fn separate_core_and_chat() {
        let dir = std::env::temp_dir().join(format!("kokona-bak3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = config::Paths {
            root: dir.clone(),
            config: dir.join("config.toml"),
            identity: dir.join("identity.key"),
            friends: dir.join("friends.toml"),
            log_dir: dir.join("logs"),
        };
        std::fs::write(&paths.config, "port = 1212\n").unwrap();
        std::fs::write(&paths.friends, "").unwrap();
        std::fs::create_dir_all(&paths.log_dir).unwrap();
        std::fs::write(paths.log_dir.join("messages.log"), "===\n").unwrap();

        let identity = Identity::generate();
        let core_bak = dir.join("core.kba");
        let chat_bak = dir.join("chat.kba");
        export_core(&core_bak, &paths, &identity).unwrap();
        export_chat(&chat_bak, &paths, &identity).unwrap();
        assert!(core_bak.exists() && chat_bak.exists());
    }
}