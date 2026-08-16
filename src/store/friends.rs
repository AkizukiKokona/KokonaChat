//! 好友列表（昵称、公钥即用户 ID、最后已知 IP 列表、最近在线时间）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto::id;

pub const MAX_IPS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct Friend {
    /// 昵称（本地自定义）
    pub nickname: String,
    /// 用户 ID（Ed25519 公钥 hex）
    pub pubkey: String,
    /// 最后已知 IP 列表（IPv6 优先，最近在最前）
    pub ips: Vec<String>,
    /// 最近一次直连时间（unix 毫秒）
    pub last_seen: Option<u64>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FriendsFile {
    pub friends: Vec<Friend>,
}

pub struct FriendStore {
    path: PathBuf,
    data: FriendsFile,
}

impl FriendStore {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            if raw.trim().is_empty() {
                FriendsFile::default()
            } else {
                toml::from_str(&raw)?
            }
        } else {
            FriendsFile::default()
        };
        Ok(FriendStore { path, data })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let s = toml::to_string(&self.data)?;
        std::fs::write(&self.path, s)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<Friend> {
        self.data.friends.clone()
    }

    pub fn get(&self, pubkey: &[u8; 32]) -> Option<Friend> {
        let key = id::encode(*pubkey);
        self.data.friends.iter().find(|f| f.pubkey == key).cloned()
    }

    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        let key = id::encode(*pubkey);
        self.data.friends.iter().any(|f| f.pubkey == key)
    }

    pub fn add(&mut self, nickname: String, pubkey: [u8; 32], ip: Option<String>) -> anyhow::Result<()> {
        let key = id::encode(pubkey);
        if self.data.friends.iter().any(|f| f.pubkey == key) {
            anyhow::bail!("该公钥已存在好友列表中");
        }
        let mut f = Friend { nickname, pubkey: key, ips: Vec::new(), last_seen: None };
        if let Some(ip) = ip {
            f.ips.push(ip);
        }
        self.data.friends.push(f);
        self.save()
    }

    /// 收到直连流量时更新：记录来源 IP（最近在前）+ 最近在线时间。
    pub fn update_last_seen_and_ip(&mut self, pubkey: &[u8; 32], ip: Option<&str>) -> bool {
        let key = id::encode(*pubkey);
        let now = crate::util::unix_millis();
        let mut changed = false;
        if let Some(f) = self.data.friends.iter_mut().find(|f| f.pubkey == key) {
            if f.last_seen != Some(now) {
                f.last_seen = Some(now);
                changed = true;
            }
            if let Some(ip) = ip {
                if let Some(pos) = f.ips.iter().position(|x| x == ip) {
                    if pos != 0 {
                        f.ips.remove(pos);
                        f.ips.insert(0, ip.to_string());
                        changed = true;
                    }
                } else {
                    f.ips.insert(0, ip.to_string());
                    changed = true;
                }
            }
            while f.ips.len() > MAX_IPS {
                f.ips.pop();
                changed = true;
            }
            if changed {
                let _ = self.save();
            }
        }
        changed
    }

    /// 合并寻址应答中的 IP（去重，IPv6 优先，最多 MAX_IPS 个）。
    pub fn merge_ips(&mut self, pubkey: &[u8; 32], new_ips: &[String]) -> bool {
        let key = id::encode(*pubkey);
        let mut changed = false;
        if let Some(f) = self.data.friends.iter_mut().find(|f| f.pubkey == key) {
            for ip in new_ips {
                if !f.ips.contains(ip) {
                    f.ips.insert(0, ip.clone());
                    changed = true;
                }
            }
            f.ips.sort_by_key(|s| !s.contains(':'));
            while f.ips.len() > MAX_IPS {
                f.ips.pop();
                changed = true;
            }
            if changed {
                let _ = self.save();
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_merge() {
        let dir = std::env::temp_dir().join(format!("kokona-friends-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("friends.toml");
        let _ = std::fs::remove_file(&path);
        let mut s = FriendStore::open(path.clone()).unwrap();
        let pk = [1u8; 32];
        s.add("alice".into(), pk, Some("2001:db8::1".into())).unwrap();
        assert!(s.contains(&pk));
        s.merge_ips(&pk, &["1.2.3.4".into(), "2001:db8::1".into()]);
        let f = s.get(&pk).unwrap();
        assert_eq!(f.ips[0], "2001:db8::1"); // v6 优先，排在最前
    }
}