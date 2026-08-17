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

    /// 收到直连流量时更新：记录来源地址（最近在前）+ 最近在线时间。
    /// 仅接受可达地址（过滤 link-local / ULA / 多播 / 未指定等不可用地址）。
    pub fn update_last_seen_and_ip(&mut self, pubkey: &[u8; 32], ip: Option<&str>) -> bool {
        let key = id::encode(*pubkey);
        let now = crate::util::unix_millis();
        let mut changed = false;
        if let Some(f) = self.data.friends.iter_mut().find(|f| f.pubkey == key) {
            if f.last_seen != Some(now) {
                f.last_seen = Some(now);
                changed = true;
            }
            if let Some(ip) = ip.filter(|s| reachable_addr(s)) {
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

    /// 合并寻址应答/公告中的地址（去重，IPv6 优先，最多 MAX_IPS 个）。
    /// 只接受可达地址；顺序按地址真实类型排序（修正带端口 v4 被误判为 v6 的问题）。
    pub fn merge_ips(&mut self, pubkey: &[u8; 32], new_ips: &[String]) -> bool {
        let key = id::encode(*pubkey);
        let mut changed = false;
        if let Some(f) = self.data.friends.iter_mut().find(|f| f.pubkey == key) {
            let before = f.ips.clone();
            let mut merged: Vec<String> = new_ips.iter().filter(|s| reachable_addr(s)).cloned().collect();
            for ip in before.iter() {
                if !merged.contains(ip) {
                    merged.push(ip.clone());
                }
            }
            merged.sort_by_key(|s| !is_v6_addr(s));
            merged.truncate(MAX_IPS);
            if merged != before {
                f.ips = merged;
                changed = true;
            }
            if changed {
                let _ = self.save();
            }
        }
        changed
    }
}

/// 解析 "ip" 或 "ip:port" / "[v6]:port" 为 IP；失败返回 None。
fn parse_ip(s: &str) -> Option<std::net::IpAddr> {
    if let Ok(a) = s.parse::<std::net::SocketAddr>() {
        return Some(a.ip());
    }
    if let Ok(a) = s.parse::<std::net::IpAddr>() {
        return Some(a);
    }
    None
}

/// 仅接受可达地址（过滤 link-local / ULA / 多播 / 未指定等）。
fn reachable_addr(s: &str) -> bool {
    parse_ip(s).map(|ip| crate::net::socket::filter_reachable(ip)).unwrap_or(false)
}

/// 判断地址字符串是否为 IPv6（按实际地址类型，而非字符串是否含冒号）。
fn is_v6_addr(s: &str) -> bool {
    matches!(parse_ip(s), Some(std::net::IpAddr::V6(_)))
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

    #[test]
    fn merge_filters_unreachable_and_sorts_by_family() {
        let dir = std::env::temp_dir().join(format!("kokona-friends-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("friends-f2.toml");
        let mut s = FriendStore::open(path.clone()).unwrap();
        let pk = [2u8; 32];
        s.add("bob".into(), pk, Some("1.2.3.4:9999".into())).unwrap();
        // fe80 link-local 与 224.x 多播应被过滤；带端口的 v4 不能被误判为 v6
        s.merge_ips(
            &pk,
            &[
                "fe80::1".into(),
                "224.0.0.1".into(),
                "1.2.3.4:9999".into(),
                "2001:db8::2".into(),
            ],
        );
        let f = s.get(&pk).unwrap();
        assert!(!f.ips.iter().any(|x| x.starts_with("fe80")));
        assert!(!f.ips.iter().any(|x| x.starts_with("224")));
        // v6 排前，带端口 v4 靠后
        assert_eq!(f.ips[0], "2001:db8::2");
        assert!(f.ips.contains(&"1.2.3.4:9999".to_string()));
        let v4_pos = f.ips.iter().position(|x| x == "1.2.3.4:9999").unwrap();
        let v6_pos = f.ips.iter().position(|x| x == "2001:db8::2").unwrap();
        assert!(v4_pos > v6_pos);
    }

    #[test]
    fn update_last_seen_filters_unreachable() {
        let dir = std::env::temp_dir().join(format!("kokona-friends-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("friends-f3.toml");
        let mut s = FriendStore::open(path.clone()).unwrap();
        let pk = [3u8; 32];
        s.add("carol".into(), pk, None).unwrap();
        // 不可达地址应被过滤；last_seen 更新本身会使返回值变化，故只断言列表内容
        s.update_last_seen_and_ip(&pk, Some("fe80::1"));
        let f = s.get(&pk).unwrap();
        assert!(f.ips.is_empty(), "fe80 不应入库: {:?}", f.ips);
        assert!(s.update_last_seen_and_ip(&pk, Some("240e::5:1212")));
        let f = s.get(&pk).unwrap();
        assert!(f.ips.contains(&"240e::5:1212".to_string()));
    }
}