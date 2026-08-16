//! `~/.kokona` 数据目录布局与配置。
//! 说明：默认守护端口 1212 是 Kokona（心夏）的生日，作为协议的守护端口。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 1212;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    /// UDP 守护端口。1212 是 Kokona（心夏）的生日。
    pub port: u16,
    /// 消息发送失败后自动向共同好友发起寻址（默认关闭，符合被动寻址策略）。
    pub auto_addressing: bool,
    pub nickname: String,
}

impl Default for Config {
    fn default() -> Self {
        Config { port: DEFAULT_PORT, auto_addressing: false, nickname: "kokona".into() }
    }
}

pub struct Paths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub identity: PathBuf,
    pub friends: PathBuf,
    pub log_dir: PathBuf,
}

/// 数据目录：默认 `~/.kokona`，可通过 `--data-dir` 覆盖（便于单机多实例联调）。
pub fn resolve_paths(data_dir: Option<PathBuf>) -> Paths {
    let root = data_dir.unwrap_or_else(|| {
        let home = dirs::home_dir().expect("无法定位用户目录");
        home.join(".kokona")
    });
    Paths {
        log_dir: root.join("logs"),
        config: root.join("config.toml"),
        identity: root.join("identity.key"),
        friends: root.join("friends.toml"),
        root,
    }
}

/// 加载配置；不存在时写入默认配置。
pub fn load_config(path: &Path) -> Config {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(c) = toml::from_str(&raw) {
            return c;
        }
    }
    let c = Config::default();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
    if let Ok(s) = toml::to_string(&c) {
        let _ = std::fs::write(path, s);
    }
    c
}