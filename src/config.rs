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
    /// 公网 IPv4（稳定地址模式）：
    /// 有公网 IPv4 的用户把它设为默认对外地址后，地址长期稳定，
    /// 无需反复通告本机地址，好友也无需反复重新寻址。
    #[serde(default)]
    pub public_ipv4: Option<String>,
    /// 头像功能开关（关掉后使用软件默认头像）。
    #[serde(default = "default_true")]
    pub avatar_feature: bool,
    /// 多媒体功能开关（仅图片、视频）。
    #[serde(default = "default_true")]
    pub media_feature: bool,
    /// 完整文件传送开关（依赖媒体与头像，开启时自动带上两者）。
    #[serde(default)]
    pub file_feature: bool,
    /// 自定义头像文件路径（None = 软件默认头像）。
    #[serde(default)]
    pub avatar_path: Option<String>,
    /// 发送大文件（图片/视频/文件）时的警告是否“不再显示”。
    #[serde(default)]
    pub no_warn_large_attach: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: DEFAULT_PORT,
            auto_addressing: false,
            nickname: "kokona".into(),
            public_ipv4: None,
            avatar_feature: true,
            media_feature: true,
            file_feature: false,
            avatar_path: None,
            no_warn_large_attach: false,
        }
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
    let cfg = if let Ok(raw) = std::fs::read_to_string(path) {
        toml::from_str::<Config>(&raw).unwrap_or_default()
    } else {
        Config::default()
    };
    if let Ok(s) = toml::to_string(&cfg) {
        let _ = std::fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
        let _ = std::fs::write(path, s);
    }
    cfg
}

/// 解析用户输入的"公网 IPv4"配置串：接受纯 IP 或 `IP:port`，统一存为纯 IP。
pub fn normalize_public_ipv4(s: &str) -> anyhow::Result<String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let text = s.trim();
    let ip = if let Ok(a) = text.parse::<SocketAddr>() {
        a.ip()
    } else if let Ok(a) = text.parse::<IpAddr>() {
        a
    } else {
        anyhow::bail!("无法解析 IPv4 地址: {s}");
    };
    let IpAddr::V4(v4) = ip else {
        anyhow::bail!("公网 IPv4 必须是 IPv4 地址: {s}");
    };
    if v4 == Ipv4Addr::new(0, 0, 0, 0) {
        anyhow::bail!("地址不能是 0.0.0.0");
    }
    if !crate::net::socket::is_public_v4(v4) {
        anyhow::bail!("{v4} 不是公网 IPv4（回环/内网/保留地址不能作为稳定地址）");
    }
    Ok(v4.to_string())
}