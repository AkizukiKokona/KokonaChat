//! 固定链接 / 深链（`kokonachat://`）。
//!
//! 用途：**加好友时通过链接拉起客户端**。好友在浏览器/聊天窗口里点击
//! `kokonachat://add?nickname=..&pubkey=..&ip=..`，即可拉起本机客户端添加好友；
//! 客户端若已在运行，则通过本地 IPC 转发（见 `crate::ipc`）。
//!
//! 免安装（无需管理员）：Windows 注册到 **HKCU**（当前用户），Linux 写
//! `~/.local/share/applications/kokonachat.desktop` 并用 `xdg-mime` 设为默认处理。
//!
//! 链接格式：
//! ```text
//! kokonachat://add?nickname=<url编码>&pubkey=<64位hex>&ip=<ip[:port]>
//! kokonachat://talk?pubkey=<64位hex>
//! ```
//! `add` = 添加好友（可带 ip，不带则之后交由寻址补齐）；`talk` = 定位并转到聊天。

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::crypto::id;

/// 协议名称（即 URL scheme）。
pub const SCHEME: &str = "kokonachat";

/// 解析后的链接含义。
#[derive(Debug, Clone, PartialEq)]
pub enum Invite {
    /// 添加好友：昵称 + 对方公钥 + 最后已知 IP（可选，交由寻址补齐）。
    Add { nickname: String, pubkey: [u8; 32], ip: Option<String> },
    /// 直接与已是好友的人聊天（仅用于拉起）。
    Talk { pubkey: [u8; 32] },
}

impl Invite {
    pub fn pubkey(&self) -> [u8; 32] {
        match self {
            Invite::Add { pubkey, .. } | Invite::Talk { pubkey } => *pubkey,
        }
    }
}

/// 生成加好友邀请链接。`ips` 为对外提供的可达地址列表（如稳定公网 IPv4 / 本地 IPv4）。
pub fn build_invite(cfg: &Config, pubkey: [u8; 32], ips: &[String]) -> String {
    let n = pct_encode(cfg.nickname.trim());
    let k = id::encode(pubkey);
    let mut q = format!("nickname={n}&pubkey={k}");
    if let Some(ip) = ips.first() {
        q = format!("{q}&ip={}", pct_encode(ip));
    }
    format!("{SCHEME}://add?{q}")
}

/// 解析 `kokonachat://` 链接。
pub fn parse_url(raw: &str) -> Result<Invite> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("链接为空");
    }
    let rest = raw
        .split_once("://")
        .map(|(s, r)| {
            if s == SCHEME {
                Ok(r)
            } else {
                bail!("不是 {SCHEME}:// 链接: {raw}")
            }
        })
        .ok_or_else(|| anyhow::anyhow!("不是 {SCHEME}:// 链接: {raw}"))??;
    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    let params = parse_query(query);
    let q = |k: &str| params.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

    match authority {
        "add" => {
            let pubkey = q("pubkey").filter(|s| !s.is_empty()).context("链接缺少 pubkey 参数")?;
            let pk = id::decode(pubkey).map_err(|_| anyhow::anyhow!("pubkey 不是有效的 64 位 hex"))?;
            let ip = q("ip")
                .filter(|s| !s.is_empty())
                .map(|s| crate::net::socket::parse_sockaddr(s, crate::config::DEFAULT_PORT).map(crate::net::socket::fmt_addr))
                .transpose()
                .context("链接中的 ip 参数不合法")?;
            let nickname = q("nickname")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| id::short_from_hex(pubkey));
            Ok(Invite::Add { nickname, pubkey: pk, ip })
        }
        "talk" => {
            let pubkey = q("pubkey").filter(|s| !s.is_empty()).context("链接缺少 pubkey 参数")?;
            Ok(Invite::Talk { pubkey: id::decode(pubkey)? })
        }
        other => bail!("不支持的链接类型: {other}"),
    }
}

// ---------- 免安装协议注册 ----------

/// 注册 `kokonachat://` 协议处理（Windows: HKCU；Linux: ~/.local/share/applications + xdg-mime）。
/// 均无需管理员权限。
pub fn register_protocol(exe: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        register_windows(exe)
    }
    #[cfg(target_os = "linux")]
    {
        register_linux(exe)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        println!("当前系统不支持自动注册协议；请手动把默认打开方式指向 `{}`（参数: handle \"%1\"）。", exe.display());
        Ok(())
    }
}

/// 注销 `kokonachat://` 协议处理。
pub fn unregister_protocol() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let _ = run_reg(&["delete", r"HKCU\Software\Classes\kokonachat", "/f"]);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let file = desktop_file();
        match std::fs::remove_file(&file) {
            Ok(_) => {
                println!("已删除 {}", file.display());
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("协议未注册（没有 {}）", file.display());
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        println!("当前系统无需注销操作。");
        Ok(())
    }
}

/// 查询 `kokonachat://` 是否已注册。
pub fn is_registered() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        Ok(run_reg(&["query", r"HKCU\Software\Classes\kokonachat"]).is_ok())
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("xdg-mime")
            .args(["query", "default", &format!("x-scheme-handler/{SCHEME}")])
            .output();
        Ok(out.map(|o| String::from_utf8_lossy(&o.stdout).contains("kokonachat")).unwrap_or(false))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
fn register_windows(exe: &Path) -> Result<()> {
    let root = r"HKCU\Software\Classes\kokonachat";
    run_reg(&["add", root, "/ve", "/d", "URL:KokonaChat", "/f"])?;
    run_reg(&["add", root, "/v", "URL Protocol", "/d", "", "/f"])?;
    let cmd = format!("\"{}\" handle \"%1\"", exe.display());
    run_reg(&["add", &format!("{root}\\shell\\open\\command"), "/ve", "/d", &cmd, "/f"])?;
    println!("已注册 kokonachat:// 协议（当前用户，免安装）");
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_reg(args: &[&str]) -> Result<()> {
    let st = Command::new("reg").args(args).status().context("reg.exe 执行失败")?;
    if st.success() {
        Ok(())
    } else {
        bail!("reg 命令失败: {}", args.join(" "))
    }
}

#[cfg(target_os = "linux")]
fn register_linux(exe: &Path) -> Result<()> {
    let file = desktop_file();
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=KokonaChat\n\
         Comment=去中心化 P2P 即时通讯\n\
         Exec=\"{}\" handle %u\n\
         MimeType=x-scheme-handler/{SCHEME};\n\
         NoDisplay=true\n\
         Terminal=false\n",
        exe.display()
    );
    std::fs::write(&file, content)?;
    let st = Command::new("xdg-mime")
        .args(["default", "kokonachat.desktop", &format!("x-scheme-handler/{SCHEME}")])
        .status()
        .context("xdg-mime 执行失败")?;
    if st.success() {
        println!("已注册 kokonachat:// 协议（用户级 .desktop，免安装）");
        Ok(())
    } else {
        bail!("xdg-mime 设置默认处理失败")
    }
}

#[cfg(target_os = "linux")]
fn desktop_file() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| dirs::home_dir().expect("无法定位用户目录").join(".local/share"))
        .join("applications")
        .join("kokonachat.desktop")
}

// ---------- URL 编码 ----------

/// 简单 percent 编码（非 ASCII / 保留字符转 %XX）。
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// 简单 percent 解码。
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hexv(bytes[i + 1]), hexv(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hexv(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty() && s.contains('='))
        .filter_map(|kv| kv.split_once('=').map(|(k, v)| (pct_decode(k), pct_decode(v))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn build_parse_roundtrip() {
        let cfg = Config {
            port: 1212,
            auto_addressing: false,
            nickname: "心夏 Kokona".into(),
            public_ipv4: Some("8.8.8.8".into()),
            avatar_feature: true,
            media_feature: true,
            file_feature: false,
            avatar_path: None,
            no_warn_large_attach: false,
        };
        let pk = [0xab; 32];
        let url = build_invite(&cfg, pk, &["8.8.8.8:1212".into()]);
        assert!(url.starts_with("kokonachat://add?"));
        let inv = parse_url(&url).unwrap();
        match inv {
            Invite::Add { nickname, pubkey, ip } => {
                assert_eq!(nickname, "心夏 Kokona");
                assert_eq!(pubkey, pk);
                assert_eq!(ip, Some("8.8.8.8:1212".into()));
            }
            _ => panic!("应为 add"),
        }
    }

    #[test]
    fn parse_talk_and_errors() {
        let pk = [1u8; 32];
        let k = crate::crypto::id::encode(pk);
        match parse_url(&format!("kokonachat://talk?pubkey={k}")).unwrap() {
            Invite::Talk { pubkey } => assert_eq!(pubkey, pk),
            _ => panic!("应为 talk"),
        }
        assert!(parse_url("http://example.com").is_err());
        assert!(parse_url("kokonachat://add?nickname=x").is_err(), "缺 pubkey 应报错");
        assert!(parse_url("kokonachat://add?nickname=x&pubkey=zzz&ip=1.2.3.4").is_err(), "非法 pubkey 应报错");
        assert!(parse_url("kokonachat://add?nickname=x&pubkey=01&ip=not-an-ip").is_err(), "非法 ip 应报错");
    }

    #[test]
    fn pct_roundtrip() {
        assert_eq!(pct_decode(&pct_encode("你好 world!")), "你好 world!");
        assert_eq!(pct_decode("2001%3Adb8%3A%3A1"), "2001:db8::1");
    }
}