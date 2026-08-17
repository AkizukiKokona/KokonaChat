//! 本地 IPC：固定链接的"应用已在运行时"转发通道。
//!
//! 客户端启动（非调试模式）时监听 `127.0.0.1:<派生端口>` 上的 TCP；
//! 收到 `kokonachat://` 链接的第二个进程（被系统拉起）用相同派生端口连上来，
//! 把邀请内容以一行 JSON 发送，由运行中的实例写入好友列表并提示 UI，
//! 转发进程随即返回结果并退出。若没有运行中的实例（连接失败），
//! 调用方直接写好友存储即可。
//!
//! 端口由数据目录稳定派生，避免与本机 UDP 守护端口（默认 1212）冲突；
//! 实际监听端口写回 `<root>/.ipc_port` 供自动定位。

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::id;
use crate::net::NetEvent;
use crate::store::friends::FriendStore;

/// IPC 端口区间：9100 + (data-dir hash % 2000)。
const IPC_BASE: u16 = 9100;
const IPC_RANGE: u16 = 2000;
/// 端口冲突时最多向后扫描的偏移数。
const PORT_SCAN: u16 = 16;
/// 客户端连接/读写超时（避免被 http 错误拉起时一直卡住）。
const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn ipc_base_port(root: &Path) -> u16 {
    let mut h = 0x811c9dc5u32;
    for b in root.to_string_lossy().bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    IPC_BASE + ((h % (IPC_RANGE as u32)) as u16)
}

fn ipc_file(root: &Path) -> PathBuf {
    root.join(".ipc_port")
}

#[derive(Serialize, Deserialize)]
struct Msg {
    cmd: String,
    nickname: Option<String>,
    pubkey: Option<String>,
    ip: Option<String>,
}

/// 在运行中的客户端里启动 IPC 监听（返回前已尝试绑定；端口不足时静默停用）。
pub async fn serve(
    friends: Arc<Mutex<FriendStore>>,
    evt_tx: std::sync::mpsc::Sender<NetEvent>,
    root: &Path,
) -> anyhow::Result<()> {
    let base = ipc_base_port(root);
    let mut bound = None;
    for d in 0..PORT_SCAN {
        match tokio::net::TcpListener::bind(("127.0.0.1", base + d)).await {
            Ok(l) => {
                let _ = write_port_file(root, base + d);
                bound = Some(l);
                break;
            }
            Err(_) => continue,
        }
    }
    let Some(listener) = bound else {
        // 全部端口被占（罕见）：IPC 不可用不阻塞客户端主功能。
        return Ok(());
    };

    loop {
        let (sock, _) = listener.accept().await?;
        let friends = friends.clone();
        let evt_tx = evt_tx.clone();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(sock);
            let mut line = String::new();
            if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.is_err() {
                return;
            }
            let resp = handle_msg(&line, &friends, &evt_tx);
            let _ = tokio::io::AsyncWriteExt::write_all(&mut reader, resp.as_bytes()).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut reader, b"\n").await;
        });
    }
}

/// 记录实际绑定端口（尽力而为；失败无碍）。
fn write_port_file(root: &Path, port: u16) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    std::fs::write(ipc_file(root), port.to_string())
}

/// 处理一行 JSON 邀请消息，返回响应文本。
fn handle_msg(
    line: &str,
    friends: &Mutex<FriendStore>,
    evt_tx: &std::sync::mpsc::Sender<NetEvent>,
) -> String {
    let msg: Msg = match serde_json::from_str(line.trim()) {
        Ok(m) => m,
        Err(e) => return format!("err: 无法解析邀请消息: {e}"),
    };
    let pk = match msg.pubkey.as_deref() {
        Some(k) => match id::decode(k) {
            Ok(p) => p,
            Err(_) => return "err: pubkey 不是有效的 64 位 hex".into(),
        },
        None => return "err: 缺少 pubkey".into(),
    };
    match msg.cmd.as_str() {
        "add_friend" => {
            let nickname = msg.nickname.unwrap_or_default();
            let mut f = friends.lock().unwrap();
            if f.contains(&pk) {
                evt_tx.send(NetEvent::Status(format!("链接里的好友 {nickname} 已存在"))).ok();
                return "already".into();
            }
            match f.add(nickname.clone(), pk, msg.ip) {
                Ok(_) => {
                    drop(f);
                    evt_tx
                        .send(NetEvent::Status(format!("通过链接添加了好友 {nickname}")))
                        .ok();
                    "ok".into()
                }
                Err(e) => format!("err: {e}"),
            }
        }
        "talk" => {
            if friends.lock().unwrap().contains(&pk) {
                evt_tx.send(NetEvent::Status("链接已定位到好友，开始聊天吧".into())).ok();
                "ok".into()
            } else {
                evt_tx.send(NetEvent::Status("链接指向的用户还不是好友".into())).ok();
                "err: not-friend".into()
            }
        }
        other => format!("err: 未知命令 {other}"),
    }
}

/// 尝试把添加好友的邀请转发给正在运行的实例。
/// 返回 `Some(响应)` 表示转发成功；`None` 表示没有运行中的实例（请直接写入好友列表）。
pub fn try_add_friend(root: &Path, nickname: &str, pubkey: &str, ip: Option<&str>) -> Option<String> {
    let msg = Msg {
        cmd: "add_friend".into(),
        nickname: Some(nickname.into()),
        pubkey: Some(pubkey.into()),
        ip: ip.map(|s| s.into()),
    };
    let body = serde_json::to_vec(&msg).ok()?;
    run(root, &body)
}

/// 尝试把"定位好友"的链接转发给正在运行的实例。
pub fn try_talk(root: &Path, pubkey: &str) -> Option<String> {
    let msg = Msg {
        cmd: "talk".into(),
        nickname: None,
        pubkey: Some(pubkey.into()),
        ip: None,
    };
    let body = serde_json::to_vec(&msg).ok()?;
    run(root, &body)
}

fn run(root: &Path, body: &[u8]) -> Option<String> {
    let base = read_port(root).unwrap_or_else(|| ipc_base_port(root));
    // 扫描端口落在 9100-11099 区间，可能与其它本机程序冲突；
    // 用 connect_timeout + 总时限兜底，确保被错误拉起时也绝不长时间卡住。
    let start = Instant::now();
    for d in 0..PORT_SCAN {
        if start.elapsed() >= IO_TIMEOUT {
            break;
        }
        let Ok(addr) = format!("127.0.0.1:{}", base + d).parse::<SocketAddr>() else {
            continue;
        };
        let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(400)) else {
            continue;
        };
        let _ = s.set_read_timeout(Some(IO_TIMEOUT));
        let _ = s.set_write_timeout(Some(IO_TIMEOUT));
        if s.write_all(body).is_err() {
            continue;
        }
        if s.write_all(b"\n").is_err() {
            continue;
        }
        let mut line = String::new();
        let mut reader = BufReader::new(&s);
        let r = if reader.read_line(&mut line).is_err() {
            "err: 转发后未收到回复".to_string()
        } else {
            line.trim().to_string()
        };
        let r = if r.is_empty() { "ok".to_string() } else { r };
        return Some(r);
    }
    None
}

fn read_port(root: &Path) -> Option<u16> {
    let s = std::fs::read_to_string(ipc_file(root)).ok()?;
    s.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_derived_stable() {
        let root = Path::new(r"C:\Users\tester\.kokona");
        assert_eq!(ipc_base_port(root), ipc_base_port(root));
        let other = Path::new(r"C:\Users\tester\.kokona-b");
        assert!(ipc_base_port(root) != ipc_base_port(other));
        assert!((9100..=11099).contains(&ipc_base_port(root)));
    }

    #[tokio::test]
    async fn serve_and_forward_end_to_end() {
        let dir = std::env::temp_dir().join(format!("kokona-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Mutex::new(FriendStore::open(dir.join("friends.toml")).unwrap()));
        let (tx, rx) = std::sync::mpsc::channel();

        let sa = store.clone();
        let sx = tx.clone();
        let root_dir = dir.clone();
        // 服务端跑在独立线程的 runtime 上，测试线程可以放心做阻塞的 socket 调用
        let server = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(serve(sa, sx, &root_dir))
        });

        // 等端口文件写出
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let port = loop {
            if let Some(p) = read_port(&dir) {
                break p;
            }
            if std::time::Instant::now() > deadline {
                panic!("IPC 端口未就绪");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!((9100..=11099).contains(&port));

        let pk = [7u8; 32];
        let resp = try_add_friend(&dir, "喜多", &id::encode(pk), Some("1.2.3.4:1212"));
        assert_eq!(resp.as_deref(), Some("ok"), "转发应成功: {resp:?}");
        assert!(store.lock().unwrap().contains(&pk), "运行实例的好友存储应已写入");

        // 事件：提醒 UI
        let got = rx.recv_timeout(Duration::from_secs(2));
        assert!(matches!(got, Ok(NetEvent::Status(s)) if s.contains("喜多")));

        // 重复添加 -> already
        assert_eq!(try_add_friend(&dir, "喜多", &id::encode(pk), None).as_deref(), Some("already"));

        // 未运行（换个 root）-> None
        let dead = dir.join("dead");
        assert_eq!(try_add_friend(&dead, "x", &id::encode(pk), None), None);

        // serve 是常驻循环，drop JoinHandle 即分离线程，随测试进程退出终止。
        drop(server);
    }
}