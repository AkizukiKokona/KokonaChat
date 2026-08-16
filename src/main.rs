mod cli;
mod config;
mod crypto;
mod headless;
mod net;
mod proto;
mod store;
mod tui;
mod util;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::cli::{Command, FriendAction};

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let paths = config::resolve_paths(cli.data_dir.clone());
    match cli.cmd {
        Command::Init => cmd_init(&paths),
        Command::Id => cmd_id(&paths),
        Command::Import { seed_hex } => cmd_import(&paths, &seed_hex),
        Command::Friend { action } => cmd_friend(&paths, action),
        Command::Start { port, auto_addr } => cmd_start(&paths, port, auto_addr, cli.debug),
    }
}

fn cmd_init(paths: &config::Paths) -> Result<()> {
    std::fs::create_dir_all(&paths.root)?;
    if paths.identity.exists() {
        // 身份重叠检测：已有身份的公钥不应与好友列表重合
        let ident = crypto::keys::Identity::load(&paths.identity)?;
        check_overlap(paths, &ident.ed_pub)?;
        println!("已存在身份，直接复用：");
        println!("  用户 ID: {}", ident.user_id());
        println!("  种子备份: {}", ident.seed_hex());
        return Ok(());
    }
    let ident = crypto::keys::Identity::generate();
    check_overlap(paths, &ident.ed_pub)?;
    ident.save(&paths.identity)?;
    println!("身份已生成并保存到 {}", paths.identity.display());
    println!("  用户 ID: {}", ident.user_id());
    println!("  种子备份: {}", ident.seed_hex());
    println!("  监听端口: {}（注：1212 是 Kokona/心夏 的生日，作为协议的守护端口）", config::DEFAULT_PORT);
    println!();
    println!("请将此用户 ID（公钥）告知好友，并将对方公钥+IP 用以下命令添加：");
    println!("  kokonachat friend add <昵称> <对方公钥> <对方IP>");
    Ok(())
}

/// 启动/初始化时校验：本机账户公钥不允许出现在好友列表中（同一身份不允许既是自己又是好友）。
/// 返回 Err 时说明存在身份重叠。
fn check_overlap(paths: &config::Paths, own_pub: &[u8; 32]) -> Result<()> {
    let store = store::friends::FriendStore::open(paths.friends.clone())?;
    let key = crypto::id::encode(*own_pub);
    let dups: Vec<String> = store.list().into_iter().filter(|f| f.pubkey == key).map(|f| f.nickname).collect();
    if !dups.is_empty() {
        bail!("检测到身份重叠：本机账户公钥与好友列表中的「{}」相同。同一身份不能同时是自己和好友，请确认数据目录/种子是否正确。", dups.join("、"));
    }
    Ok(())
}

/// 切换账户：导入身份种子（64 位 hex）覆盖当前身份。
fn cmd_import(paths: &config::Paths, seed_hex: &str) -> Result<()> {
    let bytes = hex::decode(seed_hex.trim()).context("种子应为 64 位 hex（即 init 输出的“种子备份”）")?;
    if bytes.len() != 32 {
        bail!("种子应为 32 字节（64 位 hex），实际 {} 字节", bytes.len());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let ident = crypto::keys::Identity::from_seed(seed);

    // 与好友列表比对：导入的账户不应同时出现在自己的好友里
    check_overlap(paths, &ident.ed_pub)?;

    if let Ok(old) = crypto::keys::Identity::load(&paths.identity) {
        if old.ed_pub == ident.ed_pub {
            bail!("该种子就是当前身份，无需导入");
        }
        println!("当前账户: {}（备份种子: {}）", old.user_id(), old.seed_hex());
    }
    ident.save(&paths.identity)?;
    println!("账户已切换 -> {}", ident.user_id());
    println!("新种子备份: {}", ident.seed_hex());
    Ok(())
}

fn cmd_id(paths: &config::Paths) -> Result<()> {
    let ident = crypto::keys::Identity::load(&paths.identity).context("身份不存在，请先运行 `kokonachat init`")?;
    println!("用户 ID: {}", ident.user_id());
    println!("监听端口: {}", config::load_config(&paths.config).port);
    println!("本机地址:");
    match local_ip_address::local_ip() {
        Ok(ip) => println!("  IPv4: {ip}"),
        Err(e) => println!("  IPv4: (无法获取: {e})"),
    }
    match local_ip_address::local_ipv6() {
        Ok(ip) => println!("  IPv6: {ip}"),
        Err(e) => println!("  IPv6: (无法获取: {e})"),
    }
    Ok(())
}

fn cmd_friend(paths: &config::Paths, action: FriendAction) -> Result<()> {
    let mut store = store::friends::FriendStore::open(paths.friends.clone())?;
    match action {
        FriendAction::Add { nickname, pubkey, ip } => {
            let pk = crypto::id::decode(&pubkey).context("公钥格式错误（应为 64 位 hex，即对方用户 ID）")?;
            // 解析并保留端口：同一 IP 上可能有多个用户，端口用于区分。
            let sock = net::socket::parse_sockaddr(&ip, config::DEFAULT_PORT).context("IP 格式错误（支持 ip / ip:port / [v6]:port）")?;
            let stored = net::socket::fmt_addr(sock);
            store.add(nickname.clone(), pk, Some(stored.clone()))?;
            println!("已添加好友: {nickname}");
            println!("  公钥: {pubkey}");
            println!("  IP:   {stored}");
        }
        FriendAction::List => {
            let list = store.list();
            if list.is_empty() {
                println!("好友列表为空");
                return Ok(());
            }
            for f in list {
                let ips = if f.ips.is_empty() { "-".into() } else { f.ips.join(", ") };
                let seen = f.last_seen.map(util::format_ts).unwrap_or_else(|| "-".into());
                println!("{:<12} {:<16} IP[{}] 最近在线 {seen}", f.nickname, crypto::id::short_from_hex(&f.pubkey), ips);
            }
        }
    }
    Ok(())
}

fn cmd_start(paths: &config::Paths, port: Option<u16>, auto_addr: bool, debug: bool) -> Result<()> {
    // 身份与配置
    let identity = crypto::keys::Identity::load(&paths.identity).context("身份不存在，请先运行 `kokonachat init`")?;
    check_overlap(paths, &identity.ed_pub)?;

    let mut cfg = config::load_config(&paths.config);
    if let Some(p) = port {
        cfg.port = p;
    }
    if auto_addr {
        cfg.auto_addressing = true;
    }

    // 同一账户（同一 data-dir）不允许重复登录；调试模式（本机多实例联调）除外。
    let _lock = if debug {
        None
    } else {
        Some(IdentityLock::acquire(&paths.root)?)
    };

    if debug {
        init_console_log();
    } else {
        init_file_log(&paths.log_dir)?;
    }

    // 共享好友存储（网络层读/写，界面读）
    let friends = Arc::new(Mutex::new(store::friends::FriendStore::open(paths.friends.clone())?));

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(256);
    let (evt_tx, evt_rx) = std::sync::mpsc::channel();

    let own_short = crypto::id::short(&identity.ed_pub);
    let net_init = net::NetInit { identity, port: cfg.port, friends: friends.clone(), cmd_rx, evt_tx };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let handle = rt.spawn(net::run(net_init));

    let log_file = paths.log_dir.join("messages.log");
    let res = if debug {
        headless::run(friends, cmd_tx.clone(), evt_rx, own_short, log_file)
    } else {
        let app = tui::app::App::new(friends, cmd_tx.clone(), evt_rx, &cfg, own_short, log_file);
        tui::run(app)
    };

    let _ = cmd_tx.blocking_send(net::NetCommand::Quit).ok();
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    let _ = handle;
    res
}

/// 调试模式日志：Debug 级输出到控制台（stderr），便于两个终端联调观察。
fn init_console_log() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
}

fn init_file_log(log_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(log_dir)?;
    let file = std::fs::File::create(log_dir.join("kokona.log"))?;
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .target(env_logger::Target::Pipe(Box::new(file)))
        .format_timestamp_secs()
        .init();
    Ok(())
}

/// 身份锁：同一数据目录（同一账户）一次只允许一个实例运行。
/// 释放时自动删除锁文件；若异常退出留下残留，删除该文件即可重新启动。
struct IdentityLock {
    path: PathBuf,
}

impl IdentityLock {
    fn acquire(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let path = root.join(".lock");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        match opts.open(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", process::id());
                Ok(IdentityLock { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                bail!(
                    "身份锁已存在（{}）：同一账户不允许同时登录。\n若确认没有其他实例在运行，请删除该锁文件后重试。",
                    path.display()
                )
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}