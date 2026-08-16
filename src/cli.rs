use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kokonachat", version, about = "KokonaChat：去中心化 P2P 即时通讯（IPv6/UDP 直连 + 端到端加密 + 被动寻址）")]
pub struct Cli {
    /// 自定义数据目录（默认 ~/.kokona）。可用于单机多实例联调。
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    /// 调试模式（非默认）：不用 TUI，改用终端命令行聊天 + Debug 日志输出到控制台；
    /// 跳过身份锁，配合 --port 可在本机同时启动多个实例联调。
    #[arg(long, global = true)]
    pub debug: bool,
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// 初始化身份（生成密钥对），打印用户 ID；会做与本机好友列表的身份重叠检测
    Init,
    /// 打印本机身份与网络信息
    Id,
    /// 切换账户：导入 32 字节身份种子（64 位 hex）覆盖当前身份
    Import {
        /// 身份种子 hex（64 位，来自 `init` 或 `import` 的“种子备份”输出）
        seed_hex: String,
    },
    /// 好友管理
    Friend {
        #[command(subcommand)]
        action: FriendAction,
    },
    /// 启动客户端（默认 TUI；--debug 时进入终端调试聊天模式）
    Start {
        /// 监听端口（默认 1212）
        #[arg(long)]
        port: Option<u16>,
        /// 消息发送失败后自动向共同好友寻址
        #[arg(long)]
        auto_addr: bool,
    },
}

#[derive(Subcommand)]
pub enum FriendAction {
    /// 添加好友（昵称 + 对方公钥/用户 ID + 对方 IP）
    Add {
        /// 显示名（本地自定义，用于区分同一 IP 上的不同用户）
        nickname: String,
        /// 对方公钥（64 位 hex，即用户 ID）；核对此项以确认对方身份
        pubkey: String,
        /// 对方最后已知 IP（可含端口，如 2001:db8::1 或 1.2.3.4:1212）
        ip: String,
    },
    /// 列出好友
    List,
}