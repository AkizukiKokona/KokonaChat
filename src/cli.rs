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
    /// 配置管理（公网 IPv4 稳定地址模式）
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// 备份与恢复（身份绑定加密；配置+好友与聊天记录可分开或合并）
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// 生成加好友邀请链接（并确保 kokonachat:// 协议已注册，可被链接拉起）
    Link,
    /// kokonachat:// 协议管理（免安装注册，Windows 当前用户 / Linux 用户级 .desktop）
    Protocol {
        #[command(subcommand)]
        action: ProtocolAction,
    },
    /// 处理链接：读取 kokonachat:// 邀请，添加好友或定位好友（点击链接时由系统拉起）
    Handle {
        /// kokonachat:// 开头的链接（如 kokonachat://add?nickname=..&pubkey=..&ip=..）
        url: String,
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
    /// 启动原生图形界面（winit + egui + wgpu，浅色主题；与 TUI 共用聊天数据）
    Gui {
        /// 监听端口（默认 1212）
        #[arg(long)]
        port: Option<u16>,
        /// 消息发送失败后自动向共同好友寻址
        #[arg(long)]
        auto_addr: bool,
        /// 移动端 UI 预览（竖屏手机比例窗口，在电脑上查看移动端布局效果）
        #[arg(long)]
        mobile: bool,
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

#[derive(Subcommand)]
pub enum ConfigAction {
    /// 设置公网 IPv4 为稳定地址（之后不再重复广播本机地址，好友也无需反复寻址）
    SetPublicIpv4 {
        /// 公网 IPv4（可带端口，如 1.2.3.4:1212；存储时只保留 IP）
        ip: String,
    },
    /// 清除公网 IPv4（回到默认动态通告模式）
    ClearPublicIpv4,
    /// 显示当前配置
    Show,
}

#[derive(Subcommand)]
pub enum ProtocolAction {
    /// 注册 kokonachat:// 协议（免安装，无需管理员）
    Install,
    /// 注销 kokonachat:// 协议
    Uninstall,
    /// 查询 kokonachat:// 是否已注册
    Status,
}

#[derive(Subcommand)]
pub enum BackupAction {
    /// 导出配置 + 好友列表（单独一个备份文件）
    ExportCore {
        /// 输出文件路径
        path: PathBuf,
    },
    /// 导出聊天记录（单独一个备份文件）
    ExportChat {
        /// 输出文件路径
        path: PathBuf,
    },
    /// 导出全部（配置+好友+聊天记录合并成一个加密大包）
    ExportAll {
        /// 输出文件路径
        path: PathBuf,
    },
    /// 导入备份（自动识别类型；仅本账户身份可解密）
    Import {
        /// 备份文件路径
        path: PathBuf,
    },
}