# KokonaChat

去中心化 P2P 即时通讯原型：**IPv6/UDP 直连 + 端到端加密 + 被动寻址**。无任何中心服务器。

- 身份：本地生成 `Ed25519` 密钥对，**公钥即用户 ID**（64 位 hex）。
- 加密：临时 X25519 前向保密 + HKDF-SHA256 + AES-256-GCM + Ed25519 签名。
- 寻址：**被动寻址**。上线不广播 IP；发送失败不自动全网寻址；仅在手动（或开启自动寻址）时向共同好友发起**单次、单跳** IP 询问，不递归不广播。
- 网络：UDP，默认守护端口 **1212**（注：1212 是 Kokona/心夏 的生日，作为协议的守护端口）；双栈同时监听 IPv6/IPv4，**优先 IPv6**。
- 界面：三栏 TUI（好友列表 | 聊天区 | 输入框），消息失败状态可见并提供「查找新地址」入口。
- 可靠性：UDP 丢包重传（最多 3 次，间隔 2 秒）。

## 编译

```bash
cargo build --release      # 已启用 LTO（[profile.release] lto="fat", codegen-units=1）
cargo test                 # 单元测试（编解码/加解密回环/重传调度等）
```

依赖 Rust 工具链（edition 2021）。跨平台：Windows / Linux / macOS。

## 使用

```bash
# 1) 初始化身份（生成 ~/.kokona 目录与密钥）
kokonachat init

# 2) 查看自己的用户 ID 与本机地址（复制给好友）
kokonachat id

# 3) 添加好友（对方显示名 + 对方公钥 + 对方 IP，IP 可带端口）
kokonachat friend add alice <对方用户ID> 2001:db8::1
kokonachat friend add alice <对方用户ID> 1.2.3.4:1212
kokonachat friend list

# 3.5) 切换账户（导入 32 字节身份种子，即 init 输出的“种子备份”）
kokonachat import <64位hex种子>

# 4) 启动 TUI
kokonachat start                     # 默认端口 1212
kokonachat start --port 1212 --auto-addr   # 失败消息自动向共同好友寻址
```

## 账户与好友（身份三维）

账户由三个维度构成：

| 维度 | 作用 |
|---|---|
| **密钥**（Ed25519 公钥，即用户 ID） | 锁死身份，用于端到端加密与签名校验 |
| **显示名**（本地昵称） | 再锁一层“是谁”，同一 IP 上区分不同用户 |
| **IP**（最后已知地址，可含端口） | **仅作活动寻址**，会变化、可多条；不参与身份判定 |

前两维即可唯一确定用户，第三维只是“现在在哪”。因此**同一个 IP 上可以存在多个不同用户**（不同的公钥/昵称），互不混淆；加好友只需对方 IP 以及核对对方公钥：

```bash
kokonachat friend add <显示名> <对方公钥> <对方IP[:端口]>
```

其他约定：
- **同一账户不允许重复登录**：同一数据目录（同一身份）默认只允许一个实例在线，重复启动会被拒绝；`--debug` 调试模式除外（本机联调时可同时跑多个）。
- **身份重叠检测**：`init` / `import` / `start` 都会把本机账户公钥与本机好友列表比对，若发现“自己成了自己的好友”会报错，防止身份错乱。

## 调试模式（`--debug`）

不启动全屏 TUI，改用**终端命令行聊天**，网络日志（Debug 级）直接输出到控制台，方便开两个终端本机联调；配合 `--port` 可在同一台机器同时运行多个实例。

```bash
# 终端 A
kokonachat --data-dir %TEMP%\ka --debug --port 12221 start
# 终端 B
kokonachat --data-dir %TEMP%\kb --debug --port 12222 start
```

调试模式终端内命令：直接输入文本回车 -> 发给当前好友；`/use <昵称>` 切换；`/to <昵称> <内容>` 指定发送；`:昵称 <内容>` 同上；`/list`、`/help`、`/quit`。

> Windows 防火墙默认 **BlockInbound**（阻止所有入站），本机回环联调前需先以管理员放行：
> ```powershell
> netsh advfirewall firewall add rule name="kokonachat" dir=in action=allow program="<项目路径>\target\debug\kokonachat.exe" protocol=UDP
> ```
> 也可以直接运行一键脚本 `scripts\debug-test.ps1`（管理员）：自动放行防火墙 + 生成两个临时实例 + 验证 A→B 互发。

## TUI 键位

| 键 | 功能 |
|---|---|
| `Enter` | 发送 |
| `Ctrl+N` / `Ctrl+P` / `Tab` | 切换好友 |
| `Ctrl+F` | 查找新地址（向共同好友单次询问选中好友的最新 IP） |
| `Ctrl+R` | 重发当前会话失败的已发送消息 |
| `Ctrl+H` | 帮助/提示 | 
| `Ctrl+Q` / `Esc` | 退出 |

消息状态：`…` 发送中 → `✓` 已送达；`✗ [失败]` 无响应（重传 3 次耗尽）。失败后可按 `Ctrl+F` 寻址 → 自动重发。

## 数据存储（`~/.kokona/`）

```
~/.kokona/
├── config.toml       # 端口 / auto_addressing / 昵称
├── identity.key      # 32 字节身份种子（0600）
├── friends.toml      # 好友：昵称、公钥、最后已知 IP 列表、最近在线
└── logs/             # kokona.log（网络日志）、messages.log（消息记录）
```

## 单机双实例联调

```bash
# 终端 A
kokonachat --data-dir .kokona-a init
kokonachat --data-dir .kokona-a friend add b <B的公钥> 127.0.0.1
kokonachat --data-dir .kokona-a start

# 终端 B（另开一个终端）
kokonachat --data-dir .kokona-b init
kokonachat --data-dir .kokona-b friend add a <A的公钥> 127.0.0.1
kokonachat --data-dir .kokona-b start
```

寻址流程演示：A 发消息后立即停掉 B（`Ctrl+Q`）→ A 端消息变 `✗ [失败]`；重启 B 后 A 按 `Ctrl+F` 询问共同好友获取 B 的新地址失败后可由共同好友回答・若 A/B 互为好友即可直接重发恢复。（注意：被动寻址需要至少一个"共同好友"作为询问对象。）

## 协议要点

- 包头固定 82 字节：`magic("KOKN") | version | type | flags | seq(u32) | payload_len(u32) | sender_id(32) | recipient_id(32)`，尾部 64 字节 Ed25519 签名覆盖整个头 + 载荷。
- `MSG` / `MSG_ACK` / `ADDR_QUERY` / `ADDR_ANSWER` 载荷均为加密信封：`eph_pub(32) | nonce(12) | AES-GCM 密文+tag`。寻址回复内容只对请求者可见。
- 寻址严格单跳：被询问方仅用自己好友记录中的"最后已知 IP"回答，绝不转发；请求方一轮询问后结束。