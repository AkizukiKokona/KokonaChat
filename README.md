# KokonaChat

去中心化 P2P 即时通讯原型：**IPv6/UDP 直连 + 端到端加密 + 被动寻址**。无任何中心服务器。

- 身份：本地生成 `Ed25519` 密钥对，**公钥即用户 ID**（64 位 hex）。
- 加密：临时 X25519 前向保密 + HKDF-SHA256 + AES-256-GCM + Ed25519 签名。
- 寻址：**被动寻址 + 主动通告**。上线（或本机 IP 变化）时向直接好友通告当前地址（IP **携带端口**）；发送失败不自动全网寻址，仅在手动（或开启自动寻址）时向共同好友发起**单次、单跳** IP 询问，不递归不广播；好友确认/更新地址后会自动补发此前投递失败的消息。
- 网络：UDP，默认守护端口 **1212**（注：1212 是 Kokona/心夏 的生日，作为协议的守护端口）；双栈同时监听 IPv6/IPv4，**优先 IPv6**。动态通告只包含**可达地址**（自动过滤 link-local / ULA / 多播 / 内网垃圾地址）。
- 界面：三栏 TUI（好友列表 | 聊天区 | 输入框）与**原生图形界面**（winit + egui，浅色主题，桌面端与移动端两套布局），消息失败状态可见并提供「查找新地址」入口。
- 多媒体：可发送**图片 / 视频 / 文件**，>2MB 自动弹出大文件警告（可"不再显示"）；图片直接在聊天区预览。
- 个人资料：**头像上传**（自定义头像或恢复默认）、身份密钥查看/重新生成/手动修改（带二次确认）、昵称修改、三个功能开关（头像 / 多媒体 / 完整文件，文件 ⇒ 多媒体 ⇒ 头像 的包含关系）、**生成加好友二维码**。
- 可靠性：UDP 丢包重传（消息最多 3 次，间隔 2 秒）；附件按 2400 字节分片传输、逐片重传，任一片失败即整体终止并通知；寻址询问与共同好友代投递同样带 UDP 重发兜底。

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

# 3.6) 公网 IPv4 稳定地址模式（可选）
kokonachat config set-public-ipv4 1.2.3.4   # 设置后地址长期稳定，不再反复通告本机地址，好友也无需反复重新寻址
kokonachat config show                      # 查看当前配置
kokonachat config clear-public-ipv4         # 清除，恢复默认动态通告

# 3.7) 备份与恢复（身份绑定加密，仅本账户可解密；配置+好友与聊天记录可分开或合并）
kokonachat backup export-all bak.kba        # 配置+好友+聊天记录合并加密大包
kokonachat backup export-core core.kba      # 仅配置+好友
kokonachat backup export-chat chat.kba      # 仅聊天记录
kokonachat backup import bak.kba            # 导入（自动识别类型；导入会覆盖配置/好友，聊天记录追加合并）

# 3.8) 固定链接（深链，免安装）：生成加好友邀请链接 + 注册 kokonachat:// 协议
kokonachat protocol install         # 注册协议（Windows=HKCU / Linux=用户级 .desktop，均免管理员）
kokonachat link                     # 生成邀请链接（未注册时自动注册）
kokonachat protocol status          # 查看注册状态
# 好友点击形如 kokonachat://add?... 的链接即可拉起本客户端添加好友；
# 若客户端已在运行，链接会经本地 IPC 转发到当前实例，无需重启。

# 4) 启动 TUI
kokonachat start                     # 默认端口 1212
kokonachat start --port 1212 --auto-addr   # 失败消息自动向共同好友寻址

# 5) 图形界面（浅色主题，原生窗口）
kokonachat gui                       # 桌面端布局
kokonachat gui --mobile              # 移动端竖屏布局预览（手机上查看效果）
```

## 图形界面（GUI）

`kokonachat gui` 启动桌面窗口，`--mobile` 切换为手机竖屏比例预览。与 TUI 共用同一份数据目录（身份、好友、聊天记录）。

- **顶栏**：左侧头像按钮（点击进入个人资料页）+ 标题。首页保持简洁，IP 等数据一律在个人资料页查看。
- **个人资料页**（点头像进入）：
  - 头像：`更换头像`（文件选择器）/ `恢复默认头像`。
  - 身份信息：用户 ID、身份种子（私钥）只读展示；`重新生成密钥` 或 `手动修改密钥`（输入 64 位 hex 种子）均需弹窗二次确认，改后网络层重启生效。
  - 昵称修改：弹窗确认后写入，影响后续加好友链接/二维码中的显示名。
  - 功能开关：**头像功能**、**多媒体功能（图片/视频）**、**完整文件传送**。包含关系：文件 ⇒ 多媒体 ⇒ 头像（开高一级自动带上低一级，关低一级连带关掉高一级）。
  - `生成我的添加二维码`：弹窗内展示 `kokonachat://add?...` 邀请链接的二维码（与链接等宽，可扫码添加好友）。
- **聊天区**：输入框上方为附件栏，按开关显示 `图片 / 视频 / 文件` 按钮（>2MB 先弹大文件警告，可「确定并不再显示」）；图片消息直接在气泡内预览，视频/文件显示为「文件名（大小）」芯片。
- 主页保持简洁：只保留好友列表、聊天、输入等核心功能；身份/IP/开关等数据一律在个人资料页中查看，不在主页重复展示。

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
├── config.toml       # 端口 / auto_addressing / 昵称 / 公网 IPv4 / 功能开关 / 头像路径 / 大文件警告
├── identity.key      # 32 字节身份种子（0600）
├── friends.toml      # 好友：昵称、公钥、最后已知 IP 列表、最近在线
├── avatar.jpg|png…   # 自定义头像（更换头像后生成）
└── logs/             # kokona.log（网络日志）、messages.log（消息记录）

备份文件为自包含二进制容器（`*.kba`），内置加密信封，**仅同一账户身份可解密导入**；`identity.key` 丢失后任何备份（以及账户、消息）都无法再恢复。
```

## 免安装固定链接（深链）

Windows / Linux 版本均为免安装单文件，通过**自定义协议 `kokonachat://`** 实现"点击链接拉起客户端"：

- 注册（无需管理员）：Windows 写当前用户注册表 `HKCU\Software\Classes\kokonachat`；Linux 写 `~/.local/share/applications/kokonachat.desktop` 并用 `xdg-mime` 设默认。
- 邀请链接格式：`kokonachat://add?nickname=<昵称>&pubkey=<对方用户ID>&ip=<对方IP[:端口]>`。
- 点击行为：客户端未运行 -> 直接写入好友列表；已运行 -> 经本地 IPC（127.0.0.1 派生端口）转发到当前实例，好友列表即时出现，无需重启。
- 对方在浏览器 / 聊天中打开链接即可加你为好友；公网用户可用 `kokonachat config set-public-ipv4 <公网IP>` 让邀请链接里的地址长期稳定。

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