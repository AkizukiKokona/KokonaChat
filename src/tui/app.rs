//! TUI 应用状态机：好友列表 / 聊天记录 / 输入 / 发送状态。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use crate::crypto::id;
use crate::net::{NetCommand, NetEvent};
use crate::store::friends::{Friend, FriendStore};
use crate::store::log;

/// 附件类型：1=图片 2=视频 3=文件。
pub const ATTACH_IMAGE: u8 = 1;
pub const ATTACH_VIDEO: u8 = 2;
pub const ATTACH_FILE: u8 = 3;

#[derive(Clone, Copy, PartialEq)]
pub enum Dir {
    In,
    Out,
}

#[derive(Clone, Copy, PartialEq)]
pub enum MsgStatus {
    Sending,
    Sent,
    Failed,
}

#[derive(Clone)]
pub enum MsgKind {
    Text,
    /// 图片（字节流，用于预览）。
    Image(Vec<u8>),
    /// 视频：文件名 + 数据。
    Video(String, Vec<u8>),
    /// 文件：文件名 + 数据。
    File(String, Vec<u8>),
}

#[derive(Clone)]
pub struct UiMsg {
    pub dir: Dir,
    pub text: String,
    pub status: MsgStatus,
    pub seq: u32,
    pub ts: u64,
    pub kind: MsgKind,
    /// 附件传输 ID（用于匹配发送成功/失败事件）。
    pub transfer: Option<[u8; 16]>,
}

/// 待发送的附件草稿（用户已选文件，等大文件警告确认后读取发送）。
#[derive(Clone)]
pub struct AttachDraft {
    pub kind: u8,
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
}

/// 大文件警告弹窗的返回选项。
#[derive(Clone, Copy, PartialEq)]
pub enum WarnChoice {
    Cancel,
    Confirm,
    ConfirmNoMore,
}

/// 随机附件传输 ID（16 字节）。
pub fn random_id16() -> [u8; 16] {
    let mut v = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut v);
    v
}

pub struct App {
    pub friends: Vec<Friend>,
    pub selected: usize,
    pub msgs: HashMap<String, Vec<UiMsg>>,
    pub next_seq: HashMap<String, u32>,
    pub input: String,
    pub status: Vec<String>,
    pub quit: bool,
    pub own_short: String,
    pub own_id: String,
    pub seed_hex: String,
    pub local_ip: String,
    pub own_nickname: String,
    pub auto_addr: bool,
    pub show_help: bool,
    /// 资料页是否打开（GUI 用）。
    pub show_profile: bool,
    /// 正在等待用户确认的密钥修改（"regenerate" 或手动密钥 hex）。
    pub confirm_key: Option<String>,
    /// 正在等待用户确认的昵称修改。
    pub confirm_nick: bool,
    /// 昵称输入框。
    pub nick_input: String,
    /// 手动密钥输入框。
    pub seed_input: String,
    /// 大文件警告待确认的附件。
    pub warn_attach: Option<AttachDraft>,
    /// 二维码弹窗是否打开。
    pub show_qr: bool,
    /// “扫描二维码”弹窗是否打开。
    pub show_scan: bool,
    pub avatar_feature: bool,
    pub media_feature: bool,
    pub file_feature: bool,
    pub no_warn_large_attach: bool,
    pub avatar_path: Option<String>,
    store: Arc<Mutex<FriendStore>>,
    pub tx: tokio::sync::mpsc::Sender<NetCommand>,
    pub rx: Receiver<NetEvent>,
    log_file: PathBuf,
    config_path: PathBuf,
    identity_path: PathBuf,
}

impl App {
    pub fn new(
        store: Arc<Mutex<FriendStore>>,
        tx: tokio::sync::mpsc::Sender<NetCommand>,
        rx: Receiver<NetEvent>,
        cfg: &crate::config::Config,
        own_short: String,
        own_id: String,
        seed_hex: String,
        local_ip: String,
        log_file: PathBuf,
        config_path: PathBuf,
        identity_path: PathBuf,
    ) -> Self {
        let friends = store.lock().unwrap().list();
        let mut msgs = HashMap::new();
        for f in &friends {
            msgs.entry(f.pubkey.clone()).or_default();
        }
        App {
            friends,
            selected: 0,
            msgs,
            next_seq: HashMap::new(),
            input: String::new(),
            status: vec![format!("KokonaChat @ {own_short}")],
            quit: false,
            own_short,
            own_id,
            seed_hex,
            local_ip,
            own_nickname: cfg.nickname.clone(),
            auto_addr: cfg.auto_addressing,
            show_help: true,
            show_profile: false,
            confirm_key: None,
            confirm_nick: false,
            nick_input: cfg.nickname.clone(),
            seed_input: String::new(),
            warn_attach: None,
            show_qr: false,
            show_scan: false,
            avatar_feature: cfg.avatar_feature,
            media_feature: cfg.media_feature,
            file_feature: cfg.file_feature,
            no_warn_large_attach: cfg.no_warn_large_attach,
            avatar_path: cfg.avatar_path.clone(),
            store,
            tx,
            rx,
            log_file,
            config_path,
            identity_path,
        }
    }

    /// 修改配置并立即写回 `config.toml`（寻址/显示类开关）。
    pub fn update_config(&self, mutate: impl FnOnce(&mut crate::config::Config)) {
        let mut cfg = crate::config::load_config(&self.config_path);
        mutate(&mut cfg);
        if let Ok(s) = toml::to_string(&cfg) {
            let _ = std::fs::write(&self.config_path, s);
        }
    }

    /// 设置“发送失败后自动向共同好友寻址”并持久化。
    pub fn set_auto_addr(&mut self, on: bool) {
        self.auto_addr = on;
        self.update_config(|c| c.auto_addressing = on);
    }

    /// 功能开关（头像/多媒体/文件），带包含关系：
    /// 文件 ⇒ 多媒体 ⇒ 头像。开高一级会自动带上低一级，关低一级会连带关掉高一级。
    pub fn set_feature(&mut self, feature: u8, on: bool) {
        match (feature, on) {
            (1, true) => self.avatar_feature = true,
            (1, false) => {
                self.avatar_feature = false;
                self.media_feature = false;
                self.file_feature = false;
            }
            (2, true) => {
                self.avatar_feature = true;
                self.media_feature = true;
            }
            (2, false) => {
                self.media_feature = false;
                self.file_feature = false;
            }
            (3, true) => {
                self.avatar_feature = true;
                self.media_feature = true;
                self.file_feature = true;
            }
            (3, false) => self.file_feature = false,
            _ => {}
        }
        let (a, m, f) = (self.avatar_feature, self.media_feature, self.file_feature);
        self.update_config(|c| {
            c.avatar_feature = a;
            c.media_feature = m;
            c.file_feature = f;
        });
    }

    /// 设置自定义头像路径并持久化（None = 恢复默认头像）。
    pub fn set_avatar_path(&mut self, path: Option<String>) {
        self.avatar_path = path.clone();
        self.update_config(|c| c.avatar_path = path);
    }

    /// 把用户选择的图片复制进数据目录并设为头像。
    pub fn set_avatar_from(&mut self, src: &Path) {
        let Some(root) = self.config_path.parent() else { return };
        let ext = src
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "png".into());
        let dest = root.join(format!("avatar.{ext}"));
        if std::fs::copy(src, &dest).is_ok() {
            self.set_avatar_path(Some(dest.to_string_lossy().into_owned()));
            self.push_status("头像已更新".into());
        } else {
            self.push_status("头像保存失败".into());
        }
    }

    /// 设置“大文件警告不再显示”并持久化。
    pub fn set_no_warn_large(&mut self, on: bool) {
        self.no_warn_large_attach = on;
        self.update_config(|c| c.no_warn_large_attach = on);
    }

    /// 修改本机昵称并持久化。
    pub fn set_nickname(&mut self, name: &str) {
        let name = name.trim().to_string();
        if name.is_empty() {
            return;
        }
        self.own_nickname = name.clone();
        self.nick_input = name.clone();
        self.update_config(|c| c.nickname = name);
        self.push_status(format!("昵称已更新为：{}", self.own_nickname));
    }

    /// 重新生成身份密钥（随机种子）并写入磁盘。网络层在下次重启时生效。
    pub fn regenerate_key(&mut self) {
        let identity = crate::crypto::keys::Identity::generate();
        let _ = identity.save(&self.identity_path);
        self.own_short = id::short(&identity.ed_pub);
        self.own_id = identity.user_id();
        self.seed_hex = identity.seed_hex();
        self.push_status("身份密钥已重新生成（重启后生效）。好友需重新添加你的新 ID。".into());
    }

    /// 手动设置身份种子（64 位 hex），写入磁盘。网络层在下次重启时生效。
    pub fn set_seed(&mut self, hex: &str) -> anyhow::Result<()> {
        let raw = hex.trim();
        if raw.len() != 64 {
            anyhow::bail!("种子必须是 64 位 hex（32 字节）");
        }
        let bytes = hex::decode(raw).map_err(|_| anyhow::anyhow!("非法 hex 字符串"))?;
        if bytes.len() != 32 {
            anyhow::bail!("种子必须是 32 字节");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let identity = crate::crypto::keys::Identity::from_seed(seed);
        identity.save(&self.identity_path)?;
        self.own_short = id::short(&identity.ed_pub);
        self.own_id = identity.user_id();
        self.seed_hex = identity.seed_hex();
        self.push_status("身份密钥已更新（重启后生效）。".into());
        Ok(())
    }

    /// 生成“加好友邀请链接”（供二维码显示）。
    pub fn invite_link(&self) -> String {
        let cfg = crate::config::load_config(&self.config_path);
        if let Ok(pk) = id::decode(&self.own_id) {
            let ips = vec![self.local_ip.clone()];
            crate::deeplink::build_invite(&cfg, pk, &ips)
        } else {
            String::new()
        }
    }

    /// 解析扫码/链接得到的加好友链接并写入好友列表。
    /// 返回错误信息给调用方展示（成功返回空串）。
    pub fn add_friend_from_link(&mut self, url: &str) -> Result<(), String> {
        let invite = crate::deeplink::parse_url(url).map_err(|e| format!("链接无效: {e}"))?;
        let pk = invite.pubkey();
        let own = id::decode(&self.own_id).map_err(|e| format!("本机身份异常: {e}"))?;
        if pk == own {
            return Err("二维码里的用户就是本机账户，不能添加自己".into());
        }
        {
            let mut store = self.store.lock().unwrap();
            if store.contains(&pk) {
                return Ok(());
            }
            match &invite {
                crate::deeplink::Invite::Add { nickname, pubkey, ip } => {
                    store.add(nickname.clone(), *pubkey, ip.clone()).map_err(|e| format!("添加失败: {e}"))?;
                }
                crate::deeplink::Invite::Talk { .. } => {
                    return Err("这是“开始聊天”链接，不是加好友链接".into());
                }
            }
        }
        self.push_status("已通过扫码添加好友".into());
        Ok(())
    }

    /// 选择附件后调用：注册大文件警告（需确认）或直接发送。
    /// `size` 超过阈值且未勾选“不再警告”时进入待确认状态。
    pub fn pick_attach(&mut self, kind: u8, path: PathBuf) {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "附件".into());
        let draft = AttachDraft { kind, path, name, size };
        const WARN_THRESHOLD: u64 = 2 * 1024 * 1024; // 2MB 以上视为大文件
        if size > WARN_THRESHOLD && !self.no_warn_large_attach {
            self.warn_attach = Some(draft);
        } else {
            self.confirm_send_attach(draft);
        }
    }

    /// 大文件警告弹窗的选择结果。
    pub fn resolve_warn(&mut self, choice: WarnChoice) {
        let Some(draft) = self.warn_attach.take() else { return };
        match choice {
            WarnChoice::Cancel => {}
            WarnChoice::ConfirmNoMore => {
                self.set_no_warn_large(true);
                self.confirm_send_attach(draft);
            }
            WarnChoice::Confirm => self.confirm_send_attach(draft),
        }
    }

    /// 读取附件并发送（分片由网络层完成）。
    pub fn confirm_send_attach(&mut self, draft: AttachDraft) {
        let Some(pubkey) = self.current_pubkey() else { return };
        let Ok(pk) = id::decode(&pubkey) else { return };
        let data = match std::fs::read(&draft.path) {
            Ok(d) => d,
            Err(e) => {
                self.push_status(format!("读取附件失败: {e}"));
                return;
            }
        };
        let ts = crate::util::unix_millis();
        let seq = {
            let e = self.next_seq.entry(pubkey.clone()).and_modify(|s| *s += 1).or_insert(0);
            *e
        };
        let kind = match draft.kind {
            ATTACH_IMAGE => MsgKind::Image(data.clone()),
            ATTACH_VIDEO => MsgKind::Video(draft.name.clone(), data.clone()),
            ATTACH_FILE => MsgKind::File(draft.name.clone(), data.clone()),
            _ => MsgKind::File(draft.name.clone(), data.clone()),
        };
        let transfer = random_id16();
        self.msgs.get_mut(&pubkey).unwrap().push(UiMsg {
            dir: Dir::Out,
            text: String::new(),
            status: MsgStatus::Sending,
            seq,
            ts,
            kind,
            transfer: Some(transfer),
        });
        let _ = log::append(
            &self.log_file,
            &format!("{} > {}: [附件 {:?} {}]", crate::util::format_time(ts), id::short_from_hex(&pubkey), draft.kind, draft.name),
        );
        let _ = self.tx.try_send(NetCommand::SendAttach { recipient: pk, kind: draft.kind, name: draft.name, data, ts, transfer });
    }

    /// 当前头像来源签名（用于判断是否需要重新加载头像纹理）。
    pub fn avatar_signature(&self) -> String {
        if self.avatar_feature {
            if let Some(p) = &self.avatar_path {
                let mtime = std::fs::metadata(p).map(|m| m.modified().ok().map(|t| t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)).unwrap_or(0)).unwrap_or(0);
                return format!("custom|{p}|{mtime}");
            }
            "custom_missing".into()
        } else {
            "default".into()
        }
    }

    /// 自定义头像文件路径（feature 关闭或不存在时为 None）。
    pub fn custom_avatar(&self) -> Option<PathBuf> {
        if !self.avatar_feature {
            return None;
        }
        self.avatar_path.as_ref().and_then(|p| {
            let pb = PathBuf::from(p);
            if pb.exists() { Some(pb) } else { None }
        })
    }

    pub fn current(&self) -> Option<&Friend> {
        self.friends.get(self.selected)
    }

    pub fn current_pubkey(&self) -> Option<String> {
        self.current().map(|f| f.pubkey.clone())
    }

    pub fn current_msgs(&self) -> Vec<UiMsg> {
        self.current_pubkey()
            .and_then(|k| self.msgs.get(&k))
            .cloned()
            .unwrap_or_default()
    }

    pub fn unread(&self, pubkey: &str) -> usize {
        self.msgs.get(pubkey).map(|v| v.iter().filter(|m| m.dir == Dir::In).count()).unwrap_or(0)
    }

    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn select_next(&mut self) {
        if self.selected + 1 < self.friends.len() {
            self.selected += 1;
        }
    }

    pub fn send_current(&mut self) {
        let content = self.input.trim().to_string();
        if content.is_empty() {
            return;
        }
        let Some(pubkey) = self.current_pubkey() else { return };
        let Ok(pk) = id::decode(&pubkey) else { return };
        let seq = {
            let e = self.next_seq.entry(pubkey.clone()).and_modify(|s| *s += 1).or_insert(0);
            *e
        };
        let ts = crate::util::unix_millis();
        self.msgs.get_mut(&pubkey).unwrap().push(UiMsg { dir: Dir::Out, text: content.clone(), status: MsgStatus::Sending, seq, ts, kind: MsgKind::Text, transfer: None });
        let _ = self.tx.try_send(NetCommand::Send { recipient: pk, content: content.clone(), seq });
        let _ = log::append(&self.log_file, &format!("{} > {}: {}", crate::util::format_time(ts), id::short_from_hex(&pubkey), content));
        self.input.clear();
    }

    pub fn retry_failed(&mut self) {
        let Some(pubkey) = self.current_pubkey() else { return };
        let failed: Vec<String> = self
            .msgs
            .get(&pubkey)
            .map(|v| v.iter().filter(|m| m.dir == Dir::Out && m.status == MsgStatus::Failed).map(|m| m.text.clone()).collect())
            .unwrap_or_default();
        if failed.is_empty() {
            self.push_status("当前会话没有失败的已发送消息".into());
            return;
        }
        if let Ok(pk) = id::decode(&pubkey) {
            for text in failed {
                let seq = {
                    let e = self.next_seq.entry(pubkey.clone()).and_modify(|s| *s += 1).or_insert(0);
                    *e
                };
                let ts = crate::util::unix_millis();
                self.msgs.get_mut(&pubkey).unwrap().push(UiMsg { dir: Dir::Out, text: text.clone(), status: MsgStatus::Sending, seq, ts, kind: MsgKind::Text, transfer: None });
                let _ = self.tx.try_send(NetCommand::Send { recipient: pk, content: text, seq });
            }
            self.push_status("已重发失败消息".into());
        }
    }

    pub fn find_address(&mut self) {
        let Some(pubkey) = self.current_pubkey() else { return };
        if let Ok(pk) = id::decode(&pubkey) {
            let _ = self.tx.try_send(NetCommand::FindAddress { recipient: pk });
            self.push_status(format!("正在请求共同好友提供 {} 的新地址…", id::short_from_hex(&pubkey)));
        }
    }

    pub fn push_status(&mut self, s: String) {
        self.status.push(s);
        if self.status.len() > 20 {
            self.status.remove(0);
        }
    }

    pub fn handle_event(&mut self, ev: NetEvent) {
        match ev {
            NetEvent::MessageReceived { from, content, seq, ts } => {
                let key = id::encode(from);
                let list = self.msgs.entry(key.clone()).or_default();
                list.push(UiMsg { dir: Dir::In, text: content.clone(), status: MsgStatus::Sent, seq, ts, kind: MsgKind::Text, transfer: None });
                if let Some(f) = self.friends.iter_mut().find(|f| f.pubkey == key) {
                    f.last_seen = Some(ts);
                }
                let _ = log::append(&self.log_file, &format!("{} < {}: {}", crate::util::format_time(ts), id::short_from_hex(&key), content));
                self.push_status(format!("收到 {}: {}", id::short(&from), content));
            }
            NetEvent::MessageAcked { to, seq } => {
                let key = id::encode(to);
                if let Some(list) = self.msgs.get_mut(&key) {
                    if let Some(m) = list.iter_mut().rev().find(|m| m.dir == Dir::Out && m.seq == seq) {
                        m.status = MsgStatus::Sent;
                    }
                }
                self.push_status(format!("已送达 {}", id::short(&to)));
            }
            NetEvent::MessageFailed { to, seq } => {
                let key = id::encode(to);
                if let Some(list) = self.msgs.get_mut(&key) {
                    if let Some(m) = list.iter_mut().rev().find(|m| m.dir == Dir::Out && m.seq == seq) {
                        m.status = MsgStatus::Failed;
                    }
                }
                self.push_status(format!(
                    "消息到 {} 发送失败（无响应）。Ctrl+F 查找新地址 / Ctrl+R 重发",
                    id::short(&to)
                ));
                // 自动寻址开关开启时，失败自动触发一轮共同好友询问
                if self.auto_addr {
                    let _ = self.tx.try_send(NetCommand::FindAddress { recipient: to });
                }
            }
            NetEvent::AddrResult { target, found, count } => {
                if found {
                    self.push_status(format!("寻址成功：{} 的新地址已更新（{count} 个），已自动重发失败消息", id::short(&target)));
                } else {
                    self.push_status(format!("寻址失败：未找到 {} 的新地址", id::short(&target)));
                }
            }
            NetEvent::AttachReceived { from, kind, name, data, ts } => {
                let key = id::encode(from);
                let list = self.msgs.entry(key.clone()).or_default();
                let msg_kind = match kind {
                    crate::tui::app::ATTACH_IMAGE => MsgKind::Image(data),
                    crate::tui::app::ATTACH_VIDEO => MsgKind::Video(name.clone(), data),
                    _ => MsgKind::File(name.clone(), data),
                };
                list.push(UiMsg { dir: Dir::In, text: String::new(), status: MsgStatus::Sent, seq: 0, ts, kind: msg_kind, transfer: None });
                if let Some(f) = self.friends.iter_mut().find(|f| f.pubkey == key) {
                    f.last_seen = Some(ts);
                }
                self.push_status(format!("收到 {} 的附件: {name}", id::short(&from)));
            }
            NetEvent::AttachAcked { to, transfer } => {
                let key = id::encode(to);
                if let Some(list) = self.msgs.get_mut(&key) {
                    for m in list.iter_mut() {
                        if m.transfer == Some(transfer) {
                            m.status = MsgStatus::Sent;
                        }
                    }
                }
                self.push_status(format!("附件已送达 {}", id::short(&to)));
            }
            NetEvent::AttachFailed { to, transfer } => {
                let key = id::encode(to);
                if let Some(list) = self.msgs.get_mut(&key) {
                    for m in list.iter_mut() {
                        if m.transfer == Some(transfer) {
                            m.status = MsgStatus::Failed;
                        }
                    }
                }
                self.push_status(format!("附件发送失败 {}", id::short(&to)));
            }
            NetEvent::FriendSeen { id: fid } => {
                let key = id::encode(fid);
                if let Some(f) = self.friends.iter_mut().find(|f| f.pubkey == key) {
                    f.last_seen = Some(crate::util::unix_millis());
                }
            }
            NetEvent::Status(s) => self.push_status(s),
        }
    }

    /// 主循环每帧调用：拉取网络事件并刷新好友列表（可能被网络层更新 IP/在线状态）。
    pub fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            self.handle_event(ev);
        }
        self.friends = self.store.lock().unwrap().list();
        if self.selected >= self.friends.len() {
            self.selected = self.friends.len().saturating_sub(1);
        }
    }
}