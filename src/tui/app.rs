//! TUI 应用状态机：好友列表 / 聊天记录 / 输入 / 发送状态。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use crate::crypto::id;
use crate::net::{NetCommand, NetEvent};
use crate::store::friends::{Friend, FriendStore};
use crate::store::log;

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
pub struct UiMsg {
    pub dir: Dir,
    pub text: String,
    pub status: MsgStatus,
    pub seq: u32,
    pub ts: u64,
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
    pub auto_addr: bool,
    pub show_help: bool,
    store: Arc<Mutex<FriendStore>>,
    pub tx: tokio::sync::mpsc::Sender<NetCommand>,
    pub rx: Receiver<NetEvent>,
    log_file: PathBuf,
}

impl App {
    pub fn new(
        store: Arc<Mutex<FriendStore>>,
        tx: tokio::sync::mpsc::Sender<NetCommand>,
        rx: Receiver<NetEvent>,
        cfg: &crate::config::Config,
        own_short: String,
        log_file: PathBuf,
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
            auto_addr: cfg.auto_addressing,
            show_help: true,
            store,
            tx,
            rx,
            log_file,
        }
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
        self.msgs.get_mut(&pubkey).unwrap().push(UiMsg { dir: Dir::Out, text: content.clone(), status: MsgStatus::Sending, seq, ts });
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
                self.msgs.get_mut(&pubkey).unwrap().push(UiMsg { dir: Dir::Out, text: text.clone(), status: MsgStatus::Sending, seq, ts });
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
                list.push(UiMsg { dir: Dir::In, text: content.clone(), status: MsgStatus::Sent, seq, ts });
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