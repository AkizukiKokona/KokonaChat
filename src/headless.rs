//! 调试模式（`--debug`）的终端聊天界面。
//!
//! 不使用全屏 TUI，直接在当前终端打印收发消息与网络事件，日志（Debug 级）输出到 stderr，
//! 方便同时开两个终端做本机联调。同一身份（账户）在非调试模式下只能有一个实例在线，
//! 调试模式可配合 `--port` 在本机同时启动多个实例。

use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;

use crate::crypto::id;
use crate::net::{NetCommand, NetEvent};
use crate::store::friends::FriendStore;
use crate::store::log;

pub fn run(
    store: Arc<Mutex<FriendStore>>,
    tx: tokio::sync::mpsc::Sender<NetCommand>,
    rx: Receiver<NetEvent>,
    own_short: String,
    log_file: PathBuf,
) -> Result<()> {
    let (in_tx, in_rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if in_tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let friends = store.lock().unwrap().list();
    let mirror = Mirror { tx, store: store.clone(), log_file, seq: HashMap::new(), cur: String::new() };
    let mut m = mirror;
    if let Some(first) = friends.first() {
        m.cur = first.nickname.clone();
    }

    println!("== KokonaChat 调试模式 [本机 ID: {own_short}] ==");
    println!("直接输入文本回车 -> 发送给当前好友；命令：/use <昵称>  /to <昵称> <内容>  /list  /help  /quit");
    if friends.is_empty() {
        println!("! 当前没有好友，请先用 `friend add <昵称> <对方公钥> <对方IP[:端口]>` 添加");
    } else {
        for f in &friends {
            println!("  好友 {:<12} {} IP[{}]", f.nickname, id::short_from_hex(&f.pubkey), f.ips.join(", "));
        }
        println!("  当前好友: {}", m.cur);
    }
    println!("--------------------------------------------------");

    loop {
        while let Ok(ev) = rx.try_recv() {
            m.on_event(ev);
        }
        while let Ok(line) = in_rx.try_recv() {
            if !m.on_input(&line) {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct Mirror {
    tx: tokio::sync::mpsc::Sender<NetCommand>,
    store: Arc<Mutex<FriendStore>>,
    log_file: PathBuf,
    seq: HashMap<String, u32>,
    cur: String,
}

impl Mirror {
    fn friends(&self) -> Vec<crate::store::friends::Friend> {
        self.store.lock().unwrap().list()
    }

    fn nick(&self, pk: &[u8; 32]) -> String {
        let key = id::encode(*pk);
        self.friends()
            .into_iter()
            .find(|f| f.pubkey == key)
            .map(|f| f.nickname)
            .unwrap_or_else(|| id::short_from_hex(&key))
    }

    fn on_input(&mut self, line: &str) -> bool {
        let line = line.trim();
        if line.is_empty() {
            return true;
        }
        if let Some(cmd) = line.strip_prefix('/') {
            return self.on_cmd(cmd);
        }
        if let Some(rest) = line.strip_prefix(':') {
            let (nick, content) = split2(rest);
            self.cur = nick.to_string();
            self.send(nick, content);
            return true;
        }
        if self.cur.is_empty() {
            println!("! 还没有可发送的当前好友，用 /use <昵称> 指定");
        } else {
            let target = self.cur.clone();
            self.send(&target, line);
        }
        true
    }

    fn on_cmd(&mut self, cmd: &str) -> bool {
        let mut parts = cmd.splitn(2, ' ');
        let name = parts.next().unwrap_or("");
        match name {
            "quit" | "q" => {
                let _ = self.tx.try_send(NetCommand::Quit);
                false
            }
            "list" => {
                let fs = self.friends();
                if fs.is_empty() {
                    println!("好友列表为空");
                } else {
                    for f in fs {
                        println!("  好友 {:<12} {} IP[{}]", f.nickname, id::short_from_hex(&f.pubkey), f.ips.join(", "));
                    }
                }
                true
            }
            "use" => {
                let nick = parts.next().unwrap_or("").trim();
                if nick.is_empty() {
                    println!("用法: /use <昵称>");
                } else {
                    match self.friends().into_iter().find(|f| f.nickname == nick) {
                        Some(_) => {
                            self.cur = nick.to_string();
                            println!("当前好友 -> {nick}");
                        }
                        None => println!("找不到昵称 {nick} 的好友（用 /list 查看）"),
                    }
                }
                true
            }
            "to" => {
                let rest = parts.next().unwrap_or("");
                let (nick, content) = split2(rest);
                if nick.is_empty() || content.is_empty() {
                    println!("用法: /to <昵称> <内容>");
                } else {
                    self.cur = nick.to_string();
                    self.send(nick, content);
                }
                true
            }
            "help" => {
                println!("命令:");
                println!("  /use <昵称>          切换到当前好友");
                println!("  /to <昵称> <内容>     发送给指定好友");
                println!("  /list               列出好友");
                println!("  /quit                退出");
                println!("  :昵称 <内容>          同 /to");
                println!("其余非 / 开头的输入回车后直接发送给当前好友");
                true
            }
            _ => {
                println!("未知命令: /{name}（/help 查看帮助）");
                true
            }
        }
    }

    fn send(&mut self, nickname: &str, content: &str) {
        let content = content.trim();
        if content.is_empty() {
            return;
        }
        let Some(f) = self.friends().into_iter().find(|f| f.nickname == nickname) else {
            println!("! 找不到昵称 {nickname} 的好友（用 /list 查看）");
            return;
        };
        let Ok(pk) = id::decode(&f.pubkey) else {
            println!("! 好友公钥格式无效");
            return;
        };
        let seq = self.seq.entry(nickname.to_string()).and_modify(|s| *s += 1).or_insert(0);
        let seq = *seq;
        if self.tx.try_send(NetCommand::Send { recipient: pk, content: content.to_string(), seq }).is_err() {
            println!("! 消息队列已满");
            return;
        }
        let ts = crate::util::unix_millis();
        let _ = log::append(&self.log_file, &format!("{} > {}: {}", crate::util::format_time(ts), nickname, content));
        println!(">>> [{nickname}] {content}");
    }

    fn on_event(&mut self, ev: NetEvent) {
        match ev {
            NetEvent::MessageReceived { from, content, seq, ts } => {
                let nick = self.nick(&from);
                println!("<<< {} [{}] {nick}: {content}", crate::util::format_time(ts), seq);
            }
            NetEvent::MessageAcked { to, seq } => {
                println!("+ 已送达 [{} -> {}] seq={seq}", id::short(&to), self.nick(&to));
            }
            NetEvent::MessageFailed { to, seq } => {
                println!("- 发送失败 [{}] seq={seq}（无响应），可在对方恢复后重发或寻址", self.nick(&to));
            }
            NetEvent::AddrResult { target, found, count } => {
                println!("@ 寻址结果: {} {}", self.nick(&target), if found { "命中" } else { "未命中" });
                println!("   已询问 {count} 位共同好友");
            }
            NetEvent::FriendSeen { id } => {
                println!("* 好友在线: {}", self.nick(&id));
            }
            NetEvent::Status(s) => {
                println!("~ {s}");
            }
        }
    }
}

fn split2(s: &str) -> (&str, &str) {
    let mut it = s.trim().splitn(2, ' ');
    let a = it.next().unwrap_or("");
    let b = it.next().unwrap_or("");
    (a, b)
}