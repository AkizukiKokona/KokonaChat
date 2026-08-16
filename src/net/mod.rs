//! 网络层：双栈 UDP 监听/收发、端到端加解密分发、重传调度、被动寻址编排。

pub mod packet;
pub mod retransmit;
pub mod session;
pub mod socket;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use log::{debug, info, warn};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver as TokioReceiver;

use crate::crypto::cipher;
use crate::crypto::id;
use crate::crypto::keys::Identity;
use crate::net::packet::{envelope_close, envelope_open, Packet, PktType, FLAG_ACK, FLAG_EPHEMERAL};
use crate::net::retransmit::{PendingPacket, Retransmitter, RETRY_INTERVAL};
use crate::net::session::SessionTable;
use crate::net::socket::{normalize_recv, to_send_addr};
use crate::proto;
use crate::store::friends::FriendStore;

/// TUI -> 网络层命令。
pub enum NetCommand {
    Send { recipient: [u8; 32], content: String, seq: u32 },
    FindAddress { recipient: [u8; 32] },
    Quit,
}

/// 网络层 -> TUI 事件。
#[derive(Clone)]
pub enum NetEvent {
    MessageReceived { from: [u8; 32], content: String, seq: u32, ts: u64 },
    MessageAcked { to: [u8; 32], seq: u32 },
    MessageFailed { to: [u8; 32], seq: u32 },
    AddrResult { target: [u8; 32], found: bool, count: usize },
    FriendSeen { id: [u8; 32] },
    Status(String),
}

const ADDR_QUERY_TIMEOUT: Duration = Duration::from_secs(6);
/// 反向探针：好友未回复时的重试间隔。
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(10);
/// 反向探针最多重试次数（含首次共 3 次尝试）。
const PROBE_MAX_RETRIES: u32 = 2;
/// 本地 IPv6 地址变化检测周期。
const LOCAL_IP_CHECK_INTERVAL: Duration = Duration::from_secs(30);

struct PendingQuery {
    target: [u8; 32],
    started: Instant,
    asked: Vec<[u8; 32]>,
    answered: HashSet<[u8; 32]>,
    fail_seqs: Vec<u32>,
}

/// 待确认的反向探针（按好友维度）。
struct PendingProbe {
    bytes: Vec<u8>,
    probe_id: u64,
    attempts: u32,
    next_try: Instant,
}

/// 共同好友托付我们转交的新 IP。
struct PendingPush {
    source: [u8; 32],
    ips: Vec<String>,
}

pub struct NetInit {
    pub identity: Identity,
    pub port: u16,
    pub friends: Arc<Mutex<FriendStore>>,
    pub cmd_rx: TokioReceiver<NetCommand>,
    pub evt_tx: Sender<NetEvent>,
}

struct Network {
    identity: Identity,
    sock: UdpSocket,
    use_v6: bool,
    sessions: SessionTable,
    retx: Retransmitter,
    friends: Arc<Mutex<FriendStore>>,
    cmd_rx: TokioReceiver<NetCommand>,
    evt_tx: Sender<NetEvent>,
    addr_queries: HashMap<[u8; 16], PendingQuery>,
    failed_sends: HashMap<([u8; 32], u32), Vec<u8>>,
    /// 上一次采样到的本地 IPv6（用于变化检测）
    last_local_ipv6: Option<String>,
    next_local_ip_check: Instant,
    /// 反向探针：好友 -> 待确认探针
    ip_probes: HashMap<[u8; 32], PendingProbe>,
    /// 共同好友托付转交的地址更新：victim -> 列表
    pending_pushes: HashMap<[u8; 32], Vec<PendingPush>>,
}

pub async fn run(init: NetInit) -> Result<()> {
    let bound = match socket::bind_dual(init.port).await {
        Ok(b) => b,
        Err(e) => {
            let _ = init.evt_tx.send(NetEvent::Status(format!("端口 {} 绑定失败: {e}", init.port)));
            return Err(e);
        }
    };
let NetInit { identity, port, friends, cmd_rx, evt_tx } = init;
    info!("已绑定 UDP 双栈端口 {}（IPv6 双栈: {}）", port, bound.is_v6);
    let mut n = Network {
        sock: bound.sock,
        use_v6: bound.is_v6,
        identity,
        sessions: SessionTable::default(),
        retx: Retransmitter::default(),
        friends,
        cmd_rx,
        evt_tx,
        addr_queries: HashMap::new(),
        failed_sends: HashMap::new(),
        last_local_ipv6: local_ipv6(),
        next_local_ip_check: Instant::now() + LOCAL_IP_CHECK_INTERVAL,
        ip_probes: HashMap::new(),
        pending_pushes: HashMap::new(),
    };
    n.startup_ping().await?;
    n.run_loop().await
}

impl Network {
    // ---------- 主循环 ----------

    async fn run_loop(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        loop {
            let now = Instant::now();

            // 重传调度（最多 3 次，间隔 2 秒）
            let (resend, failed) = self.retx.poll_retries(now);
            for p in &resend {
                info!("重传 seq={} -> {}", p.seq, id::short(&p.recipient));
                self.send_to_peer(&p.bytes, &p.recipient).await;
            }
            for f in &failed {
                self.failed_sends.insert((f.recipient, f.seq), f.bytes.clone());
                let _ = self.evt_tx.send(NetEvent::MessageFailed { to: f.recipient, seq: f.seq });
                info!("消息 seq={} 发送失败（重传 {} 次耗尽）", f.seq, retransmit::MAX_RETRIES);
            }

// 寻址询问超时/完成检查
            self.check_addr_queries(now);

            // 反向探针：重试未确认好友 / 判定未确认后向共同好友广播
            self.poll_probes(now).await;

            // 本地 IPv6 变化检测（变化即触发反向探针，上线时不主动广播）
            if self.detect_local_ip_change(now) {
                self.trigger_ip_probe().await;
            }

            let timeout_dur = self.next_wakeup(now);
            tokio::select! {
                res = self.sock.recv_from(&mut buf) => {
                    let (len, src) = res?;
                    let src = normalize_recv(src);
                    if let Err(e) = self.handle_packet(&buf[..len], src).await {
                        debug!("处理包失败: {e}");
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(NetCommand::Send { recipient, content, seq }) => {
                            if let Err(e) = self.handle_send(recipient, content, seq).await {
                                warn!("发送失败: {e}");
                                let _ = self.evt_tx.send(NetEvent::MessageFailed { to: recipient, seq });
                            }
                        }
                        Some(NetCommand::FindAddress { recipient }) => {
                            self.handle_find_address(recipient).await;
                        }
                        Some(NetCommand::Quit) | None => {
                            info!("网络任务退出");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(timeout_dur) => {}
            }
        }
        Ok(())
    }

fn next_wakeup(&self, now: Instant) -> Duration {
        let mut deadlines: Vec<Instant> = Vec::new();
        if let Some(d) = self.retx.next_deadline(now) {
            deadlines.push(d);
        }
        for q in self.addr_queries.values() {
            deadlines.push(q.started + ADDR_QUERY_TIMEOUT);
        }
        for p in self.ip_probes.values() {
            deadlines.push(p.next_try);
        }
        deadlines.push(self.next_local_ip_check);
        deadlines
            .into_iter()
            .min()
            .map(|d| if d > now { d - now } else { Duration::ZERO })
            .unwrap_or(Duration::from_secs(3600))
    }

    /// 上线后向全部直接好友发送连通性探测（仅好友，非广播；好友应答可刷新其最后已知 IP）。
    /// 注意：这是被动寻址的组成部分——不向网络广播，仅联系已添加的好友。
    async fn startup_ping(&mut self) -> Result<()> {
        let mut count = 0usize;
        let friends_snapshot = {
            let store = self.friends.lock().unwrap();
            store.list()
        };
        for f in friends_snapshot {
            if let Ok(pk) = id::decode(&f.pubkey) {
                if let Ok(pkt) = self.build_simple(PktType::Ping, &pk, Vec::new()) {
                    self.send_to_peer(&pkt, &pk).await;
                    count += 1;
                }
            }
        }
        if count > 0 {
            let _ = self.evt_tx.send(NetEvent::Status(format!("已向 {count} 位好友发送连通性探测（仅好友，不广播）")));
        }
        Ok(())
    }

    // ---------- 发送 ----------

    fn build_simple(&self, ptype: PktType, recipient: &[u8; 32], payload: Vec<u8>) -> Result<Vec<u8>> {
        let pkt = Packet { ptype, flags: 0, seq: 0, sender_id: self.identity.ed_pub, recipient_id: *recipient, payload };
        Ok(pkt.encode(&self.identity.signing))
    }

fn peer_addrs(&self, id: &[u8; 32]) -> Vec<SocketAddr> {
        let store = self.friends.lock().unwrap();
        if let Some(f) = store.get(id) {
            let mut addrs: Vec<SocketAddr> = f
                .ips
                .iter()
                .filter_map(|ip| crate::net::socket::parse_sockaddr(ip, crate::config::DEFAULT_PORT).ok())
                .collect();
            // IPv6 优先
            addrs.sort_by_key(|a| !matches!(a, SocketAddr::V6(_)));
            addrs
        } else {
            Vec::new()
        }
    }

    async fn send_to_addr(&self, bytes: &[u8], addr: SocketAddr) {
        let target = if self.use_v6 { to_send_addr(addr) } else { addr };
        if let Err(e) = self.sock.send_to(bytes, target).await {
            warn!("UDP 发送失败: {e}");
        }
    }

    async fn send_to_peer(&self, bytes: &[u8], recipient: &[u8; 32]) {
        for a in self.peer_addrs(recipient) {
            self.send_to_addr(bytes, a).await;
        }
    }

    async fn handle_send(&mut self, recipient: [u8; 32], content: String, seq: u32) -> Result<()> {
        let recip_xpub = match cipher::ed_pub_to_x25519(&recipient) {
            Some(x) => x,
            None => bail!("无法由对方 ID 派生 X25519 密钥"),
        };
        if !self.is_friend(&recipient) {
            bail!("不是好友，无法发送");
        }
        let inner = proto::encode_msg_inner(&content);
        let sealed = cipher::seal(&self.identity.x25519_sk, &recip_xpub, &self.identity.ed_pub, &recipient, &inner)?;
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::Msg, flags: FLAG_EPHEMERAL, seq, sender_id: self.identity.ed_pub, recipient_id: recipient, payload };
        let bytes = pkt.encode(&self.identity.signing);

        let addrs = self.peer_addrs(&recipient);
        if addrs.is_empty() {
            self.failed_sends.insert((recipient, seq), bytes);
            let _ = self.evt_tx.send(NetEvent::MessageFailed { to: recipient, seq });
            info!("发送消息 seq={} 失败：无已知地址 -> {} ", seq, id::short(&recipient));
            return Ok(());
        }
        for a in &addrs {
            self.send_to_addr(&bytes, *a).await;
        }
        self.retx.insert(PendingPacket { bytes, recipient, seq, attempts: 0, next_retry: Instant::now() + RETRY_INTERVAL });
        info!("已发送消息 seq={} -> {}（{} 个地址）", seq, id::short(&recipient), addrs.len());
        Ok(())
    }

    // ---------- 接收分发 ----------

    async fn handle_packet(&mut self, bytes: &[u8], src: SocketAddr) -> Result<()> {
        debug!("收到 {} 字节的包，来自 {src}", bytes.len());
        let dec = packet::Packet::decode(bytes)?;
        packet::Packet::verify(&dec)?;
        let p = &dec.packet;
        if p.recipient_id != self.identity.ed_pub {
            bail!("非目标包，丢弃");
        }
        if !self.is_friend(&p.sender_id) {
            bail!("来自未知身份 {} 的包，丢弃", id::short(&p.sender_id));
        }
// 被动记录对端最后已知地址（IP:端口；端口用于区分同一 IP 上的不同用户）
        self.note_friend_seen(&p.sender_id, Some(crate::net::socket::fmt_addr(src)));

match p.ptype {
            PktType::Msg => self.handle_msg(p, src).await,
            PktType::MsgAck => self.handle_ack(p).await,
            PktType::Ping => self.handle_ping(p, src).await,
            PktType::Pong => {
                let _ = self.evt_tx.send(NetEvent::FriendSeen { id: p.sender_id });
                Ok(())
            }
            PktType::AddrQuery => self.handle_addr_query(p, src).await,
            PktType::AddrAnswer => self.handle_addr_answer(p).await,
            PktType::IpChanged => self.handle_ip_changed(p, src).await,
            PktType::IpChangedAck => self.handle_ip_changed_ack(p).await,
            PktType::Gossip => self.handle_gossip(p).await,
            PktType::PushIp => self.handle_push_ip(p).await,
        }?;
        // 对方与我们有直连流量 -> 视为已上线；投递共同好友托付的待转发 IP
        if let Err(e) = self.deliver_pending_pushes(&p.sender_id).await {
            debug!("投递待转发 IP 失败: {e}");
        }
        Ok(())
    }

    async fn handle_msg(&mut self, p: &Packet, src: SocketAddr) -> Result<()> {
        let seq = p.seq;
        {
            let sess = self.sessions.get_mut(&p.sender_id);
            if sess.is_seen(seq) {
                // 重传导致的重复包：补发 ACK 以停止对方重传
                self.send_ack(&p.sender_id, seq, src).await?;
                return Ok(());
            }
            sess.mark_seen(seq);
        }
        let sender_xpub = match cipher::ed_pub_to_x25519(&p.sender_id) {
            Some(x) => x,
            None => {
                warn!("无法由对方 ID 派生 X25519 密钥，放弃");
                return Ok(());
            }
        };
let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)
            .map_err(|e| anyhow::anyhow!("解密失败: {e}"))?;
        let (mtype, ts, content) = proto::decode_msg_inner(&pt)?;
        if mtype != proto::MSG_TEXT {
            bail!("未知消息子类型");
        }
        self.send_ack(&p.sender_id, seq, src).await?;
        let _ = self.evt_tx.send(NetEvent::MessageReceived { from: p.sender_id, content, seq, ts });
        Ok(())
    }

    /// 发送 ACK（投递确认）。直接回复到来源地址。
    async fn send_ack(&self, sender_id: &[u8; 32], seq: u32, src: SocketAddr) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(sender_id).ok_or_else(|| anyhow::anyhow!("无法派生对方 X25519"))?;
        let inner = proto::encode_ack_inner(seq);
        let sealed = cipher::seal(&self.identity.x25519_sk, &sender_xpub, &self.identity.ed_pub, sender_id, &inner)?;
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::MsgAck, flags: FLAG_ACK, seq, sender_id: self.identity.ed_pub, recipient_id: *sender_id, payload };
        let bytes = pkt.encode(&self.identity.signing);
        self.send_to_addr(&bytes, src).await;
        Ok(())
    }

    async fn handle_ack(&mut self, p: &Packet) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let ack_seq = proto::decode_ack_inner(&pt)?;
        if self.retx.ack(&p.sender_id, ack_seq).is_some() {
            self.failed_sends.remove(&(p.sender_id, ack_seq));
            let _ = self.evt_tx.send(NetEvent::MessageAcked { to: p.sender_id, seq: ack_seq });
            info!("收讫 ACK seq={} <- {}", ack_seq, id::short(&p.sender_id));
        }
        Ok(())
    }

    async fn handle_ping(&self, p: &Packet, src: SocketAddr) -> Result<()> {
        let bytes = self.build_simple(PktType::Pong, &p.sender_id, Vec::new())?;
        self.send_to_addr(&bytes, src).await;
        Ok(())
    }

    // ---------- 被动寻址 ----------

    /// 我们是被询问方：仅当请求者与目标都在我们的好友列表中（共同好友）才回答。
    async fn handle_addr_query(&mut self, p: &Packet, src: SocketAddr) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let q = proto::decode_addr_query(&pt)?;

        let target_ips: Vec<String> = {
            let store = self.friends.lock().unwrap();
            if !store.contains(&p.sender_id) || !store.contains(&q.target_id) {
                Vec::new()
            } else {
                store.get(&q.target_id).map(|f| f.ips.clone()).unwrap_or_default()
            }
        };

        let inner = proto::encode_addr_answer(&q.target_id, &q.nonce_q, &target_ips);
        let sealed = cipher::seal(&self.identity.x25519_sk, &sender_xpub, &self.identity.ed_pub, &p.sender_id, &inner)?;
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::AddrAnswer, flags: 0, seq: 0, sender_id: self.identity.ed_pub, recipient_id: p.sender_id, payload };
        let bytes = pkt.encode(&self.identity.signing);
        self.send_to_addr(&bytes, src).await;
        let hit = if target_ips.is_empty() { "未知" } else { "命中" };
        info!("回答 {} 关于 {} 的地址询问（{}）", id::short(&p.sender_id), id::short(&q.target_id), hit);
        // 顺手把共同好友托付给请求者的新 IP 一并投递（"一起送过去"）
        if let Err(e) = self.deliver_pending_pushes(&p.sender_id).await {
            debug!("回答寻址时投递待转发 IP 失败: {e}");
        }
        Ok(())
    }

    /// 我们是被询问请求方：合并答案的 IP，命中则自动重发失败消息。
    /// 严格单跳：绝不中继他人的查询；一旦命中或所有好友回答完毕即结束。
    async fn handle_addr_answer(&mut self, p: &Packet) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let ans = proto::decode_addr_answer(&pt)?;

        let mut q = match self.addr_queries.remove(&ans.nonce_q) {
            Some(q) => q,
            None => return Ok(()),
        };
        if ans.target_id != q.target {
            return Ok(());
        }
        q.answered.insert(p.sender_id);

        let mut found = false;
        let mut count = 0usize;
        if ans.hit && !ans.ips.is_empty() {
            let target = q.target;
            if self.merge_ips(&target, &ans.ips) {
                info!("已更新好友 {} 的地址: {:?}", id::short(&target), ans.ips);
            }
            // 重发此前失败的消息
            let seqs = std::mem::take(&mut q.fail_seqs);
            for seq in seqs {
                if let Some(bytes) = self.failed_sends.remove(&(target, seq)) {
                    let addrs = self.peer_addrs(&target);
                    let mut sent = false;
                    for a in &addrs {
                        self.send_to_addr(&bytes, *a).await;
                        sent = true;
                    }
                    if sent {
                        self.retx.insert(PendingPacket { bytes, recipient: target, seq, attempts: 0, next_retry: Instant::now() + RETRY_INTERVAL });
                        info!("寻址成功，重发失败消息 seq={} -> {}", seq, id::short(&target));
                    } else {
                        self.failed_sends.insert((target, seq), bytes);
                    }
                }
            }
            found = true;
            count = ans.ips.len();
        }

        let finished = found || q.answered.len() >= q.asked.len();
        if finished {
            if !found {
                info!("寻址未命中：{} 的共同好友均不知道其新地址", id::short(&q.target));
            }
            let _ = self.evt_tx.send(NetEvent::AddrResult { target: q.target, found, count });
        } else {
            self.addr_queries.insert(ans.nonce_q, q);
        }
        Ok(())
    }

    fn check_addr_queries(&mut self, now: Instant) {
        let expired: Vec<[u8; 16]> = self
            .addr_queries
            .iter()
            .filter(|(_, q)| now >= q.started + ADDR_QUERY_TIMEOUT)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            if let Some(q) = self.addr_queries.remove(&k) {
                info!("寻址超时：未能找到 {} 的新地址", id::short(&q.target));
                let _ = self.evt_tx.send(NetEvent::AddrResult { target: q.target, found: false, count: 0 });
            }
        }
    }

    /// 手动/自动触发的被动寻址：向每个共同好友发起一次单跳 IP 询问。
    /// 不递归、不广播，一轮结束即止。
    async fn handle_find_address(&mut self, target: [u8; 32]) {
        if target == self.identity.ed_pub {
            let _ = self.evt_tx.send(NetEvent::Status("不能查询自己".into()));
            return;
        }
        if !self.is_friend(&target) {
            let _ = self.evt_tx.send(NetEvent::Status("目标不是好友".into()));
            return;
        }

        // 可询问的对象：除 target 外的所有直接好友
        let candidates: Vec<[u8; 32]> = {
            let store = self.friends.lock().unwrap();
            store
                .list()
                .into_iter()
                .filter_map(|f| id::decode(&f.pubkey).ok())
                .filter(|pk| *pk != target)
                .collect()
        };
        if candidates.is_empty() {
            let _ = self.evt_tx.send(NetEvent::Status("没有可询问的共同好友".into()));
            return;
        }

        let mut nonce_q = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_q);

        let fail_seqs: Vec<u32> = self
            .failed_sends
            .iter()
            .filter(|((pk, _), _)| *pk == target)
            .map(|((_, s), _)| *s)
            .collect();

        let mut asked: Vec<[u8; 32]> = Vec::new();
        for friend_pk in candidates {
            let Some(fxpub) = cipher::ed_pub_to_x25519(&friend_pk) else { continue };
            let inner = proto::encode_addr_query(&target, &nonce_q, 0);
            let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &fxpub, &self.identity.ed_pub, &friend_pk, &inner) else {
                continue;
            };
            let payload = envelope_close(&sealed);
            let pkt = Packet { ptype: PktType::AddrQuery, flags: 0, seq: 0, sender_id: self.identity.ed_pub, recipient_id: friend_pk, payload };
            let bytes = pkt.encode(&self.identity.signing);
            self.send_to_peer(&bytes, &friend_pk).await;
            asked.push(friend_pk);
        }

        if asked.is_empty() {
            let _ = self.evt_tx.send(NetEvent::Status("没有可询问的共同好友".into()));
            return;
        }
        info!("已向 {} 位共同好友发起对 {} 的单次地址询问", asked.len(), id::short(&target));
        let _ = self.evt_tx.send(NetEvent::Status(format!(
            "正在向 {} 位共同好友询问 {} 的新地址…",
            asked.len(),
            id::short(&target)
        )));
        self.addr_queries.insert(
            nonce_q,
            PendingQuery { target, started: Instant::now(), asked, answered: HashSet::new(), fail_seqs },
        );
    }

    // ---------- 反向探针与共同好友代投递 ----------

    /// 检测本地 IPv6 地址是否变化。变化返回 true（由主循环触发反向探针）。
    /// 上线时不主动广播；仅在检测到地址变化后才向好友发起探针。
    fn detect_local_ip_change(&mut self, now: Instant) -> bool {
        if now < self.next_local_ip_check {
            return false;
        }
        self.next_local_ip_check = now + LOCAL_IP_CHECK_INTERVAL;
        let cur = local_ipv6();
        match (&self.last_local_ipv6, &cur) {
            (Some(prev), Some(curr)) if prev == curr => false,
            (None, None) => false,
            _ => {
                self.last_local_ipv6 = cur;
                true
            }
        }
    }

    /// 反向探针：向全部直接好友发送 IP_CHANGED（E2E 加密 + 签名，要求对方回复）。
    async fn trigger_ip_probe(&mut self) {
        let current = local_ips();
        if current.is_empty() {
            return;
        }
        let probe_id = rand::random::<u64>();
        let inner = proto::encode_ip_changed(probe_id, &current);
        let friends_snapshot = self.friends.lock().unwrap().list();
        let mut count = 0usize;
        for f in &friends_snapshot {
            let Ok(pk) = id::decode(&f.pubkey) else { continue };
            let Some(fx) = cipher::ed_pub_to_x25519(&pk) else { continue };
            let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &fx, &self.identity.ed_pub, &pk, &inner) else {
                continue;
            };
            let payload = envelope_close(&sealed);
            let pkt = Packet { ptype: PktType::IpChanged, flags: FLAG_EPHEMERAL, seq: 0, sender_id: self.identity.ed_pub, recipient_id: pk, payload };
            let bytes = pkt.encode(&self.identity.signing);
            self.send_to_peer(&bytes, &pk).await;
            self.ip_probes.insert(pk, PendingProbe { bytes, probe_id, attempts: 0, next_try: Instant::now() + PROBE_RETRY_INTERVAL });
            count += 1;
        }
        if count > 0 {
            info!("检测到本地 IPv6 变化，向 {count} 位好友发起反向探针");
            let _ = self.evt_tx.send(NetEvent::Status(format!("检测到本地 IPv6 地址变化，已向 {count} 位好友发起反向探针")));
        }
    }

    /// 轮询反向探针：重试未确认的好友；重试耗尽则判定未确认并向共同好友广播。
    async fn poll_probes(&mut self, now: Instant) {
        let mut to_resend: Vec<([u8; 32], Vec<u8>, u32)> = Vec::new();
        let mut to_finalize: Vec<[u8; 32]> = Vec::new();
        for (k, p) in self.ip_probes.iter_mut() {
            if now >= p.next_try {
                if p.attempts >= PROBE_MAX_RETRIES {
                    to_finalize.push(*k);
                } else {
                    p.attempts += 1;
                    p.next_try = now + PROBE_RETRY_INTERVAL;
                    to_resend.push((*k, p.bytes.clone(), p.attempts));
                }
            }
        }
        for (k, bytes, attempts) in to_resend {
            info!("重发反向探针 -> {}（第 {attempts} 次）", id::short(&k));
            self.send_to_peer(&bytes, &k).await;
        }
        for k in to_finalize {
            self.ip_probes.remove(&k);
            info!("好友 {} 未确认反向探针，向共同好友广播", id::short(&k));
            let _ = self.evt_tx.send(NetEvent::Status(format!("好友 {} 未确认新 IP，已向共同好友广播", id::short(&k))));
            self.gossip_unconfirmed(&k).await;
        }
    }

    /// 向所有其他直接好友广播 GOSSIP：victim 没收到我的新 IP，请代转。
    /// 收到方会再次校验 victim 是否为共同好友后才存储转发（见 handle_gossip）。
    async fn gossip_unconfirmed(&mut self, victim: &[u8; 32]) {
        let ips = local_ips();
        let inner = proto::encode_gossip(&[*victim], &ips);
        let friends_snapshot = self.friends.lock().unwrap().list();
        let mut count = 0usize;
        for f in &friends_snapshot {
            let Ok(pk) = id::decode(&f.pubkey) else { continue };
            if pk == *victim {
                continue;
            }
            let Some(fx) = cipher::ed_pub_to_x25519(&pk) else { continue };
            let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &fx, &self.identity.ed_pub, &pk, &inner) else {
                continue;
            };
            let payload = envelope_close(&sealed);
            let pkt = Packet { ptype: PktType::Gossip, flags: FLAG_EPHEMERAL, seq: 0, sender_id: self.identity.ed_pub, recipient_id: pk, payload };
            let bytes = pkt.encode(&self.identity.signing);
            self.send_to_peer(&bytes, &pk).await;
            count += 1;
        }
        if count > 0 {
            info!("已向 {count} 位共同好友广播：{} 未收到我的新 IP", id::short(victim));
        }
    }

    /// 收到 IP_CHANGED（我们是被通知方）：更新对方记录并回复 ACK。
    /// 权威新地址 = 包源地址（对方当前真实 IP）；载荷 IP 一并合并。
    async fn handle_ip_changed(&mut self, p: &Packet, src: SocketAddr) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生对方 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let (probe_id, payload_ips) = proto::decode_ip_changed(&pt)?;

        self.friends.lock().unwrap().update_last_seen_and_ip(&p.sender_id, Some(&src.ip().to_string()));
        if !payload_ips.is_empty() {
            self.friends.lock().unwrap().merge_ips(&p.sender_id, &payload_ips);
        }

        let inner = proto::encode_ip_changed_ack(probe_id);
        let sealed = cipher::seal(&self.identity.x25519_sk, &sender_xpub, &self.identity.ed_pub, &p.sender_id, &inner)?;
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::IpChangedAck, flags: FLAG_ACK, seq: 0, sender_id: self.identity.ed_pub, recipient_id: p.sender_id, payload };
        let bytes = pkt.encode(&self.identity.signing);
        self.send_to_addr(&bytes, src).await;
        info!("好友 {} 通知了新 IP（probe={probe_id}），已回复确认", id::short(&p.sender_id));
        let _ = self.evt_tx.send(NetEvent::Status(format!("好友 {} 通知了新 IP，已确认", id::short(&p.sender_id))));
        Ok(())
    }

    /// 收到 IP_CHANGED_ACK（我们发起的探针被对方确认）。
    async fn handle_ip_changed_ack(&mut self, p: &Packet) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生对方 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let probe_id = proto::decode_ip_changed_ack(&pt)?;
        if let Some(probe) = self.ip_probes.remove(&p.sender_id) {
            if probe.probe_id == probe_id {
                info!("好友 {} 已确认反向探针（probe={probe_id}）", id::short(&p.sender_id));
            }
        }
        Ok(())
    }

    /// 收到 GOSSIP（我们是被委托的共同好友 M）：仅当 victim 也是我们的好友时
    /// 才托付 source 的新 IP 待转；source = 签名者（已在 handle_packet 校验为好友）。
    async fn handle_gossip(&mut self, p: &Packet) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生对方 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let (victims, ips) = proto::decode_gossip(&pt)?;
        let source = p.sender_id;

        let mut stored = 0usize;
        let mut online_victims: Vec<[u8; 32]> = Vec::new();
        for victim in victims {
            if victim == source || victim == self.identity.ed_pub {
                continue;
            }
            // 一手校验：victim 必须是我们的共同好友才代为转交
            if !self.is_friend(&victim) {
                debug!("拒绝为未知身份 {} 代转 IP", id::short(&victim));
                continue;
            }
            let e = self.pending_pushes.entry(victim).or_default();
            if !e.iter().any(|x| x.source == source) {
                e.push(PendingPush { source, ips: ips.clone() });
                stored += 1;
            }
            if self.recently_seen(&victim) {
                online_victims.push(victim);
            }
        }
        if stored > 0 {
            info!("收到 {} 的委托：代转其新 IP 给 {stored} 位好友", id::short(&source));
            let _ = self.evt_tx.send(NetEvent::Status(format!("好友 {} 委托我代转新 IP（{stored} 人待转）", id::short(&source))));
        }
        // victim 当前在线则立即投递
        for victim in online_victims {
            self.deliver_pending_pushes(&victim).await?;
        }
        Ok(())
    }

    /// 收到 PUSH_IP（我们是被代转方 D）：仅接受"来源也是我们好友"的 IP 更新。
    async fn handle_push_ip(&mut self, p: &Packet) -> Result<()> {
        let sender_xpub = cipher::ed_pub_to_x25519(&p.sender_id).ok_or_else(|| anyhow::anyhow!("无法派生对方 X25519"))?;
        let sealed = envelope_open(&p.payload)?;
        let pt = cipher::open(&sealed, &self.identity.x25519_sk, &sender_xpub, &p.sender_id, &self.identity.ed_pub)?;
        let (source_id, ips) = proto::decode_push_ip(&pt)?;
        // 一手校验：只接受好友列表中的来源，否则丢弃（防止陌生人地址注入）
        if source_id == self.identity.ed_pub || !self.is_friend(&source_id) {
            warn!("来自 {} 的转发包含非好友 {} 的 IP，已丢弃", id::short(&p.sender_id), id::short(&source_id));
            return Ok(());
        }
        if ips.is_empty() {
            return Ok(());
        }
        if self.merge_ips(&source_id, &ips) {
            info!("经共同好友 {} 获得 {} 的新 IP: {:?}", id::short(&p.sender_id), id::short(&source_id), ips);
            let _ = self.evt_tx.send(NetEvent::Status(format!("经共同好友获得 {} 的新 IP（{} 个）", id::short(&source_id), ips.len())));
        }
        Ok(())
    }

    /// 把共同好友托付的 PUSH_IP 投递给 victim（投递后移除该批待转项）。
    async fn deliver_pending_pushes(&mut self, victim: &[u8; 32]) -> Result<()> {
        let Some(pushes) = self.pending_pushes.remove(victim) else {
            return Ok(());
        };
        if pushes.is_empty() {
            return Ok(());
        }
        let victim_xpub = match cipher::ed_pub_to_x25519(victim) {
            Some(x) => x,
            None => return Ok(()),
        };
        for push in pushes {
            let inner = proto::encode_push_ip(&push.source, &push.ips);
            if let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &victim_xpub, &self.identity.ed_pub, victim, &inner) {
                let payload = envelope_close(&sealed);
                let pkt = Packet { ptype: PktType::PushIp, flags: FLAG_EPHEMERAL, seq: 0, sender_id: self.identity.ed_pub, recipient_id: *victim, payload };
                let bytes = pkt.encode(&self.identity.signing);
                self.send_to_peer(&bytes, victim).await;
                info!("已把 {} 的新 IP 代转给 {}（其已上线）", id::short(&push.source), id::short(victim));
            }
        }
        Ok(())
    }

    fn recently_seen(&self, id: &[u8; 32]) -> bool {
        match self.friends.lock().unwrap().get(id) {
            Some(f) => match f.last_seen {
                Some(ts) => crate::util::unix_millis().saturating_sub(ts) < 300_000,
                None => false,
            },
            None => false,
        }
    }

    // ---------- 好友状态 ----------

    fn is_friend(&self, id: &[u8; 32]) -> bool {
        self.friends.lock().unwrap().contains(id)
    }

    fn merge_ips(&self, id: &[u8; 32], new_ips: &[String]) -> bool {
        self.friends.lock().unwrap().merge_ips(id, new_ips)
    }

    fn note_friend_seen(&self, id: &[u8; 32], ip: Option<String>) {
        let changed = self.friends.lock().unwrap().update_last_seen_and_ip(id, ip.as_deref());
        if changed {
            let _ = self.evt_tx.send(NetEvent::FriendSeen { id: *id });
        }
    }
}

/// 当前本地 IPv6 地址（用于变化检测）。失败返回 None。
fn local_ipv6() -> Option<String> {
    local_ip_address::local_ipv6().ok().map(|ip| ip.to_string())
}

/// 当前本地全部 IP（v4 + v6）。
fn local_ips() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(ip) = local_ip_address::local_ip() {
        out.push(ip.to_string());
    }
    if let Ok(ip) = local_ip_address::local_ipv6() {
        out.push(ip.to_string());
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Identity;
    use crate::store::friends::FriendStore;

    fn wait_for<T>(rx: &std::sync::mpsc::Receiver<T>, timeout: Duration, pred: impl Fn(&T) -> bool) -> Option<T> {
        let deadline = Instant::now() + timeout;
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return None;
            }
            match rx.recv_timeout(remain) {
                Ok(ev) => {
                    if pred(&ev) {
                        return Some(ev);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// 端到端回环测试：两个节点各自跑完整网络栈，A 发消息 B 收并回 ACK。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_two_nodes() {
        let base = 12142 + (std::process::id() % 100) as u16;
        let port_a = base;
        let port_b = base + 1;

let a = Identity::generate();
        let b = Identity::generate();
        let a_pub = a.ed_pub;
        let b_pub = b.ed_pub;

        let dir_a = std::env::temp_dir().join(format!("kc-e2e-a-{}", std::process::id()));
        let dir_b = std::env::temp_dir().join(format!("kc-e2e-b-{}", std::process::id()));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();

        let store_a = Arc::new(Mutex::new(FriendStore::open(dir_a.join("friends.toml")).unwrap()));
        let store_b = Arc::new(Mutex::new(FriendStore::open(dir_b.join("friends.toml")).unwrap()));
store_a.lock().unwrap().add("bob".into(), b_pub, Some(format!("127.0.0.1:{port_b}"))).unwrap();
        store_b.lock().unwrap().add("alice".into(), a_pub, Some(format!("127.0.0.1:{port_a}"))).unwrap();

        let (cmd_tx_a, cmd_rx_a) = tokio::sync::mpsc::channel(64);
        let (evt_tx_a, evt_rx_a) = std::sync::mpsc::channel();
        let (evt_tx_b, evt_rx_b) = std::sync::mpsc::channel();
        let (_cmd_tx_b, cmd_rx_b) = tokio::sync::mpsc::channel::<NetCommand>(64);

        let task_a = tokio::spawn(run(NetInit {
            identity: a,
            port: port_a,
            friends: store_a.clone(),
            cmd_rx: cmd_rx_a,
            evt_tx: evt_tx_a,
        }));
        let _task_b = tokio::spawn(run(NetInit {
            identity: b,
            port: port_b,
            friends: store_b.clone(),
            cmd_rx: cmd_rx_b,
            evt_tx: evt_tx_b,
        }));

        // 等两节点就绪
        tokio::time::sleep(Duration::from_millis(300)).await;

cmd_tx_a
            .send(NetCommand::Send { recipient: b_pub, content: "hello kokona".into(), seq: 7 })
            .await
            .unwrap();

        // B 收到明文消息
        let got = wait_for(&evt_rx_b, Duration::from_secs(5), |ev| {
            matches!(ev, NetEvent::MessageReceived { content, .. } if content == "hello kokona")
        });
        assert!(got.is_some(), "B 未收到消息");

        // A 收到 ACK（seq=7）
        let acked = wait_for(&evt_rx_a, Duration::from_secs(5), |ev| {
            matches!(ev, NetEvent::MessageAcked { seq, .. } if *seq == 7)
        });
        assert!(acked.is_some(), "A 未收到 ACK");

// B 的好友记录应已记录 A 的最后来源 IP / 在线时间
        let b_view = store_b.lock().unwrap().get(&a_pub).unwrap();
        assert!(b_view.last_seen.is_some());

        let _ = cmd_tx_a.send(NetCommand::Quit).await;
        task_a.abort();
    }
}
