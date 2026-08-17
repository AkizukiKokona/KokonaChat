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
    SendAttach { recipient: [u8; 32], kind: u8, name: String, data: Vec<u8>, ts: u64, transfer: [u8; 16] },
    FindAddress { recipient: [u8; 32] },
    Quit,
}

/// 网络层 -> TUI 事件。
#[derive(Clone)]
pub enum NetEvent {
    MessageReceived { from: [u8; 32], content: String, seq: u32, ts: u64 },
    MessageAcked { to: [u8; 32], seq: u32 },
    MessageFailed { to: [u8; 32], seq: u32 },
    AttachReceived { from: [u8; 32], kind: u8, name: String, data: Vec<u8>, ts: u64 },
    AttachAcked { to: [u8; 32], transfer: [u8; 16] },
    AttachFailed { to: [u8; 32], transfer: [u8; 16] },
    AddrResult { target: [u8; 32], found: bool, count: usize },
    FriendSeen { id: [u8; 32] },
    Status(String),
}

const ADDR_QUERY_TIMEOUT: Duration = Duration::from_secs(6);
/// 寻址询问在超时之前的重发间隔（UDP 丢包兜底）。
const ADDR_QUERY_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// 寻址询问最多重发次数（含首次共 3 次尝试）。
const ADDR_QUERY_MAX_RETRIES: u8 = 2;
/// 反向探针：好友未回复时的重试间隔。
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(10);
/// 反向探针最多重试次数（含首次共 3 次尝试）。
const PROBE_MAX_RETRIES: u32 = 2;
/// 本地 IPv6 地址变化检测周期。
const LOCAL_IP_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// PUSH_IP（共同好友代投递）的重发间隔与上限。
const PUSH_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const PUSH_MAX_RETRIES: u8 = 2;
/// 单条消息明文上限（字节）。接收缓冲 4096，留出协议头/加密/签名开销后取 3000。
const MAX_MSG_CONTENT_BYTES: usize = 3000;
/// 附件分片单片数据长度（字节）。小于 4096 接收缓冲，留出协议/加密/签名开销。
const ATTACH_CHUNK_DATA: usize = 2400;
/// 附件总量上限（接收侧内存保护）。
const MAX_ATTACH_TOTAL: u64 = 256 * 1024 * 1024;
/// 附件分片 seq 起点：与文本消息（app 层自 0 递增）错开，避免重传表冲突。
const ATTACH_SEQ_BASE: u32 = 0x8000_0000;
/// 接收侧未收齐分片缓冲的保留时长。
const ATTACH_RECV_TTL: Duration = Duration::from_secs(120);

/// 进行中的附件发送（按 transfer_id）。
struct AttachSend {
    recipient: [u8; 32],
    total_chunks: u32,
    acked: HashSet<u32>,
}

/// 接收侧组装缓冲（按 transfer_id）。
struct AttachRecv {
    kind: u8,
    name: String,
    total_size: u64,
    total_chunks: u32,
    data: Vec<u8>,
    got: HashSet<u32>,
    updated: Instant,
}

/// 在途分片 -> 所属传输映射（用于 ACK/失败时反查并清理）。
struct ChunkRef {
    recipient: [u8; 32],
    transfer: [u8; 16],
    index: u32,
}

fn hex16(t: &[u8; 16]) -> String {
    hex::encode(t)
}

struct PendingQuery {
    target: [u8; 32],
    started: Instant,
    asked: Vec<[u8; 32]>,
    answered: HashSet<[u8; 32]>,
    fail_seqs: Vec<u32>,
    /// 已重发次数与下次重发时刻。
    attempts: u8,
    next_retry: Instant,
}

/// 待确认的反向探针（按好友维度）。
struct PendingProbe {
    bytes: Vec<u8>,
    probe_id: u64,
    attempts: u32,
    next_try: Instant,
}

/// 共同好友托付我们转交的新 IP（带重发状态）。
#[derive(Clone)]
struct PendingPush {
    source: [u8; 32],
    ips: Vec<String>,
    attempts: u8,
    next_try: Instant,
}

/// 我方最新地址公告尚未被某好友确认时，待其上线后补投递。
#[derive(Clone)]
struct PendingAnnounce {
    bytes: Vec<u8>,
    probe_id: u64,
}

pub struct NetInit {
    pub identity: Identity,
    pub port: u16,
    /// 公网 IPv4 稳定地址（Some 时启用"稳定地址模式"，见 Network::stable_ipv4）。
    pub stable_ipv4: Option<String>,
    pub friends: Arc<Mutex<FriendStore>>,
    pub cmd_rx: TokioReceiver<NetCommand>,
    pub evt_tx: Sender<NetEvent>,
}

struct Network {
    identity: Identity,
    sock: UdpSocket,
    use_v6: bool,
    port: u16,
    /// 公网 IPv4 稳定地址模式：
    /// 有公网 IPv4 的用户地址长期稳定，本机不再因地址变化反复广播，
    /// 好友记录的有效地址也不会轻易失效，从而无需一遍遍重新寻址。
    /// 稳定模式下通告仍会带端口，但跳过"本地地址变化检测"。
    stable_ipv4: Option<String>,
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
    /// 我方最新地址公告尚未被确认的好友：待其上线后补投递
    pending_announce: HashMap<[u8; 32], PendingAnnounce>,
    /// 进行中的附件发送（transfer_id -> 状态）
    attach_sends: HashMap<[u8; 16], AttachSend>,
    /// 接收侧附件组装缓冲（transfer_id -> 状态）
    attach_recvs: HashMap<[u8; 16], AttachRecv>,
    /// 在途分片 seq -> 所属传输（用于 ACK/失败反查与清理）
    chunk_seqs: HashMap<u32, ChunkRef>,
    /// 附件分片 seq 分配（自高位起递增）
    attach_seq: u32,
}

pub async fn run(init: NetInit) -> Result<()> {
    let bound = match socket::bind_dual(init.port).await {
        Ok(b) => b,
        Err(e) => {
            let _ = init.evt_tx.send(NetEvent::Status(format!("端口 {} 绑定失败: {e}", init.port)));
            return Err(e);
        }
    };
let NetInit { identity, port, stable_ipv4, friends, cmd_rx, evt_tx } = init;
    info!("已绑定 UDP 双栈端口 {}（IPv6 双栈: {}）", port, bound.is_v6);
    let mut n = Network {
        sock: bound.sock,
        use_v6: bound.is_v6,
        port,
        identity,
        stable_ipv4,
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
        pending_announce: HashMap::new(),
        attach_sends: HashMap::new(),
        attach_recvs: HashMap::new(),
        chunk_seqs: HashMap::new(),
        attach_seq: ATTACH_SEQ_BASE,
    };
    n.startup_ping().await?;
    // 上线时主动通告一次当前地址（不仅限地址变化时），
    // 让"离线期间换了地址"的本机在上线后立即通知在线的直接好友。
    n.announce_ips().await;
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
                if let Some(cr) = self.chunk_seqs.remove(&f.seq) {
                    // 附件分片重传耗尽 -> 整次传输失败（只通知一次）
                    if cr.recipient == f.recipient {
                        self.attach_sends.remove(&cr.transfer);
                        let _ = self.evt_tx.send(NetEvent::AttachFailed { to: f.recipient, transfer: cr.transfer });
                        info!("附件传输 {} 分片 seq={} 失败，整体终止 -> {}", hex16(&cr.transfer), f.seq, id::short(&cr.recipient));
                        self.cancel_transfer(f.recipient, cr.transfer);
                    }
                    continue;
                }
                self.failed_sends.insert((f.recipient, f.seq), f.bytes.clone());
                let _ = self.evt_tx.send(NetEvent::MessageFailed { to: f.recipient, seq: f.seq });
                info!("消息 seq={} 发送失败（重传 {} 次耗尽）", f.seq, retransmit::MAX_RETRIES);
            }

// 寻址询问超时/完成检查 + UDP 丢包重发
            self.check_addr_queries(now);
            self.retry_addr_queries(now).await;

            // 反向探针：重试未确认好友 / 判定未确认后向共同好友广播
            self.poll_probes(now).await;

            // 共同好友代投递（PUSH_IP）的 UUDP 丢包重发
            self.poll_pushes(now).await;

            // 本地 IPv6 变化检测（变化即触发反向探针）
            if self.detect_local_ip_change(now) {
                self.announce_ips().await;
            }

            // 清理接收侧长期未收齐的附件缓冲
            self.prune_attach_recvs(now);

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
                        Some(NetCommand::SendAttach { recipient, kind, name, data, ts, transfer }) => {
                            self.handle_send_attach(recipient, kind, name, data, ts, transfer).await;
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
            deadlines.push(q.next_retry);
            deadlines.push(q.started + ADDR_QUERY_TIMEOUT);
        }
        for p in self.ip_probes.values() {
            deadlines.push(p.next_try);
        }
        for pushes in self.pending_pushes.values() {
            for p in pushes {
                deadlines.push(p.next_try);
            }
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
        if content.len() > MAX_MSG_CONTENT_BYTES {
            bail!("消息过长（超过 {} 字节）", MAX_MSG_CONTENT_BYTES);
        }
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
        self.note_friend_seen(&p.sender_id, Some(crate::net::socket::fmt_addr(src))).await;

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
        // 若对方尚未确认我方最新地址公告，立即用其当前地址补投递
        self.deliver_pending_announce(&p.sender_id, src).await;
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
        if mtype == proto::MSG_ATTACH {
            self.send_ack(&p.sender_id, seq, src).await?;
            let (_, chunk) = proto::decode_attach_chunk(&pt)?;
            self.assemble_attach(&p.sender_id, ts, chunk);
            return Ok(());
        }
        if mtype != proto::MSG_TEXT {
            bail!("未知消息子类型");
        }
        self.send_ack(&p.sender_id, seq, src).await?;
        let _ = self.evt_tx.send(NetEvent::MessageReceived { from: p.sender_id, content, seq, ts });
        Ok(())
    }

    /// 发送附件：分片后逐片发送，每片独立 seq 走统一重传/ACK 调度。
    async fn handle_send_attach(&mut self, recipient: [u8; 32], kind: u8, name: String, data: Vec<u8>, ts: u64, transfer: [u8; 16]) {
        let fail = |to: [u8; 32], transfer: [u8; 16]| {
            let _ = self.evt_tx.send(NetEvent::AttachFailed { to, transfer });
        };
        if !self.is_friend(&recipient) {
            warn!("发送附件失败：{} 不是好友", id::short(&recipient));
            fail(recipient, transfer);
            return;
        }
        let recip_xpub = match cipher::ed_pub_to_x25519(&recipient) {
            Some(x) => x,
            None => {
                warn!("发送附件失败：无法派生 {} 的 X25519", id::short(&recipient));
                fail(recipient, transfer);
                return;
            }
        };
        let addrs = self.peer_addrs(&recipient);
        if addrs.is_empty() {
            info!("发送附件失败：{} 无已知地址", id::short(&recipient));
            fail(recipient, transfer);
            return;
        }
        let total_size = data.len() as u64;
        let total_chunks = if data.is_empty() {
            1
        } else {
            ((total_size + ATTACH_CHUNK_DATA as u64 - 1) / ATTACH_CHUNK_DATA as u64) as u32
        };

        // 预构造所有分片包：任一分片加密/编码失败即整体终止
        let mut packets = Vec::with_capacity(total_chunks as usize);
        for i in 0..total_chunks as usize {
            let start = i * ATTACH_CHUNK_DATA;
            let end = ((i + 1) * ATTACH_CHUNK_DATA).min(data.len());
            let chunk = proto::AttachChunk {
                transfer,
                kind,
                index: i as u32,
                total: total_chunks,
                total_size,
                name: name.clone(),
                data: data[start..end].to_vec(),
            };
            let inner = proto::encode_attach_chunk(&chunk, ts);
            let sealed = match cipher::seal(&self.identity.x25519_sk, &recip_xpub, &self.identity.ed_pub, &recipient, &inner) {
                Ok(s) => s,
                Err(e) => {
                    warn!("发送附件失败：加密错误 {e}");
                    fail(recipient, transfer);
                    return;
                }
            };
            let payload = envelope_close(&sealed);
            self.attach_seq = self.attach_seq.wrapping_add(1);
            let seq = self.attach_seq;
            let pkt = Packet { ptype: PktType::Msg, flags: FLAG_EPHEMERAL, seq, sender_id: self.identity.ed_pub, recipient_id: recipient, payload };
            let bytes = pkt.encode(&self.identity.signing);
            packets.push((seq, i as u32, bytes));
        }

        for (seq, index, bytes) in packets {
            for a in &addrs {
                self.send_to_addr(&bytes, *a).await;
            }
            self.chunk_seqs.insert(seq, ChunkRef { recipient, transfer, index });
            self.retx.insert(PendingPacket { bytes, recipient, seq, attempts: 0, next_retry: Instant::now() + RETRY_INTERVAL });
        }
        self.attach_sends.insert(
            transfer,
            AttachSend { recipient, total_chunks, acked: HashSet::new() },
        );
        info!("已发送附件 {}（{} 字节，{total_chunks} 片）-> {}", id::short(&recipient), total_size, hex16(&transfer));
    }

    /// 附件分片失败时，取消同一传输的其余在途分片（避免无谓重传）。
    fn cancel_transfer(&mut self, recipient: [u8; 32], transfer: [u8; 16]) {
        let doomed: Vec<u32> = self
            .chunk_seqs
            .iter()
            .filter(|(_, cr)| cr.recipient == recipient && cr.transfer == transfer)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in doomed {
            self.chunk_seqs.remove(&seq);
            self.retx.ack(&recipient, seq);
        }
    }

    /// 清理长时间未收齐的接收侧缓冲。
    fn prune_attach_recvs(&mut self, now: Instant) {
        self.attach_recvs.retain(|_, r| now.duration_since(r.updated) < ATTACH_RECV_TTL);
    }

    /// 接收侧组装：收齐后发出 AttachReceived。
    fn assemble_attach(&mut self, from: &[u8; 32], ts: u64, chunk: proto::AttachChunk) {
        if chunk.total_size > MAX_ATTACH_TOTAL {
            warn!("附件过大（{} 字节），丢弃", chunk.total_size);
            return;
        }
        let entry = self.attach_recvs.entry(chunk.transfer).or_insert_with(|| AttachRecv {
            kind: chunk.kind,
            name: chunk.name.clone(),
            total_size: chunk.total_size,
            total_chunks: chunk.total,
            data: vec![0u8; chunk.total_size as usize],
            got: HashSet::new(),
            updated: Instant::now(),
        });
        entry.updated = Instant::now();
        if entry.got.insert(chunk.index) {
            let start = chunk.index as usize * ATTACH_CHUNK_DATA;
            if start < entry.data.len() {
                let n = (entry.data.len() - start).min(chunk.data.len());
                entry.data[start..start + n].copy_from_slice(&chunk.data[..n]);
            }
        }
        if entry.got.len() == entry.total_chunks as usize {
            let done = entry.data.clone();
            let total_size = entry.total_size;
            let name = entry.name.clone();
            let kind = entry.kind;
            self.attach_recvs.remove(&chunk.transfer);
            let _ = self.evt_tx.send(NetEvent::AttachReceived {
                from: *from,
                kind,
                name,
                data: done[..total_size as usize].to_vec(),
                ts,
            });
            info!("附件分片收齐（{total_size} 字节）<- {}", id::short(from));
        }
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
        // 附件分片 ACK：更新对应传输进度，收齐则整次完成
        if let Some(cr) = self.chunk_seqs.remove(&ack_seq) {
            self.retx.ack(&p.sender_id, ack_seq);
            self.failed_sends.remove(&(p.sender_id, ack_seq));
            if cr.recipient == p.sender_id {
                if let Some(s) = self.attach_sends.get_mut(&cr.transfer) {
                    s.acked.insert(cr.index);
                    if s.acked.len() == s.total_chunks as usize {
                        let transfer = cr.transfer;
                        let recipient = s.recipient;
                        self.attach_sends.remove(&transfer);
                        let _ = self.evt_tx.send(NetEvent::AttachAcked { to: recipient, transfer });
                        info!("附件传输 {} 完成 -> {}", hex16(&transfer), id::short(&recipient));
                    }
                }
            }
            return Ok(());
        }
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
                self.retry_failed_for(&target).await;
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

    /// 构造并发送一次寻址查询包给指定好友。返回是否成功构造。
    async fn send_addr_query_pkt(&self, target: &[u8; 32], nonce_q: &[u8; 16], friend_pk: &[u8; 32]) -> bool {
        let Some(fxpub) = cipher::ed_pub_to_x25519(friend_pk) else { return false };
        let inner = proto::encode_addr_query(target, nonce_q, 0);
        let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &fxpub, &self.identity.ed_pub, friend_pk, &inner) else {
            return false;
        };
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::AddrQuery, flags: 0, seq: 0, sender_id: self.identity.ed_pub, recipient_id: *friend_pk, payload };
        let bytes = pkt.encode(&self.identity.signing);
        self.send_to_peer(&bytes, friend_pk).await;
        true
    }

    /// 寻址询问在超时前的 UDP 丢包重发：向仍未回答的每位共同好友补发一次。
    async fn retry_addr_queries(&mut self, now: Instant) {
        let due: Vec<[u8; 16]> = self
            .addr_queries
            .iter()
            .filter(|(_, q)| now >= q.next_retry && q.attempts < ADDR_QUERY_MAX_RETRIES)
            .map(|(k, _)| *k)
            .collect();
        for k in due {
            let (target, nonce, asked, answered) = {
                let q = self.addr_queries.get_mut(&k).unwrap();
                q.attempts += 1;
                q.next_retry = now + ADDR_QUERY_RETRY_INTERVAL;
                (q.target, k, q.asked.clone(), q.answered.clone())
            };
            for pk in asked.iter().filter(|pk| !answered.contains(*pk)) {
                self.send_addr_query_pkt(&target, &nonce, pk).await;
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
            if self.send_addr_query_pkt(&target, &nonce_q, &friend_pk).await {
                asked.push(friend_pk);
            }
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
            PendingQuery {
                target,
                started: Instant::now(),
                asked,
                answered: HashSet::new(),
                fail_seqs,
                attempts: 0,
                next_retry: Instant::now() + ADDR_QUERY_RETRY_INTERVAL,
            },
        );
    }

    // ---------- 反向探针与共同好友代投递 ----------

    /// 检测本地 IPv6 地址是否变化。变化返回 true（由主循环触发反向探针）。
    /// 上线时不主动广播；仅在检测到地址变化后才向好友发起探针。
    fn detect_local_ip_change(&mut self, now: Instant) -> bool {
        // 稳定地址模式：公网 IPv4 长期不变，跳过本地地址变化检测（不再因地址变化反复通告）。
        if self.stable_ipv4.is_some() {
            return false;
        }
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
    /// 通告内容为"可达地址 + 本机监听端口"（动态通告必须携带端口，否则对方无法寻址）。
    async fn announce_ips(&mut self) {
        let current = local_announce(self.stable_ipv4.as_deref(), self.port);
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
            info!("已向 {count} 位好友发起地址通告（probe={probe_id}）");
            let _ = self.evt_tx.send(NetEvent::Status(format!("已向 {count} 位好友通告当前地址")));
        }
    }

    /// 轮询反向探针：重试未确认的好友；重试耗尽则判定未确认并向共同好友广播。
    async fn poll_probes(&mut self, now: Instant) {
        let mut to_resend: Vec<([u8; 32], Vec<u8>, u32)> = Vec::new();
        let mut to_finalize: Vec<([u8; 32], Vec<u8>, u64)> = Vec::new();
        for (k, p) in self.ip_probes.iter_mut() {
            if now >= p.next_try {
                if p.attempts >= PROBE_MAX_RETRIES {
                    to_finalize.push((*k, p.bytes.clone(), p.probe_id));
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
        for (k, bytes, probe_id) in to_finalize {
            self.ip_probes.remove(&k);
            // 保留公告：若对方日后与我们通信（上线/换地址），用其当前地址补投递。
            self.pending_announce.insert(k, PendingAnnounce { bytes, probe_id });
            info!("好友 {} 未确认反向探针，向共同好友广播", id::short(&k));
            let _ = self.evt_tx.send(NetEvent::Status(format!("好友 {} 未确认新 IP，已向共同好友广播", id::short(&k))));
            self.gossip_unconfirmed(&k).await;
        }
    }

    /// 向所有其他直接好友广播 GOSSIP：victim 没收到我的新 IP，请代转。
    /// 收到方会再次校验 victim 是否为共同好友后才存储转发（见 handle_gossip）。
    async fn gossip_unconfirmed(&mut self, victim: &[u8; 32]) {
        let ips = local_announce(self.stable_ipv4.as_deref(), self.port);
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

        // 权威新地址 = 包源地址（对方当前真实 IP）**含端口**；
        // 端口是关键信息（同一 IP 上不同用户靠端口区分），动态通告必须保留。
        let seen_changed =
            self.friends.lock().unwrap().update_last_seen_and_ip(&p.sender_id, Some(&crate::net::socket::fmt_addr(src)));
        let mut merged = false;
        if !payload_ips.is_empty() {
            merged = self.friends.lock().unwrap().merge_ips(&p.sender_id, &payload_ips);
        }
        if seen_changed || merged {
            self.retry_failed_for(&p.sender_id).await;
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
        let confirmed = self.pending_announce.get(&p.sender_id).map(|pa| pa.probe_id == probe_id).unwrap_or(false);
        if confirmed {
            self.pending_announce.remove(&p.sender_id);
            info!("好友 {} 已确认地址公告（probe={probe_id}）", id::short(&p.sender_id));
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
                e.push(PendingPush { source, ips: ips.clone(), attempts: 0, next_try: Instant::now() });
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
            self.retry_failed_for(&source_id).await;
            let _ = self.evt_tx.send(NetEvent::Status(format!("经共同好友获得 {} 的新 IP（{} 个）", id::short(&source_id), ips.len())));
        }
        Ok(())
    }

    /// 把共同好友托付的 PUSH_IP 投递给 victim。
    /// 仅在"投递时刻已到"时发送（避免对方每来一个包都重复）；重发与清理由 poll_pushes 负责。
    async fn deliver_pending_pushes(&mut self, victim: &[u8; 32]) -> Result<()> {
        let due: Vec<PendingPush> = {
            let now = Instant::now();
            let mut out = Vec::new();
            if let Some(pushes) = self.pending_pushes.get(victim) {
                for p in pushes {
                    if now >= p.next_try {
                        out.push(p.clone());
                    }
                }
            }
            out
        };
        for push in due {
            if self.send_push_ip(victim, &push.source, &push.ips).await {
                if let Some(vec) = self.pending_pushes.get_mut(victim) {
                    if let Some(p) = vec.iter_mut().find(|p| p.source == push.source) {
                        p.attempts += 1;
                        p.next_try = Instant::now() + PUSH_RETRY_INTERVAL;
                    }
                }
                info!("已把 {} 的新 IP 代转给 {}（其已上线）", id::short(&push.source), id::short(victim));
            }
        }
        Ok(())
    }

    /// 构造并发送一条 PUSH_IP。返回是否成功构造。
    async fn send_push_ip(&self, victim: &[u8; 32], source: &[u8; 32], ips: &[String]) -> bool {
        let Some(victim_xpub) = cipher::ed_pub_to_x25519(victim) else { return false };
        let inner = proto::encode_push_ip(source, ips);
        let Ok(sealed) = cipher::seal(&self.identity.x25519_sk, &victim_xpub, &self.identity.ed_pub, victim, &inner) else {
            return false;
        };
        let payload = envelope_close(&sealed);
        let pkt = Packet { ptype: PktType::PushIp, flags: FLAG_EPHEMERAL, seq: 0, sender_id: self.identity.ed_pub, recipient_id: *victim, payload };
        let bytes = pkt.encode(&self.identity.signing);
        self.send_to_peer(&bytes, victim).await;
        true
    }

    /// 轮询 PUSH_IP 重发（UDP 丢包兜底）并在次数耗尽后清理。
    async fn poll_pushes(&mut self, now: Instant) {
        let victims: Vec<[u8; 32]> = self.pending_pushes.keys().copied().collect();
        for v in victims {
            let due: Vec<PendingPush> = {
                let mut out = Vec::new();
                if let Some(pushes) = self.pending_pushes.get(&v) {
                    for p in pushes {
                        if now >= p.next_try {
                            out.push(p.clone());
                        }
                    }
                }
                out
            };
            for push in due {
                if self.send_push_ip(&v, &push.source, &push.ips).await {
                    if let Some(vec) = self.pending_pushes.get_mut(&v) {
                        if let Some(p) = vec.iter_mut().find(|p| p.source == push.source) {
                            p.attempts += 1;
                            p.next_try = now + PUSH_RETRY_INTERVAL;
                        }
                    }
                }
            }
            if let Some(vec) = self.pending_pushes.get_mut(&v) {
                vec.retain(|p| p.attempts <= PUSH_MAX_RETRIES);
                if vec.is_empty() {
                    self.pending_pushes.remove(&v);
                }
            }
        }
    }

    /// 对方上线/回连时，若其尚未确认我方最新地址公告，用其当前 src 补投递。
    async fn deliver_pending_announce(&mut self, friend: &[u8; 32], src: SocketAddr) {
        let Some(pa) = self.pending_announce.get(friend).cloned() else { return };
        self.send_to_addr(&pa.bytes, src).await;
        info!("好友 {} 已上线，用其当前地址补投递地址公告（probe={}）", id::short(friend), pa.probe_id);
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

    async fn note_friend_seen(&mut self, id: &[u8; 32], ip: Option<String>) {
        let changed = self.friends.lock().unwrap().update_last_seen_and_ip(id, ip.as_deref());
        if changed {
            let _ = self.evt_tx.send(NetEvent::FriendSeen { id: *id });
            // 对方上线/地址出现 -> 自动补发此前投递失败的消息（无需人工干预）
            self.retry_failed_for(id).await;
        }
    }

    /// 好友地址更新（新地址出现）后，自动补发此前投递失败的消息。
    /// 无需用户干预，也不需要依赖 auto_addressing 开关。
    async fn retry_failed_for(&mut self, recipient: &[u8; 32]) {
        let keys: Vec<([u8; 32], u32)> = self
            .failed_sends
            .keys()
            .filter(|(rid, _)| rid == recipient)
            .map(|(rid, seq)| (*rid, *seq))
            .collect();
        for (rid, seq) in keys {
            if let Some(bytes) = self.failed_sends.remove(&(rid, seq)) {
                let addrs = self.peer_addrs(&rid);
                if addrs.is_empty() {
                    self.failed_sends.insert((rid, seq), bytes);
                    continue;
                }
                for a in &addrs {
                    self.send_to_addr(&bytes, *a).await;
                }
                self.retx.insert(PendingPacket {
                    bytes,
                    recipient: rid,
                    seq,
                    attempts: 0,
                    next_retry: Instant::now() + RETRY_INTERVAL,
                });
                info!("好友 {} 地址更新，自动补发失败消息 seq={}", id::short(&rid), seq);
            }
        }
    }
}

/// 当前本地 IPv6 地址（用于变化检测）。失败返回 None。
/// 过滤 link-local 等不可路由地址，以其为基准，临时地址轮换时也能检测到。
fn local_ipv6() -> Option<String> {
    local_ip_address::local_ipv6()
        .ok()
        .filter(|ip| socket::filter_reachable(*ip))
        .map(|ip| ip.to_string())
}

/// 当前本地全部可达地址（v4 + v6），**均携带本机监听端口**。
/// 过滤 link-local / ULA / 多播 / 未指定等不可达地址（保留 loopback 供本机联调）。
/// 稳定地址模式下（`stable_ipv4` 为 Some）：只通告这一个公网 IPv4，不再重复变化。
fn local_announce(stable_ipv4: Option<&str>, port: u16) -> Vec<String> {
    if let Some(ip) = stable_ipv4 {
        return vec![format!("{ip}:{port}")];
    }
    let mut out = Vec::new();
    if let Ok(ip) = local_ip_address::local_ip() {
        if socket::filter_reachable(ip) {
            out.push(socket::fmt_ip_port(ip, port));
        }
    }
    if let Ok(ip) = local_ip_address::local_ipv6() {
        if socket::filter_reachable(ip) {
            out.push(socket::fmt_ip_port(ip, port));
        }
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
            stable_ipv4: None,
            friends: store_a.clone(),
            cmd_rx: cmd_rx_a,
            evt_tx: evt_tx_a,
        }));
        let _task_b = tokio::spawn(run(NetInit {
            identity: b,
            port: port_b,
            stable_ipv4: None,
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

// B 的好友记录应已记录 A 的最后来源 IP（带端口）/ 在线时间
        let b_view = store_b.lock().unwrap().get(&a_pub).unwrap();
        assert!(b_view.last_seen.is_some());
        assert!(
            b_view.ips.iter().any(|x| x == &format!("127.0.0.1:{port_a}")),
            "B 应记录 A 的带端口来源地址，实际: {:?}",
            b_view.ips
        );

        let _ = cmd_tx_a.send(NetCommand::Quit).await;
        task_a.abort();
    }
}
