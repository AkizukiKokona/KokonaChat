//! UDP 丢包重传调度器。
//!
//! 规则：消息发出后，每隔 `RETRY_INTERVAL`（2 秒）重传一次，
//! 最多重传 `MAX_RETRIES`（3 次）；重传耗尽仍未收到 ACK 则判定发送失败。
//! 时钟由上层网络主循环统一驱动（非阻塞，单线程内无竞态）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// 最多重传次数（3 次）
pub const MAX_RETRIES: u32 = 3;

#[derive(Clone)]
pub struct PendingPacket {
    pub bytes: Vec<u8>,
    pub recipient: [u8; 32],
    pub seq: u32,
    /// 已重传次数
    pub attempts: u32,
    /// 下次重传时刻
    pub next_retry: Instant,
}

#[derive(Default)]
pub struct Retransmitter {
    pending: HashMap<([u8; 32], u32), PendingPacket>,
}

impl Retransmitter {
    pub fn insert(&mut self, p: PendingPacket) {
        self.pending.insert((p.recipient, p.seq), p);
    }

    /// 收到 ACK：移除对应在途包。
    pub fn ack(&mut self, recipient: &[u8; 32], seq: u32) -> Option<PendingPacket> {
        self.pending.remove(&(*recipient, seq))
    }

    /// 下一个需要唤醒的时刻。
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.pending.values().map(|p| p.next_retry).filter(|d| *d > now).min()
    }

    /// 轮询到期包：返回 (待重传列表, 超时失败列表)。
    pub fn poll_retries(&mut self, now: Instant) -> (Vec<PendingPacket>, Vec<PendingPacket>) {
        let mut resend = Vec::new();
        let mut failed = Vec::new();
        for (k, p) in self.pending.iter_mut() {
            if now >= p.next_retry {
                if p.attempts >= MAX_RETRIES {
                    failed.push(PendingPacket {
                        bytes: p.bytes.clone(),
                        recipient: k.0,
                        seq: k.1,
                        attempts: p.attempts,
                        next_retry: p.next_retry,
                    });
                } else {
                    p.attempts += 1;
                    p.next_retry = now + RETRY_INTERVAL;
                    resend.push(p.clone());
                }
            }
        }
        for f in &failed {
            self.pending.remove(&(f.recipient, f.seq));
        }
        (resend, failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

#[test]
    fn retry_then_fail() {
        let mut r = Retransmitter::default();
        let now = Instant::now();
        r.insert(PendingPacket { bytes: vec![1], recipient: [0u8; 32], seq: 1, attempts: 0, next_retry: now + RETRY_INTERVAL });

        // t=2s：第 1 次重传
        let (resend, failed) = r.poll_retries(now + RETRY_INTERVAL);
        assert_eq!(resend.len(), 1);
        assert_eq!(resend[0].attempts, 1);
        assert!(failed.is_empty());
        assert!(!r.pending.is_empty());

        // t=4s：第 2 次重传
        let (resend, failed) = r.poll_retries(now + RETRY_INTERVAL * 2);
        assert_eq!(resend.len(), 1);
        assert_eq!(resend[0].attempts, 2);
        assert!(failed.is_empty());

        // t=6s：第 3 次重传
        let (resend, failed) = r.poll_retries(now + RETRY_INTERVAL * 3);
        assert_eq!(resend.len(), 1);
        assert_eq!(resend[0].attempts, 3);
        assert!(failed.is_empty());

        // t=8s：重传耗尽 -> 失败
        let (resend, failed) = r.poll_retries(now + RETRY_INTERVAL * 4);
        assert!(resend.is_empty());
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].seq, 1);
        assert!(r.pending.is_empty());

        // ACK 语义
        let mut r2 = Retransmitter::default();
        r2.insert(PendingPacket { bytes: vec![2], recipient: [0u8; 32], seq: 2, attempts: 0, next_retry: now + RETRY_INTERVAL });
        assert!(r2.ack(&[0u8; 32], 2).is_some());
        assert!(r2.pending.is_empty());
        assert!(r2.ack(&[0u8; 32], 99).is_none());
    }
}