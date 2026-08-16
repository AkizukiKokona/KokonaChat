//! 每人会话状态：去重（应对 UDP 重传导致的重复包）。

use std::collections::{HashMap, HashSet, VecDeque};

pub struct PeerSession {
    seen: VecDeque<u32>,
    seen_set: HashSet<u32>,
}

impl PeerSession {
    const MAX_SEEN: usize = 256;

    pub fn new() -> Self {
        PeerSession { seen: VecDeque::new(), seen_set: HashSet::new() }
    }

    pub fn is_seen(&self, seq: u32) -> bool {
        self.seen_set.contains(&seq)
    }

    pub fn mark_seen(&mut self, seq: u32) {
        if self.seen_set.insert(seq) {
            self.seen.push_back(seq);
            while self.seen.len() > Self::MAX_SEEN {
                if let Some(old) = self.seen.pop_front() {
                    self.seen_set.remove(&old);
                }
            }
        }
    }
}

#[derive(Default)]
pub struct SessionTable {
    peers: HashMap<[u8; 32], PeerSession>,
}

impl SessionTable {
    pub fn get_mut(&mut self, id: &[u8; 32]) -> &mut PeerSession {
        self.peers.entry(*id).or_insert_with(PeerSession::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup() {
        let mut s = PeerSession::new();
        assert!(!s.is_seen(1));
        s.mark_seen(1);
        assert!(s.is_seen(1));
        assert!(!s.is_seen(2));
    }
}