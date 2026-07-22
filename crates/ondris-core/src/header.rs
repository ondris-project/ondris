use ondris_pow::Dataset;
use ondris_primitives::{Address, Hash256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: Hash256,
    pub tx_root: Hash256,
    pub timestamp: u64,
    pub difficulty: u64,
    pub miner: Address,
    pub nonce: u64,
}

impl BlockHeader {
    /// Canonical serialization of the header WITHOUT the nonce: this is
    /// the `header_bytes` passed to `ondris_hash`, which appends the nonce
    /// itself.
    pub fn bytes_for_pow(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        buf.extend_from_slice(self.tx_root.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.difficulty.to_le_bytes());
        buf.extend_from_slice(&self.miner.0);
        buf
    }

    /// This header's PoW hash also serves as the block identifier (like
    /// Bitcoin: block hash = the header hash that satisfies the target).
    pub fn id(&self, dataset: &Dataset) -> Hash256 {
        ondris_pow::ondris_hash(&self.bytes_for_pow(), self.nonce, dataset)
    }
}
