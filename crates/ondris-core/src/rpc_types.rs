//! DTOs shared between the node (RPC server), the wallet and the miner
//! (RPC clients). Live in `ondris-core` so a single definition serves
//! everyone, instead of duplicating incompatible structs across binaries.

use crate::block::Block;
use crate::state::Account;
use ondris_primitives::{Address, Hash256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainInfo {
    pub network: String,
    pub height: u64,
    pub tip_hash: Hash256,
    pub next_difficulty: u64,
    pub peer_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
}

impl AccountInfo {
    pub fn new(address: Address, account: Account) -> Self {
        AccountInfo {
            address,
            balance: account.balance,
            nonce: account.nonce,
        }
    }
}

/// Work template returned by `GET /work`: a block ready to be mined
/// (nonce = 0, transactions already included) plus everything the miner
/// needs to regenerate the relevant epoch's dataset locally without
/// having to download it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkTemplate {
    pub block: Block,
    pub target: [u8; 32],
    pub epoch: u64,
    /// Hash of the epoch boundary block, `None` only for epoch 0.
    pub epoch_boundary_hash: Option<Hash256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitBlockResponse {
    pub block_hash: Hash256,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub tx_hash: Hash256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
