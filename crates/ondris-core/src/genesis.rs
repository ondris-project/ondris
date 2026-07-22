use ondris_primitives::Address;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PremineEntry {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub network_name: String,
    pub timestamp: u64,
    pub initial_difficulty: u64,
    /// Initial block reward, in smallest units (1 ONDR = 100,000,000 units, like satoshis).
    pub initial_reward: u64,
    pub halving_interval: u64,
    pub target_block_time_secs: u64,
    pub retarget_window: u64,
    pub premine: Vec<PremineEntry>,
}

impl GenesisConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let cfg: GenesisConfig = serde_json::from_str(&data)?;
        Ok(cfg)
    }

    /// Quick test config, not intended for a real network.
    pub fn testnet_default() -> Self {
        GenesisConfig {
            network_name: "ondris-testnet".to_string(),
            timestamp: 1_753_142_400, // 2026-07-22 00:00:00 UTC (project design date)
            initial_difficulty: 1000,
            initial_reward: 50 * 100_000_000,
            halving_interval: 210_000,
            target_block_time_secs: 30,
            retarget_window: 60,
            premine: vec![],
        }
    }

    pub fn premine_parsed(&self) -> anyhow::Result<Vec<(Address, u64)>> {
        self.premine
            .iter()
            .map(|e| Ok((e.address.parse::<Address>()?, e.amount)))
            .collect()
    }
}
