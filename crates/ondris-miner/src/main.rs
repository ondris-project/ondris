//! Reference CPU miner for Ondris. Used to validate consensus rules and
//! test the network; this is NOT an optimized GPU miner. An OpenCL/CUDA
//! kernel reusing the same logic (shared dataset, parallel memory access)
//! is the next piece of work documented in docs/ALGORITHM.md.

use clap::Parser;
use ondris_core::{Block, WorkTemplate};
use ondris_pow::Dataset;
use ondris_primitives::Address;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "ondris-miner",
    version,
    about = "Reference CPU miner for Ondris (testnet)"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node: String,

    /// Address (ondr...) that will receive the block reward.
    #[arg(long)]
    address: String,

    /// Number of mining threads (defaults to all available cores).
    #[arg(long)]
    threads: Option<usize>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Validate the address format right away to fail fast if it's wrong.
    let _validated: Address = args.address.parse()?;

    let threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let client = reqwest::blocking::Client::new();

    tracing::info!(
        "Ondris miner started: {threads} thread(s), node={}",
        args.node
    );

    let mut cached_dataset: Option<(u64, Arc<Dataset>)> = None;

    loop {
        let work: WorkTemplate = match client
            .get(format!("{}/work?miner={}", args.node, args.address))
            .send()
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => resp.json()?,
            Err(e) => {
                tracing::warn!("could not fetch work from the node ({e}), retrying in 5s");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let dataset = match &cached_dataset {
            Some((epoch, ds)) if *epoch == work.epoch => ds.clone(),
            _ => {
                tracing::info!(
                    "generating local dataset for epoch {} ({} MiB)...",
                    work.epoch,
                    ondris_pow::DATASET_SIZE / (1024 * 1024)
                );
                let seed = ondris_pow::epoch_seed(work.epoch_boundary_hash);
                let ds = Arc::new(Dataset::generate(work.epoch, seed));
                cached_dataset = Some((work.epoch, ds.clone()));
                ds
            }
        };

        tracing::info!(
            "mining block {} (difficulty {})",
            work.block.header.height,
            work.block.header.difficulty
        );

        let mined = mine_block(work.block.clone(), work.target, dataset, threads);

        match client
            .post(format!("{}/block/submit", args.node))
            .json(&mined)
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("block {} submitted successfully!", mined.header.height);
            }
            Ok(resp) => {
                let body = resp.text().unwrap_or_default();
                tracing::warn!("block rejected by the node: {body}");
            }
            Err(e) => tracing::warn!("failed to send block to the node: {e}"),
        }
    }
}

/// Searches for a nonce satisfying `target` by splitting the nonce space
/// across `threads` threads (thread i tries i, i+threads, i+2*threads, ...).
fn mine_block(mut block: Block, target: [u8; 32], dataset: Arc<Dataset>, threads: usize) -> Block {
    let header_bytes = block.header.bytes_for_pow();
    let found = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let result: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let start = Instant::now();

    std::thread::scope(|scope| {
        for t in 0..threads.max(1) {
            let found = found.clone();
            let counter = counter.clone();
            let result = result.clone();
            let dataset = dataset.clone();
            let header_bytes = header_bytes.clone();
            scope.spawn(move || {
                let mut nonce: u64 = t as u64;
                while !found.load(Ordering::Relaxed) {
                    let hash = ondris_pow::ondris_hash(&header_bytes, nonce, &dataset);
                    counter.fetch_add(1, Ordering::Relaxed);
                    if ondris_pow::meets_target(&hash, &target) {
                        *result.lock().unwrap() = Some(nonce);
                        found.store(true, Ordering::Relaxed);
                        break;
                    }
                    nonce = nonce.wrapping_add(threads.max(1) as u64);
                }
            });
        }

        while !found.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));
            if found.load(Ordering::Relaxed) {
                break;
            }
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed >= 4.5 {
                let hps = counter.load(Ordering::Relaxed) as f64 / elapsed;
                tracing::info!("hashrate: {:.1} H/s", hps);
            }
        }
    });

    let nonce = result
        .lock()
        .unwrap()
        .take()
        .expect("a thread must have found a nonce");
    block.header.nonce = nonce;
    block
}
