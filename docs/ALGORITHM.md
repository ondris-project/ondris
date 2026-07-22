# OndrisHash — Proof-of-Work Algorithm

## Status

**Unaudited.** This spec and its reference implementation have not yet been
reviewed by independent cryptographers. Do not trust it with real value
before an external audit. OndrisHash does not reinvent any cryptographic
primitive: it combines BLAKE3 (an audited, standardized hash function) and
a deterministic pseudo-random generator in an original "memory-hard +
data-dependent memory access" architecture, inspired by the Ethash family
(per-epoch dataset) and CryptoNight/RandomX (scratchpad mixing). What's new
here is the **architecture and parameterization**, not the underlying
cryptographic building blocks.

## Design goals

1. **GPU-friendly**: massively parallel, uniform memory access, which maps
   directly onto a GPU's strength (high memory bandwidth, thousands of
   threads).
2. **ASIC-resistant**: every hash requires random access into a dataset of
   several hundred MB to a few GB. A dedicated ASIC would need to embed the
   same amount of fast RAM as a GPU, which cancels out its cost/power
   advantage.
3. **Moderately CPU-resistant**: a CPU can technically compute the
   algorithm (needed for node-side verification), but its throughput is far
   below a GPU's due to lower memory bandwidth and a limited thread count.

## Parameters

| Constant | Testnet value | Description |
|---|---|---|
| `EPOCH_LENGTH` | 2048 blocks | How often the dataset is regenerated |
| `CACHE_SIZE` | 16 MiB | Compact seed derived from the epoch seed |
| `DATASET_SIZE` | 64 MiB (testnet/dev) / 2-4 GiB (mainnet target) | Full dataset used for mixing |
| `SCRATCHPAD_SIZE` | 2 MiB | Working memory per hash attempt |
| `MIX_ROUNDS` | 8 | Number of data-dependent mixing rounds |

Testnet sizes are intentionally reduced so development and tests run fast
on modest hardware (including CPU-only). Mainnet values will be revisited
with the auditor before any real launch.

## Step 1 — Epoch seed

```
epoch(height) = height / EPOCH_LENGTH
epoch_seed(0) = BLAKE3("ONDRIS_GENESIS_EPOCH")
epoch_seed(e) = BLAKE3(hash_of_block_at(e * EPOCH_LENGTH))   for e > 0
```

The epoch seed depends on the actual content of the chain (the hash of a
mined block), which prevents precomputing future datasets ahead of time.

## Step 2 — Cache and dataset

```
cache = BLAKE3_XOF(epoch_seed, output_len = CACHE_SIZE)

dataset[i] for i in [0, DATASET_SIZE / 64):
    item = cache[(i * 64) % CACHE_SIZE .. +64]
    repeat 2 times:
        item = BLAKE3(item || i.to_le_bytes())
    dataset[i*64 .. +64] = item
```

The cache is small and fast to generate (or verify in "light client" mode).
The full dataset is what miners generate once per epoch and keep in memory
(VRAM) to mine the whole epoch.

## Step 3 — Hashing one attempt (header + nonce)

```
input   = header_bytes || nonce.to_le_bytes()
seed    = BLAKE3(input)                       // 32 bytes
prng    = Xoshiro256** seeded with `seed`
scratchpad = [0u8; SCRATCHPAD_SIZE]

// Init: fill the scratchpad with pseudo-randomly chosen slices of the
// dataset (this is where "memory width" is required)
for each 64-byte block of the scratchpad:
    idx = prng.next_u64() % (DATASET_SIZE / 64)
    scratchpad[block] = dataset[idx*64 .. +64] XOR extended_seed(block)

// Mixing: MIX_ROUNDS rounds of mixing, dependent on data already written
for round in 0..MIX_ROUNDS:
    for each 64-byte block of the scratchpad at position p:
        dep_idx = prng.next_u64() % (SCRATCHPAD_SIZE / 64)   // depends on current state
        scratchpad[p] = BLAKE3(scratchpad[p] || scratchpad[dep_idx])[..64]

final_hash = BLAKE3(scratchpad)   // 32 bytes
```

The mixing step reads and writes the scratchpad in a way that **depends on
data already computed** (like CryptoNight/RandomX): it's impossible to
parallelize all rounds ahead of time, which limits the advantage of a fixed
circuit without enough memory to hold the intermediate state.

## Step 4 — Validation

```
valid(final_hash, target) ⟺ interpret(final_hash) as big-endian <= target
```

`target` is derived from the current difficulty, exactly like Bitcoin's
`nBits` (32-bit compact format: exponent + mantissa).

## Node-side verification (no mining required)

A node that receives a block must be able to verify the PoW without having
mined it. Two options, to be settled before the final implementation:

- **"Full" verification**: the node also keeps the full dataset for the
  current epoch (like an Ethash full node) — expensive in RAM but simple.
- **"Light" verification**: regenerate on the fly, for the few indices
  actually accessed during the computation, the dataset values needed from
  the `cache` alone (like an Ethash light client) — slower per hash but
  negligible RAM.

For the first implementation (testnet), we choose **full** verification to
keep things simple; "light" mode is documented as future work.

## What is NOT done yet (future work, not to be presented as delivered)

- **GPU kernel (OpenCL/CUDA)**: this spec defines the consensus rules via a
  CPU reference implementation. A performant GPU miner is separate work
  that will port this same logic to GPU.
- **"Useful compute" layer** discussed during design (redirecting part of
  the mining work toward reusable computation): research-grade, requires a
  cheap verification mechanism for the "useful" work so it doesn't open a
  vulnerability (a node must never have to redo the entire useful
  computation to verify a block). Not implemented in this first version —
  the interface is planned but empty.
- **Independent cryptographic audit** — a prerequisite for any launch with
  real value at stake.
