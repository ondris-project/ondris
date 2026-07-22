# Architecture

## Overview

```
┌─────────────┐      HTTP JSON       ┌──────────────┐
│ ondris-wallet│ ───────────────────▶│              │
└─────────────┘                      │              │
                                      │  ondris-node │◀──── TCP gossip ────▶ other nodes
┌─────────────┐      HTTP JSON       │  (chain +    │
│ ondris-miner │ ───────────────────▶│   network +  │
└─────────────┘                      │   RPC)       │
                                      └──────┬───────┘
                                             │ sled (embedded)
                                             ▼
                                        local disk
```

Crates:

- **ondris-primitives** — `Hash256`, `Address`, `KeyPair`/`PublicKey`/`Signature` (Ed25519). No dependency on the rest of the project.
- **ondris-pow** — the OndrisHash algorithm. Depends only on `ondris-primitives`.
- **ondris-core** — `BlockHeader`, `Transaction`, `Block`, `ChainState` (sled persistence), `Chain` (validation + application), difficulty, genesis, shared RPC DTOs.
- **ondris-network** — TCP P2P gossip, only aware of `ondris-core` types for messages.
- **ondris-node** — binary: wires up chain + network + HTTP server (axum).
- **ondris-miner** — binary: RPC client that fetches work, mines locally (CPU, multi-threaded), submits the found block.
- **ondris-wallet** — binary: encrypted keystore + RPC client for balance/sending transactions.

## Why an account model instead of a UTXO model

Simpler to reason about and to implement correctly in the time available
(a balance + a nonce per address, like Ethereum), at the cost of
transaction validation being slightly less naturally parallelizable than a
UTXO model. For a testnet, this trade-off is the right one.

## Why difficulty isn't stored as Bitcoin-style "compact bits"

Bitcoin's nBits format (32-bit exponent + mantissa) has tricky edge cases
(sign bit, rounding) that are a classic source of bugs when re-implemented
by hand. Ondris stores difficulty as a plain `u64` integer and computes the
target via `MAX_TARGET / difficulty` (256-bit division by a u64,
implemented directly). This is strictly equivalent in expressiveness for
our needs, with an implementation that's simpler to audit.

## How the miner regenerates the dataset without downloading it

The PoW dataset (tens of MB) is never transferred over the network.
`GET /work` returns the hash of the epoch boundary block
(`epoch_boundary_hash`); the miner locally computes the epoch seed
(`ondris_pow::epoch_seed`) and regenerates the dataset itself — exactly
like an Ethash miner regenerates its DAG from a lightweight seed. Every
node does the same to verify a received block.

## Known limitations (future work, not done yet)

- **No fork/reorg handling**: `Chain::submit_block` only accepts a linear
  extension of the current tip. If two miners find a block at the same
  time, one of them will simply be rejected by the rest of the network
  instead of triggering a real reorganization toward the heavier chain.
  Needed before any testnet with multiple active miners at once.
- **Minimal mempool**: `GET /work` drains the mempool on every call; if the
  resulting block is never submitted (miner crashes, restarts...), the
  transactions it contained are lost and must be resent by the wallet. No
  automatic re-queuing.
- **Unencrypted, unauthenticated P2P transport**: fine for a closed
  testnet, not for a public network with real value at stake.
- **No peer discovery (DHT)**: static seed node list provided in config.
- **"Full" PoW verification only**: every node keeps the full dataset for
  the current epoch in RAM. A "light client" mode (on-the-fly regeneration
  of only the needed indices from the cache) is not implemented.
- **"Useful compute" layer** discussed during design: not implemented,
  research-grade.
- **No independent cryptographic audit.**
