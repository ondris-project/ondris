# Contributing to Ondris

Actively developed testnet project — the architecture may still change.

## Before proposing a change

- `cargo build --workspace` and `cargo test --workspace` must pass.
- `cargo fmt --all` and `cargo clippy --workspace -- -D warnings` are
  expected to be clean.
- Any change to `ondris-pow` (the algorithm itself) must be discussed in an
  issue before the PR: it's the most sensitive part of the project and will
  require an audit before any real launch.

## Areas that especially need help

See the list of known limitations in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — fork handling, GPU miner,
"light client" verification mode, peer discovery.
