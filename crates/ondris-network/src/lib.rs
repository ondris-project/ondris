//! Minimal P2P network for Ondris: block/transaction gossip over TCP,
//! wrapped in a Noise_XX-encrypted, mutually-authenticated transport (see
//! `noise.rs`) with length-prefixed JSON messages on top, plus a
//! `GetBlock`/`BlockResponse` pair the node uses to fetch a missing parent
//! when a block arrives out of order. No automatic peer discovery (DHT)
//! in this version: the peer list (seed nodes) is supplied via config at
//! node startup — still documented as future work in
//! `docs/ARCHITECTURE.md`.

pub mod noise;

pub use noise::{peer_id_hex, NodeIdentity};

use ondris_core::{Block, Transaction};
use ondris_primitives::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Handshake {
        version: u32,
        network: String,
        height: u64,
    },
    NewBlock(Block),
    NewTransaction(Transaction),
    /// Asks a peer for a block by hash — used to resolve orphans (a block
    /// received before its parent).
    GetBlock(Hash256),
    BlockResponse(Option<Block>),
    Ping,
    Pong,
}

#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    NewBlock(Block),
    NewTransaction(Transaction),
    /// A peer asked us for a block; `SocketAddr` is who to answer.
    GetBlockRequest(SocketAddr, Hash256),
    BlockResponse(Option<Block>),
}

type PeerMap = Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Message>>>>;

#[derive(Clone)]
pub struct Network {
    peers: PeerMap,
    events_tx: mpsc::UnboundedSender<NetworkEvent>,
    network_name: String,
    my_height: Arc<AtomicU64>,
    identity: Arc<NodeIdentity>,
}

impl Network {
    pub fn new(
        network_name: String,
        events_tx: mpsc::UnboundedSender<NetworkEvent>,
        identity: NodeIdentity,
    ) -> Self {
        Network {
            peers: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
            network_name,
            my_height: Arc::new(AtomicU64::new(0)),
            identity: Arc::new(identity),
        }
    }

    pub fn set_height(&self, height: u64) {
        self.my_height.store(height, Ordering::Relaxed);
    }

    /// Starts listening for inbound connections on `addr` (background
    /// task, does not block).
    pub async fn listen(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("P2P network listening on {addr}");
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let this2 = this.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this2.handle_connection(stream, peer_addr, false).await
                            {
                                tracing::warn!("inbound connection {peer_addr} closed: {e}");
                            }
                        });
                    }
                    Err(e) => tracing::warn!("accept() error: {e}"),
                }
            }
        });
        Ok(())
    }

    /// Opens an outbound connection to a peer (config seed node).
    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.handle_connection(stream, addr, true).await {
                tracing::warn!("outbound connection to {addr} closed: {e}");
            }
        });
        Ok(())
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        is_initiator: bool,
    ) -> anyhow::Result<()> {
        let (mut reader, mut writer) = stream.into_split();

        // Every byte from here on — including the application-level
        // Handshake message below — travels over the Noise-encrypted
        // channel; nothing is ever sent in the clear on this connection.
        let (transport_state, peer_id) = if is_initiator {
            noise::handshake_initiator(&mut reader, &mut writer, &self.identity).await?
        } else {
            noise::handshake_responder(&mut reader, &mut writer, &self.identity).await?
        };
        tracing::info!(
            "noise handshake with {peer_addr} complete (peer id {})",
            noise::peer_id_hex(&peer_id)
        );
        let transport = Arc::new(Mutex::new(transport_state));
        let mut enc_reader = noise::EncryptedReader::new(reader, transport.clone());
        let mut enc_writer = noise::EncryptedWriter::new(writer, transport);

        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        self.peers.lock().await.insert(peer_addr, tx);
        let _ = self.events_tx.send(NetworkEvent::PeerConnected(peer_addr));

        let handshake = Message::Handshake {
            version: PROTOCOL_VERSION,
            network: self.network_name.clone(),
            height: self.my_height.load(Ordering::Relaxed),
        };
        write_message(&mut enc_writer, &handshake).await?;

        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if write_message(&mut enc_writer, &msg).await.is_err() {
                    break;
                }
            }
        });

        let result: anyhow::Result<()> = async {
            loop {
                let msg = read_message(&mut enc_reader).await?;
                match msg {
                    Message::Handshake { network, .. } => {
                        anyhow::ensure!(
                            network == self.network_name,
                            "different network: {network}"
                        );
                    }
                    Message::NewBlock(block) => {
                        let _ = self.events_tx.send(NetworkEvent::NewBlock(block));
                    }
                    Message::NewTransaction(tx) => {
                        let _ = self.events_tx.send(NetworkEvent::NewTransaction(tx));
                    }
                    Message::GetBlock(hash) => {
                        let _ = self
                            .events_tx
                            .send(NetworkEvent::GetBlockRequest(peer_addr, hash));
                    }
                    Message::BlockResponse(block) => {
                        let _ = self.events_tx.send(NetworkEvent::BlockResponse(block));
                    }
                    Message::Ping => self.send_to(peer_addr, Message::Pong).await,
                    Message::Pong => {}
                }
            }
        }
        .await;

        self.peers.lock().await.remove(&peer_addr);
        let _ = self
            .events_tx
            .send(NetworkEvent::PeerDisconnected(peer_addr));
        write_task.abort();
        result
    }

    pub async fn send_to(&self, addr: SocketAddr, msg: Message) {
        let peers = self.peers.lock().await;
        if let Some(tx) = peers.get(&addr) {
            let _ = tx.send(msg);
        }
    }

    pub async fn broadcast(&self, msg: Message) {
        let peers = self.peers.lock().await;
        for tx in peers.values() {
            let _ = tx.send(msg.clone());
        }
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }
}

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut noise::EncryptedWriter<W>,
    msg: &Message,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len() as u32;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&bytes);
    writer.write_all(&framed).await
}

async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut noise::EncryptedReader<R>,
) -> anyhow::Result<Message> {
    let len_bytes = reader.read_exact(4).await?;
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    anyhow::ensure!(
        len <= 64 * 1024 * 1024,
        "received message too large ({len} bytes)"
    );
    let buf = reader.read_exact(len).await?;
    let msg: Message = serde_json::from_slice(&buf)?;
    Ok(msg)
}
