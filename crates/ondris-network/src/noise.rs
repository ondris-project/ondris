//! Encrypted, mutually-authenticated transport for the P2P layer, built on
//! the Noise Protocol Framework (via the `snow` crate) rather than a
//! bespoke construction — the same reasoning as using BLAKE3 elsewhere in
//! this project: don't invent cryptography, use an audited, standardized
//! building block. Noise itself has been reviewed extensively and is what
//! WireGuard and the Lightning Network build their transport security on.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` — the standard Noise
//! pattern for two parties with no prior knowledge of each other's static
//! key, which is exactly our situation (a node accepts inbound
//! connections from peers it has never seen before). This is the
//! off-the-shelf pattern name, not a custom variant — even though the
//! rest of this project standardizes on BLAKE3, swapping it into the
//! Noise pattern string would produce a non-standard construction with no
//! external analysis behind it, which defeats the point of reaching for
//! Noise in the first place.
//!
//! After a successful handshake, each side has:
//! - an encrypted, integrity-protected channel (ChaCha20-Poly1305), and
//! - cryptographic proof the peer holds the private key for the static
//!   public key it presented — a stable [`PeerId`] for this connection.
//!
//! What this does NOT add: peer discovery (still a static seed list —
//! see `docs/ARCHITECTURE.md`) or any reputation/allow-list system —
//! anyone can still open a connection and complete a valid handshake
//! with a freshly generated keypair of their own. What it removes is
//! passive eavesdropping and on-path tampering with an established
//! connection.

use snow::Builder;
pub use snow::TransportState;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Noise caps a single transport message at 65535 bytes of ciphertext
/// (including its 16-byte authentication tag); leave room for the tag.
const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

pub type PeerId = [u8; 32];

pub fn peer_id_hex(id: &PeerId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// This node's persistent Noise identity keypair (X25519) — separate from
/// the Ed25519 keys used for wallet/transaction signing. Different curve,
/// different purpose: a long-lived transport identity, not spending
/// authority.
pub struct NodeIdentity {
    private_key: Vec<u8>,
    pub public_key: PeerId,
}

impl NodeIdentity {
    /// Loads the identity from `path`, generating and persisting a fresh
    /// one if the file doesn't exist yet (or isn't the expected size —
    /// treated the same as missing, so a corrupt file doesn't crash
    /// startup, it just mints a new identity).
    pub fn load_or_generate(path: &Path) -> io::Result<Self> {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() == 64 {
                let private_key = bytes[..32].to_vec();
                let public_key: PeerId = bytes[32..64].try_into().unwrap();
                return Ok(NodeIdentity {
                    private_key,
                    public_key,
                });
            }
        }
        let params: snow::params::NoiseParams = NOISE_PARAMS
            .parse()
            .expect("hardcoded Noise pattern parses");
        let keypair = Builder::new(params)
            .generate_keypair()
            .expect("x25519 keypair generation");
        let mut file_bytes = Vec::with_capacity(64);
        file_bytes.extend_from_slice(&keypair.private);
        file_bytes.extend_from_slice(&keypair.public);
        std::fs::write(path, &file_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let public_key: PeerId = keypair
            .public
            .as_slice()
            .try_into()
            .expect("x25519 public key is 32 bytes");
        Ok(NodeIdentity {
            private_key: keypair.private,
            public_key,
        })
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> anyhow::Result<()> {
    let len = data.len() as u16;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

fn remote_static_peer_id(hs: &snow::HandshakeState) -> anyhow::Result<PeerId> {
    let key = hs
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("peer did not present a static key"))?;
    key.try_into()
        .map_err(|_| anyhow::anyhow!("unexpected static key length"))
}

/// Runs the Noise_XX handshake as the initiator (outbound connections:
/// `-> e`, `<- e, ee, s, es`, `-> s, se`). Returns the transport state
/// (ready to encrypt/decrypt application data) and the peer's verified
/// static public key.
pub async fn handshake_initiator<R, W>(
    reader: &mut R,
    writer: &mut W,
    identity: &NodeIdentity,
) -> anyhow::Result<(TransportState, PeerId)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
    let mut hs = Builder::new(params)
        .local_private_key(&identity.private_key)
        .build_initiator()?;
    let mut buf = vec![0u8; 65535];

    let len = hs.write_message(&[], &mut buf)?;
    write_frame(writer, &buf[..len]).await?;

    let frame = read_frame(reader).await?;
    let mut payload = vec![0u8; frame.len()];
    hs.read_message(&frame, &mut payload)?;

    let len = hs.write_message(&[], &mut buf)?;
    write_frame(writer, &buf[..len]).await?;

    let peer_id = remote_static_peer_id(&hs)?;
    Ok((hs.into_transport_mode()?, peer_id))
}

/// Runs the Noise_XX handshake as the responder (inbound connections).
pub async fn handshake_responder<R, W>(
    reader: &mut R,
    writer: &mut W,
    identity: &NodeIdentity,
) -> anyhow::Result<(TransportState, PeerId)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
    let mut hs = Builder::new(params)
        .local_private_key(&identity.private_key)
        .build_responder()?;
    let mut buf = vec![0u8; 65535];

    let frame = read_frame(reader).await?;
    let mut payload = vec![0u8; frame.len()];
    hs.read_message(&frame, &mut payload)?;

    let len = hs.write_message(&[], &mut buf)?;
    write_frame(writer, &buf[..len]).await?;

    let frame = read_frame(reader).await?;
    let mut payload = vec![0u8; frame.len()];
    hs.read_message(&frame, &mut payload)?;

    let peer_id = remote_static_peer_id(&hs)?;
    Ok((hs.into_transport_mode()?, peer_id))
}

/// Encrypting half of an established Noise session. `plaintext` is
/// chunked to Noise's per-message size limit, since application messages
/// can be much larger than 64KB; each chunk goes out as its own
/// length-prefixed ciphertext frame.
pub struct EncryptedWriter<W> {
    writer: W,
    transport: Arc<AsyncMutex<TransportState>>,
}

impl<W: AsyncWrite + Unpin> EncryptedWriter<W> {
    pub fn new(writer: W, transport: Arc<AsyncMutex<TransportState>>) -> Self {
        Self { writer, transport }
    }

    pub async fn write_all(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
        let mut ct_buf = vec![0u8; 65535];
        for chunk in plaintext.chunks(MAX_NOISE_PLAINTEXT) {
            let len = {
                let mut t = self.transport.lock().await;
                t.write_message(chunk, &mut ct_buf)?
            };
            write_frame(&mut self.writer, &ct_buf[..len]).await?;
        }
        Ok(())
    }
}

/// Decrypting half of an established Noise session. A single Noise frame
/// generally decrypts to more or fewer bytes than any one caller happens
/// to ask for in a given `read_exact` call (frame boundaries are a
/// property of how the *sender* chunked its write, not of the reader's
/// request sizes) — `leftover` carries any bytes decrypted-but-not-yet-
/// consumed across calls so frame and request boundaries don't have to
/// line up.
pub struct EncryptedReader<R> {
    reader: R,
    transport: Arc<AsyncMutex<TransportState>>,
    leftover: Vec<u8>,
}

impl<R: AsyncRead + Unpin> EncryptedReader<R> {
    pub fn new(reader: R, transport: Arc<AsyncMutex<TransportState>>) -> Self {
        Self {
            reader,
            transport,
            leftover: Vec::new(),
        }
    }

    pub async fn read_exact(&mut self, n: usize) -> anyhow::Result<Vec<u8>> {
        while self.leftover.len() < n {
            let ct = read_frame(&mut self.reader).await?;
            let mut pt_buf = vec![0u8; ct.len()];
            let len = {
                let mut t = self.transport.lock().await;
                t.read_message(&ct, &mut pt_buf)?
            };
            self.leftover.extend_from_slice(&pt_buf[..len]);
        }
        Ok(self.leftover.drain(..n).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::split;

    fn temp_identity_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ondris-noise-test-{name}-{}", std::process::id()))
    }

    #[tokio::test]
    async fn handshake_completes_and_peer_ids_cross_match() {
        let alice_id = NodeIdentity::load_or_generate(&temp_identity_path("alice-cross")).unwrap();
        let bob_id = NodeIdentity::load_or_generate(&temp_identity_path("bob-cross")).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut a_r, mut a_w) = split(a);
        let (mut b_r, mut b_w) = split(b);

        let alice_pub = alice_id.public_key;
        let bob_pub = bob_id.public_key;

        let (alice_result, bob_result) = tokio::join!(
            handshake_initiator(&mut a_r, &mut a_w, &alice_id),
            handshake_responder(&mut b_r, &mut b_w, &bob_id),
        );

        let (_alice_transport, alice_saw_peer) = alice_result.unwrap();
        let (_bob_transport, bob_saw_peer) = bob_result.unwrap();

        assert_eq!(
            alice_saw_peer, bob_pub,
            "initiator should see the responder's real key"
        );
        assert_eq!(
            bob_saw_peer, alice_pub,
            "responder should see the initiator's real key"
        );
    }

    #[tokio::test]
    async fn encrypted_round_trip_survives_chunking_of_a_large_message() {
        let alice_id = NodeIdentity::load_or_generate(&temp_identity_path("alice-rt")).unwrap();
        let bob_id = NodeIdentity::load_or_generate(&temp_identity_path("bob-rt")).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (mut a_r, mut a_w) = split(a);
        let (mut b_r, mut b_w) = split(b);

        let (alice_result, bob_result) = tokio::join!(
            handshake_initiator(&mut a_r, &mut a_w, &alice_id),
            handshake_responder(&mut b_r, &mut b_w, &bob_id),
        );
        let (alice_transport, _) = alice_result.unwrap();
        let (bob_transport, _) = bob_result.unwrap();
        let mut writer = EncryptedWriter::new(a_w, Arc::new(AsyncMutex::new(alice_transport)));
        let mut reader = EncryptedReader::new(b_r, Arc::new(AsyncMutex::new(bob_transport)));

        // Larger than one Noise frame (65519 bytes of plaintext), forcing
        // write_all/read_exact to split across multiple chunks.
        let payload: Vec<u8> = (0..200_003u32).map(|i| (i % 251) as u8).collect();

        let payload_clone = payload.clone();
        let expected_len = payload.len();
        let write_task = tokio::spawn(async move {
            writer.write_all(&payload_clone).await.unwrap();
        });
        let read_task = tokio::spawn(async move { reader.read_exact(expected_len).await.unwrap() });

        write_task.await.unwrap();
        let received = read_task.await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn read_exact_reassembles_two_small_messages_sent_as_one_frame() {
        // Regression test: a single Noise frame that decrypts to MORE
        // bytes than one read_exact call asked for must not be dropped —
        // the leftover has to survive into the next call. This is exactly
        // what broke in a live two-node smoke test before EncryptedReader
        // grew a leftover buffer: the very first application message (a
        // small Handshake) was written as one Noise frame, but read back
        // in two steps (4-byte length, then the payload), and the second
        // step used to see zero buffered bytes instead of the remainder.
        let alice_id = NodeIdentity::load_or_generate(&temp_identity_path("alice-two")).unwrap();
        let bob_id = NodeIdentity::load_or_generate(&temp_identity_path("bob-two")).unwrap();

        let (a, b) = tokio::io::duplex(1 << 16);
        let (mut a_r, mut a_w) = split(a);
        let (mut b_r, mut b_w) = split(b);

        let (alice_result, bob_result) = tokio::join!(
            handshake_initiator(&mut a_r, &mut a_w, &alice_id),
            handshake_responder(&mut b_r, &mut b_w, &bob_id),
        );
        let (alice_transport, _) = alice_result.unwrap();
        let (bob_transport, _) = bob_result.unwrap();
        let mut writer = EncryptedWriter::new(a_w, Arc::new(AsyncMutex::new(alice_transport)));
        let mut reader = EncryptedReader::new(b_r, Arc::new(AsyncMutex::new(bob_transport)));

        // One write_all call, like write_message's 4-byte-length-prefix +
        // JSON-payload framing, all encrypted as a single Noise frame.
        let mut framed = Vec::new();
        framed.extend_from_slice(&11u32.to_be_bytes());
        framed.extend_from_slice(b"hello world");

        let write_task = tokio::spawn(async move { writer.write_all(&framed).await.unwrap() });
        let read_task = tokio::spawn(async move {
            let len_bytes = reader.read_exact(4).await.unwrap();
            let len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
            let payload = reader.read_exact(len).await.unwrap();
            (len, payload)
        });

        write_task.await.unwrap();
        let (len, payload) = read_task.await.unwrap();
        assert_eq!(len, 11);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn tampered_ciphertext_is_rejected_not_silently_accepted() {
        let alice_id = NodeIdentity::load_or_generate(&temp_identity_path("alice-tamper")).unwrap();
        let bob_id = NodeIdentity::load_or_generate(&temp_identity_path("bob-tamper")).unwrap();

        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let mut alice_hs = Builder::new(params.clone())
            .local_private_key(&alice_id.private_key)
            .build_initiator()
            .unwrap();
        let mut bob_hs = Builder::new(params)
            .local_private_key(&bob_id.private_key)
            .build_responder()
            .unwrap();

        let mut buf1 = vec![0u8; 65535];
        let mut buf2 = vec![0u8; 65535];

        let len = alice_hs.write_message(&[], &mut buf1).unwrap();
        bob_hs.read_message(&buf1[..len], &mut buf2).unwrap();
        let len = bob_hs.write_message(&[], &mut buf1).unwrap();
        alice_hs.read_message(&buf1[..len], &mut buf2).unwrap();
        let len = alice_hs.write_message(&[], &mut buf1).unwrap();
        bob_hs.read_message(&buf1[..len], &mut buf2).unwrap();

        let mut alice_t = alice_hs.into_transport_mode().unwrap();
        let mut bob_t = bob_hs.into_transport_mode().unwrap();

        let mut ct = vec![0u8; 128];
        let len = alice_t
            .write_message(b"a real ondris message", &mut ct)
            .unwrap();
        ct[0] ^= 0xff; // flip a bit in the ciphertext, simulating tampering
        let mut pt = vec![0u8; 128];
        assert!(
            bob_t.read_message(&ct[..len], &mut pt).is_err(),
            "a tampered ciphertext must fail authentication, not decrypt to garbage silently"
        );
    }
}
