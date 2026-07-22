use ondris_primitives::{Address, Hash256, KeyPair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub from: PublicKey,
    pub to: Address,
    pub amount: u64,
    pub fee: u64,
    /// Sender account's nonce, must be strictly increasing (replay
    /// protection); unrelated to the block's PoW nonce.
    pub account_nonce: u64,
    pub signature: Option<Signature>,
}

impl Transaction {
    pub fn new_unsigned(
        from: PublicKey,
        to: Address,
        amount: u64,
        fee: u64,
        account_nonce: u64,
    ) -> Self {
        Self {
            from,
            to,
            amount,
            fee,
            account_nonce,
            signature: None,
        }
    }

    /// Signed bytes: everything except the signature itself.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.from.0);
        buf.extend_from_slice(&self.to.0);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.fee.to_le_bytes());
        buf.extend_from_slice(&self.account_nonce.to_le_bytes());
        buf
    }

    pub fn sign(&mut self, keypair: &KeyPair) {
        assert_eq!(
            keypair.public().0,
            self.from.0,
            "key does not match the sender"
        );
        self.signature = Some(keypair.sign(&self.signing_bytes()));
    }

    pub fn is_signature_valid(&self) -> bool {
        match &self.signature {
            Some(sig) => self.from.verify(&self.signing_bytes(), sig),
            None => false,
        }
    }

    pub fn hash(&self) -> Hash256 {
        let bytes = serde_json::to_vec(self).expect("serializing a transaction cannot fail");
        Hash256::hash(&bytes)
    }
}
