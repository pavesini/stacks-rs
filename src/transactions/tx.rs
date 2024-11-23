use crate::network::Network;
use crate::transactions::constants::*;

pub struct TokenTransferPayload {
    recipient: String,
    amount: u64,
    memo: Option<String>,
}

enum Payload {
    TokenTransfer(TokenTransferPayload),
}

pub trait TransactionSerialization {
    fn serialize(&self) -> Vec<u8>;
}

pub struct StacksTransaction {
    version: TransactionVersion,
    network: Network,
    payload: Payload,
    post_condition_mode: PostConditionMode,
    // post_conditions:
}

impl TransactionSerialization for StacksTransaction {
    fn serialize(&self) -> Vec<u8> { vec![] }
}

pub fn build_token_transfer_transaction(
    recipient: String,
    amount: u64,
    sender_key: String,
    network: Network,
    memo: Option<String>,
    nonce: Option<u64>,
    fee: Option<u64>,
) -> StacksTransaction {
    StacksTransaction {
        payload: Payload::TokenTransfer(TokenTransferPayload {
            amount: amount,
            memo: memo,
            recipient: recipient,
        }),
        network: network.clone(),
        post_condition_mode: PostConditionMode::Deny,
        version: TransactionVersion::from_network(&network.kind),
    }
}
