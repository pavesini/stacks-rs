use crate::network::NetworkKind;
use crate::transactions::clarity::ClarityType;
use crate::transactions::constants::*;
use stacks_common::address::c32::c32_address;
use stacks_common::address::c32::c32_address_decode;
use stacks_common::address::AddressHashMode;
use stacks_common::address::Error;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use std::fmt;

#[derive(Debug)]
pub enum PayloadSerializationError {
    MemoTooLong(usize),
    InvalidAddress(Error),
}

impl fmt::Display for PayloadSerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match *self {
            PayloadSerializationError::MemoTooLong(v) => f.write_str(&format!(
                "Memo too long! Got {}, max is {}",
                v, MEMO_MAX_LENGTH_BYTES
            )),
            PayloadSerializationError::InvalidAddress(_) => {
                f.write_str(&format!("Invalid address!"))
            }
        }
    }
}

impl std::error::Error for PayloadSerializationError {}

pub trait Serialize {
    fn serialize(&self) -> Result<Vec<u8>, PayloadSerializationError>;
    fn deserialize(serialized: Vec<u8>) -> Self;
}

pub struct TokenTransferPayload {
    recipient: String,
    amount: u64,
    memo: String,
}

impl Serialize for TokenTransferPayload {
    fn serialize(&self) -> Result<Vec<u8>, PayloadSerializationError> {
        let memo_bytes = self.memo.as_bytes();
        if memo_bytes.len() > MEMO_MAX_LENGTH_BYTES {
            return Err(PayloadSerializationError::MemoTooLong(memo_bytes.len()));
        }

        let mut serialization: Vec<u8> = vec![];
        serialization.extend(vec![PayloadType::TokenTransfer.value()]);
        match c32_address_decode(&self.recipient) {
            Ok(v) => {
                let (version, data) = v;
                let mut hash_bytes = [0u8; 20];
                hash_bytes.copy_from_slice(&data[..]);
                let addr = StacksAddress::new(version, Hash160(hash_bytes));
                serialization.extend(vec![ClarityType::Address.value()]);
                serialization.extend(addr.version.to_be_bytes());
                serialization.extend(addr.bytes.as_bytes().to_vec());
            }
            Err(e) => return Err(PayloadSerializationError::InvalidAddress(e)),
        }

        serialization.extend(self.amount.to_be_bytes());

        let padding = vec![0; MEMO_MAX_LENGTH_BYTES - memo_bytes.len()];
        serialization.extend(memo_bytes);
        serialization.extend(padding);

        Ok(serialization)
    }

    fn deserialize(serialized: Vec<u8>) -> TokenTransferPayload {
        let addr_version = serialized[2];
        assert!(serialized.len() >= 23, "Slice has fewer than 23 elements!");
        let addr = c32_address(addr_version, &serialized[3..23]).unwrap();

        let mut amount_bytes: [u8; 8] = [0; 8];
        amount_bytes.copy_from_slice(&serialized[23..31]);
        let amount = u64::from_be_bytes(amount_bytes);

        assert!(serialized.len() >= 31 + MEMO_MAX_LENGTH_BYTES);
        let mut memo_bytes: [u8; MEMO_MAX_LENGTH_BYTES] = [0; MEMO_MAX_LENGTH_BYTES];
        memo_bytes.copy_from_slice(&serialized[31..31 + MEMO_MAX_LENGTH_BYTES]);
        let memo = String::from_utf8(memo_bytes.to_vec()).expect("Invalid UTF-8");

        TokenTransferPayload {
            recipient: addr,
            amount: amount,
            memo: String::from(memo.trim_matches(char::from(0))),
        }
    }
}

enum Payload {
    TokenTransfer(TokenTransferPayload),
}

pub struct StacksTransaction {
    version: TransactionVersion,
    network: NetworkKind,
    payload: Payload,
    post_condition_mode: PostConditionMode,
    // post_conditions:
    anchor_mode: AnchorMode,
}

pub fn build_token_transfer_transaction(
    recipient: String,
    amount: u64,
    sender_key: Secp256k1PrivateKey, // private key
    network: NetworkKind,
    memo: String,
    nonce: Option<u64>,
    fee: Option<u64>,
) -> StacksTransaction {
    let public_key = Secp256k1PublicKey::from_private(&sender_key);
    let addr =
        StacksAddress::from_public_keys(1, &AddressHashMode::SerializeP2WPKH, 1, &vec![public_key])
            .expect("Invalid params for generating address");

    StacksTransaction {
        payload: Payload::TokenTransfer(TokenTransferPayload {
            amount: amount,
            memo: memo,
            recipient: recipient,
        }),
        network: network.clone(),
        post_condition_mode: PostConditionMode::Deny,
        version: TransactionVersion::from_network(&network),
        anchor_mode: AnchorMode::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_token_transfer_serialize() {
        let payload = TokenTransferPayload {
            recipient: String::from("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159"),
            amount: 12345,
            memo: String::from("test memo"),
        };

        let serialized = payload.serialize().unwrap();

        let hex: String = serialized
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        assert_eq!(hex, String::from("000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303974657374206d656d6f00000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn payload_token_transfer_serialize_empty_memo() {
        let payload = TokenTransferPayload {
            recipient: String::from("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159"),
            amount: 12345,
            memo: String::from(""),
        };

        let serialized = payload.serialize().unwrap();

        let hex: String = serialized
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        assert_eq!(hex, String::from("000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303900000000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn payload_token_transfer_serialize_memo_too_long() {
        let payload = TokenTransferPayload {
            recipient: String::from("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159"),
            amount: 12345,
            memo: String::from("Itami o kanjiro, Itami o kangaero, Itami o uketore, Itami o shire Koko yori, sekai ni itami o... SHINRA TENSEI"),
        };

        let serialized = payload.serialize();
        assert!(matches!(
            serialized,
            Err(PayloadSerializationError::MemoTooLong(110))
        ))
    }

    #[test]
    fn payload_token_transfer_serialize_invalid_address() {
        let payload = TokenTransferPayload {
            recipient: String::from("invalid"),
            amount: 12345,
            memo: String::from(""),
        };

        let serialized = payload.serialize();
        assert!(matches!(
            serialized,
            Err(PayloadSerializationError::InvalidAddress(_))
        ))
    }

    #[test]
    fn payload_token_transfer_deserialize() {
        let serialized_hex = String::from("000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303974657374206d656d6f00000000000000000000000000000000000000000000000000");
        let serialized = hex::decode(serialized_hex).expect("Error while decoding hex");
        let payload = TokenTransferPayload::deserialize(serialized);
        assert_eq!(payload.amount, 12345);
        assert_eq!(
            payload.recipient,
            String::from("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159")
        );
        assert_eq!(payload.memo, String::from("test memo"));
    }

    #[test]
    fn payload_token_transfer_deserialize_empty_memo() {
        let serialized_hex = String::from("000516df0ba3e79792be7be5e50a370289accfc8c9e032000000000000303900000000000000000000000000000000000000000000000000000000000000000000");
        let serialized = hex::decode(serialized_hex).expect("Error while decoding hex");
        let payload = TokenTransferPayload::deserialize(serialized);
        assert_eq!(payload.amount, 12345);
        assert_eq!(
            payload.recipient,
            String::from("SP3FGQ8Z7JY9BWYZ5WM53E0M9NK7WHJF0691NZ159")
        );
        assert_eq!(payload.memo, String::from(""));
    }
}
