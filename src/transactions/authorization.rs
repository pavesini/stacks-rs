use crate::transactions::constants::PubKeyEncoding;
use stacks_common::address::AddressHashMode;
use stacks_common::util::uint::Uint256;

pub enum SingleSigHashMode {
    P2PKH,
    P2WPKH,
}

impl SingleSigHashMode {
    fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            SingleSigHashMode::P2PKH => AddressHashMode::SerializeP2PKH,
            SingleSigHashMode::P2WPKH => AddressHashMode::SerializeP2WPKH,
        }
    }
}

pub struct SingleSigSpendingCondition {
    hash_mode: SingleSigHashMode,
    signer: String,
    nonce: Uint256,
    fee: Uint256,
    pubkey_encoding: PubKeyEncoding,
    signature: Vec<u8>,
}
