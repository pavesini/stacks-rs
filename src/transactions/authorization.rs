use stacks_common::address::AddressHashMode;
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::uint::Uint256;

#[derive(Debug, PartialEq, Eq)]
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
    pub hash_mode: SingleSigHashMode,
    pub nonce: Uint256,
    pub fee: Uint256,
    pub sender_pubkey: Secp256k1PublicKey,
    pub signature: Option<Vec<u8>>,
}

impl SingleSigSpendingCondition {
    pub fn new(
        hash_mode: SingleSigHashMode,
        nonce: Uint256,
        fee: Uint256,
        sender_pubkey: Secp256k1PublicKey,
        signature: Option<Vec<u8>>,
    ) -> SingleSigSpendingCondition {
        SingleSigSpendingCondition {
            hash_mode,
            nonce,
            fee,
            sender_pubkey,
            signature,
        }
    }
}

pub struct MultiSigSpendingCondition {}

pub enum SpendingCondition {
    SingleSig(SingleSigSpendingCondition),
    MultiSig(MultiSigSpendingCondition),
}

pub struct StandardAuthorization {
    pub spending_condition: SpendingCondition,
}

impl StandardAuthorization {
    pub fn new(spending_condition: SpendingCondition) -> StandardAuthorization {
        StandardAuthorization { spending_condition }
    }
}

pub struct SponsoredAuthorization {}

pub enum Authorization {
    Standard(StandardAuthorization),
    Sponsored(SponsoredAuthorization),
}
