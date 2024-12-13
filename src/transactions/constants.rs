use crate::network::NetworkKind;

pub const MEMO_MAX_LENGTH_BYTES: usize = 34;

pub enum TransactionVersion {
    Mainnet,
    Testnet,
}

impl TransactionVersion {
    fn value(&self) -> u32 {
        match *self {
            TransactionVersion::Mainnet => 0x00,
            TransactionVersion::Testnet => 0x80,
        }
    }

    pub fn from_network(network: &NetworkKind) -> Self {
        return match network {
            NetworkKind::Mainnet => Self::Mainnet,
            NetworkKind::Testnet => Self::Testnet,
            NetworkKind::Mocknet => Self::Testnet,
        };
    }
}

pub enum PayloadType {
    TokenTransfer,
}

impl PayloadType {
    pub fn value(&self) -> u8 {
        return match *self {
            PayloadType::TokenTransfer => 0x00,
        };
    }
}

pub enum PostConditionMode {
    Allow,
    Deny,
}

impl PostConditionMode {
    fn value(&self) -> u8 {
        match *self {
            PostConditionMode::Allow => 0x01,
            PostConditionMode::Deny => 0x02,
        }
    }
}

pub enum AnchorMode {
    OnChainOnly,  //  The transaction MUST be included in an anchored block
    OffChainOnly, // The transaction MUST be included in a microblock
    Any,          // The leader can choose where to include the transaction.
}

impl AnchorMode {
    fn value(&self) -> u8 {
        match *self {
            AnchorMode::OnChainOnly => 0x01,
            AnchorMode::OffChainOnly => 0x02,
            AnchorMode::Any => 0x03,
        }
    }
}

pub enum PubKeyEncoding {
    Compressed,
    Uncompressed,
}

impl PubKeyEncoding {
    fn value(&self) -> u8 {
        match *self {
            PubKeyEncoding::Compressed => 0x00,
            PubKeyEncoding::Uncompressed => 0x01,
        }
    }
}
