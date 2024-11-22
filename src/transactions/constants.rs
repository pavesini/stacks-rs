use crate::network::NetworkKind;

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

    pub fn from_network(network: NetworkKind) -> Self {
        return match network {
            NetworkKind::Mainnet => Self::Mainnet,
            NetworkKind::Testnet => Self::Testnet,
            NetworkKind::Mocknet => Self::Testnet,
        };
    }
}

pub enum TransactionKind {
    TokenTransfer,
    ContractDeploy,
    ContractCall,
}

pub enum PostConditionMode {
    Allow,
    Deny,
}

impl PostConditionMode {
    fn value(&self) -> u32 {
        match *self {
            PostConditionMode::Allow => 0x01,
            PostConditionMode::Deny => 0x02,
        }
    }
}
