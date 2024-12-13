#[derive(PartialEq, Eq, Clone)]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Mocknet,
}

impl NetworkKind {
    fn chain_id(&self) -> u32 {
        match *self {
            NetworkKind::Mainnet => 0x00000001,
            NetworkKind::Testnet => 0x80000000,
            NetworkKind::Mocknet => 0x80000000,
        }
    }

    fn version_number(&self) -> u8 {
        match *self {
            NetworkKind::Mainnet => 0b00000000,
            NetworkKind::Testnet => 0b10000000,
            NetworkKind::Mocknet => 0b10000000,
        }
    }
}

#[derive(Clone)]
pub struct Network {
    pub kind: NetworkKind,
    pub url: String,
}

impl Network {
    fn is_mainnet(&self) -> bool {
        return self.kind == NetworkKind::Mainnet;
    }
}

pub enum AddressVersion {
    MainnetSingleSig,
    MainnetMultiSig,
    TestnetSingleSig,
    TestnetMultiSig,
}

impl AddressVersion {
    fn value(&self) -> u8 {
        match *self {
            AddressVersion::MainnetSingleSig => 22, // `P` — A single-sig address for mainnet (starting with `SP`)
            AddressVersion::MainnetMultiSig => 20, // `M` — A multi-sig address for mainnet (starting with `SM`)
            AddressVersion::TestnetSingleSig => 26, // `T` — A single-sig address for testnet (starting with `ST`)
            AddressVersion::TestnetMultiSig => 21, // `N` — A multi-sig address for testnet (starting with `SN`)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_mainnet() {
        let mainnet = Network {
            kind: NetworkKind::Mainnet,
            url: String::from("https://www.mystacksnode.com/"),
        };
        assert_eq!(mainnet.is_mainnet(), true);
        assert_eq!(mainnet.url, String::from("https://www.mystacksnode.com/"));

        let testnet = Network {
            kind: NetworkKind::Testnet,
            url: String::from("https://www.mystacksnode.com/"),
        };
        assert_eq!(testnet.is_mainnet(), false);
        assert_eq!(testnet.url, String::from("https://www.mystacksnode.com/"));

        let mocknet = Network {
            kind: NetworkKind::Mocknet,
            url: String::from("https://www.mystacksnode.com/"),
        };
        assert_eq!(mocknet.is_mainnet(), false);
        assert_eq!(mocknet.url, String::from("https://www.mystacksnode.com/"));
    }
}
