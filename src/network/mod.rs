#[derive(PartialEq, Eq)]
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
}

pub struct Network {
    pub kind: NetworkKind,
    pub url: String,
}

impl Network {
    fn is_mainnet(&self) -> bool {
        return self.kind == NetworkKind::Mainnet;
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
