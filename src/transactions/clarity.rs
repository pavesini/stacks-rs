pub enum ClarityType {
    Address,
}

impl ClarityType {
    pub fn value(&self) -> u8 {
        match *self {
            ClarityType::Address => 0x5,
        }
    }
}
