use std::str::FromStr;
use bip39::{Language, Mnemonic};
use crate::crypto::utils;

const ENTROPY_128_BITS: usize = 16; 
const ENTROPY_256_BITS: usize = 32; 

pub enum AllowedKeyEntropyBits {
    Entropy256Bits,
    Entropy128Bits,
}

impl AllowedKeyEntropyBits {
    fn byte_len(&self) -> usize {
        match *self {
            AllowedKeyEntropyBits::Entropy128Bits => ENTROPY_128_BITS,
            AllowedKeyEntropyBits::Entropy256Bits => ENTROPY_256_BITS
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip39Mnemonic {
    mnemonic: Mnemonic
}

pub trait Bip39MnemonicMethods {
    fn new(entropy_bits: Option<AllowedKeyEntropyBits>) -> Result<Bip39Mnemonic, bip39::Error>;
    fn word_count(&self) -> usize;
    fn language(&self) -> Language;
    fn mnemonic_from_words(words: &str) -> Result<Bip39Mnemonic, bip39::Error>;
    fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Bip39Mnemonic, bip39::Error>;
    fn to_entropy(&self) -> Vec<u8>;
    fn get_seed(&self, password: &str) -> [u8; 64];
}

impl Bip39MnemonicMethods for Bip39Mnemonic {
    /// Generates a new mnemonic of 12/24 words based on the desired input entropy bits.
    /// The entropy can be of [`AllowedKeyEntropyBits::Entropy256Bits`] or [`AllowedKeyEntropyBits::Entropy128Bits`] 
    /// (16/32) bytes.
    /// By default a 24-word mnemonic is generated
    fn new(entropy_bits: Option<AllowedKeyEntropyBits>) -> Result<Self, bip39::Error> {
        let byte_len = if let Some(entropy_bits) = entropy_bits {
            entropy_bits.byte_len()
        } else{
            AllowedKeyEntropyBits::byte_len(&AllowedKeyEntropyBits::Entropy256Bits)
        };
        let mut entropy = vec![0; byte_len];
        utils::generate_random_bytes(&mut entropy, byte_len);
        Ok(Self {mnemonic: Mnemonic::from_entropy(&entropy)? })
    }

    /// Converts `words` into a [`Mnemonic`]
    fn mnemonic_from_words(words: &str) -> Result<Self, bip39::Error> {
        Ok(Bip39Mnemonic{mnemonic: Mnemonic::from_str(words)?})
    }

    /// Converts `entropy` into a [`Mnemonic`]
    fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Bip39Mnemonic, bip39::Error> {
        Ok(Self {mnemonic: Mnemonic::from_entropy(entropy)?})
    }

    fn to_entropy(&self) -> Vec<u8> {
        self.mnemonic.to_entropy()
    }

    fn get_seed(&self, password: &str) -> [u8; 64] {
        self.mnemonic.to_seed(password)
    }

    fn language(&self) -> Language {
        self.mnemonic.language()
    }

    fn word_count(&self) -> usize {
        self.mnemonic.word_count()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic256() {
        let mnemonic256 = Bip39Mnemonic::new(None).unwrap();
        assert_eq!(mnemonic256.language(), bip39::Language::English);
        assert_eq!(mnemonic256.word_count(), 24);
    }

    #[test]
    fn test_generate_mnemonic128() {
        let mnemonic128 = Bip39Mnemonic::new(Some(AllowedKeyEntropyBits::Entropy128Bits)).unwrap();
        assert_eq!(mnemonic128.language(), bip39::Language::English);
        assert_eq!(mnemonic128.word_count(), 12);
    }
}