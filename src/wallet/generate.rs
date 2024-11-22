use bip39::Mnemonic;
use rand::{thread_rng, RngCore};

const ENTROPY_128_BITS: usize = 16; 
const ENTROPY_256_BITS: usize = 32; 

pub enum AllowedKeyEntropyBits {
    Entropy256Bits,
    Entropy128Bits
}

/// Generate a new mnemonic of 12/24 words based on the desired input entropy bits.
/// The entropy can be of `AllowedKeyEntropyBits::Entropy256Bits` or `AllowedKeyEntropyBits::Entropy128Bits` 
/// (16/32) bytes
pub fn generate_mnemonic(entropy_bits: AllowedKeyEntropyBits) -> Mnemonic {
    let entropy: &mut [u8] = match entropy_bits {
        AllowedKeyEntropyBits::Entropy128Bits => { 
            &mut [0u8; ENTROPY_128_BITS]
        },
        AllowedKeyEntropyBits::Entropy256Bits => { 
            &mut [0u8; ENTROPY_256_BITS]
        }
    }; 
    thread_rng().fill_bytes( entropy);
    Mnemonic::from_entropy(entropy).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic256() {
        let mnemonic256 = generate_mnemonic(AllowedKeyEntropyBits::Entropy256Bits);
        assert_eq!(mnemonic256.language(), bip39::Language::English);
        assert_eq!(mnemonic256.word_count(), 24);
    }

    #[test]
    fn test_generate_mnemonic128() {
        let mnemonic128 = generate_mnemonic(AllowedKeyEntropyBits::Entropy128Bits);
        assert_eq!(mnemonic128.language(), bip39::Language::English);
        assert_eq!(mnemonic128.word_count(), 12);
    }
}