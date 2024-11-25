use std::{fmt, str::FromStr, vec};
use aes::cipher::block_padding::UnpadError;
use bip39::Mnemonic;
use crate::crypto::{encryption, hash, hmac::{self, HmacError}, utils};

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

pub struct Wallet {
    //salt: [u8],
    //config_private_key: [u8],

    /** The private key associated with the root of a BIP39 keychain */
    root_key: Vec<u8>,
    /** The mnemonic encrypted with the password provided at Wallet creation */
    encrypted_secret_key: Vec<u8>,
    
    // accounts: 
}

impl Wallet {
    
    /// creates a new [`Wallet`]. If no `mnemonic` is provided a 24-word mnemonic is generated.
    /// The mnemonic (or secret_key) is then encrypted using AES-128-CBC with SHA256 HMAC.
    /// The `password` is passed to a pbkdf2 for deriving the required keys
    pub fn new(mnemonic: Option<&Mnemonic>, password: &str) -> Result<Self, WalletError> {
        // generate mnemonic
        let mnemonic = if let Some(mnemonic) = mnemonic {
            mnemonic
        } else {
            &Self::generate_mnemonic(AllowedKeyEntropyBits::Entropy256Bits)
        };
        // encrypt mnemonic with password
        let encrypted_secret_key = Self::encrypt_mnemonic(mnemonic, password.as_bytes(), None)?;

        // get root_key from the mnemonic (get the seed)
        let root_key = Vec::new();

        Ok(Wallet {encrypted_secret_key: encrypted_secret_key, root_key: root_key})
    }

    /// Generate a new mnemonic of 12/24 words based on the desired input entropy bits.
    /// The entropy can be of [`AllowedKeyEntropyBits::Entropy256Bits`] or [`AllowedKeyEntropyBits::Entropy128Bits`] 
    /// (16/32) bytes
    pub fn generate_mnemonic(entropy_bits: AllowedKeyEntropyBits) -> Mnemonic {
        let byte_len = entropy_bits.byte_len();
        let mut entropy = vec![0; byte_len];
        utils::generate_random_bytes(&mut entropy, byte_len);
        Mnemonic::from_entropy(&entropy).unwrap()
    }

    /// Converts `words` into a [`Mnemonic`]
    pub fn mnemonic_from_words(words: &str) -> Result<Mnemonic, bip39::Error> {
        Mnemonic::from_str(words)
    }
    
    fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Mnemonic, bip39::Error> {
        Mnemonic::from_entropy(entropy)
    }

    /// Encryption with AES-128-CBC with SHA256 HMAC
    fn encrypt_mnemonic(mnemonic: &Mnemonic, password: &[u8], salt: Option<[u8; 16]>) -> Result<Vec<u8>, WalletError> {
        let (enc_key, mac_key, iv, salt) = 
            hmac::HmacSha512::pbkdf2_hmac(password, salt, 100_000);

        // encrypt the mnenomic entropy
        let ciphertext = encryption::aes_128_cbc_encrypt(&enc_key, &iv, &mnemonic.to_entropy());

        // hmac256
        let hmac_payload = [salt.clone(), ciphertext.clone()].concat();
        let hmac_sig = hmac::HmacSha256::compute_digest(&hmac_payload, &mac_key)
        .map_err(|err| {
            WalletError::HmacError(err)
        })?;

        Ok([salt, hmac_sig, ciphertext].concat())
    }   

    fn decrypt_mnenomic(encrypted_secret_key: & [u8], password: &[u8]) -> Result<Mnemonic, WalletError> {
        let salt: &[u8; 16] = &encrypted_secret_key[0..16].try_into().unwrap();
        let hmac_sig = &encrypted_secret_key[16..48];
        let ciphertext = &encrypted_secret_key[48..];
        let hmac_payload = [salt.to_vec().clone(), ciphertext.to_owned().clone()].concat();
    
        let (enc_key, mac_key, iv, _salt) = 
        hmac::HmacSha512::pbkdf2_hmac(password, Some(*salt), 100_000);
    
        let decrypted_mnemonic_entropy = encryption::aes_128_cbc_decrypt(&enc_key, &iv, &ciphertext)
        .map_err(|err| {
            WalletError::AesUnpadError(err)
        })?;
    
        let hmac_digest = hmac::HmacSha256::compute_digest(&hmac_payload, &mac_key)
        .map_err(|err| {
            WalletError::HmacError(err)
        })?;
    
        let hmac_sig_hash = hash::Sha256::hash(hash::Sha256::new(), hmac_sig);
        let hmac_digest_hash = hash::Sha256::hash(hash::Sha256::new(), &hmac_digest);
    
        if hmac_digest_hash[..] != hmac_sig_hash[..] {
            return Err(WalletError::HmacMismatch);
        };
    
        Self::entropy_to_mnemonic(&decrypted_mnemonic_entropy).or_else(|_err| {
            Err(WalletError::WrongPassword)
        })
    }

}


#[derive(Clone, Copy, Debug)]
pub enum WalletError {
    AesUnpadError(UnpadError),
    HmacMismatch,
    HmacError(hmac::HmacError),
    WrongPassword
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            WalletError::AesUnpadError(unpad_error)  => {
                f.write_str(&format!("{unpad_error}"))
            }
            WalletError::HmacMismatch => f.write_str("Wrong password (HMAC mismatch)"),
            WalletError::WrongPassword => f.write_str("Wrong password (invalid plaintext)"),
            WalletError::HmacError(hmac_error) => {
                match hmac_error {
                    HmacError::InvalidKeyLength(err) => {
                        f.write_str(&format!("{err}"))
                    }
                }
            },
        }
    }
}

impl std::error::Error for WalletError {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic256() {
        let mnemonic256 = Wallet::generate_mnemonic(AllowedKeyEntropyBits::Entropy256Bits);
        assert_eq!(mnemonic256.language(), bip39::Language::English);
        assert_eq!(mnemonic256.word_count(), 24);
    }

    #[test]
    fn test_generate_mnemonic128() {
        let mnemonic128 = Wallet::generate_mnemonic(AllowedKeyEntropyBits::Entropy128Bits);
        assert_eq!(mnemonic128.language(), bip39::Language::English);
        assert_eq!(mnemonic128.word_count(), 12);
    }

    #[test]
    fn test_encrypt_decrypt_mnemonic() {
        /*
         * Data taken from the tests of the official stacks.js library 
         */
        let words = "march eager husband pilot waste rely exclude taste twist donkey actress scene";
        let password = b"testtest";
        const EXPECTED_ENCRYPTED_MNEMONIC: &str =
        "ffffffffffffffffffffffffffffffffca638cc39fc270e8be5cbf98347e42a52ee955e287ab589c571af5f7c80269295b0039e32ae13adf11bc6506f5ec32dda2f79df4c44276359c6bac178ae393de";
        const TEST_SALT: Option<[u8; 16]> = Some([0xffu8; 16]);
        /* */

        let mnemonic = Wallet::mnemonic_from_words(words).unwrap();
        let encrypted_mnemonic = Wallet::encrypt_mnemonic(&mnemonic, password, TEST_SALT).unwrap();
        let encrypted_mnemonic_hex = hex::encode(&encrypted_mnemonic);
        
        assert_eq!(encrypted_mnemonic_hex, EXPECTED_ENCRYPTED_MNEMONIC);

        /*
         * Now try decryption 
         */
        let decrypted_mnemonic = Wallet::decrypt_mnenomic(&encrypted_mnemonic, password).unwrap();
        assert_eq!(decrypted_mnemonic, mnemonic);
    }
}

