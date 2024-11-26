use std::fmt;
use std::str::FromStr;

use aes::cipher::block_padding::UnpadError;
use bip39::Mnemonic;
use sha2::{Sha256, Sha512};

use crate::crypto::encryption::{self, Aes128CbcDec, Aes128CbcEnc};
use crate::crypto::hash::U32;
use crate::crypto::hmac::{HmacError, HmacSha256};
use crate::crypto::{hash, hmac, utils};

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

pub type MnemonicWithPassword = (Mnemonic, Option<String>);

pub trait LockedMnemonicMethods {
    fn new(mnemo: &Mnemonic, password: Option<String>) -> Self;
    fn generate_mnemonic(entropy_bits: Option<AllowedKeyEntropyBits>) -> Result<Mnemonic, bip39::Error>;
    fn mnemonic_from_words(words: &str) -> Result<Mnemonic, bip39::Error>;
    fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Mnemonic, bip39::Error>;
    fn lock_mnemonic(&self, salt: Option<[u8; 16]>) -> Result<Vec<u8>, Error>;
    fn unlock_mnenomic(encrypted_mnemonic: &Vec<u8>, password: &str) -> Result<Self, Error> where Self: Sized;
    fn get_seed(&self) -> [u8; 64];
}

impl LockedMnemonicMethods for MnemonicWithPassword {

    fn new(mnemo: &Mnemonic, password: Option<String>) -> Self {
        (mnemo.clone(), password)
    }

    /// Generate a new mnemonic of 12/24 words based on the desired input entropy bits.
    /// The entropy can be of [`AllowedKeyEntropyBits::Entropy256Bits`] or [`AllowedKeyEntropyBits::Entropy128Bits`] 
    /// (16/32) bytes.
    /// By default a 24-word mnemonic is generated
    fn generate_mnemonic(entropy_bits: Option<AllowedKeyEntropyBits>) -> Result<Mnemonic, bip39::Error> {
        let byte_len = if let Some(entropy_bits) = entropy_bits {
            entropy_bits.byte_len()
        } else{
            AllowedKeyEntropyBits::byte_len(&AllowedKeyEntropyBits::Entropy256Bits)
        };
        let mut entropy = vec![0; byte_len];
        utils::generate_random_bytes(&mut entropy, byte_len);
        Mnemonic::from_entropy(&entropy)
    }

    /// Converts `words` into a [`Mnemonic`]
    fn mnemonic_from_words(words: &str) -> Result<Mnemonic, bip39::Error> {
        Mnemonic::from_str(words)
    }
    
    fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Mnemonic, bip39::Error> {
        Mnemonic::from_entropy(entropy)
    }

    /// Encryption with AES-128-CBC with SHA256 HMAC
    fn lock_mnemonic(&self, salt: Option<[u8; 16]>) -> Result<Vec<u8>, Error> {
        let (mnemonic, password) = self;
        let (enc_key, mac_key, iv, salt) = 
            hmac::get_pbkdf2_hmac_keys::<Sha512>(password.as_deref().unwrap_or("").as_bytes(), salt, 100_000);

        // encrypt the mnenomic entropy
        let ciphertext = encryption::cbc_encrypt::<Aes128CbcEnc>(&enc_key, &iv, &mnemonic.to_entropy());

        // hmac256
        let hmac_payload = [salt.clone(), ciphertext.clone()].concat();
        let hmac_sig = hmac::compute_hmac::<HmacSha256>(&hmac_payload, &mac_key)
        .map_err(|err| {
            Error::HmacError(err)
        })?;

        Ok([salt, hmac_sig, ciphertext].concat())
    }   

    fn unlock_mnenomic(encrypted_mnemonic: &Vec<u8>, password: &str) -> Result<Self, Error> {
        let salt: &[u8; 16] = encrypted_mnemonic[0..16].try_into().unwrap();
        let hmac_sig: &[u8; 32] = encrypted_mnemonic[16..48].try_into().unwrap();
        let ciphertext = &encrypted_mnemonic[48..];
        let hmac_payload = [salt.to_vec().clone(), ciphertext.to_owned().clone()].concat();
    
        let (enc_key, mac_key, iv, _salt) = 
        hmac::get_pbkdf2_hmac_keys::<Sha512>(password.as_bytes(), Some(*salt), 100_000);
    
        let decrypted_mnemonic_entropy = encryption::cbc_decrypt::<Aes128CbcDec>(&enc_key, &iv, &ciphertext)
        .map_err(|err| {
            Error::AesUnpadError(err)
        })?;
    
        let hmac_digest = hmac::compute_hmac::<HmacSha256>(&hmac_payload, &mac_key)
        .map_err(|err| {
            Error::HmacError(err)
        })?;
        
        let hmac_sig_hash = hash::compute_hash::<Sha256, U32>(hmac_sig);
        let hmac_digest_hash = hash::compute_hash::<Sha256, U32>(&hmac_digest);
    
        if hmac_digest_hash[..] != hmac_sig_hash[..] {
            return Err(Error::HmacMismatch);
        };
    
        let mnemonic = Self::entropy_to_mnemonic(&decrypted_mnemonic_entropy).or_else(|_err| {
            Err(Error::WrongPassword)
        });

        Ok((mnemonic?, Some(password.to_string())))
    }

    fn get_seed(&self) -> [u8; 64] {
        let (mnemonic, password) = self;
        mnemonic.to_seed(password.as_deref().unwrap_or(""))
    }

}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AesUnpadError(UnpadError),
    HmacMismatch,
    HmacError(hmac::HmacError),
    WrongPassword
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Error::AesUnpadError(unpad_error)  => {
                f.write_str(&format!("{unpad_error}"))
            }
            Error::HmacMismatch => f.write_str("Wrong password (HMAC mismatch)"),
            Error::WrongPassword => f.write_str("Wrong password (invalid plaintext)"),
            Error::HmacError(hmac_error) => {
                match hmac_error {
                    HmacError::InvalidKeyLength(err) => {
                        f.write_str(&format!("{err}"))
                    }
                }
            },
        }
    }
}

impl std::error::Error for Error {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic256() {
        let mnemonic256 = MnemonicWithPassword::generate_mnemonic(None).unwrap();
        assert_eq!(mnemonic256.language(), bip39::Language::English);
        assert_eq!(mnemonic256.word_count(), 24);
    }

    #[test]
    fn test_generate_mnemonic128() {
        let mnemonic128 = MnemonicWithPassword::generate_mnemonic(Some(AllowedKeyEntropyBits::Entropy128Bits)).unwrap();
        assert_eq!(mnemonic128.language(), bip39::Language::English);
        assert_eq!(mnemonic128.word_count(), 12);
    }

    #[test]
    fn test_encrypt_decrypt_mnemonic() {
        /*
         * Data taken from the tests of the official stacks.js library 
         */
        let words = "march eager husband pilot waste rely exclude taste twist donkey actress scene";
        let password = "testtest";
        const EXPECTED_ENCRYPTED_MNEMONIC: &str =
        "ffffffffffffffffffffffffffffffffca638cc39fc270e8be5cbf98347e42a52ee955e287ab589c571af5f7c80269295b0039e32ae13adf11bc6506f5ec32dda2f79df4c44276359c6bac178ae393de";
        const TEST_SALT: Option<[u8; 16]> = Some([0xffu8; 16]);
        /* */

        let mnemonic = MnemonicWithPassword::mnemonic_from_words(words).unwrap();
        let mnemonic_with_password = MnemonicWithPassword::new(&mnemonic, Some(password.to_string()));
        let encrypted_mnemonic = mnemonic_with_password.lock_mnemonic( TEST_SALT).unwrap();
        let encrypted_mnemonic_hex = hex::encode(&encrypted_mnemonic);
        
        assert_eq!(encrypted_mnemonic_hex, EXPECTED_ENCRYPTED_MNEMONIC);
        
        /*
         * Now try decryption 
         */
        let decrypted_mnemonic_with_password = MnemonicWithPassword::unlock_mnenomic(
            &encrypted_mnemonic, password)
            .unwrap();
        assert_eq!(decrypted_mnemonic_with_password.0, mnemonic);
    }
}