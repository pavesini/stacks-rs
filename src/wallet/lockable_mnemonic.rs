use std::fmt;
use aes::cipher::block_padding::UnpadError;
use sha2::{Sha256, Sha512};

use crate::crypto::encryption::{self, Aes128CbcDec, Aes128CbcEnc};
use crate::crypto::hash::U32;
use crate::crypto::hmac::{HmacError, HmacSha256};
use crate::crypto::{hash, hmac};

use super::bip39::{Bip39Mnemonic, Bip39MnemonicMethods};

pub struct LockableMnemonic {
    b39_mnemonic: Bip39Mnemonic, 
    password: Option<String>
}

pub trait LockedMnemonicMethods {
    fn new(password: Option<String>) -> Self;
    fn from_bip39_mnemonic(mnemo: &Bip39Mnemonic, password: Option<String>) -> Result<Self, Error> where Self: Sized;
    fn from_bip39_words(words: &str, password: Option<String>) -> Result<Self, Error> where Self: Sized;
    fn lock_mnemonic(&self, salt: Option<[u8; 16]>) -> Result<Vec<u8>, Error>;
    fn unlock_mnenomic(encrypted_mnemonic: &Vec<u8>, password: &str) -> Result<Self, Error> where Self: Sized;
    fn get_seed(&self) -> [u8; 64];
}

impl LockedMnemonicMethods for LockableMnemonic {

    fn new(password: Option<String>) -> Self {
        LockableMnemonic{
            b39_mnemonic: Bip39Mnemonic::new(None).unwrap(),
            password: password
        }
    }

    fn from_bip39_mnemonic(mnemo: &Bip39Mnemonic, password: Option<String>) -> Result<Self, Error> {   
        Ok(Self {
            b39_mnemonic: mnemo.clone(),
            password: password
        })
    }

    fn from_bip39_words(words: &str, password: Option<String>) -> Result<Self, Error> {   
        Ok(Self {
            b39_mnemonic: Bip39Mnemonic::mnemonic_from_words(words).map_err(|err| {
                Error::BadMnemonic(err)
            })?,
            password: password
        })
    }

    /// Encryption with AES-128-CBC with SHA256 HMAC
    fn lock_mnemonic(&self, salt: Option<[u8; 16]>) -> Result<Vec<u8>, Error> {
        let (
            enc_key, 
            mac_key, 
            iv, 
            salt
        ) = hmac::get_pbkdf2_hmac_keys::<Sha512>(
                self.password.as_deref().unwrap_or("").as_bytes(), 
                salt, 
                100_000
            );

        // encrypt the mnenomic entropy
        let ciphertext = encryption::cbc_encrypt::<Aes128CbcEnc>(
            &enc_key, &iv, &self.b39_mnemonic.to_entropy()
        );

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
    
        let (
            enc_key, 
            mac_key, 
            iv, 
            _salt
        ) = hmac::get_pbkdf2_hmac_keys::<Sha512>(
                password.as_bytes(), 
                Some(*salt), 
                100_000
            );
    
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
    
        let mnemonic = Bip39Mnemonic::entropy_to_mnemonic(&decrypted_mnemonic_entropy)
        .or_else(|_err| {
            Err(Error::WrongPassword)
        });

        Ok(LockableMnemonic{b39_mnemonic: mnemonic?, password: Some(password.to_string())})
    }

    fn get_seed(&self) -> [u8; 64] {
        self.b39_mnemonic.get_seed(
            self.password.as_deref().unwrap_or("")
        )
    }

}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    AesUnpadError(UnpadError),
    HmacMismatch,
    HmacError(hmac::HmacError),
    WrongPassword,
    BadMnemonic(bip39::Error)
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
            Error::BadMnemonic(error) =>  f.write_str(&format!("{error}")),
        }
    }
}

impl std::error::Error for Error {}


#[cfg(test)]
mod tests {
    use super::*;

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

        let mnemonic_with_password = LockableMnemonic::from_bip39_words(
            words, Some(password.to_string())
        ).unwrap();
        let encrypted_mnemonic = mnemonic_with_password.lock_mnemonic( TEST_SALT).unwrap();
        let encrypted_mnemonic_hex = hex::encode(&encrypted_mnemonic);
        
        assert_eq!(encrypted_mnemonic_hex, EXPECTED_ENCRYPTED_MNEMONIC);
        
        /*
         * Now try decryption 
         */
        let decrypted_mnemonic_with_password = LockableMnemonic::unlock_mnenomic(
            &encrypted_mnemonic, password)
            .unwrap();
        assert_eq!(decrypted_mnemonic_with_password.b39_mnemonic, mnemonic_with_password.b39_mnemonic);
    }
}