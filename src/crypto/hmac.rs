use std::fmt;

use aes::cipher::InvalidLength;
use sha2::{Sha256, Sha512};
use hmac::{Hmac as ExtHmac, Mac};

use super::utils;

type HmacSha256Type = ExtHmac<Sha256>;
type HmacSha512Type = ExtHmac<Sha512>;

pub struct HmacSha256(HmacSha256Type);
pub struct HmacSha512(HmacSha512Type);

#[derive(Clone, Copy, Debug)]
pub enum HmacError {
    InvalidKeyLength(InvalidLength)
}

impl fmt::Display for HmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Invalid Key Length")
    }
}
impl std::error::Error for HmacError {}

impl HmacSha256 {
    /// computes the Hmac-Sha256 digest for the given payload and key.
    pub fn compute_digest(payload: &[u8], mac_key: & [u8]) -> Result<Vec<u8>, HmacError> {
        let mut hmac_digest = HmacSha256Type::new_from_slice(mac_key).map_err(|err|{
            HmacError::InvalidKeyLength(err)
        })?;
        hmac_digest.update(payload);
        Ok(hmac_digest.finalize().into_bytes().to_vec())
    }
}

impl HmacSha512 {
    /// computes the Hmac-Sha256 digest for the given payload and key.
    pub fn compute_digest(payload: &[u8], mac_key: & [u8]) -> Result<Vec<u8>, HmacError>{
        let mut hmac_digest = HmacSha512Type::new_from_slice(mac_key).map_err(|err|{
            HmacError::InvalidKeyLength(err)
        })?;
        hmac_digest.update(payload);
        Ok(hmac_digest.finalize().into_bytes().to_vec())
    }

    pub fn pbkdf2_hmac(password: &[u8], salt: Option<[u8; 16]>, rounds: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let salt = if let Some(salt) = salt {
            salt.to_vec()
        } else {
            let mut new_salt = vec![0; 16];
            utils::generate_random_bytes(&mut new_salt, 16);
            new_salt
        };
        let mut keys_and_iv = [0u8; 48];
        pbkdf2::pbkdf2_hmac::<Sha512>(password, &salt, rounds, &mut keys_and_iv);
        (keys_and_iv[0..16].to_vec(), keys_and_iv[16..32].to_vec(), keys_and_iv[32..48].to_vec(), salt)
    }
}