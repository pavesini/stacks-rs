use std::fmt;

use aes::cipher::{consts::U256, typenum::{IsLess, Le, NonZero}, BlockSizeUser, InvalidLength, KeyInit};
use hmac::{digest::{block_buffer::Eager, core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore}, HashMarker}, Hmac, Mac};
use sha2::{Sha256, Sha512};
use super::utils;

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha512 = Hmac<Sha512>;

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


/// Computes the hmac using the provided Hash algorithm.
/// 
/// Usage:
/// ```
/// let digest_sha256 = compute_hmac::<HmacSha256>("what do ya want for nothing?".as_bytes(), "Jefe".as_bytes()).unwrap();
/// let digest_sha512 = compute_hmac::<HmacSha512>("what do ya want for nothing?".as_bytes(), "Jefe".as_bytes()).unwrap();
/// ```
pub fn compute_hmac<D>(payload: &[u8], mac_key: &[u8]) -> Result<Vec<u8>, HmacError> 
where
    D: KeyInit + Mac,
{
    let mut hmac_digest = <D as KeyInit>::new_from_slice(mac_key).map_err(|err|{
        HmacError::InvalidKeyLength(err)
    })?;
    hmac_digest.update(payload);
    Ok(hmac_digest.finalize().into_bytes().to_vec())
}

pub fn get_pbkdf2_hmac_keys<D>(password: &[u8], salt: Option<[u8; 16]>, rounds: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)
where
    D: CoreProxy,
    D::Core: Sync
        + HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let salt = if let Some(salt) = salt {
        salt.to_vec()
    } else {
        let mut new_salt = vec![0; 16];
        utils::generate_random_bytes(&mut new_salt, 16);
        new_salt
    };
    let mut keys_and_iv = [0u8; 48];
    pbkdf2::pbkdf2_hmac::<D>(password, &salt, rounds, &mut keys_and_iv);
    (keys_and_iv[0..16].to_vec(), keys_and_iv[16..32].to_vec(), keys_and_iv[32..48].to_vec(), salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        /*
         * Test vector: https://datatracker.ietf.org/doc/html/rfc4231#section-4
         */
        let digest = compute_hmac::<HmacSha256>(
            "what do ya want for nothing?".as_bytes(), "Jefe".as_bytes()
        ).unwrap();
        let hex_digest = hex::encode(digest);
        assert_eq!(hex_digest, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        let digest = compute_hmac::<HmacSha512>(
            "what do ya want for nothing?".as_bytes(), 
            "Jefe".as_bytes()
        ).unwrap();
        let hex_digest = hex::encode(digest);
        assert_eq!(hex_digest, 
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    }
}