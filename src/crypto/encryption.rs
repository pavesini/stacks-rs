use aes::cipher::{
    block_padding::{Pkcs7, UnpadError},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

pub type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Returns resulting ciphertext (Uses Pkcs7 padding)
///
/// Usage:
/// ```rust
/// use stacks_rs::crypto::encryption::cbc_encrypt;
/// use stacks_rs::crypto::encryption::Aes128CbcEnc;
/// let key = hex::decode("1fe107d14dd8b152580f3dea8591fc3b").unwrap();
/// let iv = hex::decode("7b6070a896d41d227cc0cebbd92d797e").unwrap();
/// let plain = hex::decode("13eb26baf2b688574cadac6dba").unwrap();
/// let ciphertext = cbc_encrypt::<Aes128CbcEnc>(&key, &iv, &plain);
/// ```
pub fn cbc_encrypt<T>(enc_key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>
where
    T: KeyIvInit,
    T: BlockEncryptMut,
{
    <T as KeyIvInit>::new(enc_key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// Returns resulting plaintext. (Uses Pkcs7 padding)
///
/// Returns [`UnpadError`] if padding is malformed or if input length is
/// not multiple of the algorithm's `BlockSize` (e.g. AES128-CBC uses blocks of `128 bits`).
///
/// Usage:
/// ```rust
/// use stacks_rs::crypto::encryption::Aes128CbcDec;
/// use stacks_rs::crypto::encryption::cbc_decrypt;
/// let key = hex::decode("1fe107d14dd8b152580f3dea8591fc3b").unwrap();
/// let iv = hex::decode("7b6070a896d41d227cc0cebbd92d797e").unwrap();
/// let cipher = hex::decode("a4bfd6586344bcdef94f09d871ca8a16").unwrap();
/// let plaintext = cbc_decrypt::<Aes128CbcDec>(&key, &iv, &cipher);
/// ```
pub fn cbc_decrypt<T>(enc_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError>
where
    T: KeyIvInit,
    T: BlockDecryptMut,
{
    <T as KeyIvInit>::new(enc_key.into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_cbc_encrypt() {
        /*
         * Test vector: https://github.com/geertj/bluepass/blob/master/tests/vectors/aes-cbc-pkcs7.txt
         */
        let key = hex::decode("1fe107d14dd8b152580f3dea8591fc3b").unwrap();
        let iv = hex::decode("7b6070a896d41d227cc0cebbd92d797e").unwrap();
        let plain = hex::decode("13eb26baf2b688574cadac6dba").unwrap();
        let cipher = hex::decode("a4bfd6586344bcdef94f09d871ca8a16").unwrap();

        let encrypted = cbc_encrypt::<Aes128CbcEnc>(&key, &iv, &plain);

        assert_eq!(encrypted, cipher);
    }

    #[test]
    fn test_aes128_cbc_deccrypt() {
        /*
         * Test vector: https://github.com/geertj/bluepass/blob/master/tests/vectors/aes-cbc-pkcs7.txt
         */
        let key = hex::decode("1fe107d14dd8b152580f3dea8591fc3b").unwrap();
        let iv = hex::decode("7b6070a896d41d227cc0cebbd92d797e").unwrap();
        let plain = hex::decode("13eb26baf2b688574cadac6dba").unwrap();
        let cipher = hex::decode("a4bfd6586344bcdef94f09d871ca8a16").unwrap();

        let decrypted = cbc_decrypt::<Aes128CbcDec>(&key, &iv, &cipher).unwrap();

        assert_eq!(decrypted, plain);
    }
}
