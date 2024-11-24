use aes::cipher::{block_padding::{Pkcs7, UnpadError}, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Returns resulting ciphertext Vec
pub fn aes_128_cbc_encrypt(enc_key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    Aes128CbcEnc::new(enc_key.into(), iv.into())
    .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// Returns resulting plaintext Vec.
/// 
/// Returns [`UnpadError`] if padding is malformed or if input length is
/// not multiple of `Self::BlockSize` (AES-CBC uses blocks of `128 bits`).
pub fn aes_128_cbc_decrypt(enc_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
    Aes128CbcDec::new(enc_key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
}