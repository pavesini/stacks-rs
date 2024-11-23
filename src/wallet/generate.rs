use std::{str::FromStr, vec};

use bip39::Mnemonic;
use pbkdf2::pbkdf2_hmac;
use rand::{thread_rng, RngCore};
use sha2::Sha512;
use aes::cipher::{self, block_padding::Pkcs7, typenum::Same, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

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

/// Generates `n` rand bytes and stores them in `dest`
fn generate_random_bytes(dest: &mut [u8], n: usize) -> &[u8] {
    thread_rng().fill_bytes( &mut dest[0..n]);
    dest
}

/// Generate a new mnemonic of 12/24 words based on the desired input entropy bits.
/// The entropy can be of `AllowedKeyEntropyBits::Entropy256Bits` or `AllowedKeyEntropyBits::Entropy128Bits` 
/// (16/32) bytes
pub fn generate_mnemonic(entropy_bits: AllowedKeyEntropyBits) -> Mnemonic {
    let byte_len = entropy_bits.byte_len();
    let mut entropy = vec![0; byte_len];
    generate_random_bytes(&mut entropy, byte_len);
    Mnemonic::from_entropy(&entropy).unwrap()
}

pub fn mnemonic_from_words(words: &str) -> Result<Mnemonic, bip39::Error> {
    Mnemonic::from_str(words)
}

pub fn entropy_to_mnemonic(entropy: &Vec<u8>) -> Result<Mnemonic, bip39::Error> {
    Mnemonic::from_entropy(entropy)
}

/// Encryption with AES-128-CBC with SHA256 HMAC
fn encrypt_mnemonic(mnemonic: &Mnemonic, password: &[u8], salt: Option<[u8; 16]>) -> Vec<u8> {
    // generate a rand salt if None is given
    let salt = if let Some(salt) = salt {
        salt.to_vec()
    } else {
        let mut new_salt = vec![0; 16];
        generate_random_bytes(&mut new_salt, 16);
        new_salt
    };
    let mut keys_and_iv = [0u8; 48];
    pbkdf2_hmac::<Sha512>(password, &salt, 100_000, &mut keys_and_iv);

    let enc_key= &keys_and_iv[0..16];
    let mac_key = &keys_and_iv[16..32];
    let iv = &keys_and_iv[32..48];

    // encrypt the mnenomic entropy
    let ciphertext = Aes128CbcEnc::new(enc_key.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&mnemonic.to_entropy());

    // hmac256
    let hmac_payload = [salt.clone(), ciphertext.clone()].concat();
    let mut hmac_digest = HmacSha256::new_from_slice(mac_key)
        .expect("HMAC can take key of any size");
    hmac_digest.update(&hmac_payload);
    let hmac_sig = hmac_digest.finalize();

    [salt, hmac_sig.into_bytes().to_vec(), ciphertext].concat()
}   


fn decrypt_mnenomic<'a>(encrypted_secret_key: &'a [u8], password: &[u8]) -> Result<Mnemonic, &'a str> {
    let salt = &encrypted_secret_key[0..16];
    let hmac_sig = &encrypted_secret_key[16..48];
    let ciphertext = &encrypted_secret_key[48..];
    let hmac_payload = [salt.to_owned().clone(), ciphertext.to_owned().clone()].concat();

    let mut keys_and_iv = [0u8; 48];
    pbkdf2_hmac::<Sha512>(password, &salt, 100_000, &mut keys_and_iv);

    let enc_key= &keys_and_iv[0..16];
    let mac_key = &keys_and_iv[16..32];
    let iv = &keys_and_iv[32..48];

    let decrypted_mnemonic_entropy = Aes128CbcDec::new(enc_key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext).unwrap();

    let mut hmac_digest = HmacSha256::new_from_slice(mac_key)
        .expect("HMAC can take key of any size");
    hmac_digest.update(&hmac_payload);
    let hmac_digest_final = hmac_digest.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hmac_sig);
    let hmac_sig_hash = hasher.finalize();

    hasher = Sha256::new();
    hasher.update(hmac_digest_final.into_bytes());
    let hmac_digest_hash = hasher.finalize();

    if hmac_digest_hash[..] != hmac_sig_hash[..] {
        return Err("Wrong password (HMAC mismatch)");
    };

    entropy_to_mnemonic(&decrypted_mnemonic_entropy).or_else(|_err| {
        Err("Wrong password (invalid plaintext)")
    })
}


//pub struct Wallet {
//    //salt: [u8],
//    //config_private_key: [u8],
//
//    /** The private key associated with the root of a BIP39 keychain */
//    root_key: [u8],
//    /** The mnemonic encrypted with the password provided at Wallet creation */
//    encrypted_secret_key: [u8],
//    
//    // accounts: 
//}
//
//impl Wallet {
//    
//    pub fn new(mnemonic: &Mnemonic, password: &str) -> Self {
//        // encrypt mnemonic with password
//
//        // get root_key from the mnemonic (get the seed)
//
//    }
//}



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

        let mnemonic = mnemonic_from_words(words).unwrap();
        let encrypted_mnemonic = encrypt_mnemonic(&mnemonic, password, TEST_SALT);
        let encrypted_mnemonic_hex = hex::encode(&encrypted_mnemonic);
        
        assert_eq!(encrypted_mnemonic_hex, EXPECTED_ENCRYPTED_MNEMONIC);

        /*
         * Now try decryption 
         */
        let decrypted_mnemonic = decrypt_mnenomic(&encrypted_mnemonic, password).unwrap();
        assert_eq!(decrypted_mnemonic, mnemonic);
    }
}