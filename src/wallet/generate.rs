use super::lockable_mnemonic::{LockableMnemonic, LockedMnemonicMethods};

pub struct Wallet {
    //salt: [u8],
    //config_private_key: [u8],

    /** The private key associated with the root of a BIP39 keychain */
    root_key: [u8; 64],
    /** The mnemonic encrypted with the password provided at Wallet creation */
    encrypted_secret_key: Vec<u8>,
    
    // accounts: 
}

impl Wallet {
    
    /// creates a new [`Wallet`]. If no `mnemonic` is provided, a 24-word mnemonic is generated with an empty password ("").
    /// The mnemonic (or secret_key) is then encrypted using AES-128-CBC with SHA256 HMAC.
    /// The `password` is passed to a pbkdf2 for deriving the required keys
    pub fn new(lockable_mnemonic: Option<&LockableMnemonic>) -> Wallet {
        // generate mnemonic
        let lockable_mnemonic = if let Some(lockable_mnemonic) = lockable_mnemonic {
            lockable_mnemonic
        } else {
            &LockableMnemonic::new(None)
        };
        // encrypt mnemonic with password
        let encrypted_secret_key = lockable_mnemonic.lock_mnemonic(None).unwrap();

        // get root_key from the mnemonic (get the seed)
        let root_key = lockable_mnemonic.get_seed();

        Wallet {encrypted_secret_key: encrypted_secret_key, root_key: root_key}
    }

    pub fn get_mnemonic(&self, password: &str) -> LockableMnemonic {
        LockableMnemonic::unlock_mnenomic(&self.encrypted_secret_key, password).unwrap()
    }

    pub fn root_key(&self) -> &[u8; 64] {
        &self.root_key
    }
}

