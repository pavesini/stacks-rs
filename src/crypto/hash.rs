use sha2::Digest;

pub type U32 = aes::cipher::consts::U32;
pub type U64 = aes::cipher::consts::U64;

/// Computes the hash of the provided input_data.
///
/// Usage:
/// ### Sha256 hash
/// ```
/// let digest = compute_hash::<Sha256, U32>("aaaaaa".to_bytes());
/// -
/// let digest = compute_hash::<Sha256, _>("aaaaaa".to_bytes());
/// ```
/// ### Sha512 hash
/// ```
/// let digest = compute_hash::<Sha512, U64>("aaaaaa".to_bytes());
/// -
/// let digest = compute_hash::<Sha512, _>("aaaaaa".to_bytes());
pub fn compute_hash<D, L1>(input_data: &[u8]) -> Vec<u8>
where
    D: Digest<OutputSize = L1>,
    L1: aes::cipher::ArrayLength<u8>,
{
    let mut hasher = D::new();
    hasher.update(input_data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use aes::cipher::consts::{U32, U64};
    use sha2::{Sha256, Sha512};

    use super::*;

    #[test]
    fn test_sha256() {
        let digest = compute_hash::<Sha256, U32>("aaaaaaaaaaaaaaaa".as_bytes());
        let hex_digest = hex::encode(digest);
        assert_eq!(hex_digest, "0c0beacef8877bbf2416eb00f2b5dc96354e26dd1df5517320459b1236860f8c")
    }

    #[test]
    fn test_sha512() {
        let digest = compute_hash::<Sha512, U64>("aaaaaaaaaaaaaaaa".as_bytes());
        let hex_digest = hex::encode(digest);
        assert_eq!(hex_digest, 
            "987d0fc93db6a73fdb16493690fb42455c7c6fbafe9a276965424b12afad3512fb808d902faa8a019d639dc5ad07c235805e08f396147cf435913cfed501f65a")
    }
}