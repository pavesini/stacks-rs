use rand::{thread_rng, RngCore};


/// Generates `n` rand bytes and stores them in `dest`
pub fn generate_random_bytes(dest: &mut [u8], n: usize) -> &[u8] {
    thread_rng().fill_bytes( &mut dest[0..n]);
    dest
}