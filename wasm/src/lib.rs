use wasm_bindgen::prelude::*;
use sha2::{Sha512, Digest};
use curve25519_dalek::EdwardsPoint;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use std::cell::RefCell;

thread_local! {
    static WORKER_RNG: RefCell<Option<ChaCha8Rng>> = const { RefCell::new(None) };
}

/// Generate a batch of Ed25519 vanity keys, returning only those matching the pattern.
///
/// # Arguments
/// * `pattern_bytes` - Packed nibbles (high-nibble-first per byte). Wildcard nibbles are 0.
/// * `mask_bytes`    - Packed mask. Each nibble is 0xF where pattern is fixed, 0x0 where wildcard.
/// * `pattern_nibbles` - Total nibble count (1..=16).
/// * `batch_size`    - Number of keys to attempt.
///
/// Match condition (per nibble): `(pubkey[i] & mask[i]) == pattern[i]`.
///
/// # Returns
/// Flat byte buffer:
///   [match_count: u32 LE][attempted: u32 LE]
///   Per match (128 bytes): [pubkey: 32][clamped: 32][sha512_second_half: 32][seed: 32]
#[wasm_bindgen]
pub fn generate_batch(
    pattern_bytes: &[u8],
    mask_bytes: &[u8],
    pattern_nibbles: u32,
    batch_size: u32,
) -> Vec<u8> {
    WORKER_RNG.with(|rng_cell| {
        let mut rng_ref = rng_cell.borrow_mut();
        let rng = rng_ref.get_or_insert_with(|| {
            let mut rng_seed = [0u8; 32];
            getrandom::getrandom(&mut rng_seed).expect("failed to seed worker RNG");
            ChaCha8Rng::from_seed(rng_seed)
        });

        let mut results = Vec::with_capacity(8 + 128);
        results.extend_from_slice(&[0u8; 8]);

        let mut match_count: u32 = 0;
        let mut seed = [0u8; 32];
        let mut clamped = [0u8; 32];

        for _ in 0..batch_size {
            rng.fill_bytes(&mut seed);
            let digest = Sha512::digest(seed);

            clamped.copy_from_slice(&digest[..32]);
            clamped[0] &= 248;
            clamped[31] &= 63;
            clamped[31] |= 64;

            let point = EdwardsPoint::mul_base_clamped(clamped);
            let compressed = point.compress();
            let pubkey = compressed.as_bytes();

            // MeshCore reserves 0x00 and 0xFF as the first byte regardless of pattern.
            if pubkey[0] == 0x00 || pubkey[0] == 0xFF {
                continue;
            }

            if check_pattern(pubkey, pattern_bytes, mask_bytes, pattern_nibbles) {
                match_count += 1;
                results.extend_from_slice(pubkey);
                results.extend_from_slice(&clamped);
                results.extend_from_slice(&digest[32..64]);
                results.extend_from_slice(&seed);
            }
        }

        results[0..4].copy_from_slice(&match_count.to_le_bytes());
        results[4..8].copy_from_slice(&batch_size.to_le_bytes());

        results
    })
}

#[inline]
fn check_pattern(pubkey: &[u8], pattern: &[u8], mask: &[u8], nibbles: u32) -> bool {
    let full_bytes = (nibbles / 2) as usize;
    for i in 0..full_bytes {
        if (pubkey[i] & mask[i]) != pattern[i] {
            return false;
        }
    }
    if nibbles & 1 == 1 {
        let i = full_bytes;
        let m = mask[i] & 0xF0;
        if (pubkey[i] & m) != (pattern[i] & 0xF0) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::check_pattern;

    #[test]
    fn matches_full_byte_prefix() {
        let pubkey = [0xAB, 0xCD, 0xEF, 0x11];
        assert!(check_pattern(&pubkey, &[0xAB], &[0xFF], 2));
        assert!(!check_pattern(&pubkey, &[0xAC], &[0xFF], 2));
    }

    #[test]
    fn matches_odd_nibble_prefix() {
        let pubkey = [0xAB, 0xCD, 0xEF, 0x11];
        assert!(check_pattern(&pubkey, &[0xA0], &[0xF0], 1));
        assert!(check_pattern(&pubkey, &[0xAB, 0xC0], &[0xFF, 0xF0], 3));
        assert!(!check_pattern(&pubkey, &[0xAB, 0xD0], &[0xFF, 0xF0], 3));
    }

    #[test]
    fn matches_with_wildcards() {
        let pubkey = [0xAB, 0x17, 0x76, 0x99];
        assert!(check_pattern(&pubkey, &[0x00, 0x17, 0x76], &[0x00, 0xFF, 0xFF], 6));
        let pubkey2 = [0x42, 0x17, 0x76, 0x00];
        assert!(check_pattern(&pubkey2, &[0x00, 0x17, 0x76], &[0x00, 0xFF, 0xFF], 6));
        let pubkey3 = [0xAB, 0x18, 0x76, 0x00];
        assert!(!check_pattern(&pubkey3, &[0x00, 0x17, 0x76], &[0x00, 0xFF, 0xFF], 6));
    }

    #[test]
    fn matches_odd_wildcard_nibble() {
        let pubkey = [0xA7, 0x76, 0x00, 0x00];
        assert!(check_pattern(&pubkey, &[0x07, 0x76], &[0x0F, 0xFF], 4));
        let pubkey2 = [0xB7, 0x76, 0x00, 0x00];
        assert!(check_pattern(&pubkey2, &[0x07, 0x76], &[0x0F, 0xFF], 4));
        let pubkey3 = [0xA8, 0x76, 0x00, 0x00];
        assert!(!check_pattern(&pubkey3, &[0x07, 0x76], &[0x0F, 0xFF], 4));
    }
}
