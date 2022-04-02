//! This module implements parallelised AES-128/CTR on the CPU using AES-NI
//!
//! Parallelisation is done using the farming pattern

use core::arch::x86_64::{_mm_aeskeygenassist_si128, _mm_aesenc_si128, _mm_aesenclast_si128};

mod thread_pool;

#[cfg(test)]
#[test]
fn test_aes_encrypt() {
	todo!();
}

/// Perform AES-128/CTR encryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit)
/// # Panics
/// This function will panic if `key` is not 128-bit or if used on an architecture that is not x86/x86_64 or when AES-NI isn't available
pub fn aes_encrypt<'a>(data: &'a mut [u8], key: &[u8]) -> &'a mut [u8] {
	assert_eq!(key.len(), 16);

	// Compile the block if the target architecture is x86 or x86_64
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	{
		// Check for AES-NI
		if is_x86_feature_detected!("aes") {
			// TODO: Splitting `data` up into 128-bit blocks, generating the counter for each block, and giving the work to a ThreadPool instance to work on

			return data;
		}
	}

	// A software (pure rust) fallback is not implemented and won't be in the future
	unimplemented!();
}

/// Expands one 128-bit key into 11 128-bit round keys
/// # Panics
/// This function panics if `key` is not 128-bit
fn key_expansion(key: &[u8]) -> [u8; 176] {
	assert_eq!(key.len(), 16);

	// Mutable array to work on
	let mut rks = [0u8; 176];

	// TODO: Key expansion using `_mm_aeskeygenassist_si128` intrinsic

	todo!();
}

/// Performs the cipher on a 128-bit state with 11 128-bit round keys
/// # Panics
/// This function panics if the `state` length is not equal to 16, and/or `round_keys` length is not equal to 176 (16 * 11)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Enable AES-NI for this function
// This will compile code using AES-NI even if the CPU doesn't support it, so we have to check at runtime whether the CPU supports it before calling this function
#[target_feature(enable = "aes")]
unsafe fn cipher<'a>(state: &'a mut [u8], round_keys: &[u8]) -> &'a mut [u8] {
	assert_eq!(state.len(), 16);
	assert_eq!(round_keys.len(), 176); // 16 * 11

	// TODO: Cipher using `_mm_aesenc_si128` and `_mm_aesenclast_si128` intrinsics

	todo!();
}