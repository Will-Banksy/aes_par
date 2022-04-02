//! This module implements parallelised AES-128/CTR on the CPU using AES-NI
//!
//! Parallelisation is done using the farming pattern

mod thread_pool;

#[cfg(test)]
#[test]
fn test_aes_encrypt() {
	todo!();
}

/// Perform AES-128/CTR encryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit)
/// # Panics
/// This function will panic if used on an architecture that is not x86/x86_64 and when AES-NI isn't available
pub fn aes_encrypt<'a>(data: &'a mut [u8], key: &[u8]) -> &'a mut [u8] {
	// Compile the block if the target architecture is x86 or x86_64
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	{
		// Check for AES-NI
		if is_x86_feature_detected!("aes") {
			// TODO: Actually perform AES encryption

			return data;
		}
	}

	// A software (pure rust) fallback is not implemented and won't be in the future
	unimplemented!();
}

/// Performs the cipher on a 128-bit state with 11 128-bit round keys
/// # Panics
/// This function panics if the state slice length is not equal to 16, and/or the round keys slice length is not equal to 176 (16 * 11)
fn do_cipher<'a>(state: &'a mut [u8], round_keys: &[u8]) -> &'a mut [u8] {
	assert_eq!(state.len(), 16, "`state` length not equal to 16");
	assert_eq!(round_keys.len(), 176, "`round_keys` length not equal to 176"); // 16 * 11

	todo!();
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Enable AES-NI for this function. This will compile code using AES-NI even if the CPU doesn't support it, so we have to check at runtime whether the CPU supports it before calling this function
#[target_feature(enable = "aes")]
unsafe fn do_round<'a>(state: &'a mut [u8], round_key: &[u8]) -> &'a mut [u8] {
	todo!();
}