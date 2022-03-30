//! This module implements parallelised AES-128/CTR on the CPU using AES-NI
//!
//! Parallelisation is done using the farming pattern

#[cfg(test)]
#[test]
fn test_aes_encrypt() {
	todo!();
}

/// Perform AES-128/CTR encryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit)
///
/// This function will panic if used on an architecture that is not x86/x86_64 and when AES-NI isn't available
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
	let mut data = data.to_vec();

	// Compile the block if the target architecture is x86 or x86_64
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	{
		// Check for AES-NI
		if is_x86_feature_detected!("aes") {
			// TODO: Actually perform AES encryption
			return unsafe { do_round(&data, &key) };
		}
	}

	// A software (pure rust) fallback is not implemented and won't be in the future
	unimplemented!();
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Enable AES-NI for this function. This will compile code using AES-NI even if the CPU doesn't support it, so we have to check at runtime whether the CPU supports it before calling this function
#[target_feature(enable = "aes")]
unsafe fn do_round(state: &[u8], round_key: &[u8]) -> Vec<u8> {
	todo!();
}