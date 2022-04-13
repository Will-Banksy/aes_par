//! This module implements parallelised AES-128/CTR on the CPU using AES-NI
//!
//! Parallelisation is done using the farming pattern

mod thread_pool;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod simd;
mod sisd;

#[cfg(test)]
#[test]
fn test_key_expansion() {
	const EXPECTED: [u128; 11] = [
		0x2b7e151628aed2a6abf7158809cf4f3c,
		0xa0fafe1788542cb123a339392a6c7605,
		0xf2c295f27a96b9435935807a7359f67f,
		0x3d80477d4716fe3e1e237e446d7a883b,
		0xef44a541a8525b7fb671253bdb0bad00,
		0xd4d1c6f87c839d87caf2b8bc11f915bc,
		0x6d88a37a110b3efddbf98641ca0093fd,
		0x4e54f70e5f5fc9f384a64fb24ea6dc4f,
		0xead27321b58dbad2312bf5607f8d292f,
		0xac7766f319fadc2128d12941575c006e,
		0xd014f9a8c9ee2589e13f0cc8b6630ca6
	];

	let aesni_res = unsafe {
		simd::key_expansion(EXPECTED[0])
	};

	let aesrs_res = sisd::key_expansion(EXPECTED[0]);

	assert_eq!(aesni_res, aesrs_res, "[ERROR]: The two implementation produce different results");
	assert_eq!(aesni_res, EXPECTED, "[ERROR]: Both implementations produce the same result but differ from the expected result");
}

#[cfg(test)]
#[test]
fn test_cipher() {
	const KEY: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
	const INPUT: u128 = 0x6bc1bee22e409f96e93d7e117393172a;
	const EXPECTED: u128 = 0x3ad77bb40d7a3660a89ecaf32466ef97;

	let aesni_res = unsafe {
		let rks = simd::key_expansion(KEY);
		simd::cipher(INPUT, &rks)
	};

	println!("AES-NI RESULT: {:#x}", aesni_res);
	assert_eq!(aesni_res, EXPECTED);

	let aesrs_res = {
		let rks = sisd::key_expansion(KEY);
		sisd::cipher(INPUT, &rks)
	};

	assert_eq!(aesni_res, aesrs_res, "[ERROR]: The two implementation produce different results");
	assert_eq!(aesni_res, EXPECTED, "[ERROR]: Both implementations produce the same result but differ from the expected result");
}

/// Perform AES-128/CTR encryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit)
/// # Panics
/// This function will panic if `key` is not 128-bit or if used on an architecture that is not x86/x86_64 or when AES-NI isn't available
pub fn aes_encrypt<'a>(data: &'a mut [u8], key: &[u8]) -> &'a mut [u8] {
	assert_eq!(key.len(), 16);

	let key = u128::from_ne_bytes(key.try_into().unwrap());

	// TODO: Convert `data` into u128 slice

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
fn key_expansion(key: u128) -> [u128; 11] {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	{
		if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
			return unsafe { simd::key_expansion(key) };
		}
	}

	sisd::key_expansion(key)
}

/// Performs the cipher on a 128-bit state with 11 128-bit round keys
/// # Panics
/// This function panics if `round_keys` length is not equal to 11
fn cipher(state: u128, round_keys: &[u128]) -> u128 {
	assert_eq!(round_keys.len(), 11);

	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	{
		if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
			return unsafe { simd::cipher(state, round_keys) };
		}
	}

	sisd::cipher(state, round_keys)
}