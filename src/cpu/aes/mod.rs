//! This module implements AES-128/CTR on the CPU, using x86/x86_64 AES-NI intrinsics if available
//!
//! Parallelisation is available using `AesBlock::decompose` and passing them into different threads

use std::sync::Arc;

use rand::{RngCore, SeedableRng};
use rand_chacha::{self, ChaCha20Rng};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod simd;
mod sisd;

#[cfg(test)]
#[test]
fn test_aes_encrypt_decrypt() {
	const KEY: [u8; 16] = 0x2b7e151628aed2a6abf7158809cf4f3cu128.to_le_bytes(); // Can just use u128.to_le_bytes() instead of writing a reversed array literal :)
	const IV: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff; // Don't have to worry about endianness here

	// Reversed test vectors with 4 bytes cropped to make sure everything works as it should (Source: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
	// The test vectors are reversed because the test vectors from NIST are used as a little-endian array of big-endian blocks, whereas my implementation uses a little-endian array of little-endian blocks
	const PLAINTEXT: [u8; 60] = [
		0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9, 0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b,
		0x51, 0x8e, 0xaf, 0x45, 0xac, 0x6f, 0xb7, 0x9e, 0x9c, 0xac, 0x03, 0x1e, 0x57, 0x8a, 0x2d, 0xae,
		0xef, 0x52, 0x0a, 0x1a, 0x19, 0xc1, 0xfb, 0xe5, 0x11, 0xe4, 0x5c, 0xa3, 0x46, 0x1c, 0xc8, 0x30,
		0x10, 0x37, 0x6c, 0xe6, 0x7b, 0x41, 0x2b, 0xad, 0x17, 0x9b, 0x4f, 0xdf
		// 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, // Original test vector
		// 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		// 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		// 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	];
	const CIPHERTEXT: [u8; 60] = [
		0xce, 0xb6, 0x0d, 0x99, 0x64, 0x68, 0xef, 0x1b, 0x26, 0xe3, 0x20, 0xb6, 0x91, 0x61, 0x4d, 0x87,
		0xff, 0xfd, 0xff, 0xb9, 0x7b, 0x18, 0x17, 0x86, 0xff, 0xfd, 0x70, 0x79, 0x6b, 0xf6, 0x06, 0x98,
		0xab, 0x3e, 0xb0, 0x0d, 0x02, 0x09, 0x4f, 0x5b, 0x5e, 0xd3, 0xd5, 0xdb, 0x3e, 0xdf, 0xe4, 0x5a,
		0xee, 0x9c, 0x00, 0xf3, 0xa0, 0x70, 0x21, 0x79, 0xd1, 0x03, 0xbe, 0x2f
		// 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce, // Original test vector
		// 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
		// 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
		// 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
	];

	let mut input = PLAINTEXT.to_vec();

	aes_encrypt_decrypt(&mut input[..], &KEY, Some(IV));

	// println!("Ciphertext: {:#04x?}", input);
	assert_eq!(&input[..], &CIPHERTEXT, "[ERROR]: Computed ciphertext is not equal to expected ciphertext");

	let mut derived_input = input.clone();

	aes_encrypt_decrypt(&mut derived_input, &KEY, Some(IV));

	assert_eq!(&derived_input, &PLAINTEXT, "[ERROR]: Decryption using IV that was used for encryption does not yeild exactly the plaintext");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(test)]
#[test]
fn test_key_expansion() {
	const KEY: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
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

	// CORRECT
	let aesni_res = unsafe {
		simd::key_expansion(KEY)
	};

	// CORRECT
	let aesrs_res = sisd::key_expansion(KEY);

	assert_eq!(aesni_res, aesrs_res, "[ERROR]: The two implementation produce different results");
	assert_eq!(aesni_res, EXPECTED, "[ERROR]: Both implementations produce the same result but differ from the expected result");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(test)]
#[test]
fn test_cipher() {
	const KEY: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;//0x5468617473206D79204B756E67204675;
	const INPUT: u128 = 0x6bc1bee22e409f96e93d7e117393172a;//0x54776F204F6E65204E696E652054776F;
	const EXPECTED: u128 = 0x3ad77bb40d7a3660a89ecaf32466ef97;//0x0;

	// CORRECT
	let aesni_res = unsafe {
		let rks = simd::key_expansion(KEY);
		simd::cipher(INPUT, &rks)
	};

	// CORRECT
	let aesrs_res = {
		let rks = sisd::key_expansion(KEY);
		sisd::cipher(INPUT, &rks)
	};

	assert_eq!(aesni_res, aesrs_res, "[ERROR]: The two implementation produce different results");
	assert_eq!(aesni_res, EXPECTED, "[ERROR]: Both implementations produce the same result but differ from the expected result");
}

#[cfg(test)]
#[test]
fn test_aes_block_par() { // Also a test of the scoped_thread_pool - Although that is confirmed to work by it's own test
	const KEY: [u8; 16] = 0x2b7e151628aed2a6abf7158809cf4f3cu128.to_le_bytes(); // Can just use u128.to_le_bytes() instead of writing a reversed array literal :)
	const IV: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff; // Don't have to worry about endianness here

	// Reversed test vectors with 4 bytes cropped to make sure everything works as it should (Source: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
	// The test vectors are reversed because the test vectors from NIST are used as a little-endian array of big-endian blocks, whereas my implementation uses a little-endian array of little-endian blocks
	const PLAINTEXT: [u8; 60] = [
		0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9, 0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b,
		0x51, 0x8e, 0xaf, 0x45, 0xac, 0x6f, 0xb7, 0x9e, 0x9c, 0xac, 0x03, 0x1e, 0x57, 0x8a, 0x2d, 0xae,
		0xef, 0x52, 0x0a, 0x1a, 0x19, 0xc1, 0xfb, 0xe5, 0x11, 0xe4, 0x5c, 0xa3, 0x46, 0x1c, 0xc8, 0x30,
		0x10, 0x37, 0x6c, 0xe6, 0x7b, 0x41, 0x2b, 0xad, 0x17, 0x9b, 0x4f, 0xdf
		// 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, // Original test vector
		// 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		// 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		// 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	];
	const CIPHERTEXT: [u8; 60] = [
		0xce, 0xb6, 0x0d, 0x99, 0x64, 0x68, 0xef, 0x1b, 0x26, 0xe3, 0x20, 0xb6, 0x91, 0x61, 0x4d, 0x87,
		0xff, 0xfd, 0xff, 0xb9, 0x7b, 0x18, 0x17, 0x86, 0xff, 0xfd, 0x70, 0x79, 0x6b, 0xf6, 0x06, 0x98,
		0xab, 0x3e, 0xb0, 0x0d, 0x02, 0x09, 0x4f, 0x5b, 0x5e, 0xd3, 0xd5, 0xdb, 0x3e, 0xdf, 0xe4, 0x5a,
		0xee, 0x9c, 0x00, 0xf3, 0xa0, 0x70, 0x21, 0x79, 0xd1, 0x03, 0xbe, 0x2f
		// 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce, // Original test vector
		// 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
		// 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
		// 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
	];

	// Sequential
	{
		let mut input = PLAINTEXT.to_vec();

		let mut blocks = AesBlock::decompose(&mut input, &KEY, Some(IV));

		blocks.iter_mut().for_each(|b| b.encrypt());

		assert_eq!(&input[..], &CIPHERTEXT[..]);
	}

	// Parallel (using scoped thread pool)
	{
		let mut input = PLAINTEXT.to_vec();

		let blocks = AesBlock::decompose(&mut input, &KEY, Some(IV));

		use super::scoped_thread_pool::ThreadPool;

		let mut pool = ThreadPool::new();

		pool.scoped(|scope| {
			for mut b in blocks {
				scope.assign_task(move || {
					b.encrypt();
				});
			}
		});

		assert_eq!(&input[..], &CIPHERTEXT[..]);
	}
}

/// This struct contains the information necessary to encrypt one block
pub struct AesBlock<'a> {
	ctr_block: u128,
	data: &'a mut [u8],
	round_keys: Arc<[u128; 11]>
}

impl<'a> AesBlock<'a> {
	/// Creates a Vec of
	fn decompose(data: &'a mut [u8], key: &[u8], iv: Option<u128>) -> Vec<AesBlock<'a>> {
		assert_eq!(key.len(), 16);

		// Initialisation Vector (initial counter)
		// If provided, then we use that, if not provided, then we generate one
		let iv = match iv {
			Some(iv_provided) => iv_provided,
			None => {
				let mut rng = ChaCha20Rng::from_entropy(); // Seed the ChaCha20Rng CSPRNG using a non-deterministic seed, panic if can't
				let mut iv = [0u8; 16];
				rng.fill_bytes(&mut iv);
				u128::from_ne_bytes(iv) // Can just use from native endianness cause we aren't reading it from input
			}
		};

		let key = u128::from_le_bytes(key.try_into().unwrap());

		let round_keys = Arc::new(key_expansion(key));

		let num_128_blks = (data.len() as f64 / 16.0).ceil() as usize;

		// Create counter iterator with num_128_blks elements adding iv onto each one to turn it into a range from iv to num_128_blocks + iv
		// Didn't directly create a range (iv..num_128_blks + iv) cause what if num_128_blks + iv overflows? The range becomes invalid. Using map makes sure that things keep going in the case of overflows
		let counter = (0..num_128_blks).map(|n| (n as u128) + iv);

		// Get a mutable iterator to each 128-bit block of data to be encrypted, and combine that with the counter iterator above, to make a single iterator of pairs (data, counter)
		// For each element, create an AesBlock out of the element and an Arc to round keys
		// Then collect it all into a Vec
		data.chunks_mut(16).zip(counter).map(|(data_chunk, counter)| {
			AesBlock { ctr_block: counter, data: data_chunk, round_keys: round_keys.clone() }
		}).collect()
	}

	fn encrypt(&mut self) {
		// Now for the actual encryption
		let enc_counter = cipher(self.ctr_block, &*self.round_keys).to_le_bytes();
		let block = &mut self.data;
		for i in 0..block.len() {
			block[i] ^= enc_counter[i];
		}
	}
}

/// Perform AES-128/CTR encryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit)
///
/// Will use x86/x86_64 AES-NI intrinsics if available
///
/// Returns the IV that needs to be stored alongside the encrypted data and used for decryption. The data is encrypted in-place
///
/// `key` is taken as a little-endian array of bytes; `data` is taken as a little-endian array of little-endian 16-byte blocks
/// # Panics
/// This function will panic if `key` is not 128-bit/16-byte or an RNG providing secure entropy could not be found/used by the `getrandom` crate
pub fn aes_encrypt(data: &mut [u8], key: &[u8]) -> u128 {
	aes_encrypt_decrypt(data, key, None)
}

/// Perform AES-128/CTR decryption on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit) and 128-bit `iv` - The IV that was used for encryption
///
/// Will use x86/x86_64 AES-NI intrinsics if available
///
/// The data is decrypted in-place
///
/// `key` is taken as a little-endian array of bytes; `data` is taken as a little-endian array of little-endian 16-byte blocks
/// # Panics
/// This function will panic if `key` is not 128-bit/16-byte
pub fn aes_decrypt(data: &mut [u8], key: &[u8], iv: u128) {
	aes_encrypt_decrypt(data, key, Some(iv));
}

/// Perform AES-128/CTR encryption/decryption (both are the same operation) on slice `data` using slice `key` (`key` having gone through necessary key derivation and being exactly 128-bit) and an IV if provided. When performing decryption you need to provide the IV that was used for encryption in order for the decryption to be correct
///
/// Will use x86/x86_64 AES-NI intrinsics if available
///
/// Returns the IV that needs to be stored alongside the encrypted data and used for decryption. The data is encrypted in-place
///
/// `key` is taken as a little-endian array of bytes; `data` is taken as a little-endian array of little-endian 16-byte blocks
/// # Panics
/// This function will panic if `key` is not 128-bit/16-byte or, if `iv` is not provided, an RNG providing secure entropy could not be found/used by the `getrandom` crate
pub fn aes_encrypt_decrypt(data: &mut [u8], key: &[u8], iv: Option<u128>) -> u128 {
	assert_eq!(key.len(), 16);

	// Initialisation Vector (initial counter)
	// If provided, then we use that, if not provided, then we generate one
	let iv = match iv {
		Some(iv_provided) => iv_provided,
		None => {
			let mut rng = ChaCha20Rng::from_entropy(); // Seed the ChaCha20Rng CSPRNG using a non-deterministic seed, panic if can't
			let mut iv = [0u8; 16];
			rng.fill_bytes(&mut iv);
			u128::from_ne_bytes(iv) // Can just use from native endianness cause we aren't reading it from input
		}
	};

	let key = u128::from_le_bytes(key.try_into().unwrap());

	let rks = key_expansion(key);

	let num_128_blks = (data.len() as f64 / 16.0).ceil() as usize;

	// Create counter with num_128_blks elements adding iv onto each one to turn it into a range from iv to num_128_blocks + iv
	// Didn't directly create a range (iv..num_128_blks + iv) cause what if num_128_blks + iv overflows? The range becomes invalid. Using map makes sure that things keep going in the case of overflows
	let counter: Vec<u128> = (0..num_128_blks).map(|n| (n as u128) + iv).collect();

	// Get a mutable iterator to each 128-bit block of data to be encrypted
	let mut data_chunks: Vec<&mut [u8]> = data.chunks_mut(16).collect();

	// Now for the actual encryption
	for i in 0..counter.len() {
		let enc_counter = cipher(counter[i], &rks).to_le_bytes();
		let block = &mut data_chunks[i];
		for i in 0..block.len() {
			block[i] ^= enc_counter[i];
		}
	}

	iv
}

/// Expands one 128-bit key into 11 128-bit round keys
///
/// Will use x86/x86_64 AES-NI intrinsics if available
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
///
/// Will use x86/x86_64 AES-NI intrinsics if available
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