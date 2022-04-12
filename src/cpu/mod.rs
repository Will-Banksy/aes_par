//! This module implements parallelised AES-128/CTR on the CPU using AES-NI
//!
//! Parallelisation is done using the farming pattern

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_aeskeygenassist_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_loadu_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_aeskeygenassist_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_loadu_si128};
use std::arch::x86_64::_mm_xor_si128;

mod thread_pool;

const S_BOX: [u8; 256] = [
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const RCON: [u32; 10] = [
	0x01000000,
	0x02000000,
	0x04000000,
	0x08000000,
	0x10000000,
	0x20000000,
	0x40000000,
	0x80000000,
	0x1b000000,
	0x36000000
];

#[cfg(test)]
#[test]
fn test_aes_encrypt() {
	todo!();
}

#[test]
fn test_key_expansion_intrinsic() {
	let k: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;//0x5468617473206D79204B756E67204675;//0x000102030405060708090a0b0c0d0e0f;

	// FIXME: Need to get both implementations of the key schedule to produce the same result

	// INCORRECT
	let aesni_res = unsafe {
		const RCON0: i32 = (RCON[0] >> 24) as i32; // Remove the right zero padding cause _mm_aeskeygenassist_si128 does that

		assert_eq!(RCON0, 1);

		let mut xmm1 = to_sse_128(k);
		let mut xmm2 = _mm_aeskeygenassist_si128::<RCON0>(xmm1);
		let mut xmm3: __m128i;

		xmm2 = _mm_shuffle_epi32::<255>(xmm2);
		xmm3 = _mm_slli_si128::<4>(xmm1);
		xmm1 = _mm_xor_si128(xmm1, xmm3);
		xmm3 = _mm_slli_si128::<4>(xmm3);
		xmm1 = _mm_xor_si128(xmm1, xmm3);
		xmm3 = _mm_slli_si128::<4>(xmm3);
		xmm1 = _mm_xor_si128(xmm1, xmm3);
		xmm1 = _mm_xor_si128(xmm1, xmm2);

		from_sse_128(xmm1)
	};

	// CORRECT
	let aesrs_res = {
		const RCON0: u32 = RCON[0];

		let k3 = k as u32;
		let k2 = (k >> 32) as u32;
		let k1 = (k >> 64) as u32;
		let k0 = (k >> 96) as u32;

		let w0 = k0 ^ sub_word(k3.rotate_left(8)) ^ RCON0;
		let w1 = k1 ^ w0;
		let w2 = k2 ^ w1;
		let w3 = k3 ^ w2;

		((w0 as u128) << 96) | ((w1 as u128) << 64) | ((w2 as u128) << 32) | (w3 as u128)
	};

	println!("AES-NI implementation: {:#x}\nPure Rust implementation: {:#x}", aesni_res, aesrs_res);

	assert_eq!(aesni_res, aesrs_res);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
/// Transforms a rust u128 to an SSE __m128i using std::mem::transmute (no idea if there is a better way to do it)
unsafe fn to_sse_128(n: u128) -> __m128i {
	std::mem::transmute(n)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
/// Transforms a SSE __m128i to a rust u128 using std::mem::transmute (no idea if there is a better way to do it)
unsafe fn from_sse_128(n: __m128i) -> u128{
	std::mem::transmute(n)
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

// Tested and is working
fn sub_word(w: u32) -> u32 {
	let b0 = S_BOX[(w & 0xff) as usize];
	let b1 = S_BOX[((w >> 8) & 0xff) as usize];
	let b2 = S_BOX[((w >> 16) & 0xff) as usize];
	let b3 = S_BOX[((w >> 24) & 0xff) as usize];

	((b3 as u32) << 24) | ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32)
}

/// Expands one 128-bit key into 11 128-bit round keys
/// # Panics
/// This function panics if `key` is not 128-bit
fn key_expansion(key: u128) -> [u128; 11] {
	// TODO: Key expansion using `_mm_aeskeygenassist_si128` intrinsic

	// TODO: First actually need to find out what aeskeygenassist does
	// So let's test

	let k: u128 = 0xffffffffffffffffffffffffffffffff;
	const RCON: i32 = 0xff;

	let aesni_res = unsafe {
		let keyhelp = _mm_aeskeygenassist_si128::<RCON>(std::mem::transmute(k));

		let s: u128 = std::mem::transmute(_mm_shuffle_epi32::<0xff>(keyhelp));

		let mut key = k >> 4;
		let mut x = k ^ key;
		key >>= 4;
		x ^= key;
		key >>= 4;
		x ^ key ^ s
	};

	let aesrs_res = {
		let k3 = (k >> 96) as u32;
		let k2 = (k >> 64) as u32;
		let k1 = (k >> 32) as u32;
		let k0 = k as u32;

		let w0 = sub_word(k0.rotate_left(8)) ^ (RCON as u32);
		let w1 = w0 ^ k1;
		let w2 = w1 ^ k2;
		let w3 = w2 ^ k3;

		((w3 as u128) << 96) | ((w2 as u128) << 64) | ((w1 as u128) << 32) | (w0 as u128)
	};

	assert_eq!(aesni_res, aesrs_res);

	[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// Performs the cipher on a 128-bit state with 11 128-bit round keys
/// # Panics
/// This function panics if the `state` length is not equal to 16, and/or `round_keys` length is not equal to 176 (16 * 11)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Enable AES-NI for this function
// This will compile code using AES-NI even if the CPU doesn't support it, so we have to check at runtime whether the CPU supports it before calling this function
#[target_feature(enable = "aes")]
unsafe fn cipher<'a>(state: &'a mut u128, round_keys: &[u128]) -> &'a mut u128 {
	assert_eq!(round_keys.len(), 11);

	*state ^= round_keys[0];
	for i in 1..10 {
		// Using transmute perhaps a bit excessively here, it is quite unsafe, but no more than anything you'd do in C/C++ tbf, and it does max performance
		*state = std::mem::transmute(_mm_aesenc_si128(std::mem::transmute(*state), std::mem::transmute(round_keys[i])));
	}
	*state = std::mem::transmute(_mm_aesenclast_si128(std::mem::transmute(*state), std::mem::transmute(round_keys[10])));

	state
}