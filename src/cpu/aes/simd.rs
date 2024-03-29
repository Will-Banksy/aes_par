#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_aeskeygenassist_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_xor_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_aeskeygenassist_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_xor_si128};

/// Round constants; Not right padded
const RCON: [i32; 10] = [
	0x01,
	0x02,
	0x04,
	0x08,
	0x10,
	0x20,
	0x40,
	0x80,
	0x1b,
	0x36
];

/// Transforms a rust u128 to an SSE __m128i using std::mem::transmute (no idea if there is a better way to do it)
unsafe fn to_sse_128(n: u128) -> __m128i {
	std::mem::transmute(n)
}

/// Transforms a SSE __m128i to a rust u128 using std::mem::transmute (no idea if there is a better way to do it)
unsafe fn from_sse_128(n: __m128i) -> u128{
	std::mem::transmute(n)
}

/// A macro to produce the `i`th (i > 0, i <= 9) round key for AES-128 using the `_mm_aeskeygenassist_si128` intrinsic, with `key` being the previous round key (round key `i - 1`)
macro_rules! key_expand_i {
	($key: ident, $i: expr) => {
		{
			let xmm1 = to_sse_128($key.to_be()); // Reverse byte order for processing
			let xmm2 = _mm_aeskeygenassist_si128::<{RCON[$i]}>(xmm1);
			from_sse_128(key_expansion_assist(xmm1, xmm2)).to_be()
		}
	};
}

#[target_feature(enable = "aes")]
pub unsafe fn key_expansion(key: u128) -> [u128; 11] {
	let rk0 = key;
	let rk1 = key_expand_i!(rk0, 0);
	let rk2 = key_expand_i!(rk1, 1);
	let rk3 = key_expand_i!(rk2, 2);
	let rk4 = key_expand_i!(rk3, 3);
	let rk5 = key_expand_i!(rk4, 4);
	let rk6 = key_expand_i!(rk5, 5);
	let rk7 = key_expand_i!(rk6, 6);
	let rk8 = key_expand_i!(rk7, 7);
	let rk9 = key_expand_i!(rk8, 8);
	let rk10 = key_expand_i!(rk9, 9);

	[ rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10 ]
}

/// Processes the output of `_mm_aeskeygenassist_si128` (`xmm2`) and the previous round key (`xmm1`) using SSE2 intrinsics to produce a round key
#[target_feature(enable = "sse2")]
unsafe fn key_expansion_assist(mut xmm1: __m128i, mut xmm2: __m128i) -> __m128i {
	let mut xmm3: __m128i;

	xmm2 = _mm_shuffle_epi32::<255>(xmm2);
	xmm3 = _mm_slli_si128::<4>(xmm1);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm3 = _mm_slli_si128::<4>(xmm1);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm3 = _mm_slli_si128::<4>(xmm1);
	xmm1 = _mm_xor_si128(xmm1, xmm3);
	xmm1 = _mm_xor_si128(xmm1, xmm2);
	xmm1
}

#[target_feature(enable = "aes")]
pub unsafe fn cipher(state: u128, round_keys: &[u128]) -> u128 {
	assert_eq!(round_keys.len(), 11);

	let mut state = to_sse_128(state.to_be());

	state = _mm_xor_si128(state, to_sse_128(round_keys[0].to_be()));
	for i in 1..10 {
		state = _mm_aesenc_si128(state, to_sse_128(round_keys[i].to_be()));
	}
	state = _mm_aesenclast_si128(state, to_sse_128(round_keys[10].to_be()));

	from_sse_128(state).to_be()
}