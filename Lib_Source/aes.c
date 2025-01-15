#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <immintrin.h>
#include "exchangeattack.h"


#define AES128_128_ROUND 10
#define AES128_192_ROUND 12
#define AES128_256_ROUND 14
#define TEXT_LEN         16
typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
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
};

static const uint8_t inv_sbox[256] = {
	  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

#define getSBoxValue(num)		(sbox[(num)])
#define getInvSBoxValue(num)	(inv_sbox[(num)])
#define getSubKeyPtr(ptr,round)    ((uint8_t*)(ptr) + ((round) * TEXT_LEN))
#define Nb (4) //# 32-bit words

DEV_INLINE void COPY32(uint8_t * out, const uint8_t * in)
{
	memcpy(out, in, Nb);
}


static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const int keybitsize)
{
	int i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations	
	int Nk, Nr;

	if (keybitsize == 128)
	{
		Nk = 4;
		Nr = AES128_128_ROUND;
	}
	else if (keybitsize == 192)
	{
		Nk = 6;
		Nr = AES128_192_ROUND;
	}
	else if (keybitsize == 256)
	{
		Nk = 8;
		Nr = AES128_256_ROUND;
	}

	// The first round key is the key itself.
	for (i = 0; i < Nk; i++)
	{
		COPY32(RoundKey + (i * Nb), Key + (i * Nb));
	}


	for (i = Nk; i < Nb * (Nr + 1); i++)
	{
		COPY32(tempa, &RoundKey[(i - 1) * Nb + 0]);
		

		if (i % Nk == 0)
		{
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}



		if (Nr == AES128_256_ROUND) /* 256-bit only*/
		{
			if (i % Nk == 4)
			{
				// Function Subword()
				{
					tempa[0] = getSBoxValue(tempa[0]);
					tempa[1] = getSBoxValue(tempa[1]);
					tempa[2] = getSBoxValue(tempa[2]);
					tempa[3] = getSBoxValue(tempa[3]);
				}
			}
		}

		j = i * Nb;
		k = (i - Nk) * Nb;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, uint8_t * state, const uint8_t * RoundKey)
{
	uint64_t * out, * in;
	out = (uint64_t*)state;
	in = (uint64_t*)&RoundKey[(round * TEXT_LEN)];
	out[0] ^= in[0];
	out[1] ^= in[1];
}

static void SubBytes(uint8_t * state)
{
	int i;
	for (i = 0; i < TEXT_LEN; ++i)
	{
		state[i] = getSBoxValue(state[i]);
	}
}

static void ShiftRows(state_t * state)
{
	uint8_t temp;

	// Rotate first row 1 columns to left  
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// Rotate second row 2 columns to left  
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to left
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \



static void MixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x02) ^ Multiply(b, 0x03) ^ Multiply(c, 0x01) ^ Multiply(d, 0x01);
		(*state)[i][1] = Multiply(a, 0x01) ^ Multiply(b, 0x02) ^ Multiply(c, 0x03) ^ Multiply(d, 0x01);
		(*state)[i][2] = Multiply(a, 0x01) ^ Multiply(b, 0x01) ^ Multiply(c, 0x02) ^ Multiply(d, 0x03);
		(*state)[i][3] = Multiply(a, 0x03) ^ Multiply(b, 0x01) ^ Multiply(c, 0x01) ^ Multiply(d, 0x02);
	}
}



static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

static void InvSubBytes(uint8_t* state)
{
	uint8_t i;
	for (i = 0; i < TEXT_LEN; ++i)
	{
		state[i] = getInvSBoxValue(state[i]);
	}
}

static void InvShiftRows(state_t* state)
{
	uint8_t temp;

	// Rotate first row 1 columns to right  
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	// Rotate second row 2 columns to right 
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// Rotate third row 3 columns to right
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Naive_Cipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	uint8_t RoundKey[(AES128_256_ROUND + 1) * TEXT_LEN];
	KeyExpansion(RoundKey, mk, mkbitsize);

	uint8_t tmp_state[TEXT_LEN];
	memcpy(tmp_state, state, TEXT_LEN);

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, tmp_state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = 1; round_idx < round; ++round_idx)
	{
		SubBytes(tmp_state);
		ShiftRows((state_t *)tmp_state);
		MixColumns((state_t *)tmp_state);
		AddRoundKey(round_idx, tmp_state, RoundKey);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes(tmp_state);
	ShiftRows((state_t *)tmp_state);
	AddRoundKey(round, tmp_state, RoundKey);

	memcpy(out, tmp_state, TEXT_LEN);
}

static void Naive_InvCipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	uint8_t RoundKey[(AES128_256_ROUND + 1) * TEXT_LEN];
	KeyExpansion(RoundKey, mk, mkbitsize);


	uint8_t tmp_state[TEXT_LEN];
	memcpy(tmp_state, state, TEXT_LEN);

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(round, tmp_state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = (round - 1); round_idx > 0; --round_idx)
	{
		InvShiftRows((state_t *)tmp_state);
		InvSubBytes(tmp_state);
		AddRoundKey(round_idx, tmp_state, RoundKey);
		InvMixColumns((state_t *)tmp_state);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	InvShiftRows((state_t *)tmp_state);
	InvSubBytes(tmp_state);
	AddRoundKey(0, tmp_state, RoundKey);

	memcpy(out, tmp_state, TEXT_LEN);
}

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

// Cipher is the main function that encrypts the PlainText.
static void Intel_Cipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	__m128i rk;
	uint8_t RoundKey[(AES128_256_ROUND + 1) * TEXT_LEN];
	KeyExpansion(RoundKey, mk, mkbitsize);
	
	__m128i tmp_state = _mm_loadu_si128((__m128i *) state);

	// Add the First round key to the state before starting the rounds.
	rk = _mm_loadu_si128((const __m128i*) &RoundKey[0 * TEXT_LEN]);
	tmp_state = _mm_xor_si128(tmp_state, rk);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = 1; round_idx < round; ++round_idx)
	{
		rk = _mm_loadu_si128((const __m128i*) &RoundKey[round_idx * TEXT_LEN]);
		tmp_state = _mm_aesenc_si128(tmp_state, rk);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	rk = _mm_loadu_si128((const __m128i*) &RoundKey[round * TEXT_LEN]);
	tmp_state = _mm_aesenclast_si128(tmp_state, rk);

	_mm_storeu_si128((__m128i *) out, tmp_state);
}

// Cipher is the main function that encrypts the PlainText.
static void Intel_InvCipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	__m128i rk;
	uint8_t RoundKey[(AES128_256_ROUND + 1) * TEXT_LEN];
	KeyExpansion(RoundKey, mk, mkbitsize);

	__m128i tmp_state = _mm_loadu_si128((__m128i *) state);

	// Add the First round key to the state before starting the rounds.
	rk = _mm_loadu_si128((const __m128i*) &RoundKey[round * TEXT_LEN]);
	tmp_state = _mm_xor_si128(tmp_state, rk);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = (round - 1); round_idx > 0; --round_idx)
	{
		rk = _mm_loadu_si128((const __m128i*) &RoundKey[round_idx * TEXT_LEN]);
		tmp_state = _mm_aesdec_si128(tmp_state, _mm_aesimc_si128(rk));
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	rk = _mm_loadu_si128((const __m128i*) &RoundKey[0 * TEXT_LEN]);
	tmp_state = _mm_aesdeclast_si128(tmp_state, rk);

	_mm_storeu_si128((__m128i *) out, tmp_state);
}

// Cipher is the main function that encrypts the PlainText.
static void Intel_Cipher128(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];

	/*KeyExpansion()*/
	{
		RoundKey[0] = _mm_loadu_si128((const __m128i*) mk);
		RoundKey[1] = AES_128_key_exp(RoundKey[0], 0x01);
		RoundKey[2] = AES_128_key_exp(RoundKey[1], 0x02);
		RoundKey[3] = AES_128_key_exp(RoundKey[2], 0x04);
		RoundKey[4] = AES_128_key_exp(RoundKey[3], 0x08);
		RoundKey[5] = AES_128_key_exp(RoundKey[4], 0x10);
		RoundKey[6] = AES_128_key_exp(RoundKey[5], 0x20);
		RoundKey[7] = AES_128_key_exp(RoundKey[6], 0x40);
		RoundKey[8] = AES_128_key_exp(RoundKey[7], 0x80);
		RoundKey[9] = AES_128_key_exp(RoundKey[8], 0x1B);
		RoundKey[10] = AES_128_key_exp(RoundKey[9], 0x36);
	}
	__m128i tmp_state = _mm_loadu_si128((__m128i *) state);

	// Add the First round key to the state before starting the rounds.
	tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = 1; round_idx < round; ++round_idx)
	{
		tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

	_mm_storeu_si128((__m128i *) out, tmp_state);
}

// Cipher is the main function that encrypts the PlainText.
static void Intel_InvCipher128(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];

	/*KeyExpansion()*/
	{
		RoundKey[0] = _mm_loadu_si128((const __m128i*) mk);
		RoundKey[1] = AES_128_key_exp(RoundKey[0], 0x01);
		RoundKey[2] = AES_128_key_exp(RoundKey[1], 0x02);
		RoundKey[3] = AES_128_key_exp(RoundKey[2], 0x04);
		RoundKey[4] = AES_128_key_exp(RoundKey[3], 0x08);
		RoundKey[5] = AES_128_key_exp(RoundKey[4], 0x10);
		RoundKey[6] = AES_128_key_exp(RoundKey[5], 0x20);
		RoundKey[7] = AES_128_key_exp(RoundKey[6], 0x40);
		RoundKey[8] = AES_128_key_exp(RoundKey[7], 0x80);
		RoundKey[9] = AES_128_key_exp(RoundKey[8], 0x1B);
		RoundKey[10] = AES_128_key_exp(RoundKey[9], 0x36);
	}
	__m128i tmp_state = _mm_loadu_si128((__m128i *) state);

	// Add the First round key to the state before starting the rounds.
	tmp_state = _mm_xor_si128(tmp_state, RoundKey[round]);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for (round_idx = (round - 1); round_idx > 0; --round_idx)
	{
		tmp_state = _mm_aesdec_si128(tmp_state, _mm_aesimc_si128(RoundKey[round_idx]));
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	tmp_state = _mm_aesdeclast_si128(tmp_state, RoundKey[0]);

	_mm_storeu_si128((__m128i *) out, tmp_state);
}





static int intel_aes_ni_av = 0;

#ifdef _MSC_VER		//Visual Studio
void intel_AES_Check(void)
{
	int regs[4];
	__cpuid(regs, 1);
	if ((regs[3] & 0x2000000) != 0)
		intel_aes_ni_av = 1; //AES-NI supported
	else
		intel_aes_ni_av = 0; //AES-NI not-supported
}
#elif __GNUC__		//GCC
#include <cpuid.h>
int intel_AES_Check(void)
{
	unsigned int regs[4];
	__get_cpuid(1, &regs[0], &regs[1], &regs[2], &regs[3]);
	if ((regs[3] & 0x2000000) != 0)
		intel_aes_ni_av = 1; //AES-NI supported
	else
		intel_aes_ni_av = 0; //AES-NI not-supported
}
#endif

static void Naive_Cipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round);
static void Naive_InvCipher(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round);


static void Intel_Cipher128(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round);
static void Intel_InvCipher128(uint8_t * out, uint8_t * state, const uint8_t * mk, const int mkbitsize, const int round);

void(*Cipher)(uint8_t * , uint8_t * , const uint8_t * , const int , const int );
void(*InvCipher)(uint8_t *, uint8_t *, const uint8_t *, const int, const int);

static int aes128_128_enc_init = 1;
static int aes128_128_dec_init = 1;

static int aes128_192_enc_init = 1;
static int aes128_192_dec_init = 1;

static int aes128_256_enc_init = 1;
static int aes128_256_dec_init = 1;

int AES128_128_ENC(uint8_t ct[16], uint8_t pt[16], uint8_t mk[16], int32_t round)
{
	if (aes128_128_enc_init == 1)
	{
		uint8_t pt_tv[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		uint8_t mk_tv[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		uint8_t ct_tv[16] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
		uint8_t ct_ou[16];
		
		intel_AES_Check();
		
		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			Cipher = Intel_Cipher128;
		else 
			//Naive Implementation
			Cipher = Naive_Cipher;
		
		Cipher(ct_ou, pt_tv, mk_tv, 128, 10);

		if (memcmp(ct_ou, ct_tv, sizeof(ct_tv)) != 0)
		{
			printf("Test Fail : AES128_128 Encryption\n");
			return -1;
		}
		else
		{
			aes128_128_enc_init = 0;
		}
	}
	Cipher(ct, pt, mk, 128, round);
	return 0;
}



int AES128_128_DEC(uint8_t pt[16], uint8_t ct[16], uint8_t mk[16], int32_t round)
{
	if (aes128_128_dec_init == 1)
	{
		uint8_t pt_tv[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		uint8_t mk_tv[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		uint8_t ct_tv[16] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
		uint8_t pt_ou[16];

		intel_AES_Check();

		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			InvCipher = Intel_InvCipher128;
		else
			//Naive Implementation
			InvCipher = Naive_InvCipher;


		InvCipher(pt_ou, ct_tv, mk_tv, 128, 10);

		if (memcmp(pt_ou, pt_tv, sizeof(pt_tv)) != 0)
		{
			printf("Test Fail : AES128_128 Decryption\n");
			return -1;
		}
		else
		{
			aes128_128_dec_init = 0;
		}
	}
	InvCipher(pt, ct, mk, 128, round);
	return 0;
}

int AES128_192_ENC(uint8_t ct[16], uint8_t pt[16], uint8_t mk[24], int32_t round)
{
	if (aes128_192_enc_init == 1)
	{
		uint8_t pt_tv[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		uint8_t mk_tv[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
		uint8_t ct_tv[16] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
		uint8_t ct_ou[16];

		intel_AES_Check();

		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			Cipher = Intel_Cipher;
		else
			//Naive Implementation
			Cipher = Naive_Cipher;

		Cipher(ct_ou, pt_tv, mk_tv, 192, 12);

		if (memcmp(ct_ou, ct_tv, sizeof(ct_tv)) != 0)
		{
			printf("Test Fail : AES128_192 Encryption\n");
			return -1;
		}
		else
		{
			aes128_192_enc_init = 0;
		}
	}
	Cipher(ct, pt, mk, 192, round);
	return 0;
}


int AES128_192_DEC(uint8_t pt[16], uint8_t ct[16], uint8_t mk[24], int32_t round)
{
	if (aes128_192_dec_init == 1)
	{
		uint8_t pt_tv[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		uint8_t mk_tv[24] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
		uint8_t ct_tv[16] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
		uint8_t pt_ou[16];

		intel_AES_Check();

		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			InvCipher = Intel_InvCipher;
		else
			//Naive Implementation
			InvCipher = Naive_InvCipher;


		InvCipher(pt_ou, ct_tv, mk_tv, 192, 12);

		if (memcmp(pt_ou, pt_tv, sizeof(pt_tv)) != 0)
		{
			printf("Test Fail : AES128_192 Decryption\n");
			return -1;
		}
		else
		{
			aes128_192_dec_init = 0;
		}
	}
	InvCipher(pt, ct, mk, 192, round);
	return 0;
}

int AES128_256_ENC(uint8_t ct[16], uint8_t pt[16], uint8_t mk[32], int32_t round)
{
	if (aes128_256_enc_init == 1)
	{
		uint8_t pt_tv[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		uint8_t mk_tv[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
		uint8_t ct_tv[16] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
		uint8_t ct_ou[16];

		intel_AES_Check();

		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			Cipher = Intel_Cipher;
		else
			//Naive Implementation
			Cipher = Naive_Cipher;

		Cipher(ct_ou, pt_tv, mk_tv, 256, 14);

		if (memcmp(ct_ou, ct_tv, sizeof(ct_tv)) != 0)
		{
			printf("Test Fail : AES128_256 Encryption\n");
			return -1;
		}
		else
		{
			aes128_256_enc_init = 0;
		}
	}
	Cipher(ct, pt, mk, 256, round);
	return 0;
}


int AES128_256_DEC(uint8_t pt[16], uint8_t ct[16], uint8_t mk[32], int32_t round)
{
	if (aes128_256_dec_init == 1)
	{
		uint8_t pt_tv[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		uint8_t mk_tv[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
		uint8_t ct_tv[16] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
		uint8_t pt_ou[16];

		intel_AES_Check();

		if (intel_aes_ni_av == 1)
			//Intel AES-NI
			InvCipher = Intel_InvCipher;
		else
			//Naive Implementation
			InvCipher = Naive_InvCipher;


		InvCipher(pt_ou, ct_tv, mk_tv, 256, 14);

		if (memcmp(pt_ou, pt_tv, sizeof(pt_tv)) != 0)
		{
			printf("Test Fail : AES128_256 Decryption\n");
			return -1;
		}
		else
		{
			aes128_256_dec_init = 0;
		}
	}
	InvCipher(pt, ct, mk, 256, round);
	return 0;
}