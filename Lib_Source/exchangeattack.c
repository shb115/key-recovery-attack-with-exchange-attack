#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <immintrin.h>
#include <stdlib.h>
#include <time.h>
#include "exchangeattack.h"

#define AES128_128_ROUND 10
#define AES128_192_ROUND 12
#define AES128_256_ROUND 14

#define FAIL 0
#define SUCC 1
#define NO_NINE_PAIRS 2

int num_active_sboxes_in = 8;
int num_active_sboxes_in1 = 4;
int num_active_sboxes_in2 = 4;
int num_pasive_sboxes_ou = 4;

int in_active_indexes1[4];
int in_active_indexes2[4];
int ou_pasive_indexes[4];

typedef uint8_t ct_t[16];

typedef struct {
	uint8_t * pt;
	ct_t      ct;
}pair_t;

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

int comp_states(const void * first, const void * second)
{
	pair_t * first_ptr = (pair_t *)first;
	pair_t * second_ptr = (pair_t *)second;
	int i;

	for (i = 0; i < num_pasive_sboxes_ou; i++)
	{
		uint8_t first_val = (*first_ptr).ct[ou_pasive_indexes[i]];
		uint8_t second_val = (*second_ptr).ct[ou_pasive_indexes[i]];

		if (first_val == second_val)
			continue;
		else if (first_val > second_val)
			return 1;
		else
			return -1;
	}
	return 0;
}

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

#define getSBoxValue(num)		(sbox[(num)])

#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

static void MixColumns(uint8_t* state)
{
	int i;
	uint8_t a, b, c, d;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	state[0] = Multiply(a, 0x02) ^ Multiply(b, 0x03) ^ Multiply(c, 0x01) ^ Multiply(d, 0x01);
	state[1] = Multiply(a, 0x01) ^ Multiply(b, 0x02) ^ Multiply(c, 0x03) ^ Multiply(d, 0x01);
	state[2] = Multiply(a, 0x01) ^ Multiply(b, 0x01) ^ Multiply(c, 0x02) ^ Multiply(d, 0x03);
	state[3] = Multiply(a, 0x03) ^ Multiply(b, 0x01) ^ Multiply(c, 0x01) ^ Multiply(d, 0x02);
}

void EXCHANGE_DISTINGUISHER(uint8_t mk[16], uint8_t state[16], int32_t round)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];
	__m128i tmp_state;
	pair_t* dat_tab = NULL;
	uint64_t dat_idx1, dat_idx2, dat_idx;
	uint64_t dat = 0, a, cnt;
	uint8_t temp_state1[16], temp_state2[16];
	int idx, idx1, idx2, cnt_idx;
	int i;	
	int flag0 = 1, flag1 = 1, flag = 1;	
	uint64_t mask[8] = { 0xffffffffffffff00ULL, 0xffffffffffff00ffULL, 0xffffffffff00ffffULL, 0xffffffff00ffffffULL, 0xffffff00ffffffffULL, 0xffff00ffffffffffULL, 0xff00ffffffffffffULL, 0x00ffffffffffffff };
    uint64_t num_dat1 = (1ULL) << (15), num_dat2 = (1ULL) << (15);
    uint64_t num_dat = num_dat1 * num_dat2;			
	uint64_t found_pairs_num = 0;	
	uint8_t** found_pairs = NULL;

	// KeyExpansion()
	RoundKey[0]  = _mm_loadu_si128((const __m128i*) mk);
	RoundKey[1]  = AES_128_key_exp(RoundKey[0], 0x01);
	RoundKey[2]  = AES_128_key_exp(RoundKey[1], 0x02);
	RoundKey[3]  = AES_128_key_exp(RoundKey[2], 0x04);
	RoundKey[4]  = AES_128_key_exp(RoundKey[3], 0x08);
	RoundKey[5]  = AES_128_key_exp(RoundKey[4], 0x10);
	RoundKey[6]  = AES_128_key_exp(RoundKey[5], 0x20);
	RoundKey[7]  = AES_128_key_exp(RoundKey[6], 0x40);
	RoundKey[8]  = AES_128_key_exp(RoundKey[7], 0x80);
	RoundKey[9]  = AES_128_key_exp(RoundKey[8], 0x1B);
	RoundKey[10] = AES_128_key_exp(RoundKey[9], 0x36);

	dat_tab = (pair_t *)malloc(sizeof(pair_t)* num_dat);

	srand(time(NULL));

	in_active_indexes1[0] = 0;
	in_active_indexes1[1] = 5;
	in_active_indexes1[2] = 10;
	in_active_indexes1[3] = 15;

	in_active_indexes2[0] = 3;
	in_active_indexes2[1] = 4;
	in_active_indexes2[2] = 9;
	in_active_indexes2[3] = 14;

	for (dat_idx1 = 0; dat_idx1 < num_dat1; dat_idx1++)
	{
		//consider little-endian
		for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
		{
			a = rand() % ((1) << (8));
			dat &= mask[idx1];
			dat |= (a) << (idx1 * 8);
			state[in_active_indexes1[idx1]] = a;
		}

		for (dat_idx2 = 0; dat_idx2 < num_dat2; dat_idx2++)
		{
			dat_idx = dat_idx1 * num_dat1 + dat_idx2;			

			//consider little-endian
			for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
			{
				a = rand() % ((1) << (8));
				dat &= mask[idx2+4];
				dat |= (a) << (idx2 * 8 + 32);
				state[in_active_indexes2[idx2]] = a;
			}

			///////////////////////////////////////////////////////////////
			//Encryption
			tmp_state = _mm_loadu_si128((__m128i*) state);

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
			///////////////////////////////////////////////////////////////

			dat_tab[dat_idx].pt = (uint8_t*)malloc(sizeof(uint8_t) * num_active_sboxes_in);
			memcpy(dat_tab[dat_idx].pt, &dat, sizeof(uint8_t) * num_active_sboxes_in);
			_mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);
		}		
	}

	printf("Data Generation Finished\n");
	
	ou_pasive_indexes[0] = 3;
	ou_pasive_indexes[1] = 6;
	ou_pasive_indexes[2] = 9;
	ou_pasive_indexes[3] = 12;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	printf("Sorting Data 1 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{				
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}
				
				if ((flag0 == 1) | (flag1 == 1)) continue;
				
				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs = (uint8_t**)realloc(found_pairs, (found_pairs_num + 1) * sizeof(uint8_t*));
					if (found_pairs == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs);
						return -1;
					}

					found_pairs[found_pairs_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs[found_pairs_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs[found_pairs_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs[found_pairs_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs[found_pairs_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_num++;
				}
			}			
		}
		else cnt = 0;
	}
	
	printf("Totally Pairs are Found in Data 1\n");

	ou_pasive_indexes[0] = 2;
	ou_pasive_indexes[1] = 5;
	ou_pasive_indexes[2] = 8;
	ou_pasive_indexes[3] = 15;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	printf("Sorting Data 2 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs = (uint8_t**)realloc(found_pairs, (found_pairs_num + 1) * sizeof(uint8_t*));
					if (found_pairs == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs);
						return -1;
					}

					found_pairs[found_pairs_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs[found_pairs_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs[found_pairs_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs[found_pairs_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs[found_pairs_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_num++;
				}
			}
		}
		else cnt = 0;
	}

	printf("Totally Pairs are Found in Data 2\n");

	ou_pasive_indexes[0] = 1;
	ou_pasive_indexes[1] = 4;
	ou_pasive_indexes[2] = 11;
	ou_pasive_indexes[3] = 14;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	printf("Sorting Data 3 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs = (uint8_t**)realloc(found_pairs, (found_pairs_num + 1) * sizeof(uint8_t*));
					if (found_pairs == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs);
						return -1;
					}

					found_pairs[found_pairs_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs[found_pairs_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs[found_pairs_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs[found_pairs_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs[found_pairs_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_num++;
				}
			}
		}
		else cnt = 0;
	}

	printf("Totally Pairs are Found in Data 3\n");

	ou_pasive_indexes[0] = 0;
	ou_pasive_indexes[1] = 7;
	ou_pasive_indexes[2] = 10;
	ou_pasive_indexes[3] = 13;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	printf("Sorting Data 4 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs = (uint8_t**)realloc(found_pairs, (found_pairs_num + 1) * sizeof(uint8_t*));
					if (found_pairs == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs);
						return -1;
					}

					found_pairs[found_pairs_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs[found_pairs_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs[found_pairs_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs[found_pairs_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs[found_pairs_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_num++;
				}
			}
		}
		else cnt = 0;
		free(dat_tab[dat_idx - 1].pt);
	}
	free(dat_tab[num_dat - 1].pt);
	free(dat_tab);

	printf("Totally %llu Pairs are Found in Data 4\n", found_pairs_num);
	
	uint64_t succ = 0, fail = 0;
	uint64_t found_pairs_cnt, zero_cnt1, zero_cnt2;
	uint8_t found_pairs_partial_1_state[4], found_pairs_partial_2_state[4];

	uint8_t dia0[4] = { 0,5,10,15 }, dia1[4] = { 4,9,14,3 };
	
	for (found_pairs_cnt = 0; found_pairs_cnt < found_pairs_num; found_pairs_cnt++)
	{
		for (i = 0; i < 4; i++)
		{
			found_pairs_partial_1_state[i] = found_pairs[found_pairs_cnt][i] ^ mk[dia0[i]];
			found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

			found_pairs_partial_2_state[i] = found_pairs[found_pairs_cnt][i + 8] ^ mk[dia0[i]];
			found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
		}

		MixColumns(found_pairs_partial_1_state);
		MixColumns(found_pairs_partial_2_state);

		for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

		zero_cnt1 = 0;

		for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt1++;

		for (i = 0; i < 4; i++)
		{
			found_pairs_partial_1_state[i] = found_pairs[found_pairs_cnt][((i + 1) % 4) + 4] ^ mk[dia1[i]];
			found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

			found_pairs_partial_2_state[i] = found_pairs[found_pairs_cnt][((i + 1) % 4) + 12] ^ mk[dia1[i]];
			found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
		}

		MixColumns(found_pairs_partial_1_state);
		MixColumns(found_pairs_partial_2_state);

		for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

		zero_cnt2 = 0;

		for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt2++;

		if (zero_cnt1 == 0 || zero_cnt2 == 0) fail++;
		else succ++;
	}

	printf("succ : %llu\n", succ);
	printf("fail : %llu\n", fail);
}

uint64_t EXCHANGE_DISTINGUISHER_NUM_ONLY(uint8_t mk[16], uint8_t state[16], int32_t round)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];
	__m128i tmp_state;
	pair_t* dat_tab = NULL;
	uint64_t dat_idx1, dat_idx2, dat_idx;
	uint64_t dat = 0, a;
	uint64_t cnt = 0;
	uint8_t temp_state1[16], temp_state2[16];
	int idx, idx1, idx2, cnt_idx;
	int i;	
	int flag0 = 1, flag1 = 1, flag = 1;
	uint64_t mask[8] = { 0xffffffffffffff00ULL, 0xffffffffffff00ffULL, 0xffffffffff00ffffULL, 0xffffffff00ffffffULL, 0xffffff00ffffffffULL, 0xffff00ffffffffffULL, 0xff00ffffffffffffULL, 0x00ffffffffffffff };
	uint64_t num_dat1 = (1ULL) << (15), num_dat2 = (1ULL) << (15);
    uint64_t num_dat = num_dat1 * num_dat2;
	uint64_t found_pairs = 0;

	/*KeyExpansion()*/
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

	in_active_indexes1[0] = 0;
	in_active_indexes1[1] = 5;
	in_active_indexes1[2] = 10;
	in_active_indexes1[3] = 15;

	in_active_indexes2[0] = 3;
	in_active_indexes2[1] = 4;
	in_active_indexes2[2] = 9;
	in_active_indexes2[3] = 14;

	dat_tab = (pair_t*)malloc(sizeof(pair_t) * num_dat);

	srand(time(NULL));

	for (dat_idx1 = 0; dat_idx1 < num_dat1; dat_idx1++)
	{
		//consider little-endian
		for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
		{
			a = rand() % ((1) << (8));
			dat &= mask[idx1];
			dat |= (a) << (idx1 * 8);
			state[in_active_indexes1[idx1]] = a;
		}

		for (dat_idx2 = 0; dat_idx2 < num_dat2; dat_idx2++)
		{
			dat_idx = dat_idx1 * num_dat1 + dat_idx2;

			//consider little-endian
			for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
			{
				a = rand() % ((1) << (8));
				dat &= mask[idx2 + 4];
				dat |= (a) << (idx2 * 8 + 32);
				state[in_active_indexes2[idx2]] = a;
			}

			///////////////////////////////////////////////////////////////
			//Encryption
			tmp_state = _mm_loadu_si128((__m128i*) state);

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
			///////////////////////////////////////////////////////////////

			dat_tab[dat_idx].pt = (uint8_t*)malloc(sizeof(uint8_t) * num_active_sboxes_in);
			memcpy(dat_tab[dat_idx].pt, &dat, sizeof(uint8_t) * num_active_sboxes_in);
			_mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);
		}
	}

	ou_pasive_indexes[0] = 3;
	ou_pasive_indexes[1] = 6;
	ou_pasive_indexes[2] = 9;
	ou_pasive_indexes[3] = 12;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}	

				if (flag == 1) found_pairs++;
			}
		}
		else cnt = 0;
	}

	ou_pasive_indexes[0] = 2;
	ou_pasive_indexes[1] = 5;
	ou_pasive_indexes[2] = 8;
	ou_pasive_indexes[3] = 15;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}	

				if (flag == 1) found_pairs++;
			}
		}
		else cnt = 0;
	}

	ou_pasive_indexes[0] = 1;
	ou_pasive_indexes[1] = 4;
	ou_pasive_indexes[2] = 11;
	ou_pasive_indexes[3] = 14;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1) found_pairs++;
			}
		}
		else cnt = 0;
	}

	ou_pasive_indexes[0] = 0;
	ou_pasive_indexes[1] = 7;
	ou_pasive_indexes[2] = 10;
	ou_pasive_indexes[3] = 13;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}	

				if (flag == 1) found_pairs++;
			}
		}
		else cnt = 0;
		free(dat_tab[dat_idx - 1].pt);
	}
	free(dat_tab[num_dat - 1].pt);
	free(dat_tab);

	return found_pairs;
}

uint64_t EXCHANGE_KEY_RECOVERY(uint8_t mk[16], uint8_t state[16], int32_t round)
{
	uint8_t round_idx = 0;
	__m128i RoundKey[AES128_128_ROUND + 1];
	__m128i tmp_state;
	pair_t* dat_tab;
	uint64_t dat_idx1, dat_idx2, dat_idx;
	uint64_t dat = 0, a, cnt;
	uint8_t temp_state1[16], temp_state2[16];
	int idx, idx1, idx2, cnt_idx;
	int i;
	int flag0 = 1, flag1 = 1, flag = 1;	
	uint64_t mask[8] = { 0xffffffffffffff00ULL, 0xffffffffffff00ffULL, 0xffffffffff00ffffULL, 0xffffffff00ffffffULL, 0xffffff00ffffffffULL, 0xffff00ffffffffffULL, 0xff00ffffffffffffULL, 0x00ffffffffffffff };
    uint64_t num_dat1 = 41494; // 2**15.34
    uint64_t num_dat2 = 41494; // 2**15.34
    uint64_t num_dat = num_dat1 * num_dat2;	
	uint64_t found_pairs_1_num = 0;
	uint64_t found_pairs_2_num = 0;
	uint8_t** found_pairs_1 = NULL;
	uint8_t** found_pairs_2 = NULL;

	//KeyExpansion()
	RoundKey[0]  = _mm_loadu_si128((const __m128i*) mk);
	RoundKey[1]  = AES_128_key_exp(RoundKey[0], 0x01);
	RoundKey[2]  = AES_128_key_exp(RoundKey[1], 0x02);
	RoundKey[3]  = AES_128_key_exp(RoundKey[2], 0x04);
	RoundKey[4]  = AES_128_key_exp(RoundKey[3], 0x08);
	RoundKey[5]  = AES_128_key_exp(RoundKey[4], 0x10);
	RoundKey[6]  = AES_128_key_exp(RoundKey[5], 0x20);
	RoundKey[7]  = AES_128_key_exp(RoundKey[6], 0x40);
	RoundKey[8]  = AES_128_key_exp(RoundKey[7], 0x80);
	RoundKey[9]  = AES_128_key_exp(RoundKey[8], 0x1B);
	RoundKey[10] = AES_128_key_exp(RoundKey[9], 0x36);

	srand(time(NULL));

	in_active_indexes1[0] = 0;
	in_active_indexes1[1] = 5;
	in_active_indexes1[2] = 10;
	in_active_indexes1[3] = 15;

	in_active_indexes2[0] = 3;
	in_active_indexes2[1] = 4;
	in_active_indexes2[2] = 9;
	in_active_indexes2[3] = 14;

	dat_tab = (pair_t*)malloc(sizeof(pair_t) * num_dat);

	for (dat_idx1 = 0; dat_idx1 < num_dat1; dat_idx1++)
	{
		//consider little-endian
		for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
		{
			a = rand() % ((1) << (8));
			dat &= mask[idx1];
			dat |= (a) << (idx1 * 8);
			state[in_active_indexes1[idx1]] = a;
		}

		for (dat_idx2 = 0; dat_idx2 < num_dat2; dat_idx2++)
		{
			dat_idx = dat_idx1 * num_dat1 + dat_idx2;			

			//consider little-endian
			for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
			{
				a = rand() % ((1) << (8));
				dat &= mask[idx2+4];
				dat |= (a) << (idx2 * 8 + 32);
				state[in_active_indexes2[idx2]] = a;
			}

			///////////////////////////////////////////////////////////////
			//Encryption
			tmp_state = _mm_loadu_si128((__m128i*) state);

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
			///////////////////////////////////////////////////////////////

			dat_tab[dat_idx].pt = (uint8_t*)malloc(sizeof(uint8_t) * num_active_sboxes_in);
			if (dat_tab[dat_idx].pt == NULL) printf("dat_tab[dat_idx].pt==NULL");
			memcpy(dat_tab[dat_idx].pt, &dat, sizeof(uint8_t) * num_active_sboxes_in);
			_mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);
			if (dat_tab[dat_idx].ct == NULL) printf("dat_tab[dat_idx].ct==NULL");
		}		
	}

	//printf("Data 1 Generation Finished\n");

	ou_pasive_indexes[0] = 3;
	ou_pasive_indexes[1] = 6;
	ou_pasive_indexes[2] = 9;
	ou_pasive_indexes[3] = 12;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 1.1 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{				
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}
				
				if ((flag0 == 1) | (flag1 == 1)) continue;
				
				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_1 = (uint8_t**)realloc(found_pairs_1, (found_pairs_1_num + 1) * sizeof(uint8_t*));
					if (found_pairs_1 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_1);
						return -1;
					}

					found_pairs_1[found_pairs_1_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_1[found_pairs_1_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs_1[found_pairs_1_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_1[found_pairs_1_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_1[found_pairs_1_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_1_num++;
				}
			}			
		}
		else cnt = 0;
	}
	
	//printf("Totally Pairs are Found in Data 1.1\n");

	ou_pasive_indexes[0] = 2;
	ou_pasive_indexes[1] = 5;
	ou_pasive_indexes[2] = 8;
	ou_pasive_indexes[3] = 15;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 1.2 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_1 = (uint8_t**)realloc(found_pairs_1, (found_pairs_1_num + 1) * sizeof(uint8_t*));
					if (found_pairs_1 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_1);
						return -1;
					}

					found_pairs_1[found_pairs_1_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_1[found_pairs_1_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs_1[found_pairs_1_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_1[found_pairs_1_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_1[found_pairs_1_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_1_num++;
				}
			}
		}
		else cnt = 0;
	}

	//printf("Totally Pairs are Found in Data 1.2\n");

	ou_pasive_indexes[0] = 1;
	ou_pasive_indexes[1] = 4;
	ou_pasive_indexes[2] = 11;
	ou_pasive_indexes[3] = 14;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 1.3 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_1 = (uint8_t**)realloc(found_pairs_1, (found_pairs_1_num + 1) * sizeof(uint8_t*));
					if (found_pairs_1 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_1);
						return -1;
					}

					found_pairs_1[found_pairs_1_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_1[found_pairs_1_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs_1[found_pairs_1_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_1[found_pairs_1_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_1[found_pairs_1_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_1_num++;
				}
			}
		}
		else cnt = 0;
	}

	//printf("Totally Pairs are Found in Data 1.3\n");

	ou_pasive_indexes[0] = 0;
	ou_pasive_indexes[1] = 7;
	ou_pasive_indexes[2] = 10;
	ou_pasive_indexes[3] = 13;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 1.4 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_1 = (uint8_t**)realloc(found_pairs_1, (found_pairs_1_num + 1) * sizeof(uint8_t*));
					if (found_pairs_1 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_1);
						return -1;
					}

					found_pairs_1[found_pairs_1_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_1[found_pairs_1_num] == NULL)
					{
						printf("found_pairs_1[found_pairs_1_num] memory reallocation fail\n");
						free(found_pairs_1[found_pairs_1_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_1[found_pairs_1_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_1[found_pairs_1_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_1_num++;
				}
			}
		}
		else cnt = 0;
		free(dat_tab[dat_idx - 1].pt);
	}
	free(dat_tab[num_dat - 1].pt);
	free(dat_tab);

	//printf("Totally Pairs are Found in Data 1.4\n");	

	//printf("found_pairs_1_num: %llu\n", found_pairs_1_num);

	in_active_indexes1[0] = 2;
	in_active_indexes1[1] = 7;
	in_active_indexes1[2] = 8;
	in_active_indexes1[3] = 13;

	in_active_indexes2[0] = 1;
	in_active_indexes2[1] = 6;
	in_active_indexes2[2] = 11;
	in_active_indexes2[3] = 12;

	dat_tab = (pair_t*)malloc(sizeof(pair_t) * num_dat);

	for (dat_idx1 = 0; dat_idx1 < num_dat1; dat_idx1++)
	{
		//consider little-endian
		for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
		{
			a = rand() % ((1) << (8));
			dat &= mask[idx1];
			dat |= (a) << (idx1 * 8);
			state[in_active_indexes1[idx1]] = a;
		}

		for (dat_idx2 = 0; dat_idx2 < num_dat2; dat_idx2++)
		{
			dat_idx = dat_idx1 * num_dat1 + dat_idx2;

			//consider little-endian
			for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
			{
				a = rand() % ((1) << (8));
				dat &= mask[idx2 + 4];
				dat |= (a) << (idx2 * 8 + 32);
				state[in_active_indexes2[idx2]] = a;
			}

			///////////////////////////////////////////////////////////////
			//Encryption
			tmp_state = _mm_loadu_si128((__m128i*) state);

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
			///////////////////////////////////////////////////////////////

			dat_tab[dat_idx].pt = (uint8_t*)malloc(sizeof(uint8_t) * num_active_sboxes_in);
			if (dat_tab[dat_idx].pt == NULL) printf("dat_tab[dat_idx].pt==NULL");
			memcpy(dat_tab[dat_idx].pt, &dat, sizeof(uint8_t) * num_active_sboxes_in);
			_mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);
			if (dat_tab[dat_idx].ct == NULL) printf("dat_tab[dat_idx].ct==NULL");
		}
	}

	//printf("Data 2 Generation Finished\n");

	ou_pasive_indexes[0] = 3;
	ou_pasive_indexes[1] = 6;
	ou_pasive_indexes[2] = 9;
	ou_pasive_indexes[3] = 12;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 2.1 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt++;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}
				
				if (flag == 1)
				{
					found_pairs_2 = (uint8_t**)realloc(found_pairs_2, (found_pairs_2_num + 1) * sizeof(uint8_t*));
					if (found_pairs_2 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_2);
						return -1;
					}

					found_pairs_2[found_pairs_2_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_2[found_pairs_2_num] == NULL)
					{
						printf("found_pairs_2[found_pairs_2_num] memory reallocation fail\n");
						free(found_pairs_2[found_pairs_2_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_2[found_pairs_2_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_2[found_pairs_2_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_2_num++;
				}
			}
		}
		else cnt = 0;
	}

	//printf("Totally Pairs are Found in Data 2.1\n");

	ou_pasive_indexes[0] = 2;
	ou_pasive_indexes[1] = 5;
	ou_pasive_indexes[2] = 8;
	ou_pasive_indexes[3] = 15;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 2.2 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt++;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_2 = (uint8_t**)realloc(found_pairs_2, (found_pairs_2_num + 1) * sizeof(uint8_t*));
					if (found_pairs_2 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_2);
						return -1;
					}

					found_pairs_2[found_pairs_2_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_2[found_pairs_2_num] == NULL)
					{
						printf("found_pairs_2[found_pairs_2_num] memory reallocation fail\n");
						free(found_pairs_2[found_pairs_2_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_2[found_pairs_2_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_2[found_pairs_2_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_2_num++;
				}
			}
		}
		else cnt = 0;
	}

	//printf("Totally Pairs are Found in Data 2.2\n");

	ou_pasive_indexes[0] = 1;
	ou_pasive_indexes[1] = 4;
	ou_pasive_indexes[2] = 11;
	ou_pasive_indexes[3] = 14;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 2.3 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_2 = (uint8_t**)realloc(found_pairs_2, (found_pairs_2_num + 1) * sizeof(uint8_t*));
					if (found_pairs_2 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_2);
						return -1;
					}

					found_pairs_2[found_pairs_2_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_2[found_pairs_2_num] == NULL)
					{
						printf("found_pairs_2[found_pairs_2_num] memory reallocation fail\n");
						free(found_pairs_2[found_pairs_2_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_2[found_pairs_2_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_2[found_pairs_2_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_2_num++;
				}
			}
		}
		else cnt = 0;
	}

	//printf("Totally Pairs are Found in Data 2.3\n");

	ou_pasive_indexes[0] = 0;
	ou_pasive_indexes[1] = 7;
	ou_pasive_indexes[2] = 10;
	ou_pasive_indexes[3] = 13;

	qsort(dat_tab, num_dat, sizeof(pair_t), comp_states);

	//printf("Sorting Data 2.4 Finished\n");

	cnt = 0;

	for (dat_idx = 1; dat_idx < num_dat; dat_idx++)
	{
		if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
		{
			cnt += 1;

			for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
			{
				flag0 = 1;
				flag1 = 1;
				flag = 1;

				for (i = 0; i < num_active_sboxes_in1; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag0 = 0;
						break;
					}
				}
				for (i = 4; i < num_active_sboxes_in; i++)
				{
					if (dat_tab[(dat_idx - cnt_idx)].pt[i] != dat_tab[(dat_idx)].pt[i])
					{
						flag1 = 0;
						break;
					}
				}

				if ((flag0 == 1) | (flag1 == 1)) continue;

				for (i = 0; i < 16; i++)
				{
					temp_state1[i] = state[i];
					temp_state2[i] = state[i];
				}

				for (idx1 = 0; idx1 < num_active_sboxes_in1; idx1++)
				{
					temp_state1[in_active_indexes1[idx1]] = dat_tab[(dat_idx - cnt_idx)].pt[idx1];
					temp_state2[in_active_indexes1[idx1]] = dat_tab[(dat_idx)].pt[idx1];
				}
				for (idx2 = 0; idx2 < num_active_sboxes_in2; idx2++)
				{
					temp_state1[in_active_indexes2[idx2]] = dat_tab[(dat_idx)].pt[idx2 + 4];
					temp_state2[in_active_indexes2[idx2]] = dat_tab[(dat_idx - cnt_idx)].pt[idx2 + 4];
				}

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state1);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state1, tmp_state);
				///////////////////////////////////////////////////////////////

				///////////////////////////////////////////////////////////////
				//Encryption
				tmp_state = _mm_loadu_si128((__m128i*) temp_state2);

				// Add the First round key to the state before starting the rounds.
				tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);

				// There will be Nr rounds.
				// The first Nr-1 rounds are identical.
				// These Nr-1 rounds are executed in the loop below.
				for (round_idx = 1; round_idx < round; ++round_idx) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);

				// The last round is given below.
				// The MixColumns function is not here in the last round.
				tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[round]);

				_mm_storeu_si128((__m128i*) temp_state2, tmp_state);
				///////////////////////////////////////////////////////////////

				for (idx = 0; idx < num_pasive_sboxes_ou; idx++)
				{
					if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
					{
						flag = 0;
						break;
					}
				}

				if (flag == 1)
				{
					found_pairs_2 = (uint8_t**)realloc(found_pairs_2, (found_pairs_2_num + 1) * sizeof(uint8_t*));
					if (found_pairs_2 == NULL)
					{
						printf("found_pairs_1 memory reallocation fail\n");
						free(found_pairs_2);
						return -1;
					}

					found_pairs_2[found_pairs_2_num] = (uint8_t*)malloc(16 * sizeof(uint8_t));
					if (found_pairs_2[found_pairs_2_num] == NULL)
					{
						printf("found_pairs_2[found_pairs_2_num] memory reallocation fail\n");
						free(found_pairs_2[found_pairs_2_num]);
						return -1;
					}

					for (i = 0; i < 8; i++)
					{
						found_pairs_2[found_pairs_2_num][i] = dat_tab[(dat_idx)].pt[i];
						found_pairs_2[found_pairs_2_num][i + 8] = dat_tab[(dat_idx - cnt_idx)].pt[i];
					}

					found_pairs_2_num++;
				}
			}
		}
		else cnt = 0;
		free(dat_tab[dat_idx - 1].pt);
	}
	free(dat_tab[num_dat - 1].pt);
	free(dat_tab);

	//printf("Totally Pairs are Found in Data 2.4\n");
	
	//printf("found_pairs_2_num: %llu\n", found_pairs_2_num);	

	if (found_pairs_1_num + found_pairs_2_num < 9)
	{
		return NO_NINE_PAIRS;
	}

	int found_pairs_cnt, zero_cnt1 = 0, zero_cnt2 = 0;

	uint32_t* key_candidate_dia0 = NULL;
	uint32_t* key_candidate_dia1 = NULL;
	uint32_t* key_candidate_dia2 = NULL;
	uint32_t* key_candidate_dia3 = NULL;
	uint64_t key_candidate_num_dia0 = 0;
	uint64_t key_candidate_num_dia1 = 0;
	uint64_t key_candidate_num_dia2 = 0;
	uint64_t key_candidate_num_dia3 = 0;
	int flag_key_dia0;
	int flag_key_dia1;
	int flag_key_dia2;
	int flag_key_dia3;

	uint64_t key_guess;
	uint8_t found_pairs_partial_1_state[4], found_pairs_partial_2_state[4] ;

	uint8_t dia0[4] = { 0,5,10,15 }, dia1[4] = { 4,9,14,3 }, dia2[4] = { 8,13,2,7 }, dia3[4] = { 12,1,6,11 };
	
	for (key_guess = 0; key_guess <= UINT32_MAX; key_guess++)
	{
		flag_key_dia0 = 1;
		flag_key_dia1 = 1;

		for (found_pairs_cnt = 0; found_pairs_cnt < found_pairs_1_num; found_pairs_cnt++)
		{
			for (i = 0; i < 4; i++)
			{
				found_pairs_partial_1_state[i] = found_pairs_1[found_pairs_cnt][i] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

				found_pairs_partial_2_state[i] = found_pairs_1[found_pairs_cnt][i + 8] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
			}

			MixColumns(found_pairs_partial_1_state);
			MixColumns(found_pairs_partial_2_state);

			for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

			zero_cnt1 = 0;

			for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt1++;

			for (i = 0; i < 4; i++)
			{
				found_pairs_partial_1_state[i] = found_pairs_1[found_pairs_cnt][((i + 1) % 4) + 4] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

				found_pairs_partial_2_state[i] = found_pairs_1[found_pairs_cnt][((i + 1) % 4) + 12] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
			}

			MixColumns(found_pairs_partial_1_state);
			MixColumns(found_pairs_partial_2_state);

			for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

			zero_cnt2 = 0;

			for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt2++;

			if (zero_cnt1 == 0) flag_key_dia0 = 0;
			if (zero_cnt2 == 0) flag_key_dia1 = 0;
		}

		if (flag_key_dia0 == 1)
		{
			key_candidate_dia0 = (uint32_t*)realloc(key_candidate_dia0, (key_candidate_num_dia0 + 1) * sizeof(uint32_t));
			if (key_candidate_dia0 == NULL)
			{
				printf("key_candidate_dia0 memory reallocation fail\n");
				free(key_candidate_dia0);
				return 1;
			}

			key_candidate_dia0[key_candidate_num_dia0] = key_guess;
			key_candidate_num_dia0++;
		}

		if (flag_key_dia1 == 1)
		{
			key_candidate_dia1 = (uint32_t*)realloc(key_candidate_dia1, (key_candidate_num_dia1 + 1) * sizeof(uint32_t));
			if (key_candidate_dia1 == NULL)
			{
				printf("key_candidate_dia1 memory reallocation fail\n");
				free(key_candidate_dia1);
				return 1;
			}

			key_candidate_dia1[key_candidate_num_dia1] = key_guess;
			key_candidate_num_dia1++;
		}
	}

	//printf("key_candidate_num_dia0: %llu\n", key_candidate_num_dia0);
	//printf("key_candidate_num_dia1: %llu\n", key_candidate_num_dia1);

	for (key_guess = 0; key_guess <= UINT32_MAX; key_guess++)
	{
		flag_key_dia2 = 1;
		flag_key_dia3 = 1;

		for (found_pairs_cnt = 0; found_pairs_cnt < found_pairs_2_num; found_pairs_cnt++)
		{
			for (i = 0; i < 4; i++)
			{
				found_pairs_partial_1_state[i] = found_pairs_2[found_pairs_cnt][((i + 2) % 4)] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

				found_pairs_partial_2_state[i] = found_pairs_2[found_pairs_cnt][((i + 2) % 4) + 8] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
			}

			MixColumns(found_pairs_partial_1_state);
			MixColumns(found_pairs_partial_2_state);

			for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

			zero_cnt1 = 0;

			for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt1++;

			for (i = 0; i < 4; i++)
			{
				found_pairs_partial_1_state[i] = found_pairs_2[found_pairs_cnt][((i + 3) % 4) + 4] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_1_state[i] = getSBoxValue(found_pairs_partial_1_state[i]);

				found_pairs_partial_2_state[i] = found_pairs_2[found_pairs_cnt][((i + 3) % 4) + 12] ^ ((key_guess >> ((3 - i) * 8)) & 0xff);
				found_pairs_partial_2_state[i] = getSBoxValue(found_pairs_partial_2_state[i]);
			}

			MixColumns(found_pairs_partial_1_state);
			MixColumns(found_pairs_partial_2_state);

			for (i = 0; i < 4; i++) found_pairs_partial_1_state[i] ^= found_pairs_partial_2_state[i];

			zero_cnt2 = 0;

			for (i = 0; i < 4; i++) if (found_pairs_partial_1_state[i] == 0) zero_cnt2++;

			if (zero_cnt1 == 0) flag_key_dia2 = 0;
			if (zero_cnt2 == 0) flag_key_dia3 = 0;
		}		

		if (flag_key_dia2 == 1)
		{
			key_candidate_dia2 = (uint32_t*)realloc(key_candidate_dia2, (key_candidate_num_dia2 + 1) * sizeof(uint32_t));
			if (key_candidate_dia2 == NULL)
			{
				printf("key_candidate_dia2 memory reallocation fail\n");
				free(key_candidate_dia2);
				return 1;
			}

			key_candidate_dia2[key_candidate_num_dia2] = key_guess;
			key_candidate_num_dia2++;
		}

		if (flag_key_dia3 == 1)
		{
			key_candidate_dia3 = (uint32_t*)realloc(key_candidate_dia3, (key_candidate_num_dia3 + 1) * sizeof(uint32_t));
			if (key_candidate_dia3 == NULL)
			{
				printf("key_candidate_dia3 memory reallocation fail\n");
				free(key_candidate_dia3);
				return 1;
			}

			key_candidate_dia3[key_candidate_num_dia3] = key_guess;
			key_candidate_num_dia3++;
		}
	}
		
	//printf("key_candidate_num_dia2: %llu\n", key_candidate_num_dia2);
	//printf("key_candidate_num_dia3: %llu\n", key_candidate_num_dia3);

	uint8_t key_candidate[16];
	uint32_t key_dia0, key_dia1, key_dia2, key_dia3;

	if (key_candidate_num_dia0 == 0 || key_candidate_num_dia1 == 0 || key_candidate_num_dia2 == 0 || key_candidate_num_dia3 == 0)
	{
		free(key_candidate_dia0);
		free(key_candidate_dia1);
		free(key_candidate_dia2);
		free(key_candidate_dia3);
		return FAIL;
	}

	for (key_dia0 = 0; key_dia0 < key_candidate_num_dia0; key_dia0++)
	{
		for (i = 0; i < 4; i++) key_candidate[dia0[i]] = (key_candidate_dia0[key_dia0] >> ((3 - i) * 8)) & 0xff;

		for (key_dia1 = 0; key_dia1 < key_candidate_num_dia1; key_dia1++)
		{
			for (i = 0; i < 4; i++) key_candidate[dia1[i]] = (key_candidate_dia1[key_dia1] >> ((3 - i) * 8)) & 0xff;

			for (key_dia2 = 0; key_dia2 < key_candidate_num_dia2; key_dia2++)
			{
				for (i = 0; i < 4; i++) key_candidate[dia2[i]] = (key_candidate_dia2[key_dia2] >> ((3 - i) * 8)) & 0xff;

				for (key_dia3 = 0; key_dia3 < key_candidate_num_dia3; key_dia3++)
				{
					for (i = 0; i < 4; i++) key_candidate[dia3[i]] = (key_candidate_dia3[key_dia3] >> ((3 - i) * 8)) & 0xff;

					flag = 1;

					for (i = 0; i < 16; i++)
					{
						if (key_candidate[i] != mk[i])
						{
							flag = 0;
							break;
						}
					}

					if (flag == 1)
					{
						free(key_candidate_dia0);
						free(key_candidate_dia1);
						free(key_candidate_dia2);
						free(key_candidate_dia3);

						return SUCC;
					}
						
				}				
			}
		}
	}	

	free(key_candidate_dia0);
	free(key_candidate_dia1);
	free(key_candidate_dia2);
	free(key_candidate_dia3);

	return FAIL;
}
