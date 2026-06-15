/*
 * exchangeattack.c
 * - Standalone Version for GCC/Linux/WSL
 * - Fixed 5-Round Experiment
 * - English Comments Only
 */

#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <immintrin.h> // Required for AES-NI Intrinsics

// ---------------------------------------------------------------------------
// 1. Configuration
// ---------------------------------------------------------------------------
#define TARGET_ROUND    5       // Fixed to 5 rounds as requested
#define TEST_SAMPLES    100     // Number of test iterations

// Data Size Configuration: 2^DATA_LOG (e.g., 15 -> 2^15 = 32768)
// Total Data = NUM_DAT1 * NUM_DAT2 = 2^(DATA_LOG * 2)
// WARNING: DATA_LOG 15 requires approx 24~32GB RAM. 
// If you have low memory, reduce this to 12 or 13.
#define DATA_LOG        15      
#define NUM_DAT1        (1ULL << DATA_LOG)
#define NUM_DAT2        (1ULL << DATA_LOG)
#define NUM_DAT         (NUM_DAT1 * NUM_DAT2)

// ---------------------------------------------------------------------------
// 2. Data Structures & Globals
// ---------------------------------------------------------------------------
typedef uint8_t ct_t[16];

typedef struct {
    uint8_t * pt; // Store pointer only to save memory (8 bytes actual data is malloc'd)
    ct_t      ct;
} pair_t;

// AES & Attack Globals
int num_pasive_sboxes_ou = 4;
int ou_pasive_indexes[4]; // Updated dynamically during phases
int in_active_indexes1[4];
int in_active_indexes2[4];

// AES S-Box
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

// ---------------------------------------------------------------------------
// 3. Helper Functions
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// 4. Core Function (Distinguisher)
// ---------------------------------------------------------------------------
uint64_t RUN_DISTINGUISHER(uint8_t mk[16], uint8_t state[16])
{
    // Variable Declarations (Top of the block for safety)
    uint8_t round_idx = 0;
    __m128i RoundKey[11]; // AES-128 has 10 rounds, 11 keys
    __m128i tmp_state;
    pair_t* dat_tab = NULL;
    
    unsigned long long dat_idx = 0;
    unsigned long long i_idx, j_idx;
    unsigned long long cnt = 0;
    int idx, idx1, cnt_idx, i, k, b, phase;
    int flag0, flag1, flag;
    
    uint8_t temp_state1[16], temp_state2[16];
    uint8_t base_pt[16];
    uint8_t current_pt[16];
    
    pair_t *p1 = NULL;
    pair_t *p2 = NULL;
    
    uint64_t total_found_pairs = 0;

    // Phases for Output Filtering
    int PASSIVE_SETS[4][4] = {
        {3, 6, 9, 12},  // Phase 1
        {2, 5, 8, 15},  // Phase 2
        {1, 4, 11, 14}, // Phase 3
        {0, 7, 10, 13}  // Phase 4
    };

    uint8_t (*rand_diag0)[4] = NULL;
    uint8_t (*rand_diag1)[4] = NULL;

    // Fixed Active Indices (Input)
    in_active_indexes1[0] = 0; in_active_indexes1[1] = 5; in_active_indexes1[2] = 10; in_active_indexes1[3] = 15;
    in_active_indexes2[0] = 3; in_active_indexes2[1] = 4; in_active_indexes2[2] = 9;  in_active_indexes2[3] = 14;

    // Key Expansion
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

    // Memory Allocation
    // printf("[*] Allocating Memory for 2^%d elements...\n", DATA_LOG * 2);
    dat_tab = (pair_t *)malloc(sizeof(pair_t) * NUM_DAT);
    if (dat_tab == NULL) {
        printf("[Fatal Error] Memory allocation failed. Reduce DATA_LOG.\n");
        exit(1);
    }

    rand_diag0 = malloc(sizeof(uint8_t[4]) * NUM_DAT1);
    rand_diag1 = malloc(sizeof(uint8_t[4]) * NUM_DAT2);

    if (!rand_diag0 || !rand_diag1) {
        printf("[Fatal Error] Aux buffer alloc failed.\n");
        exit(1);
    }

    // Pre-generate random diagonals
    for(i_idx=0; i_idx < NUM_DAT1; i_idx++) {
        for(b=0; b<4; b++) rand_diag0[i_idx][b] = rand() & 0xFF;
    }
    for(j_idx=0; j_idx < NUM_DAT2; j_idx++) {
        for(b=0; b<4; b++) rand_diag1[j_idx][b] = rand() & 0xFF;
    }

    memcpy(base_pt, state, 16);

    // Data Generation (Double Loop)
    dat_idx = 0;
    for (i_idx = 0; i_idx < NUM_DAT1; i_idx++)
    {
        for (j_idx = 0; j_idx < NUM_DAT2; j_idx++)
        {
            memcpy(current_pt, base_pt, 16);

            // Set Diagonal 0
            for(b=0; b<4; b++) current_pt[in_active_indexes1[b]] = rand_diag0[i_idx][b];
            // Set Diagonal 1
            for(b=0; b<4; b++) current_pt[in_active_indexes2[b]] = rand_diag1[j_idx][b];

            tmp_state = _mm_loadu_si128((__m128i*) current_pt);
            tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]); 
            
            // Fixed Loop for TARGET_ROUND
            for (round_idx = 1; round_idx < TARGET_ROUND; ++round_idx) {
                tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);
            }
            tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[TARGET_ROUND]);

            _mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);
            
            // Save plaintexts (Only 8 bytes to save memory)
            dat_tab[dat_idx].pt = (uint8_t*)malloc(sizeof(uint8_t) * 8); 
            for(b=0; b<4; b++) {
                dat_tab[dat_idx].pt[b]   = rand_diag0[i_idx][b];
                dat_tab[dat_idx].pt[b+4] = rand_diag1[j_idx][b];
            }
            
            dat_idx++;
        }
    }

    free(rand_diag0);
    free(rand_diag1);

    // Collision Check Loops
    for (phase = 0; phase < 4; phase++)
    {
        // Update GLOBAL passive indexes for comp_states
        for(k=0; k<4; k++) ou_pasive_indexes[k] = PASSIVE_SETS[phase][k];
        
        qsort(dat_tab, NUM_DAT, sizeof(pair_t), comp_states);

        cnt = 0;
        for (dat_idx = 1; dat_idx < NUM_DAT; dat_idx++)
        {
            if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0)
            {
                cnt += 1;

                for (cnt_idx = 1; cnt_idx <= cnt; cnt_idx++)
                {
                    flag0 = 1; 
                    flag1 = 1; 
                    flag = 1; 

                    p1 = &dat_tab[dat_idx - cnt_idx];
                    p2 = &dat_tab[dat_idx];

                    // Input Difference Check
                    for (i = 0; i < 4; i++) {
                        if (p1->pt[i] != p2->pt[i]) { flag0 = 0; break; }
                    }
                    for (i = 4; i < 8; i++) {
                        if (p1->pt[i] != p2->pt[i]) { flag1 = 0; break; }
                    }

                    if ((flag0 == 1) || (flag1 == 1)) continue;

                    // Re-encryption & Verification
                    memcpy(temp_state1, base_pt, 16);
                    memcpy(temp_state2, base_pt, 16);

                    for (idx1 = 0; idx1 < 4; idx1++) {
                        temp_state1[in_active_indexes1[idx1]] = p1->pt[idx1];
                        temp_state2[in_active_indexes1[idx1]] = p2->pt[idx1];
                        temp_state1[in_active_indexes2[idx1]] = p2->pt[idx1 + 4];
                        temp_state2[in_active_indexes2[idx1]] = p1->pt[idx1 + 4];
                    }

                    tmp_state = _mm_loadu_si128((__m128i*) temp_state1);
                    tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);
                    for (round_idx = 1; round_idx < TARGET_ROUND; ++round_idx) 
                        tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);
                    tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[TARGET_ROUND]);
                    _mm_storeu_si128((__m128i*) temp_state1, tmp_state);

                    tmp_state = _mm_loadu_si128((__m128i*) temp_state2);
                    tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);
                    for (round_idx = 1; round_idx < TARGET_ROUND; ++round_idx) 
                        tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[round_idx]);
                    tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[TARGET_ROUND]);
                    _mm_storeu_si128((__m128i*) temp_state2, tmp_state);

                    // Output Filtering check
                    for (idx = 0; idx < 4; idx++)
                    {
                        if (temp_state1[ou_pasive_indexes[idx]] != temp_state2[ou_pasive_indexes[idx]])
                        {
                            flag = 0; 
                            break;
                        }
                    }

                    if (flag == 1) total_found_pairs++;
                }
            }
            else cnt = 0;
        }
    }

    // Clean up
    for(i_idx=0; i_idx<NUM_DAT; i_idx++) {
        if(dat_tab[i_idx].pt) free(dat_tab[i_idx].pt);
    }
    free(dat_tab);

    return total_found_pairs;
}

// ---------------------------------------------------------------------------
// 5. Main Function
// ---------------------------------------------------------------------------
int main() {
    int t, i;
    uint8_t mk[16];
    uint8_t pt[16];
    uint64_t pairs;
    uint64_t total_pairs_sum = 0;

    srand((unsigned int)time(NULL));

    printf("==============================================================\n");
    printf("[*] Exchange Distinguisher (Merged, Standalone)\n");
    printf("    Target     : %d Rounds\n", TARGET_ROUND);
    printf("    Data Log   : %d (Size: 2^%d)\n", DATA_LOG, DATA_LOG * 2);
    printf("    Samples    : %d\n", TEST_SAMPLES);
    printf("==============================================================\n\n");

    for (t = 0; t < TEST_SAMPLES; t++) {
        // Generate Random Key and Plaintext
        for(i=0; i<16; i++) {
            mk[i] = rand() % 256;
            pt[i] = rand() % 256;
        }

        printf("[%d/%d] Testing... ", t + 1, TEST_SAMPLES);
        fflush(stdout); 

        // Call Core Function
        pairs = RUN_DISTINGUISHER(mk, pt);
        
        printf("Pairs Found: %llu\n", pairs);
        total_pairs_sum += pairs;
    }

    printf("\n==============================================================\n");
    printf("[*] Final Results\n");
    printf("    Total Samples  : %d\n", TEST_SAMPLES);
    printf("    Avg Pairs Found: %.2f\n", (double)total_pairs_sum / TEST_SAMPLES);
    printf("==============================================================\n");

    return 0;
}