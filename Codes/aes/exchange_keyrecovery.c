/*
 * key_recovery_verify_v3_fixed.c
 * - Fixed Input Filtering (Diagonal separation)
 * - Fixed Plaintext Reconstruction (Exchange logic)
 * - Fixed Zero Difference Check (Column-wise check after 1 Round)
 */

#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <immintrin.h> // AES-NI

// ---------------------------------------------------------------------------
// 1. Configuration
// ---------------------------------------------------------------------------
#define TARGET_ROUND    5       
#define TEST_SAMPLES    5       
#define WRONG_KEY_TESTS 10000   
#define DATA_LOG        15      
#define NUM_DAT1        (1ULL << DATA_LOG)
#define NUM_DAT2        (1ULL << DATA_LOG)
#define NUM_DAT         (NUM_DAT1 * NUM_DAT2)

// ---------------------------------------------------------------------------
// 2. Data Structures & Globals
// ---------------------------------------------------------------------------
typedef uint8_t ct_t[16];

typedef struct {
    uint8_t * pt; 
    ct_t      ct;
} pair_t;

int num_pasive_sboxes_ou = 4;
int ou_pasive_indexes[4];
int in_active_indexes1[4];
int in_active_indexes2[4];

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

// ---------------------------------------------------------------------------
// 4. Key Filtering Logic (CORRECTED)
// ---------------------------------------------------------------------------
int check_filter_condition(uint8_t p1[16], uint8_t p2[16], uint8_t k_guess[16]) {
    __m128i m_p1 = _mm_loadu_si128((__m128i*)p1);
    __m128i m_p2 = _mm_loadu_si128((__m128i*)p2);
    __m128i m_k  = _mm_loadu_si128((__m128i*)k_guess);
    __m128i zero = _mm_setzero_si128();

    // 1-Round Encryption: SB -> SR -> MC -> XOR 0
    // We use a zero round key to inspect the state after MixColumns.
    __m128i s1 = _mm_aesenc_si128(_mm_xor_si128(m_p1, m_k), zero);
    __m128i s2 = _mm_aesenc_si128(_mm_xor_si128(m_p2, m_k), zero);

    uint8_t out1[16], out2[16];
    _mm_storeu_si128((__m128i*)out1, s1);
    _mm_storeu_si128((__m128i*)out2, s2);

    // Check Condition: 
    // For each column, IF the column has a non-zero difference (active),
    // THEN it must contain at least one zero byte (collision).
    // (Standard mapping: Bytes 0-3 are Col 0, 4-7 are Col 1, etc.)
    
    for(int col = 0; col < 4; col++) {
        int is_active = 0;
        int has_zero_byte = 0;

        for(int row = 0; row < 4; row++) {
            int idx = col * 4 + row;
            uint8_t diff_byte = out1[idx] ^ out2[idx];

            if (diff_byte != 0) is_active = 1;
            else has_zero_byte = 1;
        }

        // If the column is active but has NO zero bytes, the key guess is wrong.
        if (is_active && !has_zero_byte) {
            return 0; // Filter Fails
        }
    }

    return 1; // Filter Passes
}

int comp_states(const void * first, const void * second) {
    pair_t * p1 = (pair_t *)first;
    pair_t * p2 = (pair_t *)second;
    for (int i = 0; i < num_pasive_sboxes_ou; i++) {
        if (p1->ct[ou_pasive_indexes[i]] != p2->ct[ou_pasive_indexes[i]])
            return (p1->ct[ou_pasive_indexes[i]] > p2->ct[ou_pasive_indexes[i]]) ? 1 : -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 5. Main Attack Verification Routine
// ---------------------------------------------------------------------------
void RUN_ATTACK_VERIFICATION(uint8_t mk[16], uint8_t base_pt[16])
{
    __m128i RoundKey[11]; 
    __m128i tmp_state;
    pair_t* dat_tab = NULL;
    uint8_t (*rand_diag0)[4] = NULL;
    uint8_t (*rand_diag1)[4] = NULL;
    
    // Key Expansion
    RoundKey[0] = _mm_loadu_si128((const __m128i*) mk);
    for(int i=1; i<=10; i++) RoundKey[i] = AES_128_key_exp(RoundKey[i-1], (1<<(i-1)) >= 0x80 ? 0x1b : 0x01<<(i-1) ); 

    int PASSIVE_SETS[4][4] = {{3, 6, 9, 12}, {2, 5, 8, 15}, {1, 4, 11, 14}, {0, 7, 10, 13}};
    in_active_indexes1[0] = 0; in_active_indexes1[1] = 5; in_active_indexes1[2] = 10; in_active_indexes1[3] = 15;
    in_active_indexes2[0] = 3; in_active_indexes2[1] = 4; in_active_indexes2[2] = 9;  in_active_indexes2[3] = 14;

    dat_tab = (pair_t *)malloc(sizeof(pair_t) * NUM_DAT);
    rand_diag0 = malloc(sizeof(uint8_t[4]) * NUM_DAT1);
    rand_diag1 = malloc(sizeof(uint8_t[4]) * NUM_DAT2);
    if(!dat_tab || !rand_diag0 || !rand_diag1) { printf("Alloc fail\n"); exit(1); }

    // Generate Random Diagonals
    for(int i=0; i<NUM_DAT1; i++) for(int b=0; b<4; b++) rand_diag0[i][b] = rand() & 0xFF;
    for(int i=0; i<NUM_DAT2; i++) for(int b=0; b<4; b++) rand_diag1[i][b] = rand() & 0xFF;

    unsigned long long dat_idx = 0;
    uint8_t current_pt[16];
    
    // Structure Generation
    for (int i = 0; i < NUM_DAT1; i++) {
        for (int j = 0; j < NUM_DAT2; j++) {
            memcpy(current_pt, base_pt, 16);
            for(int b=0; b<4; b++) current_pt[in_active_indexes1[b]] = rand_diag0[i][b];
            for(int b=0; b<4; b++) current_pt[in_active_indexes2[b]] = rand_diag1[j][b];

            tmp_state = _mm_loadu_si128((__m128i*) current_pt);
            tmp_state = _mm_xor_si128(tmp_state, RoundKey[0]);
            for (int r = 1; r < TARGET_ROUND; ++r) tmp_state = _mm_aesenc_si128(tmp_state, RoundKey[r]);
            tmp_state = _mm_aesenclast_si128(tmp_state, RoundKey[TARGET_ROUND]);
            _mm_storeu_si128((__m128i*) (dat_tab[dat_idx].ct), tmp_state);

            dat_tab[dat_idx].pt = (uint8_t*)malloc(8);
            for(int b=0; b<4; b++) { 
                dat_tab[dat_idx].pt[b] = rand_diag0[i][b]; 
                dat_tab[dat_idx].pt[b+4] = rand_diag1[j][b]; 
            }
            dat_idx++;
        }
    }
    free(rand_diag0); free(rand_diag1);

    uint64_t found_pairs = 0;
    uint8_t temp_state1[16], temp_state2[16];

    // Verification Loop
    for (int phase = 0; phase < 4; phase++) {
        for(int k=0; k<4; k++) ou_pasive_indexes[k] = PASSIVE_SETS[phase][k];
        qsort(dat_tab, NUM_DAT, sizeof(pair_t), comp_states);

        unsigned long long cnt = 0;
        for (dat_idx = 1; dat_idx < NUM_DAT; dat_idx++) {
            if (comp_states(&(dat_tab[(dat_idx - 1)]), &(dat_tab[dat_idx])) == 0) {
                cnt++;
                for (int cnt_idx = 1; cnt_idx <= cnt; cnt_idx++) {
                    pair_t *p1 = &dat_tab[dat_idx - cnt_idx];
                    pair_t *p2 = &dat_tab[dat_idx];

                    // 1. INPUT FILTERING
                    int flag0 = 1; 
                    int flag1 = 1; 
                    for (int i = 0; i < 4; i++) if (p1->pt[i] != p2->pt[i]) { flag0 = 0; break; }
                    for (int i = 4; i < 8; i++) if (p1->pt[i] != p2->pt[i]) { flag1 = 0; break; }

                    if ((flag0 == 1) || (flag1 == 1)) continue;

                    // 2. CONSTRUCT EXCHANGED PAIR
                    memcpy(temp_state1, base_pt, 16);
                    memcpy(temp_state2, base_pt, 16);

                    for (int idx1 = 0; idx1 < 4; idx1++) {
                        temp_state1[in_active_indexes1[idx1]] = p1->pt[idx1];
                        temp_state1[in_active_indexes2[idx1]] = p2->pt[idx1 + 4];
                        
                        temp_state2[in_active_indexes1[idx1]] = p2->pt[idx1];
                        temp_state2[in_active_indexes2[idx1]] = p1->pt[idx1 + 4];
                    }

                    // 3. VERIFY OUTPUT CONDITION
                    __m128i t1 = _mm_loadu_si128((__m128i*) temp_state1);
                    __m128i t2 = _mm_loadu_si128((__m128i*) temp_state2);
                    
                    t1 = _mm_xor_si128(t1, RoundKey[0]);
                    t2 = _mm_xor_si128(t2, RoundKey[0]);
                    
                    for (int r = 1; r < TARGET_ROUND; ++r) {
                        t1 = _mm_aesenc_si128(t1, RoundKey[r]);
                        t2 = _mm_aesenc_si128(t2, RoundKey[r]);
                    }
                    t1 = _mm_aesenclast_si128(t1, RoundKey[TARGET_ROUND]);
                    t2 = _mm_aesenclast_si128(t2, RoundKey[TARGET_ROUND]);

                    uint8_t c1[16], c2[16];
                    _mm_storeu_si128((__m128i*)c1, t1);
                    _mm_storeu_si128((__m128i*)c2, t2);

                    int flag = 1;
                    for (int idx = 0; idx < 4; idx++) {
                        if (c1[ou_pasive_indexes[idx]] != c2[ou_pasive_indexes[idx]]) { flag = 0; break; }
                    }

                    if (flag == 1) {
                        found_pairs++;
                        printf("\n[!] Right Pair Found! (Total: %llu)\n", found_pairs);

                        // 4. ATTACK: Key Filtering
                        if (check_filter_condition(temp_state1, temp_state2, mk)) {
                            printf("    [Correct Key] PASS (As expected)\n");
                        } else {
                            printf("    [Correct Key] FAIL (!!! Logic Error !!!)\n");
                        }

                        // Wrong Key Stats
                        int pass_count = 0;
                        uint8_t wk[16];
                        for(int t=0; t<WRONG_KEY_TESTS; t++) {
                            for(int r=0; r<16; r++) wk[r] = rand() & 0xFF;
                            if (check_filter_condition(temp_state1, temp_state2, wk)) {
                                pass_count++;
                            }
                        }
                        
                        // Expected prob: (2^-6)^2 = 2^-12 approx 0.024% (for 2 active columns)
                        double pass_rate = (double)pass_count / WRONG_KEY_TESTS * 100.0;
                        printf("    [Wrong Keys]  %d / %d passed (%.2f%%) [Exp: ~0.02%%]\n", 
                               pass_count, WRONG_KEY_TESTS, pass_rate);
                    }
                }
            } else cnt = 0;
        }
    }

    for(int i=0; i<NUM_DAT; i++) if(dat_tab[i].pt) free(dat_tab[i].pt);
    free(dat_tab);
    
    printf("\n[Result] Total Right Pairs: %llu\n", found_pairs);
}

int main() {
    uint8_t mk[16], pt[16];
    srand((unsigned int)time(NULL));
    
    printf("==============================================================\n");
    printf("[*] 5-Round AES Key Recovery Verification\n");
    printf("==============================================================\n");

    for (int t = 0; t < TEST_SAMPLES; t++) {
        for(int i=0; i<16; i++) { mk[i] = rand() % 256; pt[i] = rand() % 256; }
        printf("\n>>> Trial %d/%d\n", t + 1, TEST_SAMPLES);
        RUN_ATTACK_VERIFICATION(mk, pt);
    }
    return 0;
}