/* Implementation of attacks on HALFLOOP-24.

   Copyright (C) 2022 Marcus Dansarie, Patrick Derbez, Gregor Leander, and
   Lukas Stennes.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>. */

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "halfloop-bitslice.h"
#include "halfloop-common.h"

/**
 * @brief Stores a known plaintext tuple.
 */
typedef struct {
  u64 seed;
  u32 pt;
  u32 ct;
} tuple_t;

/**
 * @brief Stores a pair of known plaintext tuples with the required differences in plaintexts,
 * ciphertexts, and tweaks.
 */
typedef struct {
  tuple_t a;
  tuple_t b;
} tuple_pair_t;

/**
 * @brief Holds a candidate middle state used in building the left table.
 */
typedef struct {
  u32 state;
  u8 key;
} left_state_t;

/**
 * @brief A member object in the left table.
 */
typedef struct {
  u32 sx;
  u32 sy;
  u32 sz;
  u8 key;
} left_table_t;

/**
 * @brief A member object in the right table.
 */
typedef struct {
  u16 xyyz;
  u8 x;
  u8 rk10;
} right_table_t;

/**
 * @brief Holds an 80-bit candidate key.
 */
typedef struct {
  left_table_t lt;
  u64 rk8910;
  u8 rk5b;
} candidate_key_t;

/**
 * @brief Arguments for the brute force search threads.
 */
typedef struct {
  int rk7_i;
  int lastpct;
  bool success;
  tuple_pair_t tp1;
  tuple_pair_t tp2;
  tuple_pair_t tp3;
  candidate_key_t candidate;
  pthread_mutex_t mutex;
  struct timespec start;
} brute_force_args_t;

/** Used by qsort in get_left_states. */
static int compare_left_states(const void *state1, const void *state2) {
  left_state_t *s1 = (left_state_t*)state1;
  left_state_t *s2 = (left_state_t*)state2;
  if (s1->key < s2->key) {
    return -1;
  }
  if (s1->key > s2->key) {
    return 1;
  }
  if (s1->state < s2->state) {
    return -1;
  }
  if (s1->state > s2->state) {
    return 1;
  }
  return 0;
}

/** Used by qsort in build_left_table. */
static int compare_left_table(const void *table1, const void *table2) {
  left_table_t *t1 = (left_table_t*)table1;
  left_table_t *t2 = (left_table_t*)table2;
  if (t1->sx < t2->sx) {
    return -1;
  }
  if (t1->sx > t2->sx) {
    return 1;
  }
  if (t1->sy < t2->sy) {
    return -1;
  }
  if (t1->sy > t2->sy) {
    return 1;
  }
  if (t1->sz < t2->sz) {
    return -1;
  }
  if (t1->sz > t2->sz) {
    return 1;
  }
  if (t1->key < t2->key) {
    return -1;
  }
  if (t1->key > t2->key) {
    return 1;
  }
  return 0;
}

/** Used by qsort in build_right_table. */
static int compare_right_table(const void *table1, const void *table2) {
  right_table_t *t1 = (right_table_t*)table1;
  right_table_t *t2 = (right_table_t*)table2;
  if (t1->xyyz < t2->xyyz) {
    return -1;
  }
  if (t1->xyyz > t2->xyyz) {
    return 1;
  }
  if (t1->x < t2->x) {
    return -1;
  }
  if (t1->x > t2->x) {
    return 1;
  }
  if (t1->rk10 < t2->rk10) {
    return -1;
  }
  if (t1->rk10 > t2->rk10) {
    return 1;
  }
  return 0;
}

/** Used by qsort in read_input_tuples. */
static int compare_tuples(const void *tuple1, const void *tuple2) {
  return memcmp(tuple1, tuple2, sizeof(tuple_t));
}

/** Used by qsort in main and by candidate_keys_intersection. */
static int compare_candidate_keys(const void *key1, const void *key2) {
  candidate_key_t *k1 = (candidate_key_t*)key1;
  candidate_key_t *k2 = (candidate_key_t*)key2;
  if (k1->rk5b < k2->rk5b) {
    return -1;
  }
  if (k1->rk5b > k2->rk5b) {
    return 1;
  }
  if (k1->lt.key < k2->lt.key) {
    return -1;
  }
  if (k1->lt.key > k2->lt.key) {
    return 1;
  }
  if (k1->rk8910 < k2->rk8910) {
    return -1;
  }
  if (k1->rk8910 > k2->rk8910) {
    return 1;
  }
  return 0;
}

/**
 * @brief Enumerates all possible states before the addition of rk8. Used as input when building the
 * left state table.
 *
 * The two seeds in tp are used in the constuction of the table. Their differences must satisfy
 * the general requirements for the attack.
 *
 * @param tp A pair of plaintext-ciphertext-seed tuples.
 * @param states Return variable for the output table pointer. Must be freed when done.
 * @param num_states the length of the constructed table.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t get_left_states(tuple_pair_t tp, left_state_t **states,
    int *num_states) {
  if (states == NULL || num_states == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  *states = NULL;
  *num_states = 0;
  int alloc = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;
  u64 seed_diff = tp.a.seed ^ tp.b.seed;
  u32 rk6_diff = ((seed_diff >> 24) ^ (seed_diff >> 56)) & 0xffffff;
  u32 rk7_diff = ((seed_diff >> 32) ^  seed_diff)        & 0xffffff;
  u32 rk8_diff = ((seed_diff >> 40) ^ (seed_diff >> 8))  & 0xffffff;
  u32 rk7_diff_inv = inv_rotate_rows(inv_mix_columns(rk7_diff));
  u32 key_inv = inv_rotate_rows(inv_mix_columns(((tp.a.seed >> 32) ^ tp.a.seed) & 0xffffff)) >> 16;
  for (int s = 0; s < 0x1000000; s++) {
    u32 s1 = inv_sub_bytes(inv_rotate_rows(inv_mix_columns(s)));
    u32 s2 = inv_sub_bytes(inv_rotate_rows(inv_mix_columns(s ^ rk8_diff)));
    s1 = inv_rotate_rows(inv_mix_columns(s1));
    s2 = inv_rotate_rows(inv_mix_columns(s2)) ^ rk7_diff_inv;
    if (((s1 ^ s2) & 0xffff) == 0) {
      for (int k = 0; k < 0x100; k++) {
        if ((inv_SBOX[(s1 >> 16) ^ k] ^ inv_SBOX[(s2 >> 16) ^ k]) == (rk6_diff >> 16)) {
          if (*num_states == alloc) {
            alloc += 100;
            left_state_t *tmp = realloc(*states, sizeof(left_state_t) * alloc);
            RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
            *states = tmp;
          }
          (*states)[*num_states].state = s;
          (*states)[*num_states].key = k ^ key_inv;
          *num_states += 1;
        }
      }
    }
  }
  qsort(*states, *num_states, sizeof(left_state_t), compare_left_states);
error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*states);
    *num_states = 0;
  }
  return err;
}

/**
 * @brief Combines three tables generated by get_left_states and builds the left state table.
 *
 * @param state1 a state table generated by get_left_states.
 * @param len1 length of state1.
 * @param state2 a state table generated by get_left_states.
 * @param len2 length of state2.
 * @param state3 a state table generated by get_left_states.
 * @param len3 length of state3.
 * @param table Return variable for the output table pointer. Must be freed when done.
 * @param table_size the length of the constructed table.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t build_left_table(left_state_t *state1, int len1,
    left_state_t *state2, int len2, left_state_t *state3, int len3, left_table_t **table,
    int *table_size) {
  if (state1 == NULL || len1 <= 0 || state2 == NULL || len2 <= 0 || state3 == NULL || len3 <= 0
      || table == NULL || table_size == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;
  *table = NULL;
  *table_size = 0;
  int alloc = 0;
  for (int i = 0, j0 = 0, k0 = 0; i < len1; i++) {
    for (;j0 < len2 && state2[j0].key < state1[i].key; j0++) {
    }
    for (;k0 < len3 && state3[k0].key < state1[i].key; k0++) {
    }
    for (int j = j0; j < len2 && state2[j].key == state1[i].key; j++) {
      for (int k = k0; k < len3 && state3[k].key == state1[i].key; k++) {
        if (*table_size == alloc) {
          alloc += 100;
          left_table_t *tmp = realloc(*table, sizeof(left_table_t) * alloc);
          RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
          *table = tmp;
        }
        (*table)[*table_size].sx = state1[i].state;
        (*table)[*table_size].sy = state2[j].state;
        (*table)[*table_size].sz = state3[k].state;
        (*table)[*table_size].key = state1[i].key;
        *table_size += 1;
      }
    }
  }
  qsort(*table, *table_size, sizeof(left_table_t), compare_left_table);
error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*table);
    *table_size = 0;
  }
  return err;
}

/**
 * @brief Builds the right state table
 *
 * @param x A tuple pair with differences that satisfy the requirements for the attack.
 * @param y A tuple pair with differences that satisfy the requirements for the attack.
 * @param z A tuple pair with differences that satisfy the requirements for the attack.
 * @param middle True to generate the right state table for the middle byte of rk10 and false to
 * generate the right state table for the most significant byte of rk10.
 * @param table Return variable for the output table pointer. Must be freed when done. Size is
 * always 255.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t build_right_table(tuple_pair_t x, tuple_pair_t y, tuple_pair_t z,
    bool middle, right_table_t **table) {
  if (table == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;
  *table = malloc(sizeof(right_table_t) * 0x100);
  RETURN_IF(*table == NULL, HALFLOOP_MEMORY_ERROR);

  u8 cx;
  u8 cy;
  u8 cz;
  if (middle) {
    cx = ((x.a.ct >> 8) ^ x.a.seed ^ (x.a.seed >> 32)) & 0xff;
    cy = ((y.a.ct >> 8) ^ y.a.seed ^ (y.a.seed >> 32)) & 0xff;
    cz = ((z.a.ct >> 8) ^ z.a.seed ^ (z.a.seed >> 32)) & 0xff;
  } else {
    cx = ((x.a.ct >> 16) ^ (x.a.seed >> 8) ^ (x.a.seed >> 40)) & 0xff;
    cy = ((y.a.ct >> 16) ^ (y.a.seed >> 8) ^ (y.a.seed >> 40)) & 0xff;
    cz = ((z.a.ct >> 16) ^ (z.a.seed >> 8) ^ (z.a.seed >> 40)) & 0xff;
  }

  for (int rk10 = 0; rk10 < 0x100; rk10++) {
    u8 vx = cx ^ rk10;
    u8 vy = cy ^ rk10;
    u8 vz = cz ^ rk10;
    if (middle) {
      vx = (vx >> 6) | (vx << 2);
      vy = (vy >> 6) | (vy << 2);
      vz = (vz >> 6) | (vz << 2);
    }
    vx = inv_SBOX[vx];
    vy = inv_SBOX[vy];
    vz = inv_SBOX[vz];
    (*table)[rk10].xyyz = ((u16)(vx ^ vy) << 8) | (vy ^ vz);
    (*table)[rk10].x = vx;
    (*table)[rk10].rk10 = rk10;
  }
  qsort(*table, 0x100, sizeof(right_table_t), compare_right_table);
error:
  return err;
}

/**
 * @brief Performs a quick lookup of a value in a right table.
 *
 * @param rt pointer to a right table of size 256.
 * @param xyyz The lookup value: ((x ^ y) << 8) ^ (y ^ z)
 * @param match Return value for the index of the found value. Will be negative on failure.
 * @return HALFLOOP_SUCCESS if an item was found, HALFLOOP_FAILURE if not.
 */
static halfloop_result_t right_table_lookup(right_table_t *rt, u16 xyyz, int *match) {
  if (rt == NULL || match == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  int left = 0;
  int right = 255;
  while (left <= right) {
    int m = (left + right) / 2;
    if (rt[m].xyyz < xyyz) {
      left = m + 1;
    } else if (rt[m].xyyz > xyyz) {
      right = m - 1;
    } else {
      while(m > 0 && rt[m - 1].xyyz == xyyz) {
        m -= 1;
      }
      *match = m;
      return HALFLOOP_SUCCESS;
    }
  }
  *match = -1;
  return HALFLOOP_FAILURE;
}

/**
 * @brief Performs a search for candidate keys using a left table and two right tables.
 *
 * @param tp1 A tuple pair with differences that satisfy the requirements for the attack.
 * @param tp2 A tuple pair with differences that satisfy the requirements for the attack.
 * @param tp3 A tuple pair with differences that satisfy the requirements for the attack.
 * @param left_table Pointer to a left table generated with tp1, tp2, and tp3.
 * @param left_table_size Size of left_table.
 * @param right_table_msb Pointer to a right table for the most significant byte of rk10 generated
 * with tp1, tp2, and tp3.
 * @param right_table_mid Pointer to a right table for the middle byte of rk10 generated with tp1,
 * tp2, and tp3.
 * @param candidate_keys Return variable for the found candidate keys.
 * @param num_candidate_keys Return variable for the number of found candidate keys.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t find_candidate_keys(tuple_pair_t tp1, tuple_pair_t tp2, tuple_pair_t tp3,
    left_table_t *left_table, int left_table_size, right_table_t *right_table_msb,
    right_table_t *right_table_mid, candidate_key_t **candidate_keys, int *num_candidate_keys) {
  if (left_table == NULL || right_table_msb == NULL || right_table_mid == NULL
      || candidate_keys == NULL || num_candidate_keys == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  *candidate_keys = NULL;
  *num_candidate_keys = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;
  u8 ctxc = tp1.a.ct & 0xff;
  u8 ctyc = tp2.a.ct & 0xff;
  u8 ctzc = tp3.a.ct & 0xff;
  u8 tw5x = tp1.a.seed >> 56;
  u8 tw5y = tp2.a.seed >> 56;
  u8 tw5z = tp3.a.seed >> 56;
  u32 tw8x = ((tp1.a.seed >> 8)  ^ (tp1.a.seed >> 40))                      & 0xffffff;
  u32 tw8y = ((tp2.a.seed >> 8)  ^ (tp2.a.seed >> 40))                      & 0xffffff;
  u32 tw8z = ((tp3.a.seed >> 8)  ^ (tp3.a.seed >> 40))                      & 0xffffff;
  u32 tw9x = ((tp1.a.seed >> 16) ^ (tp1.a.seed >> 48) ^ (tp1.a.seed << 16)) & 0xffffff;
  u32 tw9y = ((tp2.a.seed >> 16) ^ (tp2.a.seed >> 48) ^ (tp2.a.seed << 16)) & 0xffffff;
  u32 tw9z = ((tp3.a.seed >> 16) ^ (tp3.a.seed >> 48) ^ (tp3.a.seed << 16)) & 0xffffff;

  int alloc = 0;
  for (int left_p = 0; left_p < left_table_size; left_p++) {
    left_table_t *lp = left_table + left_p;
    u32 sx = lp->sx ^ tw8x;
    u32 sy = lp->sy ^ tw8y;
    u32 sz = lp->sz ^ tw8z;
    /* Iterate over all possible values for rk8. */
    for (u32 rk8 = 0; rk8 < 0x1000000; rk8++) {
      u32 qx = mix_columns(rotate_rows(sub_bytes(sx ^ rk8))) ^ tw9x;
      u32 qy = mix_columns(rotate_rows(sub_bytes(sy ^ rk8))) ^ tw9y;
      u32 qz = mix_columns(rotate_rows(sub_bytes(sz ^ rk8))) ^ tw9z;
      int msb_match = -1;
      int mid_match = -1;
      u16 xyyz_msb = ((((qx ^ qy) >> 8) & 0xff00) | ((qy ^ qz) >> 16)) & 0xffff;
      right_table_lookup(right_table_msb, xyyz_msb, &msb_match);
      if (msb_match < 0) {
        continue;
      }
      u16 xyyz_mid = ((qx ^ qy) & 0xff00) | (((qy ^ qz) & 0xff00) >> 8);
      right_table_lookup(right_table_mid, xyyz_mid, &mid_match);
      if (mid_match < 0) {
        continue;
      }
      /* There is probably only a single match in each of the tables. */
      for (;msb_match < 0x100 && right_table_msb[msb_match].xyyz == xyyz_msb; msb_match++) {
        for (int midp = mid_match; midp < 0x100 && right_table_mid[midp].xyyz == xyyz_mid; midp++) {
          right_table_t *msb = right_table_msb + msb_match;
          right_table_t *mid = right_table_mid + midp;
          u32 rk10 = (msb->rk10 << 16) | (mid->rk10 << 8);
          u32 rk9 = (qx ^ (msb->x << 16) ^ (mid->x << 8)) & 0xffff00;
          for (int rk9c = 0; rk9c < 0x100; rk9c++) {
            u8 delta_xy = SBOX[rk9c ^ (tw9x & 0xff)] ^ SBOX[rk9c ^ (tw9y & 0xff)] ^ tw5x ^ tw5y;
            u8 delta_yz = SBOX[rk9c ^ (tw9z & 0xff)] ^ SBOX[rk9c ^ (tw9y & 0xff)] ^ tw5z ^ tw5y;
            u8 wx = SBOX[(qx & 0xff) ^ rk9c];
            u8 wy = SBOX[(qy & 0xff) ^ rk9c];
            u8 wz = SBOX[(qz & 0xff) ^ rk9c];
            wx = (wx << 4) | (wx >> 4);
            wy = (wy << 4) | (wy >> 4);
            wz = (wz << 4) | (wz >> 4);
            if ((wx ^ wy) == (ctxc ^ ctyc ^ delta_xy) && (wz ^ wy) == (ctzc ^ ctyc ^ delta_yz)) {
              if (*num_candidate_keys == alloc) {
                alloc += 400;
                candidate_key_t *tmp = realloc(*candidate_keys, sizeof(candidate_key_t) * alloc);
                RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
                *candidate_keys = tmp;
              }
              candidate_key_t *ck = *candidate_keys + *num_candidate_keys;
              ck->lt = *lp;
              ck->rk8910 = ((u64)rk8 << 40) | ((u64)rk9 << 16) | (rk9c << 16) | (rk10 >> 8);
              ck->rk5b = SBOX[rk9c ^ (tw9x & 0xff)] ^ ctxc ^ wx ^ tw5x ^ 2;
              *num_candidate_keys += 1;
            }
          }
        }
      }
    }
  }

  candidate_key_t *tmp = realloc(*candidate_keys, sizeof(candidate_key_t) * *num_candidate_keys);
  if (tmp != NULL) {
    *candidate_keys = tmp;
  }

error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*candidate_keys);
    *num_candidate_keys = 0;
  }
  return err;
}

/**
 * @brief Calculates the intersection of two sets of candidate keys.
 *
 * @param set1 a list of candidate keys sorted according to the compare_candidate_keys comparison
 * function. Items not present in set2 will be removed from this list.
 * @param set2 a list of candidate keys sorted according to the compare_candidate_keys comparison
 * function. The contents of set2 are not altered.
 * @param num1 the number of items in set1. On return, num will contain the new number of items in
 * set1.
 * @param num2 the number of items in set2.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t candidate_keys_intersection(candidate_key_t *set1,
    const candidate_key_t *set2, int *num1, int num2) {
  if (set1 == NULL || set2 == NULL || num1 == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  for (int i = 0, p = 0; i < *num1;) {
    while (p < num2 && compare_candidate_keys(set2 + p, set1 + i) < 0) {
      p++;
    }
    if (p >= num2 || compare_candidate_keys(set2 + p, set1 + i) != 0) {
      memmove(set1 + i, set1 + i + 1, sizeof(candidate_key_t) * (*num1 - i - 1));
      *num1 -= 1;
    } else {
      i++;
    }
  }
  return HALFLOOP_SUCCESS;
}

/**
 * @brief Tests if a candidate 128-bit key is a valid solution for a plaintext-ciphertext-seed
 * tuple.
 *
 * @param key  a 128 bit key.
 * @param pt   a 24-bit plaintext.
 * @param seed a 64-bit seed.
 * @param s    a 24-bit ciphertext that should match the one calculated from the other three
 *             parameters.
 * @return true if the key matches.
 */
static bool test_key(u128 key, u32 pt, u64 seed, u32 s) {
  u32 rk[11];
  key_schedule(rk, key, seed);
  u32 ct = pt ^ rk[0];
  for(int i = 1; i < 8; i++) {
    ct = mix_columns(rotate_rows(sub_bytes(ct))) ^ rk[i];
  }
  ct = mix_columns(rotate_rows(sub_bytes(ct)));
  return ct == s;
}

/**
 * @brief Returns the next work unit for brute_force_thread. Prints a progress message every percent
 * of progress.
 *
 * @param args a pointer to a brute_force_args_t structure.
 * @return int the next work unit. Any return >= 0x10000 indicates there is no more work to be done.
 */
static int get_next_rk(brute_force_args_t *args) {
  halfloop_result_t err = HALFLOOP_SUCCESS;
  bool locked = false;
  RETURN_IF(pthread_mutex_lock(&args->mutex) != 0, HALFLOOP_INTERNAL_ERROR);
  locked = true;
  if (args->rk7_i >= 0x10000) {
    RETURN_IF(pthread_mutex_unlock(&args->mutex) != 0, HALFLOOP_INTERNAL_ERROR);
    return 0x10000;
  }
  int ret = args->rk7_i;
  args->rk7_i += 1;
  int pct = 100 * ret / 0x10000;
  if (pct > args->lastpct) {
    TIMER_STOP(&args->start);
    u64 speed = (u64)((1ULL << 48) * 0.01 / TIMER_ELAPSED(&args->start));
    print_message("%d%% done %'lld keys/second.", WHITE, pct, speed);
    args->lastpct = pct;
    TIMER_START(&args->start);
  }
  RETURN_IF(pthread_mutex_unlock(&args->mutex) != 0, HALFLOOP_INTERNAL_ERROR);
  return ret;
error:
  if (locked) {
    pthread_mutex_unlock(&args->mutex);
  }
  print_message("%s in get_next_rk.", RED, halfloop_get_result_text(err));
  return 0x10000;
}

/**
 * @brief Function used by the search threads spawned by brute_force_48.
 *
 * @param a a pointer to a brute_force_args_t structure.
 * @return void* always NULL.
 */
static void* brute_force_thread(void *a) {
  brute_force_args_t *args = (brute_force_args_t*)a;

  u32 *found = NULL;
  int num_found = 0;

  int rk7_i;
  while (!args->success && (rk7_i = get_next_rk(args)) < 0x10000) {
    u128 key2 = args->candidate.rk8910 | ((u128)args->candidate.rk5b << 120);
    key2 |= (u128)mix_columns(rotate_rows(rk7_i | ((u32)args->candidate.lt.key << 16))) << 64;
    u128 pkey = key2 ^ (u128)args->tp1.a.seed;
    pkey ^= (u128)args->tp1.a.seed << 32;
    pkey ^= (u128)args->tp1.a.seed << 64;
    pkey ^= (u128)args->tp1.a.seed >> 32;
    if (halfloop_bitslice(args->tp1.a.pt, args->candidate.lt.sx, pkey, &found, &num_found)
        != HALFLOOP_SUCCESS) {
      break;
    }
    u32 rk56_diff = (args->tp1.a.seed >> 24) ^ (args->tp1.a.seed >> 56);
    for (int i = 0; i < num_found; i++) {
      key2 &= ~((u128)(0x00ffffffff000000) << 64);
      key2 |= (u128)(found[i] ^ rk56_diff) << 88;
      u128 key1 = (key2 ^ (key2 >> 32)) & (((u128)0xffffffff << 64) | ~0ULL);
      key1 |= ((u128)key_schedule_g(key1 & 0xffffffff, 1) << 96)
          ^ (key2 & ((u128)0xffffffff << 96));
      if (!(test_key(key1, args->tp2.a.pt, args->tp2.a.seed, args->candidate.lt.sy))) {
        continue;
      }
      if (!(test_key(key1, args->tp3.a.pt, args->tp3.a.seed, args->candidate.lt.sz))) {
        continue;
      }
      print_message("Found key: %016" PRIx64 "%016" PRIx64, GREEN, (u64)(key1 >> 64), (u64)key1);
      /* Stop remaining threads and return. */
      args->success = true;
      free(found);
      return NULL;
    }
    FREE_AND_NULL(found);
  }

  free(found);
  return NULL;
}

/**
 * @brief Performs multithreaded brute force search for the remaining 48 bits of an 80-bit candidate
 * key. The tuple pair arguments must be identical to the ones used to calculate the left table
 * stored in the candidate structure. Any found key will be printed to stdout along with a user
 * friendly message.
 *
 * @param tp1       a tuple pair.
 * @param tp2       a tuple pair.
 * @param tp3       a tuple pair.
 * @param candidate a candidate key along with a left table that was generated with tp1, tp2, and
 * tp3.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t brute_force_48(tuple_pair_t tp1, tuple_pair_t tp2, tuple_pair_t tp3,
    candidate_key_t candidate, int num_threads) {
  if (num_threads <= 0) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  pthread_t *threads = NULL;
  brute_force_args_t args = {0};
  halfloop_result_t err = HALFLOOP_SUCCESS;

  threads = malloc(sizeof(pthread_t) * num_threads);
  RETURN_IF(threads == NULL, HALFLOOP_MEMORY_ERROR);
  for (long i = 0; i < num_threads; i++) {
    threads[i] = pthread_self(); /* Initialize with known "bad" value. */
  }

  /* Initialize arguments. */
  args.rk7_i = 0;
  args.lastpct = 0;
  args.success = false;
  args.tp1 = tp1;
  args.tp2 = tp2;
  args.tp3 = tp3;
  args.candidate = candidate;
  RETURN_IF(pthread_mutex_init(&args.mutex, NULL) != 0, HALFLOOP_INTERNAL_ERROR);
  TIMER_START(&args.start);

  /* Spawn threads. */
  print_message("Spawning %d threads.", WHITE, num_threads);
  for (int i = 0; i < num_threads; i++) {
    RETURN_IF(pthread_create(threads + i, NULL, brute_force_thread, &args) != 0,
        HALFLOOP_INTERNAL_ERROR);
  }

error:
  if (threads != NULL) {
    for (long i = 0; i < num_threads; i++) {
      if (!pthread_equal(pthread_self(), threads[i])) {
        pthread_join(threads[i], NULL);
      }
    }
    free(threads);
  }
  pthread_mutex_destroy(&args.mutex);
  if (err == HALFLOOP_SUCCESS && !args.success) {
    return HALFLOOP_FAILURE;
  }
  return err;
}

/**
 * @brief Reads plaintext-ciphertext-seed tuples from a text file.
 *
 * @param fname      the file name of the input file.
 * @param tuples     return pointer. Will contain a list of tuples on return.
 * @param num_tuples will contain the number of items in tuples on return.
 * @return HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t read_input_tuples(const char *fname, tuple_t **tuples, int *num_tuples) {
  if (fname == NULL || tuples == NULL || num_tuples == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }

  FILE *fp = NULL;
  *tuples = NULL;
  *num_tuples = 0;
  int num_alloc = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  fp = fopen(fname, "r");
  RETURN_IF(fp == NULL, HALFLOOP_FILE_ERROR);

  while (!feof(fp)) {
    tuple_t tuple;
    if (fscanf(fp, "%06x %06x %016" PRIx64 "\n", &tuple.pt, &tuple.ct, &tuple.seed) == 3) {
      if (*num_tuples == num_alloc) {
        num_alloc += 1000;
        tuple_t *tmp = realloc(*tuples, sizeof(tuple_t) * num_alloc);
        RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
        *tuples = tmp;
      }
      (*tuples)[*num_tuples] = tuple;
      *num_tuples += 1;
    } else {
      int c;
      while ((c = fgetc(fp)) != '\n' && c != EOF) {
        /* Empty. */
      }
    }
  }

  tuple_t *tmp = realloc(*tuples, sizeof(tuple_t) * *num_tuples);
  if (tmp != NULL) {
    *tuples = tmp;
  }

  /* Remove duplicates. */
  qsort(*tuples, *num_tuples, sizeof(tuple_t), compare_tuples);
  for (int i = 1; i < *num_tuples; i++) {
    if (compare_tuples(*tuples + i - 1, *tuples + i) == 0) {
      *num_tuples -= 1;
      memmove(*tuples + i, *tuples + i + 1, sizeof(tuple_t) * (*num_tuples - i));
    }
  }

error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*tuples);
    *num_tuples = 0;
  }
  if (fp != NULL) {
    fclose(fp);
  }
  return err;
}

/**
 * @brief Searches through a list of tuples for good pairs that can be used for the attack. The
 * function uses a sub-optimal O(n^2) algorithm, which may make it slow for very large lists.
 *
 * @param tuples a list if plaintext-ciphertext-seed tuples.
 * @param num_tuples the number of tuples in the list.
 * @param pairs output list of found good pairs. Must be freed.
 * @param num_pairs the number of found good pairs in the output list.
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
static halfloop_result_t get_good_pairs(tuple_t *tuples, int num_tuples, tuple_pair_t **pairs,
    int *num_pairs) {
  if (tuples == NULL || num_tuples < 2 || pairs == NULL || num_pairs == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }

  *pairs = NULL;
  *num_pairs = 0;
  int num_alloc = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  for (int i = 0; i < num_tuples; i++) {
    for (int j = i + 1; j < num_tuples; j++) {
      u64 sdiff = tuples[i].seed ^ tuples[j].seed;
      u32 pdiff = tuples[i].pt   ^ tuples[j].pt;
      u32 cdiff = tuples[i].ct   ^ tuples[j].ct;
      if ((pdiff & 0xffff00) != 0
          || (pdiff & 0xff) == 0
          || (cdiff & 0xffff) != 0
          || (cdiff >> 16) != pdiff
          || (sdiff & 0xffff00ffffffffffULL) != 0
          || (sdiff >> 40) != pdiff) {
        continue;
      }
      if (*num_pairs == num_alloc) {
        num_alloc += 1000;
        tuple_pair_t *tmp = realloc(*pairs, sizeof(tuple_pair_t) * num_alloc);
        RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
        *pairs = tmp;
      }
      (*pairs)[*num_pairs].a = tuples[i];
      (*pairs)[*num_pairs].b = tuples[j];
      *num_pairs += 1;
    }
  }

  tuple_pair_t *tmp = realloc(*pairs, sizeof(tuple_pair_t) * *num_pairs);
  if (tmp != NULL) {
    *pairs = tmp;
  }

error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*pairs);
    *num_pairs = 0;
  }
  return err;
}

int main(int argc, char *argv[]) {
  tuple_t *tuples = NULL;
  tuple_pair_t *pairs = NULL;
  left_state_t *left_states1 = NULL;
  left_state_t *left_states2 = NULL;
  left_state_t *left_states3 = NULL;
  left_table_t *left_table = NULL;
  right_table_t *right_table_msb = NULL;
  right_table_t *right_table_mid = NULL;
  candidate_key_t *candidate_keys = NULL;
  candidate_key_t *candidate_set = NULL;
  struct timespec timer = {0};
  const char *filename = NULL;
  double seconds = 0;
  int minutes = 0;
  int num_tuples = 0;
  int num_pairs = 0;
  int num_left_states1 = 0;
  int num_left_states2 = 0;
  int num_left_states3 = 0;
  int left_table_size = 0;
  int num_candidate_keys = 0;
  int num_candidate_set = INT_MAX; /* Set to correct value in first iteration. */
  int threads = sysconf(_SC_NPROCESSORS_ONLN);
  halfloop_result_t err = HALFLOOP_SUCCESS;

  /* Parse command line arguments. */
  if (argc == 4 && strcmp(argv[1], "-t") == 0) {
    threads = atoi(argv[2]);
    if (threads < 1) {
      printf("Invalid number of threads: %d\n", threads);
      return HALFLOOP_BAD_ARGUMENT;
    }
    filename = argv[3];
  } else if (argc == 2) {
    filename = argv[1];
  } else {
    printf("Usage: %s [-t threads] <filename>   -- Search for keys using tuples in file.\n",
        argv[0]);
    return HALFLOOP_BAD_ARGUMENT;
  }

  setlocale(LC_NUMERIC, ""); /* For pretty-printing large numbers. */
  print_message("Initializing HALFLOOP-24 library.", WHITE);
  RETURN_ON_ERROR(init_halfloop());
  RETURN_ON_ERROR(test_halfloop());

  print_message("Loading tuples from %s.", WHITE, filename);
  err = read_input_tuples(filename, &tuples, &num_tuples);
  if (err != HALFLOOP_SUCCESS) {
    print_message("An error occurred while loading tuples.", RED);
    RETURN_ON_ERROR(err);
  }
  print_message("Loaded %d tuples.", WHITE, num_tuples);
  err = get_good_pairs(tuples, num_tuples, &pairs, &num_pairs);
  if (err != HALFLOOP_SUCCESS) {
    print_message("An error occurred while searching for good pairs.", RED);
    RETURN_ON_ERROR(err);
  }
  FREE_AND_NULL(tuples);

  if (num_pairs < 3) {
    print_message("Found %d good pairs. At least 3 are needed.", RED, num_pairs);
    RETURN_ON_ERROR(HALFLOOP_FAILURE);
  } else {
    print_message("Found %d good pairs.", GREEN, num_pairs);
  }

  double left_time = 0;
  double right_time = 0;
  double enum_time = 0;

  print_message("Searching for 80-bit candidate keys.", WHITE);
  for (int i = 0; i < num_pairs && num_candidate_set > 1; i++) {
    TIMER_START(&timer);
    RETURN_ON_ERROR(get_left_states(pairs[i], &left_states1, &num_left_states1));
    TIMER_STOP(&timer);
    left_time += TIMER_ELAPSED(&timer);
    for (int j = i + 1; j < num_pairs && num_candidate_set > 1; j++) {
      TIMER_START(&timer);
      RETURN_ON_ERROR(get_left_states(pairs[j], &left_states2, &num_left_states2));
      TIMER_STOP(&timer);
      left_time += TIMER_ELAPSED(&timer);
      for (int k = j + 1; k < num_pairs && num_candidate_set > 1; k++) {
        TIMER_START(&timer);
        RETURN_ON_ERROR(get_left_states(pairs[k], &left_states3, &num_left_states3));
        RETURN_ON_ERROR(build_left_table(left_states1, num_left_states1, left_states2,
            num_left_states2, left_states3, num_left_states3, &left_table, &left_table_size));
        TIMER_STOP(&timer);
        left_time += TIMER_ELAPSED(&timer);
        TIMER_START(&timer);
        print_message("Left table size: %d", WHITE, left_table_size);
        RETURN_ON_ERROR(build_right_table(pairs[i], pairs[j], pairs[k], false, &right_table_msb));
        RETURN_ON_ERROR(build_right_table(pairs[i], pairs[j], pairs[k], true,  &right_table_mid));
        TIMER_STOP(&timer);
        right_time += TIMER_ELAPSED(&timer);

        TIMER_START(&timer);
        RETURN_ON_ERROR(find_candidate_keys(pairs[i], pairs[j], pairs[k], left_table,
            left_table_size, right_table_msb, right_table_mid, &candidate_keys,
            &num_candidate_keys));
        TIMER_STOP(&timer);
        enum_time += TIMER_ELAPSED(&timer);
        FREE_AND_NULL(left_table);
        FREE_AND_NULL(right_table_msb);
        FREE_AND_NULL(right_table_mid);

        print_message("Found %d candidate keys.", num_candidate_keys == 0 ? RED : GREEN,
            num_candidate_keys);

        qsort(candidate_keys, num_candidate_keys, sizeof(candidate_key_t), compare_candidate_keys);

        if (i == 0 && j == 1 && k == 2) {
          candidate_set = candidate_keys;
          candidate_keys = NULL;
          num_candidate_set = num_candidate_keys;
          num_candidate_keys = 0;
        } else {
          RETURN_ON_ERROR(candidate_keys_intersection(candidate_set, candidate_keys,
              &num_candidate_set, num_candidate_keys));
          print_message("%d candidate key%s remaining.", num_candidate_set > 0 ? GREEN : RED,
              num_candidate_set, num_candidate_set == 1 ? "" : "s");
          RETURN_IF(num_candidate_set == 0, HALFLOOP_FAILURE);
          FREE_AND_NULL(candidate_keys);
          num_candidate_keys = 0;
        }
        FREE_AND_NULL(left_states3);
      }
      FREE_AND_NULL(left_states2);
    }
    FREE_AND_NULL(left_states1);
  }
  minutes = (int)(left_time / 60);
  seconds = left_time - 60 * minutes;
  print_message("Time spent building left tables: %d minute%s and %.1f seconds.", WHITE,
      minutes, minutes == 1 ? "" : "s", seconds);
  minutes = (int)(right_time / 60);
  seconds = right_time - 60 * minutes;
  print_message("Time spent building right tables: %d minute%s and %.1f seconds.", WHITE,
      minutes, minutes == 1 ? "" : "s", seconds);
  minutes = (int)(enum_time / 60);
  seconds = enum_time - 60 * minutes;
  print_message("Time spent enumerating candidate keys: %d minute%s and %.1f seconds.", WHITE,
      minutes, minutes == 1 ? "" : "s", seconds);

  TIMER_START(&timer);
  for (int k = 0; k < num_candidate_set; k++) {
    print_message("Searching for remaining 48 bits for key %02x %02x %016" PRIx64 " (%d/%d).",
        WHITE, candidate_set[k].rk5b, candidate_set[k].lt.key, candidate_set[k].rk8910, k + 1,
        num_candidate_set);
    err = brute_force_48(pairs[0], pairs[1], pairs[2], candidate_set[k], threads);
    if (err == HALFLOOP_SUCCESS) {
      break;
    }
    RETURN_IF(err != HALFLOOP_FAILURE, err);
  }
  TIMER_STOP(&timer);
  double elapsed = TIMER_ELAPSED(&timer);
  int hours = (int)(elapsed / 3600);
  elapsed -= hours * 3600;
  minutes = (int)(elapsed / 60);
  seconds = elapsed - 60 * minutes;
  print_message("Time spent searching for key: %d hour%s, %d minute%s and %.1f seconds", WHITE,
      hours, hours == 1 ? "" : "s", minutes, minutes == 1 ? "" : "s", seconds);

error:
  if (err == HALFLOOP_FAILURE) {
    print_message("No keys found. The good pairs do not have a common key.", RED);
  } else if (err != HALFLOOP_SUCCESS) {
    print_message("Early exit due to error: %s", RED, halfloop_get_result_text(err));
  }
  free(tuples);
  free(pairs);
  free(left_states1);
  free(left_states2);
  free(left_states3);
  free(left_table);
  free(right_table_msb);
  free(right_table_mid);
  free(candidate_keys);
  free(candidate_set);
  return err;
}
