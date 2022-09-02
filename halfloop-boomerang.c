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

#include <stdio.h>
#include "halfloop-common.h"

#define GAMMA_SHIFT(g) (((u64)gamma << 8) ^ ((u64)gamma << 40))

/**
 * @brief Recover a key byte using a boomerang attack.
 *
 * @param key the full key. (Used to call halfloop_encrypt and halfloop_decrypt.)
 * @param tweak0 the base tweak to use. Can be any arbitrary tweak, but must be the same as used for
 * generating ct0 and pt0x.
 * @param pt0 the base plaintext to use. Can be any arbitrary plaintext.
 * @param ct0 pt0 encrypted using key and tweak0.
 * @param pt0x ct0 decrypted using key and GAMMA_SHIFT(gamma).
 * @param beta an arbitrary non-zero beta.
 * @param gamma an arbitrary non-zero gamma.
 * @param n the key byte to recover: 0, 1, or 2.
 * @param operations increased by one for every pair of encryption/decryption performed.
 * @return halfloop_result_t
 */
halfloop_result_t restore_byte(u128 key, u64 tweak0, u32 pt0, u32 ct0, u32 pt0x, u8 beta, u8 gamma,
    u8 n, int *operations) {
  if ((pt0 & 0xff000000) != 0 || (ct0 & 0xff000000) != 0 || beta == 0 || gamma == 0 || n >= 3
      || operations == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;

  u8 shift = 16 - (n * 8);
  u64 tweak1 = tweak0 ^ ((u64)mix_columns(rotate_rows((u32)beta << shift)) << 16);

  for (int delta = 1; delta < 0x100; delta++) {
    u32 pt1 = pt0 ^ (delta << shift);
    u32 ct1;
    u32 pt1x;
    RETURN_ON_ERROR(halfloop_encrypt(pt1, key, tweak1, &ct1));
    RETURN_ON_ERROR(halfloop_decrypt(ct1, key, tweak1 ^ GAMMA_SHIFT(gamma), &pt1x));
    *operations += 1;

    if (((pt0x ^ pt1x) & (0xffffff ^ (0xff << shift))) != 0) {
      continue;
    }

    u8 pt0b  = pt0  >> shift;
    u8 pt0xb = pt0x >> shift;
    u8 pt1b  = pt1  >> shift;
    u8 pt1xb = pt1x >> shift;

    if (n == 2) {
      pt0xb ^= gamma;
      pt1xb ^= gamma;
    }

    for (int k0 = 0; k0 < 0x100; k0++) {
      if (   (SBOX[k0 ^ pt0b]  ^ SBOX[k0 ^ pt1b])  == beta
          && (SBOX[k0 ^ pt0xb] ^ SBOX[k0 ^ pt1xb]) == beta) {
        print_message("Key byte %d: %02x (d = %02x d' = %02x).", GREEN, n,
            (k0 ^ (tweak0 >> (56 - n * 8))) & 0xff,
            delta,
            ((ct0 ^ pt1x) >> shift) & 0xff) ;
        RETURN_IF(true, HALFLOOP_SUCCESS);
      }
    }
  }

  print_message("Error: No key found.", RED);
  err = HALFLOOP_FAILURE;

error:
  return err;
}

int main(int argc, char *argv[]) {
  u8 beta = 0;
  u8 gamma = 0;
  u32 pt0 = 0;
  u32 ct0 = 0;
  u32 pt0x = 0;
  u64 tweak0 = 0;
  u128 key = 0;
  int operations = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  print_message("Initializing HALFLOOP-24 library.", WHITE);
  RETURN_ON_ERROR(init_halfloop());
  RETURN_ON_ERROR(test_halfloop());

  while (beta == 0) {
    RETURN_ON_ERROR(random_bytes(&beta, sizeof(u8)));
  }
  while (gamma == 0) {
    RETURN_ON_ERROR(random_bytes(&gamma, sizeof(u8)));
  }
  RETURN_ON_ERROR(random_bytes(&pt0, sizeof(u32)));
  pt0 &= 0xffffff;
  RETURN_ON_ERROR(random_bytes(&tweak0, sizeof(u64)));
  RETURN_ON_ERROR(random_bytes(&key, sizeof(u128)));

  RETURN_ON_ERROR(halfloop_encrypt(pt0, key, tweak0, &ct0));
  RETURN_ON_ERROR(halfloop_decrypt(ct0, key, tweak0 ^ GAMMA_SHIFT(gamma), &pt0x));
  operations += 1;

  print_message("Key:        %016" PRIx64 "%016" PRIx64, WHITE, (u64)(key >> 64), (u64)key);
  print_message("tweak:       %016" PRIx64, WHITE, tweak0);
  print_message("Plaintext:  %06x", WHITE, pt0);
  print_message("Ciphertext: %06x", WHITE, ct0);
  print_message("Beta:       %02x", WHITE, beta);
  print_message("Gamma:      %02x", WHITE, gamma);

  for (int i = 0; i < 3; i++) {
    RETURN_ON_ERROR(restore_byte(key, tweak0, pt0, ct0, pt0x, beta, gamma, i,
        &operations));
  }

  print_message("Performed %d encryptions and %d decryptions.", WHITE, operations, operations);

error:
  return err;
}
