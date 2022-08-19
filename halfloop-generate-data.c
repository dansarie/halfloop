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
#include <stdio.h>
#include <stdlib.h>
#include "halfloop-common.h"

int main(int argc, char *argv[]) {
  int found = 0;
  int num_pairs = 0;
  int queries = 0;
  u32 pt0 = 0;
  u32 ct[256] = {0};
  u64 seed0 = 0;
  u128 key = 0;
  seed_t seed = {0};
  struct timespec timer;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <number of pairs>\n\n", argv[0]);
    return HALFLOOP_BAD_ARGUMENT;
  }

  num_pairs = atoi(argv[1]);
  if (num_pairs <= 0) {
    fprintf(stderr, "Bad number of pairs: %d\n", num_pairs);
    return HALFLOOP_BAD_ARGUMENT;
  }

  RETURN_ON_ERROR(init_halfloop());
  RETURN_ON_ERROR(test_halfloop());

  RETURN_ON_ERROR(random_bytes(&key, sizeof(u128)));
  RETURN_ON_ERROR(random_bytes(&seed, sizeof(seed)));
  seed.month = (ABS(seed.month) % 12) + 1;
  int days[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  seed.day = (ABS(seed.day) % days[seed.month - 1]) + 1;
  seed.coarse_time = ABS(seed.coarse_time) % 1440;
  seed.fine_time = ABS(seed.fine_time) % 60;
  seed.word = ABS(seed.word) % 256;
  seed.zero = 0;
  seed.frequency = (ABS(seed.frequency) % 270000) * 100 + 3000000;
  RETURN_ON_ERROR(create_seed(seed, &seed0));

  fprintf(stderr, "Key: %016" PRIx64 "%016" PRIx64 "\n", (u64)(key >> 64), (u64)key);

  TIMER_START(&timer);
  while (found < num_pairs) {
    RETURN_ON_ERROR(random_bytes(&pt0, sizeof(u32)));
    pt0 &= 0xffffff;
    for (int delta = 0; delta < 0x100; delta++) {
      u64 seed = seed0 ^ ((u64)delta << 40);
      RETURN_ON_ERROR(halfloop_encrypt(pt0 ^ delta, key, seed, ct + delta));
    }
    queries += 256;
    for (int i = 0; i < 0x100 && found < num_pairs; i++) {
      for (int j = i + 1; j < 0x100 && found < num_pairs; j++) {
        u32 out_diff = (i ^ j) << 16;
        if ((ct[i] ^ ct[j]) == out_diff) {
          printf("%06x %06x %06" PRIx64 "\n", pt0 ^ i, ct[i], seed0 ^ ((u64)i << 40));
          printf("%06x %06x %06" PRIx64 "\n", pt0 ^ j, ct[j], seed0 ^ ((u64)j << 40));
          found += 1;
        }
      }
    }
  }
  TIMER_STOP(&timer);
  fprintf(stderr, "%d pairs generated in %.1f seconds.\n", found, TIMER_ELAPSED(&timer));
  fprintf(stderr, "Number of chosen plaintext queries: %d\n", queries);

error:
  return err;
}
