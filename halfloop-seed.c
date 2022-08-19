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
#include <stdlib.h>
#include "halfloop-common.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Interprets an ALE seed.\n");
    fprintf(stderr, "Usage: %s hex_seed\n", argv[0]);
    return 1;
  }
  u64 s = strtoull(argv[1], NULL, 16);
  printf("Seed:        %016" PRIx64 "\n", s);

  seed_t seed;
  if (parse_seed(s, &seed) != HALFLOOP_SUCCESS) {
    fprintf(stderr, "Format error.\n");
    return 1;
  }

  printf("Month:       %d\n", seed.month);
  printf("Day:         %d\n", seed.day);
  printf("Coarse time: %d\n", seed.coarse_time);
  printf("Fine time:   %d\n", seed.fine_time);
  printf("Time:        %02d:%02d:%02d\n", seed.coarse_time / 60, seed.coarse_time % 60,
      seed.fine_time);
  printf("Word:        %d\n", seed.word);
  printf("Frequency:   %.1f kHz\n", seed.frequency / 1000.0);

  return 0;
}
