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
    fprintf(stderr, "Interprets an ALE tweak.\n");
    fprintf(stderr, "Usage: %s hex_tweak\n", argv[0]);
    return 1;
  }
  u64 s = strtoull(argv[1], NULL, 16);
  printf("Tweak:       %016" PRIx64 "\n", s);

  tweak_t tweak;
  if (parse_tweak(s, &tweak) != HALFLOOP_SUCCESS) {
    fprintf(stderr, "Format error.\n");
    return 1;
  }

  printf("Month:       %d\n", tweak.month);
  printf("Day:         %d\n", tweak.day);
  printf("Coarse time: %d\n", tweak.coarse_time);
  printf("Fine time:   %d\n", tweak.fine_time);
  printf("Time:        %02d:%02d:%02d\n", tweak.coarse_time / 60, tweak.coarse_time % 60,
      tweak.fine_time);
  printf("Word:        %d\n", tweak.word);
  printf("Frequency:   %.1f kHz\n", tweak.frequency / 1000.0);

  return 0;
}
