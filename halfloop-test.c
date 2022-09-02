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

#include "halfloop-bitslice.h"
#include "halfloop-common.h"

int main(int argc, char *argv[]) {
  halfloop_result_t err = HALFLOOP_SUCCESS;
  u128 key = ((u128)0x2b7e151628aed2a6 << 64) | 0xabf7158809cf4f3c;
  u64 tweak = 0x543bd88000017550;
  u32 pt = 0x010203;
  u32 ct;
  print_message("Testing standard implementation.", WHITE);
  RETURN_ON_ERROR(init_halfloop());
  RETURN_ON_ERROR(halfloop_encrypt(pt, key, tweak, &ct));
  RETURN_IF(ct != 0xf28c1e, HALFLOOP_INTERNAL_ERROR);
  RETURN_ON_ERROR(halfloop_decrypt(ct, key, tweak, &pt));
  RETURN_IF(pt != 0x010203, HALFLOOP_INTERNAL_ERROR);
  print_message("Standard implementation ok.", WHITE);
  RETURN_ON_ERROR(test_halfloop_bitslice());
  print_message("All tests successful.", GREEN);
error:
  if (err != HALFLOOP_SUCCESS) {
    print_message("Halfloop test failed.", RED);
  }
  return err;
}
