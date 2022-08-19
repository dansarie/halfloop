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

#ifndef HALFLOOP_BITSLICE_H_
#define HALFLOOP_BITSLICE_H_

#include "halfloop-common.h"

/**
 * @brief Searches through 2^32 candidate keys for ones that cause pt to be encrypted to ct, using
 * a bitslice implementation of HALFLOOP-24.
 *
 * @param pt a 24-bit plaintext.
 * @param ct a 24-bit ciphertext.
 * @param pkey a partial candidate key. The least significant 88 bits represent round keys 7, 8, 9,
 * and the most significant two bytes of round key 10. The most significant 8 bits represent the
 * middle 8 bits in round key 5. The remaining 32 bits are ignored.
 * @param found return pointer to a list of found matches. The pointer must be freed. The 8 most
 * significant bits in each item represent the least significant byte of round key five. The
 * remaining 24 bits represent round key 6.
 * @param num_found returns the number of keys in found.
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
halfloop_result_t halfloop_bitslice(u32 pt, u32 ct, u128 pkey, u32 **found, int *num_found);

/**
 * @brief Tests the HALFLOOP-24 bitslice implementation and prints information to the console.
 *
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
halfloop_result_t test_halfloop_bitslice();

#endif /* HALFLOOP_BITSLICE_H_ */
