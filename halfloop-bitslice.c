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
#include <immintrin.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "halfloop-bitslice.h"

#define GET_U128_BIT(V, B) _mm256_set1_epi64x(0ULL - (((V) >> (127 - B)) & 1))
#define GET_U64_BIT(V, B)  _mm256_set1_epi64x(0ULL - (((V) >> (63  - B)) & 1))
#define GET_U32_BIT(V, B)  _mm256_set1_epi64x(0ULL - (((V) >> (31  - B)) & 1))

typedef __m256i u256;

/**
 * @brief Represents a byte in the bitslice implementation.
 */
typedef struct {
  u256 b0; /* MSB */
  u256 b1;
  u256 b2;
  u256 b3;
  u256 b4;
  u256 b5;
  u256 b6;
  u256 b7; /* LSB */
} eightbits;

/**
 * @brief Represents three bytes in the bitslice implementation.
 *
 */
typedef struct {
  eightbits msb;
  eightbits mid;
  eightbits lsb;
} twentyfourbits;

/**
 * @brief Gate network implementation of the Rijndael S-box.
 * @see https://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
 */
static eightbits bitslice_sub_bytes(eightbits in) {
  u256 y14  =   in.b3  ^ in.b5;
  u256 y13  =   in.b0  ^ in.b6;
  u256 y9   =   in.b0  ^ in.b3;
  u256 y8   =   in.b0  ^ in.b5;
  u256 t0   =   in.b1  ^ in.b2;
  u256 y1   =   t0     ^ in.b7;
  u256 y4   =   y1     ^ in.b3;
  u256 y12  =   y13    ^ y14;
  u256 y2   =   y1     ^ in.b0;
  u256 y5   =   y1     ^ in.b6;
  u256 y3   =   y5     ^ y8;
  u256 t1   =   in.b4  ^ y12;
  u256 y15  =   t1     ^ in.b5;
  u256 y20  =   t1     ^ in.b1;
  u256 y6   =   y15    ^ in.b7;
  u256 y10  =   y15    ^ t0;
  u256 y11  =   y20    ^ y9;
  u256 y7   =   in.b7  ^ y11;
  u256 y17  =   y10    ^ y11;
  u256 y19  =   y10    ^ y8;
  u256 y16  =   t0     ^ y11;
  u256 y21  =   y13    ^ y16;
  u256 y18  =   in.b0  ^ y16;
  u256 t2   =   y12    & y15;
  u256 t3   =   y3     & y6;
  u256 t4   =   t3     ^ t2;
  u256 t5   =   y4     & in.b7;
  u256 t6   =   t5     ^ t2;
  u256 t7   =   y13    & y16;
  u256 t8   =   y5     & y1;
  u256 t9   =   t8     ^ t7;
  u256 t10  =   y2     & y7;
  u256 t11  =   t10    ^ t7;
  u256 t12  =   y9     & y11;
  u256 t13  =   y14    & y17;
  u256 t14  =   t13    ^ t12;
  u256 t15  =   y8     & y10;
  u256 t16  =   t15    ^ t12;
  u256 t17  =   t4     ^ y20;
  u256 t18  =   t6     ^ t16;
  u256 t19  =   t9     ^ t14;
  u256 t20  =   t11    ^ t16;
  u256 t21  =   t17    ^ t14;
  u256 t22  =   t18    ^ y19;
  u256 t23  =   t19    ^ y21;
  u256 t24  =   t20    ^ y18;
  u256 t25  =   t21    ^ t22;
  u256 t26  =   t21    & t23;
  u256 t27  =   t24    ^ t26;
  u256 t28  =   t25    & t27;
  u256 t29  =   t28    ^ t22;
  u256 t30  =   t23    ^ t24;
  u256 t31  =   t22    ^ t26;
  u256 t32  =   t31    & t30;
  u256 t33  =   t32    ^ t24;
  u256 t34  =   t23    ^ t33;
  u256 t35  =   t27    ^ t33;
  u256 t36  =   t24    & t35;
  u256 t37  =   t36    ^ t34;
  u256 t38  =   t27    ^ t36;
  u256 t39  =   t29    & t38;
  u256 t40  =   t25    ^ t39;
  u256 t41  =   t40    ^ t37;
  u256 t42  =   t29    ^ t33;
  u256 t43  =   t29    ^ t40;
  u256 t44  =   t33    ^ t37;
  u256 t45  =   t42    ^ t41;
  u256 z0   =   t44    & y15;
  u256 z1   =   t37    & y6;
  u256 z2   =   t33    & in.b7;
  u256 z3   =   t43    & y16;
  u256 z4   =   t40    & y1;
  u256 z5   =   t29    & y7;
  u256 z6   =   t42    & y11;
  u256 z7   =   t45    & y17;
  u256 z8   =   t41    & y10;
  u256 z9   =   t44    & y12;
  u256 z10  =   t37    & y3;
  u256 z11  =   t33    & y4;
  u256 z12  =   t43    & y13;
  u256 z13  =   t40    & y5;
  u256 z14  =   t29    & y2;
  u256 z15  =   t42    & y9;
  u256 z16  =   t45    & y14;
  u256 z17  =   t41    & y8;
  u256 tc1  =   z15    ^ z16;
  u256 tc2  =   z10    ^ tc1;
  u256 tc3  =   z9     ^ tc2;
  u256 tc4  =   z0     ^ z2;
  u256 tc5  =   z1     ^ z0;
  u256 tc6  =   z3     ^ z4;
  u256 tc7  =   z12    ^ tc4;
  u256 tc8  =   z7     ^ tc6;
  u256 tc9  =   z8     ^ tc7;
  u256 tc10 =   tc8    ^ tc9;
  u256 tc11 =   tc6    ^ tc5;
  u256 tc12 =   z3     ^ z5;
  u256 tc13 =   z13    ^ tc1;
  u256 tc14 =   tc4    ^ tc12;
  eightbits out;
  out.b3    =   tc3    ^ tc11;
  u256 tc16 =   z6     ^ tc8;
  u256 tc17 =   z14    ^ tc10;
  u256 tc18 =   tc13   ^ tc14;
  out.b7    = ~(z12    ^ tc18);
  u256 tc20 =   z15    ^ tc16;
  u256 tc21 =   tc2    ^ z11;
  out.b0    =   tc3    ^ tc16;
  out.b6    = ~(tc10   ^ tc18);
  out.b4    =   tc14   ^ out.b3;
  out.b1    = ~(out.b3 ^ tc16);
  u256 tc26 =   tc17   ^ tc20;
  out.b2    = ~(tc26   ^ z17);
  out.b5    =   tc21   ^ tc17;
  return out;
}

/**
 * @brief Performs the rotate right operation six steps.
 *
 * @param in input value.
 * @return eightbits the input value rotated right six steps.
 */
static eightbits bitslice_rotate_rows_6(eightbits in) {
  eightbits out = {
    .b0 = in.b6,
    .b1 = in.b7,
    .b2 = in.b0,
    .b3 = in.b1,
    .b4 = in.b2,
    .b5 = in.b3,
    .b6 = in.b4,
    .b7 = in.b5
  };
  return out;
}

/**
 * @brief Performs the rotate right operation four steps.
 *
 * @param in input value.
 * @return eightbits the input value rotated right four steps.
 */
static eightbits bitslice_rotate_rows_4(eightbits in) {
  eightbits out = {
    .b0 = in.b4,
    .b1 = in.b5,
    .b2 = in.b6,
    .b3 = in.b7,
    .b4 = in.b0,
    .b5 = in.b1,
    .b6 = in.b2,
    .b7 = in.b3
  };
  return out;
}

/**
 * @brief Performs the HALFLOOP-24 mix columns operation.
 *
 * @param in input value.
 * @return twentyfourbits the output of the mix columns operation on the input value.
 */
static twentyfourbits bitslice_mix_columns(twentyfourbits in) {
  twentyfourbits out = {
    .lsb = {
      .b7 = in.lsb.b7 ^ in.lsb.b2 ^ in.mid.b0 ^ in.msb.b7,
      .b6 = in.lsb.b6 ^ in.lsb.b2 ^ in.lsb.b1 ^ in.mid.b7 ^ in.mid.b0 ^ in.msb.b6,
      .b5 = in.lsb.b5 ^ in.lsb.b1 ^ in.lsb.b0 ^ in.mid.b6 ^ in.msb.b5,
      .b4 = in.lsb.b7 ^ in.lsb.b4 ^ in.lsb.b2 ^ in.lsb.b0 ^ in.mid.b5 ^ in.mid.b0 ^ in.msb.b4,
      .b3 = in.lsb.b6 ^ in.lsb.b3 ^ in.lsb.b2 ^ in.lsb.b1 ^ in.mid.b4 ^ in.mid.b0 ^ in.msb.b3,
      .b2 = in.lsb.b5 ^ in.lsb.b2 ^ in.lsb.b1 ^ in.lsb.b0 ^ in.mid.b3 ^ in.msb.b2,
      .b1 = in.lsb.b4 ^ in.lsb.b1 ^ in.lsb.b0 ^ in.mid.b2 ^ in.msb.b1,
      .b0 = in.lsb.b3 ^ in.lsb.b0 ^ in.mid.b1 ^ in.msb.b0
    },
    .mid = {
      .b7 = in.lsb.b7 ^ in.mid.b7 ^ in.mid.b2 ^ in.msb.b0,
      .b6 = in.lsb.b6 ^ in.mid.b6 ^ in.mid.b2 ^ in.mid.b1 ^ in.msb.b7 ^ in.msb.b0,
      .b5 = in.lsb.b5 ^ in.mid.b5 ^ in.mid.b1 ^ in.mid.b0 ^ in.msb.b6,
      .b4 = in.lsb.b4 ^ in.mid.b7 ^ in.mid.b4 ^ in.mid.b2 ^ in.mid.b0 ^ in.msb.b5 ^ in.msb.b0,
      .b3 = in.lsb.b3 ^ in.mid.b6 ^ in.mid.b3 ^ in.mid.b2 ^ in.mid.b1 ^ in.msb.b4 ^ in.msb.b0,
      .b2 = in.lsb.b2 ^ in.mid.b5 ^ in.mid.b2 ^ in.mid.b1 ^ in.mid.b0 ^ in.msb.b3,
      .b1 = in.lsb.b1 ^ in.mid.b4 ^ in.mid.b1 ^ in.mid.b0 ^ in.msb.b2,
      .b0 = in.lsb.b0 ^ in.mid.b3 ^ in.mid.b0 ^ in.msb.b1
    },
    .msb = {
      .b7 = in.lsb.b0 ^ in.mid.b7 ^ in.msb.b7 ^ in.msb.b2,
      .b6 = in.lsb.b7 ^ in.lsb.b0 ^ in.mid.b6 ^ in.msb.b6 ^ in.msb.b2 ^ in.msb.b1,
      .b5 = in.lsb.b6 ^ in.mid.b5 ^ in.msb.b5 ^ in.msb.b1 ^ in.msb.b0,
      .b4 = in.lsb.b5 ^ in.lsb.b0 ^ in.mid.b4 ^ in.msb.b7 ^ in.msb.b4 ^ in.msb.b2 ^ in.msb.b0,
      .b3 = in.lsb.b4 ^ in.lsb.b0 ^ in.mid.b3 ^ in.msb.b6 ^ in.msb.b3 ^ in.msb.b2 ^ in.msb.b1,
      .b2 = in.lsb.b3 ^ in.mid.b2 ^ in.msb.b5 ^ in.msb.b2 ^ in.msb.b1 ^ in.msb.b0,
      .b1 = in.lsb.b2 ^ in.mid.b1 ^ in.msb.b4 ^ in.msb.b1 ^ in.msb.b0,
      .b0 = in.lsb.b1 ^ in.mid.b0 ^ in.msb.b3 ^ in.msb.b0
    }
  };
  return out;
}

halfloop_result_t halfloop_bitslice(u32 pt, u32 ct, u128 pkey, u32 **found, int *num_found) {
  if (found == NULL || num_found == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  int alloc = 300;
  *num_found = 0;
  *found = malloc(alloc * sizeof(u32));
  if (*found == NULL) {
    return HALFLOOP_MEMORY_ERROR;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;

  twentyfourbits pt_bits = {
    .msb = {
      .b0 = GET_U32_BIT(pt, 8),
      .b1 = GET_U32_BIT(pt, 9),
      .b2 = GET_U32_BIT(pt, 10),
      .b3 = GET_U32_BIT(pt, 11),
      .b4 = GET_U32_BIT(pt, 12),
      .b5 = GET_U32_BIT(pt, 13),
      .b6 = GET_U32_BIT(pt, 14),
      .b7 = GET_U32_BIT(pt, 15)
    },
    .mid = {
      .b0 = GET_U32_BIT(pt, 16),
      .b1 = GET_U32_BIT(pt, 17),
      .b2 = GET_U32_BIT(pt, 18),
      .b3 = GET_U32_BIT(pt, 19),
      .b4 = GET_U32_BIT(pt, 20),
      .b5 = GET_U32_BIT(pt, 21),
      .b6 = GET_U32_BIT(pt, 22),
      .b7 = GET_U32_BIT(pt, 23)
    },
    .lsb = {
      .b0 = GET_U32_BIT(pt, 24),
      .b1 = GET_U32_BIT(pt, 25),
      .b2 = GET_U32_BIT(pt, 26),
      .b3 = GET_U32_BIT(pt, 27),
      .b4 = GET_U32_BIT(pt, 28),
      .b5 = GET_U32_BIT(pt, 29),
      .b6 = GET_U32_BIT(pt, 30),
      .b7 = GET_U32_BIT(pt, 31)
    }
  };

  ct = (inv_sub_bytes(inv_rotate_rows(inv_mix_columns(ct))) ^ (pkey >> 64)) & 0xffffff;
  ct = inv_sub_bytes(inv_rotate_rows(inv_mix_columns(ct)));

  u32 g_value = key_schedule_g((u32)(pkey ^ (pkey >> 32)), 1);

  for (u64 rk56 = 0; rk56 < 0x100000000; rk56 += 256) {
    twentyfourbits state = pt_bits;

    /* Add rk0. */
    state.msb.b0 ^= GET_U128_BIT(pkey, 0) ^ GET_U32_BIT(g_value, 0);
    state.msb.b1 ^= GET_U128_BIT(pkey, 1) ^ GET_U32_BIT(g_value, 1);
    state.msb.b2 ^= GET_U128_BIT(pkey, 2) ^ GET_U32_BIT(g_value, 2);
    state.msb.b3 ^= GET_U128_BIT(pkey, 3) ^ GET_U32_BIT(g_value, 3);
    state.msb.b4 ^= GET_U128_BIT(pkey, 4) ^ GET_U32_BIT(g_value, 4);
    state.msb.b5 ^= GET_U128_BIT(pkey, 5) ^ GET_U32_BIT(g_value, 5);
    state.msb.b6 ^= GET_U128_BIT(pkey, 6) ^ GET_U32_BIT(g_value, 6);
    state.msb.b7 ^= GET_U128_BIT(pkey, 7) ^ GET_U32_BIT(g_value, 7);
    state.mid.b0 ^= GET_U64_BIT(rk56, 32) ^ GET_U32_BIT(g_value, 8);
    state.mid.b1 ^= GET_U64_BIT(rk56, 33) ^ GET_U32_BIT(g_value, 9);
    state.mid.b2 ^= GET_U64_BIT(rk56, 34) ^ GET_U32_BIT(g_value, 10);
    state.mid.b3 ^= GET_U64_BIT(rk56, 35) ^ GET_U32_BIT(g_value, 11);
    state.mid.b4 ^= GET_U64_BIT(rk56, 36) ^ GET_U32_BIT(g_value, 12);
    state.mid.b5 ^= GET_U64_BIT(rk56, 37) ^ GET_U32_BIT(g_value, 13);
    state.mid.b6 ^= GET_U64_BIT(rk56, 38) ^ GET_U32_BIT(g_value, 14);
    state.mid.b7 ^= GET_U64_BIT(rk56, 39) ^ GET_U32_BIT(g_value, 15);
    state.lsb.b0 ^= GET_U64_BIT(rk56, 40) ^ GET_U32_BIT(g_value, 16);
    state.lsb.b1 ^= GET_U64_BIT(rk56, 41) ^ GET_U32_BIT(g_value, 17);
    state.lsb.b2 ^= GET_U64_BIT(rk56, 42) ^ GET_U32_BIT(g_value, 18);
    state.lsb.b3 ^= GET_U64_BIT(rk56, 43) ^ GET_U32_BIT(g_value, 19);
    state.lsb.b4 ^= GET_U64_BIT(rk56, 44) ^ GET_U32_BIT(g_value, 20);
    state.lsb.b5 ^= GET_U64_BIT(rk56, 45) ^ GET_U32_BIT(g_value, 21);
    state.lsb.b6 ^= GET_U64_BIT(rk56, 46) ^ GET_U32_BIT(g_value, 22);
    state.lsb.b7 ^= GET_U64_BIT(rk56, 47) ^ GET_U32_BIT(g_value, 23);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk1 */
    state.msb.b0 ^= GET_U64_BIT(rk56, 48)  ^ GET_U32_BIT(g_value, 24);
    state.msb.b1 ^= GET_U64_BIT(rk56, 49)  ^ GET_U32_BIT(g_value, 25);
    state.msb.b2 ^= GET_U64_BIT(rk56, 50)  ^ GET_U32_BIT(g_value, 26);
    state.msb.b3 ^= GET_U64_BIT(rk56, 51)  ^ GET_U32_BIT(g_value, 27);
    state.msb.b4 ^= GET_U64_BIT(rk56, 52)  ^ GET_U32_BIT(g_value, 28);
    state.msb.b5 ^= GET_U64_BIT(rk56, 53)  ^ GET_U32_BIT(g_value, 29);
    state.msb.b6 ^= GET_U64_BIT(rk56, 54)  ^ GET_U32_BIT(g_value, 30);
    state.msb.b7 ^= GET_U64_BIT(rk56, 55)  ^ GET_U32_BIT(g_value, 31);
    state.mid.b0 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL) ^ GET_U128_BIT(pkey, 0);
    state.mid.b1 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL) ^ GET_U128_BIT(pkey, 1);
    state.mid.b2 ^= _mm256_set1_epi64x(0xFFFFFFFF00000000ULL) ^ GET_U128_BIT(pkey, 2);
    state.mid.b3 ^= _mm256_set1_epi64x(0xFFFF0000FFFF0000ULL) ^ GET_U128_BIT(pkey, 3);
    state.mid.b4 ^= _mm256_set1_epi64x(0xFF00FF00FF00FF00ULL) ^ GET_U128_BIT(pkey, 4);
    state.mid.b5 ^= _mm256_set1_epi64x(0xF0F0F0F0F0F0F0F0ULL) ^ GET_U128_BIT(pkey, 5);
    state.mid.b6 ^= _mm256_set1_epi64x(0xCCCCCCCCCCCCCCCCULL) ^ GET_U128_BIT(pkey, 6);
    state.mid.b7 ^= _mm256_set1_epi64x(0xAAAAAAAAAAAAAAAAULL) ^ GET_U128_BIT(pkey, 7);
    state.lsb.b0 ^= GET_U128_BIT(pkey, 40) ^ GET_U64_BIT(rk56, 32);
    state.lsb.b1 ^= GET_U128_BIT(pkey, 41) ^ GET_U64_BIT(rk56, 33);
    state.lsb.b2 ^= GET_U128_BIT(pkey, 42) ^ GET_U64_BIT(rk56, 34);
    state.lsb.b3 ^= GET_U128_BIT(pkey, 43) ^ GET_U64_BIT(rk56, 35);
    state.lsb.b4 ^= GET_U128_BIT(pkey, 44) ^ GET_U64_BIT(rk56, 36);
    state.lsb.b5 ^= GET_U128_BIT(pkey, 45) ^ GET_U64_BIT(rk56, 37);
    state.lsb.b6 ^= GET_U128_BIT(pkey, 46) ^ GET_U64_BIT(rk56, 38);
    state.lsb.b7 ^= GET_U128_BIT(pkey, 47) ^ GET_U64_BIT(rk56, 39);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk2 */
    state.msb.b0 ^= GET_U128_BIT(pkey, 48) ^ GET_U64_BIT(rk56, 40);
    state.msb.b1 ^= GET_U128_BIT(pkey, 49) ^ GET_U64_BIT(rk56, 41);
    state.msb.b2 ^= GET_U128_BIT(pkey, 50) ^ GET_U64_BIT(rk56, 42);
    state.msb.b3 ^= GET_U128_BIT(pkey, 51) ^ GET_U64_BIT(rk56, 43);
    state.msb.b4 ^= GET_U128_BIT(pkey, 52) ^ GET_U64_BIT(rk56, 44);
    state.msb.b5 ^= GET_U128_BIT(pkey, 53) ^ GET_U64_BIT(rk56, 45);
    state.msb.b6 ^= GET_U128_BIT(pkey, 54) ^ GET_U64_BIT(rk56, 46);
    state.msb.b7 ^= GET_U128_BIT(pkey, 55) ^ GET_U64_BIT(rk56, 47);
    state.mid.b0 ^= GET_U128_BIT(pkey, 56) ^ GET_U64_BIT(rk56, 48);
    state.mid.b1 ^= GET_U128_BIT(pkey, 57) ^ GET_U64_BIT(rk56, 49);
    state.mid.b2 ^= GET_U128_BIT(pkey, 58) ^ GET_U64_BIT(rk56, 50);
    state.mid.b3 ^= GET_U128_BIT(pkey, 59) ^ GET_U64_BIT(rk56, 51);
    state.mid.b4 ^= GET_U128_BIT(pkey, 60) ^ GET_U64_BIT(rk56, 52);
    state.mid.b5 ^= GET_U128_BIT(pkey, 61) ^ GET_U64_BIT(rk56, 53);
    state.mid.b6 ^= GET_U128_BIT(pkey, 62) ^ GET_U64_BIT(rk56, 54);
    state.mid.b7 ^= GET_U128_BIT(pkey, 63) ^ GET_U64_BIT(rk56, 55);
    state.lsb.b0 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL) ^ GET_U128_BIT(pkey, 64);
    state.lsb.b1 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL) ^ GET_U128_BIT(pkey, 65);
    state.lsb.b2 ^= GET_U128_BIT(pkey, 66) ^ _mm256_set1_epi64x(0xFFFFFFFF00000000ULL);
    state.lsb.b3 ^= GET_U128_BIT(pkey, 67) ^ _mm256_set1_epi64x(0xFFFF0000FFFF0000ULL);
    state.lsb.b4 ^= GET_U128_BIT(pkey, 68) ^ _mm256_set1_epi64x(0xFF00FF00FF00FF00ULL);
    state.lsb.b5 ^= GET_U128_BIT(pkey, 69) ^ _mm256_set1_epi64x(0xF0F0F0F0F0F0F0F0ULL);
    state.lsb.b6 ^= GET_U128_BIT(pkey, 70) ^ _mm256_set1_epi64x(0xCCCCCCCCCCCCCCCCULL);
    state.lsb.b7 ^= GET_U128_BIT(pkey, 71) ^ _mm256_set1_epi64x(0xAAAAAAAAAAAAAAAAULL);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk3 */
    state.msb.b0 ^= GET_U128_BIT(pkey, 72) ^ GET_U128_BIT(pkey, 40);
    state.msb.b1 ^= GET_U128_BIT(pkey, 73) ^ GET_U128_BIT(pkey, 41);
    state.msb.b2 ^= GET_U128_BIT(pkey, 74) ^ GET_U128_BIT(pkey, 42);
    state.msb.b3 ^= GET_U128_BIT(pkey, 75) ^ GET_U128_BIT(pkey, 43);
    state.msb.b4 ^= GET_U128_BIT(pkey, 76) ^ GET_U128_BIT(pkey, 44);
    state.msb.b5 ^= GET_U128_BIT(pkey, 77) ^ GET_U128_BIT(pkey, 45);
    state.msb.b6 ^= GET_U128_BIT(pkey, 78) ^ GET_U128_BIT(pkey, 46);
    state.msb.b7 ^= GET_U128_BIT(pkey, 79) ^ GET_U128_BIT(pkey, 47);
    state.mid.b0 ^= GET_U128_BIT(pkey, 80) ^ GET_U128_BIT(pkey, 48);
    state.mid.b1 ^= GET_U128_BIT(pkey, 81) ^ GET_U128_BIT(pkey, 49);
    state.mid.b2 ^= GET_U128_BIT(pkey, 82) ^ GET_U128_BIT(pkey, 50);
    state.mid.b3 ^= GET_U128_BIT(pkey, 83) ^ GET_U128_BIT(pkey, 51);
    state.mid.b4 ^= GET_U128_BIT(pkey, 84) ^ GET_U128_BIT(pkey, 52);
    state.mid.b5 ^= GET_U128_BIT(pkey, 85) ^ GET_U128_BIT(pkey, 53);
    state.mid.b6 ^= GET_U128_BIT(pkey, 86) ^ GET_U128_BIT(pkey, 54);
    state.mid.b7 ^= GET_U128_BIT(pkey, 87) ^ GET_U128_BIT(pkey, 55);
    state.lsb.b0 ^= GET_U128_BIT(pkey, 88) ^ GET_U128_BIT(pkey, 56);
    state.lsb.b1 ^= GET_U128_BIT(pkey, 89) ^ GET_U128_BIT(pkey, 57);
    state.lsb.b2 ^= GET_U128_BIT(pkey, 90) ^ GET_U128_BIT(pkey, 58);
    state.lsb.b3 ^= GET_U128_BIT(pkey, 91) ^ GET_U128_BIT(pkey, 59);
    state.lsb.b4 ^= GET_U128_BIT(pkey, 92) ^ GET_U128_BIT(pkey, 60);
    state.lsb.b5 ^= GET_U128_BIT(pkey, 93) ^ GET_U128_BIT(pkey, 61);
    state.lsb.b6 ^= GET_U128_BIT(pkey, 94) ^ GET_U128_BIT(pkey, 62);
    state.lsb.b7 ^= GET_U128_BIT(pkey, 95) ^ GET_U128_BIT(pkey, 63);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk4 */
    state.msb.b0 ^= GET_U128_BIT(pkey, 96)  ^ GET_U128_BIT(pkey, 64);
    state.msb.b1 ^= GET_U128_BIT(pkey, 97)  ^ GET_U128_BIT(pkey, 65);
    state.msb.b2 ^= GET_U128_BIT(pkey, 98)  ^ GET_U128_BIT(pkey, 66);
    state.msb.b3 ^= GET_U128_BIT(pkey, 99)  ^ GET_U128_BIT(pkey, 67);
    state.msb.b4 ^= GET_U128_BIT(pkey, 100) ^ GET_U128_BIT(pkey, 68);
    state.msb.b5 ^= GET_U128_BIT(pkey, 101) ^ GET_U128_BIT(pkey, 69);
    state.msb.b6 ^= GET_U128_BIT(pkey, 102) ^ GET_U128_BIT(pkey, 70);
    state.msb.b7 ^= GET_U128_BIT(pkey, 103) ^ GET_U128_BIT(pkey, 71);
    state.mid.b0 ^= GET_U128_BIT(pkey, 104) ^ GET_U128_BIT(pkey, 72);
    state.mid.b1 ^= GET_U128_BIT(pkey, 105) ^ GET_U128_BIT(pkey, 73);
    state.mid.b2 ^= GET_U128_BIT(pkey, 106) ^ GET_U128_BIT(pkey, 74);
    state.mid.b3 ^= GET_U128_BIT(pkey, 107) ^ GET_U128_BIT(pkey, 75);
    state.mid.b4 ^= GET_U128_BIT(pkey, 108) ^ GET_U128_BIT(pkey, 76);
    state.mid.b5 ^= GET_U128_BIT(pkey, 109) ^ GET_U128_BIT(pkey, 77);
    state.mid.b6 ^= GET_U128_BIT(pkey, 110) ^ GET_U128_BIT(pkey, 78);
    state.mid.b7 ^= GET_U128_BIT(pkey, 111) ^ GET_U128_BIT(pkey, 79);
    state.lsb.b0 ^= GET_U128_BIT(pkey, 112) ^ GET_U128_BIT(pkey, 80);
    state.lsb.b1 ^= GET_U128_BIT(pkey, 113) ^ GET_U128_BIT(pkey, 81);
    state.lsb.b2 ^= GET_U128_BIT(pkey, 114) ^ GET_U128_BIT(pkey, 82);
    state.lsb.b3 ^= GET_U128_BIT(pkey, 115) ^ GET_U128_BIT(pkey, 83);
    state.lsb.b4 ^= GET_U128_BIT(pkey, 116) ^ GET_U128_BIT(pkey, 84);
    state.lsb.b5 ^= GET_U128_BIT(pkey, 117) ^ GET_U128_BIT(pkey, 85);
    state.lsb.b6 ^= GET_U128_BIT(pkey, 118) ^ GET_U128_BIT(pkey, 86);
    state.lsb.b7 ^= GET_U128_BIT(pkey, 119) ^ GET_U128_BIT(pkey, 87);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk5 */
    state.msb.b0 ^= GET_U128_BIT(pkey, 120) ^ GET_U128_BIT(pkey, 88);
    state.msb.b1 ^= GET_U128_BIT(pkey, 121) ^ GET_U128_BIT(pkey, 89);
    state.msb.b2 ^= GET_U128_BIT(pkey, 122) ^ GET_U128_BIT(pkey, 90);
    state.msb.b3 ^= GET_U128_BIT(pkey, 123) ^ GET_U128_BIT(pkey, 91);
    state.msb.b4 ^= GET_U128_BIT(pkey, 124) ^ GET_U128_BIT(pkey, 92);
    state.msb.b5 ^= GET_U128_BIT(pkey, 125) ^ GET_U128_BIT(pkey, 93);
    state.msb.b6 ^= GET_U128_BIT(pkey, 126) ^ GET_U128_BIT(pkey, 94);
    state.msb.b7 ^= GET_U128_BIT(pkey, 127) ^ GET_U128_BIT(pkey, 95);
    state.mid.b0 ^= GET_U128_BIT(pkey, 0);
    state.mid.b1 ^= GET_U128_BIT(pkey, 1);
    state.mid.b2 ^= GET_U128_BIT(pkey, 2);
    state.mid.b3 ^= GET_U128_BIT(pkey, 3);
    state.mid.b4 ^= GET_U128_BIT(pkey, 4);
    state.mid.b5 ^= GET_U128_BIT(pkey, 5);
    state.mid.b6 ^= GET_U128_BIT(pkey, 6);
    state.mid.b7 ^= GET_U128_BIT(pkey, 7);
    state.lsb.b0 ^= GET_U64_BIT(rk56, 32);
    state.lsb.b1 ^= GET_U64_BIT(rk56, 33);
    state.lsb.b2 ^= GET_U64_BIT(rk56, 34);
    state.lsb.b3 ^= GET_U64_BIT(rk56, 35);
    state.lsb.b4 ^= GET_U64_BIT(rk56, 36);
    state.lsb.b5 ^= GET_U64_BIT(rk56, 37);
    state.lsb.b6 ^= GET_U64_BIT(rk56, 38);
    state.lsb.b7 ^= GET_U64_BIT(rk56, 39);

    state.msb = bitslice_sub_bytes(state.msb);
    state.mid = bitslice_rotate_rows_6(bitslice_sub_bytes(state.mid));
    state.lsb = bitslice_rotate_rows_4(bitslice_sub_bytes(state.lsb));
    state = bitslice_mix_columns(state);

    /* Add rk6 */
    state.msb.b0 ^= GET_U64_BIT(rk56, 40);
    state.msb.b1 ^= GET_U64_BIT(rk56, 41);
    state.msb.b2 ^= GET_U64_BIT(rk56, 42);
    state.msb.b3 ^= GET_U64_BIT(rk56, 43);
    state.msb.b4 ^= GET_U64_BIT(rk56, 44);
    state.msb.b5 ^= GET_U64_BIT(rk56, 45);
    state.msb.b6 ^= GET_U64_BIT(rk56, 46);
    state.msb.b7 ^= GET_U64_BIT(rk56, 47);
    state.mid.b0 ^= GET_U64_BIT(rk56, 48);
    state.mid.b1 ^= GET_U64_BIT(rk56, 49);
    state.mid.b2 ^= GET_U64_BIT(rk56, 50);
    state.mid.b3 ^= GET_U64_BIT(rk56, 51);
    state.mid.b4 ^= GET_U64_BIT(rk56, 52);
    state.mid.b5 ^= GET_U64_BIT(rk56, 53);
    state.mid.b6 ^= GET_U64_BIT(rk56, 54);
    state.mid.b7 ^= GET_U64_BIT(rk56, 55);
    state.lsb.b0 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL);
    state.lsb.b1 ^= _mm256_set_epi64x(
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0000000000000000ULL);
    state.lsb.b2 ^= _mm256_set1_epi64x(0xFFFFFFFF00000000ULL);
    state.lsb.b3 ^= _mm256_set1_epi64x(0xFFFF0000FFFF0000ULL);
    state.lsb.b4 ^= _mm256_set1_epi64x(0xFF00FF00FF00FF00ULL);
    state.lsb.b5 ^= _mm256_set1_epi64x(0xF0F0F0F0F0F0F0F0ULL);
    state.lsb.b6 ^= _mm256_set1_epi64x(0xCCCCCCCCCCCCCCCCULL);
    state.lsb.b7 ^= _mm256_set1_epi64x(0xAAAAAAAAAAAAAAAAULL);

    u256 cmp;
    cmp  = state.msb.b0 ^ GET_U32_BIT(ct, 8);
    cmp |= state.msb.b1 ^ GET_U32_BIT(ct, 9);
    cmp |= state.msb.b2 ^ GET_U32_BIT(ct, 10);
    cmp |= state.msb.b3 ^ GET_U32_BIT(ct, 11);
    cmp |= state.msb.b4 ^ GET_U32_BIT(ct, 12);
    cmp |= state.msb.b5 ^ GET_U32_BIT(ct, 13);
    cmp |= state.msb.b6 ^ GET_U32_BIT(ct, 14);
    cmp |= state.msb.b7 ^ GET_U32_BIT(ct, 15);
    cmp |= state.mid.b0 ^ GET_U32_BIT(ct, 16);
    cmp |= state.mid.b1 ^ GET_U32_BIT(ct, 17);
    cmp |= state.mid.b2 ^ GET_U32_BIT(ct, 18);
    cmp |= state.mid.b3 ^ GET_U32_BIT(ct, 19);
    cmp |= state.mid.b4 ^ GET_U32_BIT(ct, 20);
    cmp |= state.mid.b5 ^ GET_U32_BIT(ct, 21);
    cmp |= state.mid.b6 ^ GET_U32_BIT(ct, 22);
    cmp |= state.mid.b7 ^ GET_U32_BIT(ct, 23);
    cmp |= state.lsb.b0 ^ GET_U32_BIT(ct, 24);
    cmp |= state.lsb.b1 ^ GET_U32_BIT(ct, 25);
    cmp |= state.lsb.b2 ^ GET_U32_BIT(ct, 26);
    cmp |= state.lsb.b3 ^ GET_U32_BIT(ct, 27);
    cmp |= state.lsb.b4 ^ GET_U32_BIT(ct, 28);
    cmp |= state.lsb.b5 ^ GET_U32_BIT(ct, 29);
    cmp |= state.lsb.b6 ^ GET_U32_BIT(ct, 30);
    cmp |= state.lsb.b7 ^ GET_U32_BIT(ct, 31);
    cmp = ~cmp;

    u64 cmpa[4];
    _mm256_storeu_si256((u256*)cmpa, cmp);
    for (int i = 0; i < 4; i++) {
      while (cmpa[i] != 0) {
        if (*num_found == alloc) {
          alloc += 300;
          u32 *tmp = realloc(*found, alloc * sizeof(u32));
          RETURN_IF(tmp == NULL, HALFLOOP_MEMORY_ERROR);
          *found = tmp;
        }
        int low6 = __builtin_ffsl(cmpa[i]) - 1;
        (*found)[*num_found] = rk56 | (i << 6) | low6;
        cmpa[i] ^= 1ULL << low6;
        *num_found += 1;
      }
    }
  }

error:
  if (err != HALFLOOP_SUCCESS) {
    FREE_AND_NULL(*found);
    *num_found = 0;
  }
  return err;
}

/**
 * @brief Returns the least significant bit in each of the eight variables in the input struct.
 * Used for testing.
 */
static u8 get_lower_bits(eightbits in) {
  u8 ret = (_mm256_cvtsi256_si32(in.b0) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b1) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b2) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b3) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b4) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b5) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b6) & 1);
  ret = (ret << 1) | (_mm256_cvtsi256_si32(in.b7) & 1);
  return ret;
}

/**
 * @brief Returns true if, for each of the eight variables in the input struct, all 256 bits are
 * equal. Used for testing.
 */
static bool check_equal_bits(eightbits in) {
  return (_mm256_testz_si256(in.b0, in.b0) || _mm256_testz_si256(~in.b0, ~in.b0))
      && (_mm256_testz_si256(in.b1, in.b1) || _mm256_testz_si256(~in.b1, ~in.b1))
      && (_mm256_testz_si256(in.b2, in.b2) || _mm256_testz_si256(~in.b2, ~in.b2))
      && (_mm256_testz_si256(in.b3, in.b3) || _mm256_testz_si256(~in.b3, ~in.b3))
      && (_mm256_testz_si256(in.b4, in.b4) || _mm256_testz_si256(~in.b4, ~in.b4))
      && (_mm256_testz_si256(in.b5, in.b5) || _mm256_testz_si256(~in.b5, ~in.b5))
      && (_mm256_testz_si256(in.b6, in.b6) || _mm256_testz_si256(~in.b6, ~in.b6))
      && (_mm256_testz_si256(in.b7, in.b7) || _mm256_testz_si256(~in.b7, ~in.b7));
}

/**
 * @brief Returns true if the bitslice implementation of the Rijndael S-box is correct. Used for
 * testing.
 */
static halfloop_result_t test_bitslice_sbox() {
  halfloop_result_t err = HALFLOOP_SUCCESS;
  for (u32 i = 0; i < 0x100; i++) {
    eightbits in = {
      .b0 = GET_U32_BIT(i, 24),
      .b1 = GET_U32_BIT(i, 25),
      .b2 = GET_U32_BIT(i, 26),
      .b3 = GET_U32_BIT(i, 27),
      .b4 = GET_U32_BIT(i, 28),
      .b5 = GET_U32_BIT(i, 29),
      .b6 = GET_U32_BIT(i, 30),
      .b7 = GET_U32_BIT(i, 31)
    };
    eightbits out = bitslice_sub_bytes(in);
    RETURN_IF(!check_equal_bits(out), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(get_lower_bits(out) != SBOX[i], HALFLOOP_INTERNAL_ERROR);
  }
error:
  return err;
}

/**
 * @brief Returns true if the bitslice implementation of the rotate rows operations is correct. Used
 * for testing.
 */
static halfloop_result_t test_bitslice_rotate_rows() {
  halfloop_result_t err = HALFLOOP_SUCCESS;
  for (u32 i = 0; i < 0x100; i++) {
    eightbits in = {
      .b0 = GET_U32_BIT(i, 24),
      .b1 = GET_U32_BIT(i, 25),
      .b2 = GET_U32_BIT(i, 26),
      .b3 = GET_U32_BIT(i, 27),
      .b4 = GET_U32_BIT(i, 28),
      .b5 = GET_U32_BIT(i, 29),
      .b6 = GET_U32_BIT(i, 30),
      .b7 = GET_U32_BIT(i, 31)
    };
    eightbits out4 = bitslice_rotate_rows_4(in);
    eightbits out6 = bitslice_rotate_rows_6(in);
    RETURN_IF(!check_equal_bits(out4), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(!check_equal_bits(out6), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(get_lower_bits(out4) != (u8)((i << 4) | (i >> 4)), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(get_lower_bits(out6) != (u8)((i << 6) | (i >> 2)), HALFLOOP_INTERNAL_ERROR);
  }
error:
  return err;
}

/**
 * @brief Returns true if the bitslice implementation of the HALFLOOP-24 mix columns operation is
 * correct. Used for testing.
 */
static halfloop_result_t test_bitslice_mix_columns() {
  halfloop_result_t err = HALFLOOP_SUCCESS;
  for (u32 i = 0; i < 0x1000000; i++) {
    twentyfourbits in = {
      .msb = {
        .b0 = GET_U32_BIT(i, 8),
        .b1 = GET_U32_BIT(i, 9),
        .b2 = GET_U32_BIT(i, 10),
        .b3 = GET_U32_BIT(i, 11),
        .b4 = GET_U32_BIT(i, 12),
        .b5 = GET_U32_BIT(i, 13),
        .b6 = GET_U32_BIT(i, 14),
        .b7 = GET_U32_BIT(i, 15)
      },
      .mid = {
        .b0 = GET_U32_BIT(i, 16),
        .b1 = GET_U32_BIT(i, 17),
        .b2 = GET_U32_BIT(i, 18),
        .b3 = GET_U32_BIT(i, 19),
        .b4 = GET_U32_BIT(i, 20),
        .b5 = GET_U32_BIT(i, 21),
        .b6 = GET_U32_BIT(i, 22),
        .b7 = GET_U32_BIT(i, 23)
      },
      .lsb = {
        .b0 = GET_U32_BIT(i, 24),
        .b1 = GET_U32_BIT(i, 25),
        .b2 = GET_U32_BIT(i, 26),
        .b3 = GET_U32_BIT(i, 27),
        .b4 = GET_U32_BIT(i, 28),
        .b5 = GET_U32_BIT(i, 29),
        .b6 = GET_U32_BIT(i, 30),
        .b7 = GET_U32_BIT(i, 31)
      }
    };
    twentyfourbits out = bitslice_mix_columns(in);
    RETURN_IF(!check_equal_bits(out.msb), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(!check_equal_bits(out.mid), HALFLOOP_INTERNAL_ERROR);
    RETURN_IF(!check_equal_bits(out.lsb), HALFLOOP_INTERNAL_ERROR);
    u32 res = (get_lower_bits(out.msb) << 16) | (get_lower_bits(out.mid) << 8)
        | get_lower_bits(out.lsb);
    RETURN_IF(res != mix_columns(i), HALFLOOP_INTERNAL_ERROR);
  }
error:
  return err;
}

halfloop_result_t test_halfloop_bitslice() {
  u32 pt = 0;
  u64 seed = 0;
  u128 key = 0;
  u32 rk[11];
  u32 *found = NULL;
  int num_found = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  RETURN_ON_ERROR(random_bytes(&pt, sizeof(u32)));
  RETURN_ON_ERROR(random_bytes(&seed, sizeof(u64)));
  RETURN_ON_ERROR(random_bytes(&key, sizeof(u128)));
  pt &= 0xffffff;

  print_message("Testing bitslice subroutines.", WHITE);
  RETURN_ON_ERROR(test_bitslice_sbox());
  RETURN_ON_ERROR(test_bitslice_rotate_rows());
  RETURN_ON_ERROR(test_bitslice_mix_columns());
  RETURN_ON_ERROR(key_schedule(rk, key, seed));

  u32 state = pt;
  for (int i = 0; i < 8; i++) {
    state = mix_columns(rotate_rows(sub_bytes(state ^ rk[i])));
  }

  u128 pkey = ((u128)(rk[5] & 0x00ff00) << 112);
  pkey |= ((u128)rk[7]  << 64);
  pkey |= ((u128)rk[8]  << 40);
  pkey |= ((u128)rk[9]  << 16);
  pkey |= ((u128)rk[10] >> 8);
  print_message("Testing bitslice algorithm.", WHITE);
  u32 rk56 = ((rk[5] << 24) | rk[6]);
  struct timespec timer;
  TIMER_START(&timer);
  RETURN_ON_ERROR(halfloop_bitslice(pt, state, pkey, &found, &num_found));
  TIMER_STOP(&timer);
  double elapsed = TIMER_ELAPSED(&timer);
  print_message("Number of keys found during bitslice test: %d.", WHITE, num_found);
  setlocale(LC_NUMERIC, "");
  print_message("Test took %.2f seconds: %'lld keys/second.", WHITE, elapsed,
      (u64)(0x100000000ULL / elapsed));

  bool ok = false;
  for (int i = 0; i < num_found && !ok; i++) {
    if (rk56 == found[i]) {
      ok = true;
    }
  }
  RETURN_IF(!ok, HALFLOOP_INTERNAL_ERROR);
  print_message("Bitslice implementation ok.", WHITE);

error:
  if (err != HALFLOOP_SUCCESS) {
    print_message("Bitslice test failed. PT=%06x Seed=%016" PRIx64 " Key=%016" PRIx64 "%016" PRIx64,
        RED, pt, seed, (u64)(key >> 64), (u64)key);
  }
  free(found);
  return err;
}
