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

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "halfloop-common.h"

static u8 table_2[0x100] = {0};
static u8 table_6[0x100] = {0};
static u8 table_8[0x100] = {0};
static u8 table_9[0x100] = {0};
static u8 table_39[0x100] = {0};

/* Used by init_halfloop to initialize the finite field multiplication lookup tables. */
static u8 ffmul(u8 a, u8 b) {
  u32 c = 0;

  for (int x = 0; x < 8; x++) {
    for (int y = 0; y < 8; y++) {
      if ((a >> x) & (b >> y) & 1) {
        c ^= (1 << (x + y));
      }
    }
  }
  while (c > 0xff) {
    c ^= 0x11b << (23 - __builtin_clz(c));
  }
  return c;
}

const char* halfloop_get_result_text(halfloop_result_t result) {
  if (result < 0 || result > 10) {
    return NULL;
  }
  const char *result_strings[] = {
    "HALFLOOP_SUCCESS",
    "HALFLOOP_BAD_ARGUMENT",
    "HALFLOOP_FILE_ERROR",
    "HALFLOOP_END_OF_FILE",
    "HALFLOOP_FORMAT_ERROR",
    "HALFLOOP_NOT_IMPLEMENTED",
    "HALFLOOP_INTERNAL_ERROR",
    "HALFLOOP_MEMORY_ERROR",
    "HALFLOOP_FAILURE",
    "HALFLOOP_QUIT",
    "HALFLOOP_NETWORK_ERROR"
  };
  return result_strings[result];
}

halfloop_result_t init_halfloop() {
  /* Initialize the finite field multiplication lookup tables. */
  for (int i = 0; i < 0x100; i++) {
    table_2[i]  = ffmul(2, i);
    table_6[i]  = ffmul(6, i);
    table_8[i]  = ffmul(8, i);
    table_9[i]  = ffmul(9, i);
    table_39[i] = ffmul(39, i);
  }
  return HALFLOOP_SUCCESS;
}

u32 sub_bytes(u32 state) {
  u8 a0 = state >> 16;
  u8 a1 = (state >> 8) & 0xFF;
  u8 a2 = state & 0xFF;
  return ((u32)SBOX[a0] << 16) | ((u32)SBOX[a1] << 8) | (u32)SBOX[a2];
}

u32 inv_sub_bytes(u32 state) {
  u8 a0 = state >> 16;
  u8 a1 = (state >> 8) & 0xFF;
  u8 a2 = state & 0xFF;
  return ((u32)inv_SBOX[a0] << 16) | ((u32)inv_SBOX[a1] << 8) | (u32)inv_SBOX[a2];
}

u32 rotate_rows(u32 state) {
  u8 a0 = state >> 16;
  u8 a1 = (state >> 8) & 0xFF;
  u8 a2 = state & 0xFF;
  a1 = (a1 << 6) | (a1 >> 2);
  a2 = (a2 << 4) | (a2 >> 4);
  return (a0 << 16) | (a1 << 8) | a2;
}

u32 inv_rotate_rows(u32 state) {
  u8 a0 = state >> 16;
  u8 a1 = (state >> 8) & 0xFF;
  u8 a2 = state & 0xFF;
  a1 = (a1 >> 6) | (a1 << 2);
  a2 = (a2 >> 4) | (a2 << 4);
  return (a0 << 16) | (a1 << 8) | a2;
}

u32 mix_columns(u32 in) {
  u32 a = in >> 16;
  u32 b = (in >> 8) & 0xff;
  u32 c = in & 0xff;
  u32 out = (table_9[a] ^         b  ^ table_2[c]) << 16;
  out    |= (table_2[a] ^ table_9[b] ^         c)  << 8;
  out    |= (        a  ^ table_2[b] ^ table_9[c]);
  return out;
}

u32 inv_mix_columns(u32 in) {
  u32 a = in >> 16;
  u32 b = (in >> 8) & 0xff;
  u32 c = in & 0xff;
  u32 out = (table_6[a]  ^ table_8[b]  ^ table_39[c]) << 16;
  out    |= (table_39[a] ^ table_6[b]  ^ table_8[c])  << 8;
  out    |= (table_8[a]  ^ table_39[b] ^ table_6[c]);
  return out;
}

u32 key_schedule_g(u32 key_word, u32 rc) {
  u8 b0 =  key_word >> 24;
  u8 b1 = (key_word >> 16) & 0xFF;
  u8 b2 = (key_word >> 8)  & 0xFF;
  u8 b3 =  key_word        & 0xFF;
  return ((SBOX[b1] ^ rc) << 24)
        ^ (SBOX[b2]       << 16)
        ^ (SBOX[b3]       << 8)
        ^  SBOX[b0];
}

halfloop_result_t key_schedule(u32 *rk, u128 key, u64 tweak) {
  if (rk == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  key     =   key ^ ((u128)tweak << 64);
  rk[0]   =  (key >> 104) & 0xFFFFFF;
  rk[1]   =  (key >> 80)  & 0xFFFFFF;
  rk[2]   =  (key >> 56)  & 0xFFFFFF;
  rk[3]   =  (key >> 32)  & 0xFFFFFF;
  rk[4]   =  (key >> 8)   & 0xFFFFFF;
  rk[5]   =  (key & 0xFF) << 16;
  key    ^= (u128)key_schedule_g(key & 0xFFFFFFFF, 1) << 96;
  key    ^= ((key >> 96)  & 0xFFFFFFFF) << 64;
  key    ^= ((key >> 64)  & 0xFFFFFFFF) << 32;
  key    ^= ((key >> 32)  & 0xFFFFFFFF) <<  0;
  rk[5]  |=  (key >> 112) & 0xFFFF;
  rk[6]   =  (key >> 88)  & 0xFFFFFF;
  rk[7]   =  (key >> 64)  & 0xFFFFFF;
  rk[8]   =  (key >> 40)  & 0xFFFFFF;
  rk[9]   =  (key >> 16)  & 0xFFFFFF;
  rk[10]  = ((key >> 0)   & 0xFFFF) << 8;
  key    ^= (u128)key_schedule_g(key & 0xFFFFFFFF, 2) << 96;
  rk[10] |= (key >> 120)  & 0xFF;
  return HALFLOOP_SUCCESS;
}

static u32 halfloop_decrypt_round(u32 state, u32 round_key, bool last_round) {
  state ^= round_key;
  if (!last_round) {
    state = inv_mix_columns(state);
  }
  state = inv_rotate_rows(state);
  return inv_sub_bytes(state);
}

static u32 halfloop_encrypt_round(u32 state, u32 round_key, bool last_round) {
  state = sub_bytes(state);
  state = rotate_rows(state);
  if (!last_round) {
    state = mix_columns(state);
  }
  return state ^ round_key;
}

halfloop_result_t halfloop_encrypt(u32 pt, u128 key, u64 tweak, u32 *ct) {
  if ((pt & 0xFF000000) != 0 || ct == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;
  u32 rk[11] = {0};
  RETURN_ON_ERROR(key_schedule(rk, key, tweak));
  *ct = pt ^ rk[0];
  for(int i = 1; i < 10; i++) {
    *ct = halfloop_encrypt_round(*ct, rk[i], false);
  }
  *ct = halfloop_encrypt_round(*ct, rk[10], true);
error:
  return err;
}

halfloop_result_t halfloop_decrypt(u32 ct, u128 key, u64 tweak, u32 *pt) {
  if((ct & 0xFF000000) != 0 || pt == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  halfloop_result_t err = HALFLOOP_SUCCESS;
  u32 rk[11] = {0};
  RETURN_ON_ERROR(key_schedule(rk, key, tweak));
  *pt = halfloop_decrypt_round(ct, rk[10], true);
  for(int i = 9; i > 0; i--){
    *pt = halfloop_decrypt_round(*pt, rk[i], false);
  }
  *pt ^= rk[0];
error:
  return err;
}

halfloop_result_t test_halfloop() {
  u128 key = ((u128)0x2b7e151628aed2a6 << 64) | 0xabf7158809cf4f3c;
  u64 tweak = 0x543bd88000017550;
  u32 pt = 0x010203;
  u32 ct = 0xf28c1e;
  u32 ct_test = 0;
  u32 pt_test = 0;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  for (int i = 0; i < 0x100; i++) {
    RETURN_IF(inv_SBOX[SBOX[i]] != i, HALFLOOP_INTERNAL_ERROR);
  }
  halfloop_encrypt(pt, key, tweak, &ct_test);
  RETURN_IF(ct_test != ct, HALFLOOP_INTERNAL_ERROR);
  halfloop_decrypt(ct, key, tweak, &pt_test);
  RETURN_IF(pt_test != pt, HALFLOOP_INTERNAL_ERROR);
error:
  return err;
}

halfloop_result_t print_message(const char *format, color_t color, ...) {
  if (format == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  char *str = NULL;
  halfloop_result_t err = HALFLOOP_SUCCESS;

  va_list ap;
  va_start(ap, color);
  int len = vsnprintf(NULL, 0, format, ap) + 1;
  va_end(ap);
  str = malloc(len);
  RETURN_IF(str == NULL, HALFLOOP_MEMORY_ERROR);
  va_start(ap, color);
  vsnprintf(str, len, format, ap);
  va_end(ap);

  const char *normal_color = "\x1B[0m";
  const char *colorstring = normal_color;
  switch (color) {
    case RED:   colorstring = "\x1B[31m"; break;
    case GREEN: colorstring = "\x1B[32m"; break;
    case BLUE:  colorstring = "\x1B[34m"; break;
    default: break;
  }

  struct timeval tv;
  struct tm tm;
  RETURN_IF(gettimeofday(&tv, NULL) != 0, HALFLOOP_INTERNAL_ERROR);
  localtime_r(&tv.tv_sec, &tm);
  printf("[%02d:%02d:%02d] %s%s%s\n", tm.tm_hour, tm.tm_min, tm.tm_sec, colorstring, str,
      normal_color);

error:
  free(str);
  return err;
}

/**
 * @brief Checks a HALFLOOP tweak structure to ensure all values are compliant with the
 * specification.
 *
 * @param tweak a HALFLOOP tweak structure.
 * @return halfloop_result_t HALFLOOP_SUCCESS if the values in the structure are compliant.
 */
static halfloop_result_t check_tweak(tweak_t tweak) {
  int days[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (   tweak.month < 1
      || tweak.month > 12
      || tweak.day < 1
      || tweak.day > days[tweak.month - 1]
      || tweak.coarse_time < 0
      || tweak.coarse_time >= 1440
      || tweak.fine_time < 0
      || tweak.fine_time >= 60
      || tweak.word < 0
      || tweak.word > 255
      || tweak.zero != 0
      || tweak.frequency <= 0
      || tweak.frequency >= 1000000000
      || tweak.frequency % 100 != 0) {
    return HALFLOOP_FORMAT_ERROR;
  }
  return HALFLOOP_SUCCESS;
}

halfloop_result_t parse_tweak(u64 tweak, tweak_t *parsed) {
  tweak_t p = {
    .month       =  tweak >> 60,
    .day         = (tweak >> 55) & 0x1f,
    .coarse_time = (tweak >> 44) & 0x3ff,
    .fine_time   = (tweak >> 38) & 0x3f,
    .word        = (tweak >> 30) & 0xff,
    .zero        = (tweak >> 28) & 0x3,
    .frequency   = 0
  };
  for (int i = 0; i < 7; i++) {
    p.frequency *= 10;
    int d = (tweak >> (24 - i * 4)) & 0xf;
    if (d >= 10) {
      return HALFLOOP_FORMAT_ERROR;
    }
    p.frequency += d;
  }
  p.frequency *= 100;
  if (check_tweak(p) != HALFLOOP_SUCCESS) {
    return HALFLOOP_FORMAT_ERROR;
  }
  memcpy(parsed, &p, sizeof(tweak_t));
  return HALFLOOP_SUCCESS;
}

halfloop_result_t create_tweak(tweak_t values, u64 *tweak) {
  if (tweak == NULL) {
    return HALFLOOP_BAD_ARGUMENT;
  }
  if (check_tweak(values) != HALFLOOP_SUCCESS) {
    return HALFLOOP_FORMAT_ERROR;
  }
  *tweak  = (u64)values.month << 60;
  *tweak |= (u64)values.day << 55;
  *tweak |= (u64)values.coarse_time << 44;
  *tweak |= (u64)values.fine_time << 38;
  *tweak |= (u64)values.word << 30;
  values.frequency /= 100;
  for (int i = 0; i < 7; i++) {
    *tweak |= (values.frequency % 10) << i * 4;
    values.frequency /= 10;
  }
  return HALFLOOP_SUCCESS;
}

halfloop_result_t random_bytes(void *b, size_t num) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return HALFLOOP_FILE_ERROR;
  }
  ssize_t r = read(fd, b, num);
  close(fd);
  if (r != num) {
    return HALFLOOP_FILE_ERROR;
  }
  return HALFLOOP_SUCCESS;
}
