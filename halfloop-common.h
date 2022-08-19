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

#ifndef HALFLOOP_COMMON_H_
#define HALFLOOP_COMMON_H_
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;

/**
 * @brief The Rijndael S-box.
 */
static const u8 SBOX[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/**
 * @brief Inverse of the Rijndael S-box.
 */
static const u8 inv_SBOX[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/** Return values for functions. Functions returning without error will always return
    HALFLOOP_SUCCESS. */
typedef enum {
  HALFLOOP_SUCCESS = 0,     /**< The function performed its task successfully. */
  HALFLOOP_BAD_ARGUMENT,    /**< The function was called with an invalid argument. */
  HALFLOOP_FILE_ERROR,      /**< Error when reading/writing/accessing a file. */
  HALFLOOP_END_OF_FILE,     /**< The function reached the end of a file. */
  HALFLOOP_FORMAT_ERROR,    /**< A parsed file or data structure did not conform to its format
                                 specification. */
  HALFLOOP_NOT_IMPLEMENTED, /**< Feature not implemented. */
  HALFLOOP_INTERNAL_ERROR,  /**< Unknown internal error, most likely a bug. */
  HALFLOOP_MEMORY_ERROR,    /**< Some memory error, most likely out of memory. */
  HALFLOOP_FAILURE,         /**< The function failed in its task, but otherwise functioned properly.
                                 This may for instance indicate that a search did not find any
                                 matches. */
  HALFLOOP_QUIT,            /**< Signals that a QUIT message was received by a thread. */
  HALFLOOP_NETWORK_ERROR    /**< Signals that a network error occured. */
} halfloop_result_t;

/**
 * @brief Colors used as arguments to print_message.
 */
typedef enum {
  WHITE,
  RED,
  GREEN,
  BLUE
} color_t;

/**
 * @brief Structure representing the contents of a HALFLOOP seed.
 */
typedef struct {
  int month;
  int day;
  int coarse_time;
  int fine_time;
  int word;
  int zero;
  int frequency;
} seed_t;

/**
 * @brief Absolute value.
 */
#define ABS(X) ((X) < 0 ? (-(X)) : (X))

/** If C is true, the macro sets err = E and jumps to the function's error label. If E is not
    HALFLOOP_SUCCESS, debugging information is printed to stderr.
    @param C conditional, jump to error if true.
    @param E return value/error code. A member of halfloop_result_t. */
#define RETURN_IF(C, E)\
{\
  halfloop_result_t e = E;\
  if (C) {\
    if (e != HALFLOOP_SUCCESS) {\
      fprintf(stderr, "%s on line %d in %s.\n", halfloop_get_result_text(e), __LINE__, __FILE__);\
    }\
    err = e;\
    goto error;\
  }\
}

/** If E is not HALFLOOP_SUCCESS, jumps to the function's error label and prints debugging
    information to stderr.
    @param E return_value/error code. A member of halfloop_result_t. */
#define RETURN_ON_ERROR(E)\
{\
  halfloop_result_t e = E;\
  if (e != HALFLOOP_SUCCESS) {\
    fprintf(stderr, "%s on line %d in %s.\n", halfloop_get_result_text(e), __LINE__, __FILE__);\
    err = e;\
    goto error;\
  }\
}

/** Frees and nulls a pointer. */
#define FREE_AND_NULL(P) free(P); P = NULL;

#define TIMER_START(T)\
  if (clock_gettime(CLOCK_MONOTONIC, T) != 0) {\
    err = HALFLOOP_INTERNAL_ERROR;\
    goto error;\
  }

#define TIMER_STOP(T)\
  {\
    struct timespec stop_time;\
    if (clock_gettime(CLOCK_MONOTONIC, &stop_time) != 0) {\
      err = HALFLOOP_INTERNAL_ERROR;\
      goto error;\
    }\
    (T)->tv_sec  = stop_time.tv_sec  - (T)->tv_sec;\
    if (stop_time.tv_nsec < (T)->tv_nsec) {\
      (T)->tv_sec -= 1;\
      (T)->tv_nsec = 1000000000L + stop_time.tv_nsec - (T)->tv_nsec;\
    } else {\
      (T)->tv_nsec = stop_time.tv_nsec - (T)->tv_nsec;\
    }\
  }

#define TIMER_MINUTES(T) ((T)->tv_sec / 60)
#define TIMER_SECONDS(T) ((T)->tv_sec % 60)
#define TIMER_ELAPSED(T) ((T)->tv_sec + (T)->tv_nsec * 1E-9)

/** Returns the text (e.g. SENTINEL_SUCCESS) for a given sentinel_result_t instance. Returns NULL if
    the input is invalid.
    @param result an instance of sentinel_result_t. */

/**
 * @brief Returns the text (e.g. HALFLOOP_SUCCESS) for a given sentinel_result_t instance. Returns
 *  NULL if the input is invalid.
 *
 * @param result an instance of halfloop_result_t.
 */
const char* halfloop_get_result_text(halfloop_result_t result);

/**
 * @brief Performs the SubBytes operation in HALFLOOP-24.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing SubBytes on the input.
 */
u32 sub_bytes(u32 state);

/**
 * @brief Performs the InvSubBytes operation in HALFLOOP-24, i.e. the inverse of SubBytes.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing InvSubBytes on the input.
 */
u32 inv_sub_bytes(u32 state);

/**
 * @brief Performs the RotateRows operation in HALFLOOP-24.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing RotateRows on the input.
 */
u32 rotate_rows(u32 state);

/**
 * @brief Performs the InvRotateRows operation in HALFLOOP-24, i.e. the inverse of RotateRows.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing InvRotateRows on the input.
 */
u32 inv_rotate_rows(u32 state);

/**
 * @brief Performs the MixColumns operation in HALFLOOP-24.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing MixColumns on the input.
 */
u32 mix_columns(u32 state);

/**
 * @brief Performs the InvMixColumns operation in HALFLOOP-24, i.e. the inverse of MixColumns.
 *
 * @param state a 24-bit state.
 * @return u32  the result after performing InvMixColumns on the input.
 */
u32 inv_mix_columns(u32 state);

/**
 * @brief Performs the g function in the HALFLOOP-24 key schedule.
 *
 * @param key_word The input word to the g function.
 * @param rc The round constant.
 * @return u32 The g function output.
 */
u32 key_schedule_g(u32 key_word, u32 rc);

/**
 * @brief Performs the HALFLOOP-24 key schedule.
 *
 * @param rk   the round the output vector. Must be a pointer to an array of length 11.
 * @param key  the 128-bit key.
 * @param seed the 64-bit seed.
 */
halfloop_result_t key_schedule(u32 *rk, u128 key, u64 seed);

/**
 * @brief Encrypts a HALFLOOP-24 plaintext.
 *
 * @param pt   the 24-bit plaintext to encrypt. The most significant eight bits must be zero.
 * @param key  the 128-bit key to use for the encryption.
 * @param seed the 64-bit seed to use for the encryption.
 * @param ct   the encrypted 24-bit ciphertext.
 * @return HALFLOOP_SUCCESS on success.
 */
halfloop_result_t halfloop_encrypt(u32 pt, u128 key, u64 seed, u32 *ct);

/**
 * @brief Decrypts a HALFLOOP-24 ciphertext.
 *
 * @param ct   the 24-bit ciphertext to decrypt. The most significant eight bits must be zero.
 * @param key  the 128-bit key to use for the decryption.
 * @param seed the 64-bit seed to use for the decryption.
 * @param pt   the decrypted 24-bit plaintext.
 * @return HALFLOOP_SUCCESS on success.
 */
halfloop_result_t halfloop_decrypt(u32 ct, u128 key, u64 seed, u32 *pt);

/**
 * @brief Initializes various data structures that are used by the functions that implement
 * HALFLOOP-24. This function must be called before any of the other HALFLOOP functions can be used.
 *
 * @return HALFLOOP_SUCCESS on successful initiation.
 */
halfloop_result_t init_halfloop();

/**
 * @brief Tests the implementation using the test vector from MIL-STD-188-141D.
 *
 * @return HALFLOOP_SUCCESS  if the test succeeds.
 * @return HALFLOOP_FAILURE  if the test fails. In this case, the implementation is broken!
 */
halfloop_result_t test_halfloop();

/**
 * @brief Prints a formatted message to the console.
 *
 * @param format The message to be printed. This string, along with the varargs, will be sent to
 * vsnprintf.
 * @param color The color that the message should be displayed in.
 * @param ... Parameters for the format string.
 * @return HALFLOOP_SUCCESS on success.
 */
halfloop_result_t print_message(const char *format, color_t color, ...);

/**
 * @brief Parses a HALFLOOP seed.
 *
 * @param seed a 64-bit seed.
 * @param parsed pointer to a struct that will hold the parsed values on successful return.
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
halfloop_result_t parse_seed(u64 seed, seed_t *parsed);

/**
 * @brief Generates a 64-bit seed value.
 *
 * @param values the intended values of the various seed fields.
 * @param seed output pointer for the generated seed.
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
halfloop_result_t create_seed(seed_t values, u64 *seed);

/**
 * @brief Writes random bytes to an address.
 *
 * @param b destination address.
 * @param num number of bytes.
 * @return halfloop_result_t HALFLOOP_SUCCESS on success.
 */
halfloop_result_t random_bytes(void *b, size_t num);

#endif /* HALFLOOP_COMMON_H_ */
