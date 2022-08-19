# Implementation of attacks on HALFLOOP-24

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

HALFLOOP-24 is a cipher specified in MIL-STD-188-141 and used for encrypting Automatic Link
Etablishment (ALE) frames in the second and third generations of the ALE standards. This repository
contains implementations of the attacks on HALFLOOP-24 described in Breaking HALFLOOP-24. A
bitslicing implementation of HALFLOOP-24 is used for the brute force key search phase of the main
attack.

The related tweak attack requires at least three good pairs of plaintext, ciphertext, and tweak. A
utility, `halfloop-generate-data`, that generates random good pairs is provided for testing. Another
utility, `halfloop-seed`, aids in interpreting the data format of HALFLOOP-24 tweaks.

## System requirements

An x86-64 processor with the AVX instruction set.

## Dependencies

* [CMake](https://cmake.org/) (build system)

```console
apt install cmake
```

## Build

```console
mkdir build
cd build
cmake ..
make
```

Tip: clang produces significantly faster results than gcc. Call cmake with `CC=clang cmake ..` to
build with clang if it is not already set as the default compiler.

## Test

Run `halfloop-test` to check that the implementation is correct. The program will also print an
estimated speed of the bitslice implementation.

## Run

Start by generating test data. `halfloop-generate-data` will generate a random key and print it to
stderr. It will then attempt generate good pairs of plaintext-ciphertext-tuples with that key and
print them to stdout.
```console
./halfloop-generate-data 4 > data.txt
```

Use `halfloop-seed` to interpret a hexadecimal tweak value.
```console
./halfloop-seed 543bd88000017550
```

Use the test data to perform an attack. If more than three good pairs are available, the program
will combine them to attempt to reduce the number of 80-bit candidate keys as much as possible. It
will then perform a brute force search for the remaining 48 bits of each candidate key. Progress
information is continuously printed to the console. When a key is found, the program quits after
printing the key to the console.
```console
./halfloop-attack data.txt
```
The `-t` command line argument can be used to control the number of threads used in the brute force
search phase. By default, one thread per processor is created.
```console
./halfloop-attack -t 4 data.txt
```

## License

This project is licensed under the GNU General Public License — see the [LICENSE](LICENSE)
file for details.
