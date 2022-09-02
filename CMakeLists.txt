# Implementation of attacks on HALFLOOP-24.
#
# Copyright (C) 2022 Marcus Dansarie, Patrick Derbez, Gregor Leander, and
# Lukas Stennes.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 3.10...3.22.1)

project(HALFLOOP VERSION 1.0 LANGUAGES C)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(CMAKE_C_FLAGS_RELEASE "")
add_compile_options(-march=native -Ofast -ggdb -Wall -Wpedantic)

add_executable(halfloop-attack halfloop-attack.c halfloop-bitslice.c halfloop-common.c)
add_executable(halfloop-boomerang halfloop-boomerang.c halfloop-common.c)
add_executable(halfloop-generate-data halfloop-generate-data.c halfloop-common.c)
add_executable(halfloop-tweak halfloop-tweak.c halfloop-common.c)
add_executable(halfloop-test halfloop-test.c halfloop-bitslice.c halfloop-common.c)

target_link_libraries(halfloop-attack PRIVATE Threads::Threads)
