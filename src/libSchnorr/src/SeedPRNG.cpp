/*
 * Copyright (C) 2020 Zilliqa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <openssl/rand.h>
#include "SchnorrInternal.h"

bool SeedPRNG() {
  unsigned int attempt = 0;
  while ((RAND_status() == 0) && (attempt++ < 10)) {
    unsigned char buf[256];
    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)getpid();
    unsigned int v = seed;
    for (unsigned int i = 0; i < 256 / sizeof(v); i++) {
      memmove(buf + i * sizeof(v), &v, sizeof(v));
      v = v * seed + (unsigned int)i;
    }
    RAND_seed(buf, 256);
  }
  return RAND_status() != 0;
}