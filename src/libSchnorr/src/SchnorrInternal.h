/*
 * Copyright (C) 2019 Zilliqa
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

#ifndef ZILLIQA_SRC_LIBSCHNORR_SRC_SCHNORRINTERNAL_H_
#define ZILLIQA_SRC_LIBSCHNORR_SRC_SCHNORRINTERNAL_H_

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <array>
#include <boost/algorithm/hex.hpp>
#include <boost/functional/hash.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "generate_dsa_nonce.h"

using bytes = std::vector<uint8_t>;

#include "Sha2.h"

// Cryptographic sizes
const unsigned int PRIV_KEY_SIZE = 32;
const unsigned int PUB_KEY_SIZE = 33;
const unsigned int SIGNATURE_CHALLENGE_SIZE = 32;
const unsigned int SIGNATURE_RESPONSE_SIZE = 32;
const unsigned int COMMIT_SECRET_SIZE = 32;
const unsigned int COMMIT_POINT_HASH_SIZE = 32;
const unsigned int COMMIT_POINT_SIZE = 33;
const unsigned int CHALLENGE_SIZE = 32;
const unsigned int RESPONSE_SIZE = 32;

/// EC-Schnorr utility for serializing BIGNUM data type.
struct BIGNUMSerialize {
  /// Deserializes a BIGNUM from specified byte stream.
  static std::shared_ptr<BIGNUM> GetNumber(const bytes& src,
                                           unsigned int offset,
                                           unsigned int size);

  /// Serializes a BIGNUM into specified byte stream.
  static void SetNumber(bytes& dst, unsigned int offset, unsigned int size,
                        const std::shared_ptr<BIGNUM>& value);
};

/// EC-Schnorr utility for serializing ECPOINT data type.
struct ECPOINTSerialize {
  /// Deserializes an ECPOINT from specified byte stream.
  static std::shared_ptr<EC_POINT> GetNumber(const bytes& src,
                                             unsigned int offset,
                                             unsigned int size);

  /// Serializes an ECPOINT into specified byte stream.
  static void SetNumber(bytes& dst, unsigned int offset, unsigned int size,
                        const std::shared_ptr<EC_POINT>& value);
};

template <class T>
static bool SerializableCryptoToHexStr(const T& input, std::string& str) {
  bytes tmp;
  input.Serialize(tmp, 0);
  try {
    str = "";
    boost::algorithm::hex(tmp.begin(), tmp.end(), back_inserter(str));
  } catch (std::exception& e) {
    return false;
  }
  return true;
}

const uint8_t SECOND_DOMAIN_SEPARATED_HASH_FUNCTION_BYTE = 0x01;
const uint8_t THIRD_DOMAIN_SEPARATED_HASH_FUNCTION_BYTE = 0x11;

bool SeedPRNG();

#endif  // ZILLIQA_SRC_LIBSCHNORR_SRC_SCHNORRINTERNAL_H_
