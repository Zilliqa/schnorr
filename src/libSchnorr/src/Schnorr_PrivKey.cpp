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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "Schnorr.h"
#include "SchnorrInternal.h"

using namespace std;

// ============================================================================
// Construction
// ============================================================================

bool PrivKey::constructPreChecks() { return (m_d != nullptr); }

PrivKey::PrivKey() : m_d(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }

  // kpriv->d should be in [1,...,order-1]
  do {
    if (!BN_rand_range(m_d.get(), Schnorr::GetCurveOrder())) {
      // Private key generation failed
      break;
    }
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wparentheses-equality"
  } while (BN_is_zero(m_d.get()));
#pragma clang diagnostic pop
#else
  } while (BN_is_zero(m_d.get()));
#endif
}

PrivKey::PrivKey(const bytes& src, unsigned int offset)
    : m_d(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }

  if (!Deserialize(src, offset)) {
    // We failed to init PrivKey from stream
  }
}

PrivKey::PrivKey(const PrivKey& src) : m_d(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }

  if (BN_copy(m_d.get(), src.m_d.get()) == NULL) {
    // PrivKey copy failed
  }
}

PrivKey::~PrivKey() {}

// ============================================================================
// Serialization
// ============================================================================

PrivKey PrivKey::GetPrivKeyFromString(const string& key) {
  if (key.size() != 64) {
    throw std::invalid_argument(
        "Error: private key - invalid number of input characters for key");
  }

  bytes key_v;

  try {
    boost::algorithm::unhex(key.begin(), key.end(), back_inserter(key_v));
  } catch (exception& e) {
    throw std::invalid_argument(
        "Error: private key - invalid format of input characters for key - "
        "required hexadecimal characters");
  }

  return PrivKey(key_v, 0);
}

bool PrivKey::Serialize(bytes& dst, unsigned int offset) const {
  BIGNUMSerialize::SetNumber(dst, offset, PRIV_KEY_SIZE, m_d);
  return true;
}

bool PrivKey::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> result =
      BIGNUMSerialize::GetNumber(src, offset, PRIV_KEY_SIZE);

  if (result == nullptr) {
    // BIGNUMSerialize::GetNumber failed
    return false;
  }

  if (BN_copy(m_d.get(), result.get()) == NULL) {
    // PrivKey copy failed
    return false;
  }

  return true;
}

// ============================================================================
// Assignment and Comparison
// ============================================================================

PrivKey& PrivKey::operator=(const PrivKey& src) {
  if (BN_copy(m_d.get(), src.m_d.get()) == NULL) {
    // PrivKey copy failed
  }
  return *this;
}

bool PrivKey::operator==(const PrivKey& r) const {
  return BN_cmp(m_d.get(), r.m_d.get()) == 0;
}
