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
#include <boost/algorithm/hex.hpp>

#include "Schnorr.h"
#include "SchnorrInternal.h"

using namespace std;

// ============================================================================
// Construction
// ============================================================================

bool Signature::constructPreChecks() {
  return ((m_r != nullptr) && (m_s != nullptr));
}

Signature::Signature()
    : m_r(BN_new(), BN_clear_free), m_s(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }
}

Signature::Signature(const bytes& src, unsigned int offset)
    : m_r(BN_new(), BN_clear_free), m_s(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }

  if (!Deserialize(src, offset)) {
    // We failed to init Signature from stream
  }
}

Signature::Signature(const Signature& src)
    : m_r(BN_new(), BN_clear_free), m_s(BN_new(), BN_clear_free) {
  if (!constructPreChecks()) {
    // constructPreChecks failed
    throw std::bad_alloc();
  }

  if (BN_copy(m_r.get(), src.m_r.get()) == NULL) {
    // Signature challenge copy failed
    return;
  }

  if (BN_copy(m_s.get(), src.m_s.get()) == NULL) {
    // Signature response copy failed
  }
}

Signature::~Signature() {}

// ============================================================================
// Serialization
// ============================================================================

bool Signature::Serialize(bytes& dst, unsigned int offset) const {
  BIGNUMSerialize::SetNumber(dst, offset, SIGNATURE_CHALLENGE_SIZE, m_r);
  BIGNUMSerialize::SetNumber(dst, offset + SIGNATURE_CHALLENGE_SIZE,
                             SIGNATURE_RESPONSE_SIZE, m_s);
  return true;
}

bool Signature::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> result_r =
      BIGNUMSerialize::GetNumber(src, offset, SIGNATURE_CHALLENGE_SIZE);
  shared_ptr<BIGNUM> result_s = BIGNUMSerialize::GetNumber(
      src, offset + SIGNATURE_CHALLENGE_SIZE, SIGNATURE_RESPONSE_SIZE);

  if ((result_r == nullptr) || (result_s == nullptr)) {
    // BIGNUMSerialize::GetNumber failed
    return false;
  }

  if (BN_copy(m_r.get(), result_r.get()) == NULL) {
    // Signature challenge copy failed
    return false;
  }

  if (BN_copy(m_s.get(), result_s.get()) == NULL) {
    // Signature response copy failed
    return false;
  }

  return true;
}

// ============================================================================
// Assignment and Comparison
// ============================================================================

Signature& Signature::operator=(const Signature& src) {
  if (BN_copy(m_r.get(), src.m_r.get()) == NULL) {
    // Signature challenge copy failed
  }

  if (BN_copy(m_s.get(), src.m_s.get()) == NULL) {
    // Signature response copy failed
  }

  return *this;
}

bool Signature::operator==(const Signature& r) const {
  return (BN_cmp(m_r.get(), r.m_r.get()) == 0) &&
         (BN_cmp(m_s.get(), r.m_s.get()) == 0);
}

Signature::operator std::string() const {
  std::string output;
  if (!SerializableCryptoToHexStr(*this, output)) {
    return "";
  }
  return "0x" + output;
}

std::ostream& operator<<(std::ostream& os, const Signature& s) {
  std::string output;
  if (!SerializableCryptoToHexStr(s, output)) {
    os << "";
  } else {
    os << "0x" << output;
  }
  return os;
}
