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

#include "MultiSig.h"
#include "SchnorrInternal.h"

using namespace std;

bool CommitPointHash::constructPreChecks() { return (m_h != nullptr); }

CommitPointHash::CommitPointHash()
    : m_h(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }
}

CommitPointHash::CommitPointHash(const CommitPoint& point)
    : m_h(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  Set(point);
}

CommitPointHash::CommitPointHash(const bytes& src, unsigned int offset) {
  if (!Deserialize(src, offset)) {
    // We failed to init CommitPointHash
  }
}

CommitPointHash::CommitPointHash(const CommitPointHash& src)
    : m_h(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  m_initialized = (BN_copy(m_h.get(), src.m_h.get()) != NULL);
}

CommitPointHash::~CommitPointHash() {}

bool CommitPointHash::Initialized() const { return m_initialized; }

bool CommitPointHash::Serialize(bytes& dst, unsigned int offset) const {
  if (!m_initialized) {
    return false;
  }

  BIGNUMSerialize::SetNumber(dst, offset, COMMIT_POINT_HASH_SIZE, m_h);
  return true;
}

bool CommitPointHash::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> tmp =
      BIGNUMSerialize::GetNumber(src, offset, COMMIT_POINT_HASH_SIZE);

  if (tmp == nullptr) {
    return false;
  }

  m_h = tmp;
  m_initialized = true;

  return true;
}

void CommitPointHash::Set(const CommitPoint& point) {
  if (!point.Initialized()) {
    // Commitment point not initialized
    return;
  }

  m_initialized = false;
  bytes buf(Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES);

  SHA2<HashType::HASH_VARIANT_256> sha2;

  // The second domain separated hash function.

  // The first one is used in the Proof-of-Possession (PoP) phase.
  // PoP coincides with PoW when each node proves the knowledge
  // of the private key for a claimed public key.

  // Separation for the second hash function is defined by setting the first
  // byte to 0x01.
  sha2.Update({SECOND_DOMAIN_SEPARATED_HASH_FUNCTION_BYTE});

  // Convert the commitment to octets first
  if (EC_POINT_point2oct(Schnorr::GetCurveGroup(), point.m_p.get(),
                         POINT_CONVERSION_COMPRESSED, buf.data(),
                         Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES,
                         NULL) != Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES) {
    // Could not convert commitPoint to octets
    return;
  }

  // compute H(0x01||point)
  sha2.Update(buf);
  bytes digest = sha2.Finalize();

  // Build the PointHash
  if ((BN_bin2bn(digest.data(), digest.size(), m_h.get())) == NULL) {
    // Digest to scalar failed
    return;
  }

  if (BN_nnmod(m_h.get(), m_h.get(), Schnorr::GetCurveOrder(), NULL) == 0) {
    // Could not reduce hashpoint value modulo group order
    return;
  }

  m_initialized = true;
}

CommitPointHash& CommitPointHash::operator=(const CommitPointHash& src) {
  m_initialized = (BN_copy(m_h.get(), src.m_h.get()) != NULL);
  return *this;
}

bool CommitPointHash::operator==(const CommitPointHash& r) const {
  return (m_initialized && r.m_initialized &&
          (BN_cmp(m_h.get(), r.m_h.get()) == 0));
}

CommitPointHash::operator std::string() const {
  std::string temp;
  if (!SerializableCryptoToHexStr(*this, temp)) {
    return "";
  }
  return "0x" + temp;
}
