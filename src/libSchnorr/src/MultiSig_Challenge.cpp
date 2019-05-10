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

bool Challenge::constructPreChecks() { return (m_c != nullptr); }

Challenge::Challenge() : m_c(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }
}

Challenge::Challenge(const CommitPoint& aggregatedCommit,
                     const PubKey& aggregatedPubkey, const bytes& message)
    : Challenge(aggregatedCommit, aggregatedPubkey, message, 0,
                message.size()) {}

Challenge::Challenge(const CommitPoint& aggregatedCommit,
                     const PubKey& aggregatedPubkey, const bytes& message,
                     unsigned int offset, unsigned int size)
    : m_c(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  Set(aggregatedCommit, aggregatedPubkey, message, offset, size);
}

Challenge::Challenge(const bytes& src, unsigned int offset) {
  if (!Deserialize(src, offset)) {
    //
  }
}

Challenge::Challenge(const Challenge& src)
    : m_c(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  m_initialized = (BN_copy(m_c.get(), src.m_c.get()) != NULL);
}

Challenge::~Challenge() {}

bool Challenge::Initialized() const { return m_initialized; }

bool Challenge::Serialize(bytes& dst, unsigned int offset) const {
  if (!m_initialized) {
    return false;
  }

  BIGNUMSerialize::SetNumber(dst, offset, CHALLENGE_SIZE, m_c);
  return true;
}

bool Challenge::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> tmp =
      BIGNUMSerialize::GetNumber(src, offset, CHALLENGE_SIZE);
  if (tmp == nullptr) {
    return false;
  }

  m_c = tmp;
  m_initialized = true;

  return true;
}

void Challenge::Set(const CommitPoint& aggregatedCommit,
                    const PubKey& aggregatedPubkey, const bytes& message,
                    unsigned int offset, unsigned int size) {
  // Initial checks

  if (!aggregatedCommit.Initialized()) {
    // Aggregated commit not initialized
    return;
  }

  if (message.size() == 0) {
    // Empty message
    return;
  }

  if (message.size() < (offset + size)) {
    // Offset and size outside message length
    return;
  }

  // Compute the challenge c = H(r, kpub, m)

  SHA2<HASH_TYPE::HASH_VARIANT_256> sha2;

  // The third domain separated hash function.

  // The first one is used in the Proof-of-Possession (PoP) phase.
  // PoP coincides with PoW when each node proves the knowledge
  // of the private key for a claimed public key.

  // The second one is used in the Proof-of-Possession phase.

  // Separation for the third hash function is defined by setting the first byte
  // to 0x11.
  sha2.Update({THIRD_DOMAIN_SEPARATED_HASH_FUNCTION_BYTE});

  m_initialized = false;

  bytes buf(Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES);

  // Convert the committment to octets first
  if (EC_POINT_point2oct(Schnorr::GetCurveGroup(), aggregatedCommit.m_p.get(),
                         POINT_CONVERSION_COMPRESSED, buf.data(),
                         Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES,
                         NULL) != Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES) {
    // Could not convert commitment to octets
    return;
  }

  // Hash commitment
  sha2.Update(buf);

  // Clear buffer
  fill(buf.begin(), buf.end(), 0x00);

  // Convert the public key to octets
  if (EC_POINT_point2oct(Schnorr::GetCurveGroup(), aggregatedPubkey.m_P.get(),
                         POINT_CONVERSION_COMPRESSED, buf.data(),
                         Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES,
                         NULL) != Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES) {
    // Could not convert public key to octets
    return;
  }

  // Hash public key
  sha2.Update(buf);

  // Hash message
  sha2.Update(message, offset, size);
  bytes digest = sha2.Finalize();

  // Build the challenge
  if ((BN_bin2bn(digest.data(), digest.size(), m_c.get())) == NULL) {
    // Digest to challenge failed
    return;
  }

  if (BN_nnmod(m_c.get(), m_c.get(), Schnorr::GetCurveOrder(), NULL) == 0) {
    // Could not reduce challenge modulo group order
    return;
  }

  m_initialized = true;
}

Challenge& Challenge::operator=(const Challenge& src) {
  m_initialized = (BN_copy(m_c.get(), src.m_c.get()) == m_c.get());
  return *this;
}

bool Challenge::operator==(const Challenge& r) const {
  return (m_initialized && r.m_initialized &&
          (BN_cmp(m_c.get(), r.m_c.get()) == 0));
}