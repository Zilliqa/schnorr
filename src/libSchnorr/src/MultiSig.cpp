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

std::mutex m_mutexMultiSigVerify;

MultiSig::MultiSig() {}

MultiSig::~MultiSig() {}

shared_ptr<PubKey> MultiSig::AggregatePubKeys(const vector<PubKey>& pubkeys) {
  if (pubkeys.size() == 0) {
    // Empty list of public keys
    return nullptr;
  }

  shared_ptr<PubKey> aggregatedPubkey(new PubKey(pubkeys.at(0)));
  if (aggregatedPubkey == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  for (unsigned int i = 1; i < pubkeys.size(); i++) {
    if (EC_POINT_add(Schnorr::GetCurveGroup(), aggregatedPubkey->m_P.get(),
                     aggregatedPubkey->m_P.get(), pubkeys.at(i).m_P.get(),
                     NULL) == 0) {
      // Pubkey aggregation failed
      return nullptr;
    }
  }

  return aggregatedPubkey;
}

shared_ptr<CommitPoint> MultiSig::AggregateCommits(
    const vector<CommitPoint>& commitPoints) {
  if (commitPoints.size() == 0) {
    // Empty list of commits
    return nullptr;
  }

  shared_ptr<CommitPoint> aggregatedCommit(new CommitPoint(commitPoints.at(0)));
  if (aggregatedCommit == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  for (unsigned int i = 1; i < commitPoints.size(); i++) {
    if (EC_POINT_add(Schnorr::GetCurveGroup(), aggregatedCommit->m_p.get(),
                     aggregatedCommit->m_p.get(), commitPoints.at(i).m_p.get(),
                     NULL) == 0) {
      // Commit aggregation failed
      return nullptr;
    }
  }

  return aggregatedCommit;
}

shared_ptr<Response> MultiSig::AggregateResponses(
    const vector<Response>& responses) {
  if (responses.size() == 0) {
    // Empty list of responses
    return nullptr;
  }

  shared_ptr<Response> aggregatedResponse(new Response(responses.at(0)));
  if (aggregatedResponse == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
  if (ctx == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  for (unsigned int i = 1; i < responses.size(); i++) {
    if (BN_mod_add(aggregatedResponse->m_r.get(), aggregatedResponse->m_r.get(),
                   responses.at(i).m_r.get(), Schnorr::GetCurveOrder(),
                   ctx.get()) == 0) {
      // Response aggregation failed
      return nullptr;
    }
  }

  return aggregatedResponse;
}

shared_ptr<Signature> MultiSig::AggregateSign(
    const Challenge& challenge, const Response& aggregatedResponse) {
  if (!challenge.Initialized()) {
    // Challenge not initialized
    return nullptr;
  }

  if (!aggregatedResponse.Initialized()) {
    // Response not initialized
    return nullptr;
  }

  shared_ptr<Signature> result(new Signature());
  if (result == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  if (BN_copy(result->m_r.get(), challenge.m_c.get()) == NULL) {
    // Signature generation (copy challenge) failed
    return nullptr;
  }

  if (BN_copy(result->m_s.get(), aggregatedResponse.m_r.get()) == NULL) {
    // Signature generation (copy response) failed
    return nullptr;
  }

  return result;
}

bool MultiSig::VerifyResponse(const Response& response,
                              const Challenge& challenge, const PubKey& pubkey,
                              const CommitPoint& commitPoint) {
  try {
    // Initial checks

    if (!response.Initialized()) {
      // Response not initialized
      return false;
    }

    if (!challenge.Initialized()) {
      // Challenge not initialized
      return false;
    }

    if (!commitPoint.Initialized()) {
      // Commit point not initialized
      return false;
    }

    // The algorithm to check whether the commit point generated from its
    // resopnse is the same one received in the commit phase Check if s is in
    // [1, ..., order-1] Compute Q = sG + r*kpub return Q == commitPoint

    bool err = false;

    // Regenerate the commitmment part of the signature
    unique_ptr<EC_POINT, void (*)(EC_POINT*)> Q(
        EC_POINT_new(Schnorr::GetCurveGroup()), EC_POINT_clear_free);
    unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

    if ((ctx != nullptr) && (Q != nullptr)) {
      // 1. Check if s is in [1, ..., order-1]
      err = (BN_is_zero(response.m_r.get()) ||
             (BN_cmp(response.m_r.get(), Schnorr::GetCurveOrder()) != -1));
      if (err) {
        // Response not in range
        return false;
      }

      // 2. Compute Q = sG + r*kpub
      err =
          (EC_POINT_mul(Schnorr::GetCurveGroup(), Q.get(), response.m_r.get(),
                        pubkey.m_P.get(), challenge.m_c.get(), ctx.get()) == 0);
      if (err) {
        // Commit regenerate failed
        return false;
      }

      // 3. Q == commitPoint
      err = (EC_POINT_cmp(Schnorr::GetCurveGroup(), Q.get(),
                          commitPoint.m_p.get(), ctx.get()) != 0);
      if (err) {
        // Generated commit point doesn't match the given one
        return false;
      }
    } else {
      // Memory allocation failure
      throw std::bad_alloc();
    }
  } catch (const std::exception& e) {
    // LOG_GENERAL(WARNING,
    //"Error with MultiSig::VerifyResponse." << ' ' << e.what());
    return false;
  }
  return true;
}

/*
 * This method is the same as:
 * bool Schnorr::Verify(const bytes& message,
 *                    const Signature& toverify, const PubKey& pubkey);
 *
 */

bool MultiSig::MultiSigVerify(const bytes& message, const Signature& toverify,
                              const PubKey& pubkey) {
  return MultiSigVerify(message, 0, message.size(), toverify, pubkey);
}

/*
 * This method is the same as:
 * Schnorr::Verify(const bytes& message, unsigned int offset,
 *                    unsigned int size, const Signature& toverify,
 *                    const PubKey& pubkey)
 * except that the underlying hash function H() is now replaced by domain
 * separated hash function H(0x11|x).
 *
 */

bool MultiSig::MultiSigVerify(const bytes& message, unsigned int offset,
                              unsigned int size, const Signature& toverify,
                              const PubKey& pubkey) {
  // This mutex is to prevent multi-threaded issues with the use of openssl
  // functions
  lock_guard<mutex> g(m_mutexMultiSigVerify);

  // Initial checks
  if (message.size() == 0) {
    // Empty message
    return false;
  }

  if (message.size() < (offset + size)) {
    // Offset and size beyond message size
    return false;
  }

  try {
    // Main verification procedure

    // The algorithm to check the signature (r, s) on a message m using a public
    // key kpub is as follows
    // 1. Check if r,s is in [1, ..., order-1]
    // 2. Compute Q = sG + r*kpub
    // 3. If Q = O (the neutral point), return 0;
    // 4. r' = H(Q, kpub, m)
    // 5. return r' == r

    SHA2<HashType::HASH_VARIANT_256> sha2;

    // The third domain separated hash function.

    // The first one is used in the Proof-of-Possession (PoP) phase.
    // PoP coincides with PoW when each node proves the knowledge
    // of the private key for a claimed public key.

    // The second one is used in CommitPointHash::Set to generate the hash of
    // the committed point.

    // Separation for the third hash function is defined by
    // setting the first byte to 0x11.
    sha2.Update({THIRD_DOMAIN_SEPARATED_HASH_FUNCTION_BYTE});

    bytes buf(Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES);

    bool err = false;
    bool err2 = false;

    // Regenerate the commitment part of the signature
    unique_ptr<BIGNUM, void (*)(BIGNUM*)> challenge_built(BN_new(),
                                                          BN_clear_free);
    unique_ptr<EC_POINT, void (*)(EC_POINT*)> Q(
        EC_POINT_new(Schnorr::GetCurveGroup()), EC_POINT_clear_free);
    unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

    if ((challenge_built != nullptr) && (ctx != nullptr) && (Q != nullptr)) {
      // 1. Check if r,s is in [1, ..., order-1]
      err2 = (BN_is_zero(toverify.m_r.get()) ||
              BN_is_negative(toverify.m_r.get()) ||
              (BN_cmp(toverify.m_r.get(), Schnorr::GetCurveOrder()) != -1));
      err = err || err2;
      if (err2) {
        // Challenge not in range
        return false;
      }

      err2 = (BN_is_zero(toverify.m_s.get()) ||
              BN_is_negative(toverify.m_s.get()) ||
              (BN_cmp(toverify.m_s.get(), Schnorr::GetCurveOrder()) != -1));
      err = err || err2;
      if (err2) {
        // Response not in range
        return false;
      }

      // 2. Compute Q = sG + r*kpub
      err2 =
          (EC_POINT_mul(Schnorr::GetCurveGroup(), Q.get(), toverify.m_s.get(),
                        pubkey.m_P.get(), toverify.m_r.get(), ctx.get()) == 0);
      err = err || err2;
      if (err2) {
        // Commit regenerate failed
        return false;
      }

      // 3. If Q = O (the neutral point), return 0;
      err2 = (EC_POINT_is_at_infinity(Schnorr::GetCurveGroup(), Q.get()));
      err = err || err2;
      if (err2) {
        // Commit at infinity
        return false;
      }

      // 4. r' = H(Q, kpub, m)
      // 4.1 Convert the committment to octets first
      err2 = (EC_POINT_point2oct(Schnorr::GetCurveGroup(), Q.get(),
                                 POINT_CONVERSION_COMPRESSED, buf.data(),
                                 Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES, NULL) !=
              Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES);
      err = err || err2;
      if (err2) {
        // Commit octet conversion failed
        return false;
      }

      // Hash commitment
      sha2.Update(buf);

      // Reset buf
      fill(buf.begin(), buf.end(), 0x00);

      // 4.2 Convert the public key to octets
      err2 = (EC_POINT_point2oct(Schnorr::GetCurveGroup(), pubkey.m_P.get(),
                                 POINT_CONVERSION_COMPRESSED, buf.data(),
                                 Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES, NULL) !=
              Schnorr::PUBKEY_COMPRESSED_SIZE_BYTES);
      err = err || err2;
      if (err2) {
        // Pubkey octet conversion failed
        return false;
      }

      // Hash public key
      sha2.Update(buf);

      // 4.3 Hash message
      sha2.Update(message, offset, size);
      bytes digest = sha2.Finalize();

      // 5. return r' == r
      err2 = (BN_bin2bn(digest.data(), digest.size(), challenge_built.get()) ==
              NULL);
      err = err || err2;
      if (err2) {
        // Challenge bin2bn conversion failed
        return false;
      }
      err2 = (BN_nnmod(challenge_built.get(), challenge_built.get(),
                       Schnorr::GetCurveOrder(), ctx.get()) == 0);
      err = err || err2;
      if (err2) {
        // Challenge rebuild mod failed
        return false;
      }

      sha2.Reset();
    } else {
      // Memory allocation failure
      throw std::bad_alloc();
    }
    return (!err) && (BN_cmp(challenge_built.get(), toverify.m_r.get()) == 0);
  } catch (const std::exception& e) {
    // LOG_GENERAL(WARNING, "Error with Schnorr::Verify." << ' ' << e.what());
    return false;
  }
}

bool MultiSig::SignKey(const bytes& messageWithPubKey, const PairOfKey& keyPair,
                       Signature& signature) {
  // This function is only used by Messenger::SetDSPoWSubmission for
  // Proof-of-Possession (PoP) phase
  return Schnorr::Sign(messageWithPubKey, keyPair.first, keyPair.second,
                       signature);
}

bool MultiSig::VerifyKey(const bytes& messageWithPubKey,
                         const Signature& signature, const PubKey& pubKey) {
  // This function is only used by Messenger::GetDSPoWSubmission for
  // Proof-of-Possession (PoP) phase
  return Schnorr::Verify(messageWithPubKey, signature, pubKey);
}
