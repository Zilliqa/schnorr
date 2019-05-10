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

bool Response::constructPreChecks() { return (m_r != nullptr); }

Response::Response() : m_r(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }
}

Response::Response(const CommitSecret& secret, const Challenge& challenge,
                   const PrivKey& privkey)
    : m_r(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  Set(secret, challenge, privkey);
}

Response::Response(const bytes& src, unsigned int offset) {
  if (!Deserialize(src, offset)) {
    //
  }
}

Response::Response(const Response& src)
    : m_r(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  m_initialized = (BN_copy(m_r.get(), src.m_r.get()) != NULL);
}

Response::~Response() {}

bool Response::Initialized() const { return m_initialized; }

bool Response::Serialize(bytes& dst, unsigned int offset) const {
  if (!m_initialized) {
    return false;
  }

  BIGNUMSerialize::SetNumber(dst, offset, RESPONSE_SIZE, m_r);
  return true;
}

bool Response::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> tmp =
      BIGNUMSerialize::GetNumber(src, offset, RESPONSE_SIZE);

  if (tmp == nullptr) {
    return false;
  }

  m_r = tmp;
  m_initialized = true;

  return true;
}

void Response::Set(const CommitSecret& secret, const Challenge& challenge,
                   const PrivKey& privkey) {
  // Initial checks

  if (m_initialized) {
    // Response already initialized
    return;
  }

  if (!secret.Initialized()) {
    // Commit secret not initialized
    return;
  }

  if (!challenge.Initialized()) {
    // Challenge not initialized
    return;
  }

  m_initialized = false;

  // Compute s = k - krpiv*c
  unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
  if (ctx == nullptr) {
    throw std::bad_alloc();
  }

  // kpriv*c
  if (BN_mod_mul(m_r.get(), challenge.m_c.get(), privkey.m_d.get(),
                 Schnorr::GetCurveOrder(), ctx.get()) == 0) {
    // BIGNUM mod mul failed
    return;
  }

  // k-kpriv*c
  if (BN_mod_sub(m_r.get(), secret.m_s.get(), m_r.get(),
                 Schnorr::GetCurveOrder(), ctx.get()) == 0) {
    // BIGNUM mod add failed
    return;
  }

  m_initialized = true;
}

Response& Response::operator=(const Response& src) {
  m_initialized = (BN_copy(m_r.get(), src.m_r.get()) == m_r.get());
  return *this;
}

bool Response::operator==(const Response& r) const {
  return (m_initialized && r.m_initialized &&
          (BN_cmp(m_r.get(), r.m_r.get()) == 0));
}