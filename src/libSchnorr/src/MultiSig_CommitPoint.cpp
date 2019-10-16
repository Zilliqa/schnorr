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

bool CommitPoint::constructPreChecks() { return (m_p != nullptr); }

CommitPoint::CommitPoint()
    : m_p(EC_POINT_new(Schnorr::GetCurveGroup()), EC_POINT_clear_free),
      m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }
}

CommitPoint::CommitPoint(const CommitSecret& secret)
    : m_p(EC_POINT_new(Schnorr::GetCurveGroup()), EC_POINT_clear_free),
      m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  Set(secret);
}

CommitPoint::CommitPoint(const bytes& src, unsigned int offset) {
  if (!Deserialize(src, offset)) {
    // We failed to init CommitPoint
  }
}

CommitPoint::CommitPoint(const CommitPoint& src)
    : m_p(EC_POINT_new(Schnorr::GetCurveGroup()), EC_POINT_clear_free),
      m_initialized(false) {
  if (!constructPreChecks()) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  m_initialized = (EC_POINT_copy(m_p.get(), src.m_p.get()) == 1);
}

CommitPoint::~CommitPoint() {}

bool CommitPoint::Initialized() const { return m_initialized; }

bool CommitPoint::Serialize(bytes& dst, unsigned int offset) const {
  if (!m_initialized) {
    return false;
  }

  ECPOINTSerialize::SetNumber(dst, offset, COMMIT_POINT_SIZE, m_p);
  return true;
}

bool CommitPoint::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<EC_POINT> tmp;
  tmp = ECPOINTSerialize::GetNumber(src, offset, COMMIT_POINT_SIZE);
  if (tmp == nullptr) {
    // Deserialization failure
    return false;
  }

  m_p = tmp;
  m_initialized = true;

  return true;
}

void CommitPoint::Set(const CommitSecret& secret) {
  if (!secret.Initialized()) {
    return;
  }

  m_initialized = (EC_POINT_mul(Schnorr::GetCurveGroup(), m_p.get(),
                                secret.m_s.get(), NULL, NULL, NULL) == 1);
}

CommitPoint& CommitPoint::operator=(const CommitPoint& src) {
  m_initialized = (EC_POINT_copy(m_p.get(), src.m_p.get()) == 1);
  return *this;
}

bool CommitPoint::operator==(const CommitPoint& r) const {
  unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
  if (ctx == nullptr) {
    // Memory allocation failure
    throw std::bad_alloc();
  }

  return (m_initialized && r.m_initialized &&
          (EC_POINT_cmp(Schnorr::GetCurveGroup(), m_p.get(), r.m_p.get(),
                        ctx.get()) == 0));
}
