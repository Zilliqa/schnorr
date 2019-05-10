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

bool CommitSecret::constructPreChecks() { return (m_s != nullptr); }

CommitSecret::CommitSecret()
    : m_s(BN_new(), BN_clear_free), m_initialized(false) {
  // commit->secret should be in [1,...,order-1]
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  bool err = false;

  do {
    err = (BN_rand_range(m_s.get(), Schnorr::GetCurveOrder()) == 0);
    if (err) {
      // Value to commit rand failed
      break;
    }
  } while (BN_is_zero(m_s.get()));

  m_initialized = (!err);
}

CommitSecret::CommitSecret(const bytes& src, unsigned int offset) {
  if (!Deserialize(src, offset)) {
    //
  }
}

CommitSecret::CommitSecret(const CommitSecret& src)
    : m_s(BN_new(), BN_clear_free), m_initialized(false) {
  if (!constructPreChecks()) {
    throw std::bad_alloc();
  }

  m_initialized = (BN_copy(m_s.get(), src.m_s.get()) != NULL);
}

CommitSecret::~CommitSecret() {}

bool CommitSecret::Initialized() const { return m_initialized; }

bool CommitSecret::Serialize(bytes& dst, unsigned int offset) const {
  if (!m_initialized) {
    return false;
  }

  BIGNUMSerialize::SetNumber(dst, offset, COMMIT_SECRET_SIZE, m_s);
  return true;
}

bool CommitSecret::Deserialize(const bytes& src, unsigned int offset) {
  shared_ptr<BIGNUM> tmp =
      BIGNUMSerialize::GetNumber(src, offset, COMMIT_SECRET_SIZE);

  if (tmp == nullptr) {
    return false;
  }

  m_s = tmp;
  m_initialized = true;

  return 0;
}

CommitSecret& CommitSecret::operator=(const CommitSecret& src) {
  m_initialized = (BN_copy(m_s.get(), src.m_s.get()) == m_s.get());
  return *this;
}

bool CommitSecret::operator==(const CommitSecret& r) const {
  return (m_initialized && r.m_initialized &&
          (BN_cmp(m_s.get(), r.m_s.get()) == 0));
}