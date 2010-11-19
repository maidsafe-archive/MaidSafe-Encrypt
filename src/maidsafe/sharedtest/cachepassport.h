/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  A Passport which makes use of cached crypto keys (for test use)
* Version:      1.0
* Created:      2010-10-13-14.01.23
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_SHAREDTEST_CACHEPASSPORT_H_
#define MAIDSAFE_SHAREDTEST_CACHEPASSPORT_H_

#include <maidsafe/passport/passport.h>
#include <vector>
#include "maidsafe/sharedtest/cached_keys.h"

namespace maidsafe {

namespace passport {

namespace test {

class CachePassport : public Passport {
 public:
  CachePassport(const boost::uint16_t &rsa_key_size,
                const boost::int8_t &max_crypto_thread_count,
                const boost::uint16_t &key_count)
      : Passport(rsa_key_size, max_crypto_thread_count),
        kKeyCount_(key_count) {}
  virtual void Init() {
    std::vector<crypto::RsaKeyPair> keys;
    cached_keys::MakeKeys(kKeyCount_, &keys, true);
    crypto_key_pairs_.keypairs_.assign(keys.begin(), keys.end());
  }
  ~CachePassport() {}
 private:
  CachePassport &operator=(const CachePassport&);
  CachePassport(const CachePassport&);
  const boost::uint16_t kKeyCount_;
};

}  // namespace test

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_SHAREDTEST_CACHEPASSPORT_H_

