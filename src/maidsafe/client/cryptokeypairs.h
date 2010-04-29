/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class that generates in thread RSA key pairs and keeps a buffer
                full
* Version:      1.0
* Created:      2010-03-18-00.23.23
* Revision:     none
* Compiler:     gcc
* Author:       Jose Cisneros
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

#ifndef MAIDSAFE_CLIENT_CRYPTOKEYPAIRS_H_
#define MAIDSAFE_CLIENT_CRYPTOKEYPAIRS_H_

#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/base/crypto.h>
#include <list>
#include <vector>

namespace maidsafe {

const boost::int16_t kMaxCryptoThreadCount = 10;

class CryptoKeyPairs : public boost::noncopyable {
 public:
  CryptoKeyPairs();
  ~CryptoKeyPairs();
  bool StartToCreateKeyPairs(const boost::int16_t &no_of_keypairs);
  bool GetKeyPair(crypto::RsaKeyPair *keypair);
 private:
  void CreateKeyPair();
  void FinishedCreating();
  boost::int16_t keypairs_done_, keypairs_todo_, pending_requests_;
  std::list<crypto::RsaKeyPair> keypairs_;
  std::vector< boost::shared_ptr<boost::thread> > thrds_;
  boost::mutex keyslist_mutex_, keys_done_mutex_, start_mutex_, req_mutex_;
  boost::condition_variable keys_cond_, req_cond_;
  bool started_, destroying_this_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CRYPTOKEYPAIRS_H_
