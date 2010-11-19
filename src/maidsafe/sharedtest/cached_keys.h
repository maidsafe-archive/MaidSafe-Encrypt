/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Creates cached crypto keys for use of tests
* Version:      1.0
* Created:      2010-03-14-14.15.52
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_SHAREDTEST_CACHED_KEYS_H_
#define MAIDSAFE_SHAREDTEST_CACHED_KEYS_H_

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem/fstream.hpp>
#include <maidsafe/base/crypto.h>
#include <maidsafe/passport/passport.h>

#include <string>
#include <vector>

#include "maidsafe/common/filesystem.h"
#include "maidsafe/passport/signaturepacket.pb.h"

namespace fs = boost::filesystem;

namespace cached_keys {

inline void MakeKeys(const int &key_count,
                     std::vector<crypto::RsaKeyPair> *keys,
                     bool for_passport = false) {
  keys->clear();
  fs::path key_file;
  if (for_passport) {
    key_file = fs::path(file_system::TempDir() /
      ("maidsafe_CachedTestPassportKeys" + boost::posix_time::to_simple_string(
      boost::posix_time::second_clock::local_time()).substr(0, 11) + ".tmp"));
  } else {
    key_file = fs::path(file_system::TempDir() /
      ("maidsafe_CachedTestCryptoKeys" + boost::posix_time::to_simple_string(
      boost::posix_time::second_clock::local_time()).substr(0, 11) + ".tmp"));
  }
  maidsafe::passport::Keyring keyring;
  try {
    fs::ifstream fin(key_file, std::ifstream::binary);
    if (fin.good() && keyring.ParseFromIstream(&fin) &&
        keyring.key_size() > 0) {
      for (int i = 0; i < keyring.key_size(); ++i) {
        crypto::RsaKeyPair keypair;
        keypair.set_public_key(keyring.key(i).public_key());
        keypair.set_private_key(keyring.key(i).private_key());
        if (!keypair.public_key().empty() && !keypair.private_key().empty()) {
          keys->push_back(keypair);
        }
      }
    }
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    keys->clear();
  }
  int need_keys = key_count - static_cast<int>(keys->size());
  if (need_keys > 0) {
    maidsafe::passport::CryptoKeyPairs kps(4096, 5);
    kps.StartToCreateKeyPairs(need_keys);
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    for (int i = 0; i < need_keys; ++i) {
      crypto::RsaKeyPair rsakp;
      if (!kps.GetKeyPair(&rsakp))
        break;
      keys->push_back(rsakp);
      maidsafe::passport::Key *key = keyring.add_key();
      key->set_public_key(rsakp.public_key());
      key->set_private_key(rsakp.private_key());
      // These are required fields for keyring keys, but not needed here
      key->set_name("B");
      key->set_packet_type(0);
      key->set_public_key_signature("o");
      key->set_signer_private_key("b");
    }
    std::ofstream ofs(key_file.string().c_str(),
                      std::ofstream::trunc | std::ofstream::binary);
    keyring.SerializeToOstream(&ofs);
    ofs.close();
  }
}

}  // namespace cached_keys

#endif  // MAIDSAFE_SHAREDTEST_CACHED_KEYS_H_
