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

#ifndef TESTS_MAIDSAFE_CACHED_KEYS_H_
#define TESTS_MAIDSAFE_CACHED_KEYS_H_

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem/fstream.hpp>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/client/cryptokeypairs.h"

namespace fs = boost::filesystem;

namespace cached_keys {

inline void MakeKeys(const int &key_count,
                     std::vector<crypto::RsaKeyPair> *keys) {
  keys->clear();
  fs::path key_file(file_system::TempDir() /
      ("maidsafe_CachedTestCryptoKeys" + boost::posix_time::to_simple_string(
      boost::posix_time::second_clock::local_time()).substr(0, 11)));
  maidsafe::BufferPacket keys_buffer;
  try {
    fs::ifstream fin(key_file, std::ifstream::binary);
    if (fin.good() && keys_buffer.ParseFromIstream(&fin) &&
        keys_buffer.messages_size() > 0) {
      for (int i = 0; i < keys_buffer.messages_size(); ++i) {
        crypto::RsaKeyPair keypair;
        keypair.set_public_key(keys_buffer.messages(i).data());
        keypair.set_private_key(keys_buffer.messages(i).signature());
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
    maidsafe::CryptoKeyPairs kps;
    kps.StartToCreateKeyPairs(need_keys);
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    for (int i = 0; i < need_keys; ++i) {
      crypto::RsaKeyPair rsakp;
      if (!kps.GetKeyPair(&rsakp))
        break;
      keys->push_back(rsakp);
      maidsafe::GenericPacket *gp = keys_buffer.add_messages();
      gp->set_data(rsakp.public_key());
      gp->set_signature(rsakp.private_key());
    }
    std::ofstream ofs(key_file.string().c_str(),
                      std::ofstream::trunc | std::ofstream::binary);
    keys_buffer.SerializeToOstream(&ofs);
    ofs.close();
  }
}

}  // namespace cached_keys

#endif  // TESTS_MAIDSAFE_CACHED_KEYS_H_
