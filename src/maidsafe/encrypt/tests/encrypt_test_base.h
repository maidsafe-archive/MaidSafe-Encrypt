
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

#ifndef MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
#define MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_

#include <thread>
#include <memory>

#include "boost/scoped_array.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace encrypt {
namespace test {

typedef data_store::DataStore<data_store::DataBuffer> DataStore;
typedef std::shared_ptr<DataStore> DataStorePtr;
typedef DataStore::PopFunctor PopFunctor;
typedef std::shared_ptr<nfs::TemporaryClientMaidNfs> ClientNfsPtr;
typedef std::shared_ptr<SelfEncryptor> SelfEncryptorPtr;

class EncryptTestBase {
 public:
  explicit EncryptTestBase(int num_procs)
      : test_dir_(maidsafe::test::CreateTestPath()),
        num_procs_(num_procs),
        client_nfs_(),
        data_store_(new DataStore(MemoryUsage(uint64_t(0)),
                                  DiskUsage(uint64_t(4294967296)),  // 1 << 32
                                  PopFunctor())),
        data_map_(new DataMap),
        self_encryptor_(),
        original_(),
        decrypted_() {
    self_encryptor_.reset(new SelfEncryptor(data_map_, *client_nfs_, *data_store_, num_procs_));
  }
  virtual ~EncryptTestBase() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  ClientNfsPtr client_nfs_;
  DataStorePtr data_store_;
  DataMapPtr data_map_;
  SelfEncryptorPtr self_encryptor_;
  boost::scoped_array<char> original_, decrypted_;

 private:
};

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
