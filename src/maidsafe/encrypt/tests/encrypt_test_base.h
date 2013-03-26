
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

#include "maidsafe/common/utils.h"
#include "maidsafe/data_store/permanent_store.h"
#include "maidsafe/nfs/nfs.h"
#include "maidsafe/encrypt/self_encryptor.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace encrypt {
namespace test {

typedef data_store::PermanentStore DataStore;
typedef std::shared_ptr<DataStore> DataStorePtr;
typedef std::shared_ptr<nfs::ClientMaidNfs> ClientNfsPtr;
typedef std::shared_ptr<SelfEncryptor> SelfEncryptorPtr;

class EncryptTestBase {
 public:
  explicit EncryptTestBase(int num_procs)
      : test_dir_(maidsafe::test::CreateTestPath()),
        num_procs_(num_procs),
        maid_(maidsafe::passport::Maid::signer_type()),
        routing_(maid_),
        client_nfs_(new nfs::ClientMaidNfs(routing_, maid_)),
        data_store_(std::make_shared<DataStore>(*test_dir_ / "data_store",
                                                DiskUsage(uint64_t(4294967296)))),
        data_map_(std::make_shared<DataMap>()),
        self_encryptor_(std::make_shared<SelfEncryptor>(data_map_,
                                                        *client_nfs_,
                                                        *data_store_,
                                                        num_procs_)),
        original_(),
        decrypted_() {}
  virtual ~EncryptTestBase() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  passport::Maid maid_;
  routing::Routing routing_;
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
