
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

#include <memory>

#include "boost/scoped_array.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/omp.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include "maidsafe/encrypt/self_encryptor.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace encrypt {
namespace test {

class EncryptTestBase {
 public:
  explicit EncryptTestBase(int num_procs)
      : test_dir_(maidsafe::test::CreateTestPath()),
        num_procs_(num_procs),
        asio_service_(),
        chunk_store_(),
        data_map_(new DataMap),
        self_encryptor_(),
        original_(),
        decrypted_() {
    asio_service_.Start(5);
    fs::path buffered_chunk_store_path;
    chunk_store_ =
        priv::chunk_store::CreateLocalChunkStore(*test_dir_,
                                                 asio_service_.service(),
                                                 &buffered_chunk_store_path);
    self_encryptor_.reset(new SelfEncryptor(data_map_,
                                            chunk_store_,
                                            num_procs_));
  }
  virtual ~EncryptTestBase() {
    asio_service_.Stop();
    if (testing::UnitTest::GetInstance()->current_test_info()->result()->
        Failed()) {
      std::cerr << "Number of available processors set in SelfEncryptor: "
                << ((num_procs_ == 0) ? omp_get_num_procs() : num_procs_)
                << std::endl;
    }
  }

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  AsioService asio_service_;
  RemoteChunkStorePtr chunk_store_;
  DataMapPtr data_map_;
  std::shared_ptr<SelfEncryptor> self_encryptor_;
  boost::scoped_array<char> original_, decrypted_;

 private:
};

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
