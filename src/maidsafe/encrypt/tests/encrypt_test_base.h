
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
#include "maidsafe/common/hashable_chunk_validation.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {
namespace encrypt {
namespace test {

class EncryptTestBase {
 public:
  explicit EncryptTestBase(int num_procs = 0)
      : chunk_store_(new MemoryChunkStore(
            false, std::shared_ptr<ChunkValidation>(
                new HashableChunkValidation<crypto::SHA512>))),
        data_map_(new DataMap),
        self_encryptor_(new SelfEncryptor(data_map_, chunk_store_, num_procs)),
        original_(),
        decrypted_() {}
 protected:
  std::shared_ptr<MemoryChunkStore> chunk_store_;
  DataMapPtr data_map_;
  std::shared_ptr<SelfEncryptor> self_encryptor_;
  boost::scoped_array<char> original_, decrypted_;
};

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
