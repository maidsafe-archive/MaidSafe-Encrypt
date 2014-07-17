/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
#define MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_

#include <memory>
#include <string>
#include <thread>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {

namespace encrypt {

namespace test {

class EncryptTestBase {
 public:
  EncryptTestBase()
      : test_dir_(maidsafe::test::CreateTestPath()),
        num_procs_(RandomUint32() % (Concurrency() + 1)),
        local_store_(MemoryUsage(1024 * 1024), DiskUsage(4294967296),
                     [](const std::string& name, const NonEmptyString&) {
                         LOG(kError) << "Buffer full - deleting " << Base64Substr(name);
                         BOOST_THROW_EXCEPTION(MakeError(CommonErrors::cannot_exceed_limit));
                     },
                     *test_dir_),
        data_map_(),
        get_from_store_([this](const std::string& name) { return local_store_.Get(name); }),
        self_encryptor_(new SelfEncryptor(data_map_, local_store_, get_from_store_, num_procs_)),
        original_(),
        decrypted_() {}

  virtual ~EncryptTestBase() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  DataBuffer<std::string> local_store_;
  DataMap data_map_;
  std::function<NonEmptyString(const std::string&)> get_from_store_;
  std::unique_ptr<SelfEncryptor> self_encryptor_;
  std::unique_ptr<char[]> original_, decrypted_;
};

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
