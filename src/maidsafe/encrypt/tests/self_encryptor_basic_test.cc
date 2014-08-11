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

#include <thread>
#include <array>
#include <cstdlib>
#include <string>
#include <memory>
#include "boost/filesystem.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/data_buffer.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

class EncryptBasicTest : public testing::Test {
 public:
   EncryptBasicTest()
      : test_dir_(maidsafe::test::CreateTestPath()),
        local_store_(MemoryUsage(1024 * 1024), DiskUsage(4294967296),
                     [](const std::string& name, const NonEmptyString&) {
                       LOG(kError) << "Buffer full - deleting " << Base64Substr(name);
                       BOOST_THROW_EXCEPTION(MakeError(CommonErrors::cannot_exceed_limit));
                     },
                     *test_dir_),
        data_map_(),
        get_from_store_([this](const std::string& name) { return local_store_.Get(name); }),
        self_encryptor_(new SelfEncryptor(data_map_, local_store_, get_from_store_)),
        original_(),
        decrypted_() {}

  virtual ~EncryptBasicTest() = default;

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  DataBuffer<std::string> local_store_;
  DataMap data_map_;
  std::function<NonEmptyString(const std::string&)> get_from_store_;
  std::unique_ptr<SelfEncryptor> self_encryptor_;
  std::unique_ptr<char[]> original_, decrypted_;
};

TEST_F(EncryptBasicTest, BEH_SMallfileContentOnly) {
  auto size(1024);
  std::string temp(RandomString(size));
  std::string result;
  result.reserve(size);
  char* res(new char[size]);
  EXPECT_TRUE(self_encryptor_->Write(&temp.data()[0], size, 0));
  EXPECT_TRUE(self_encryptor_->Read(res, size, 0));
  result.assign(res, res + size);
  EXPECT_EQ(result, temp);
  EXPECT_TRUE(self_encryptor_->Write(&temp.data()[0], size, 0));
  self_encryptor_->Close();
  EXPECT_EQ(size, data_map_.size());
  auto encryptor_(new SelfEncryptor(data_map_, local_store_, get_from_store_));
  EXPECT_TRUE(encryptor_->Read(res, size, 0));
  result.assign(res, res + size);
  EXPECT_EQ(result, temp);
}

TEST_F(EncryptBasicTest, BEH_LargeFileWithLargeGap) {
  auto size(5 * 1024 * 1024);
  std::string temp(RandomString(size));
  std::string result;
  result.reserve(size);
  char* res(new char[size]);
  EXPECT_TRUE(self_encryptor_->Write(&temp.data()[0], size, 0));
  EXPECT_TRUE(self_encryptor_->Read(res, size, 0));
  result.assign(res, res + size);
  EXPECT_EQ(result, temp);
  EXPECT_TRUE(self_encryptor_->Write(&temp.data()[0], size, 0));
  // write a large gap in the file
  // EXPECT_TRUE(self_encryptor_->Write(&temp.data()[0], size, size * 2));
  self_encryptor_->Close();
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
