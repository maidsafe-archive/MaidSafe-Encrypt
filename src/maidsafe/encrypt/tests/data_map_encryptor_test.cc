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

#ifdef WIN32
#pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/channels.h"
#include "cryptopp/gzip.h"
#include "cryptopp/ida.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#ifdef WIN32
#pragma warning(pop)
#endif
#include "boost/scoped_array.hpp"
#include "boost/shared_array.hpp"
#include "boost/filesystem.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/data_map_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace {

typedef std::pair<uint32_t, uint32_t> SizeAndOffset;
const int g_num_procs(Concurrency());
}  // unnamed namespace

class EncryptDataMapTest : public EncryptTestBase, public testing::Test {
 public:
  EncryptDataMapTest()
      : EncryptTestBase(), kDataSize_(1024 * 1024 * 20), content_(RandomString(kDataSize_)) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kDataSize_]);
  }

 protected:
  virtual void SetUp() override {
    std::copy(content_.data(), content_.data() + kDataSize_, original_.get());
    memset(decrypted_.get(), 1, kDataSize_);
  }
  const uint32_t kDataSize_;
  std::string content_;
};


TEST_F(EncryptDataMapTest, BEH_SerialiseParseDataMap) {
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));
  EXPECT_NO_THROW(self_encryptor_->Close());

  std::string serialised_data_map;
  SerialiseDataMap(data_map_, serialised_data_map);
   
  DataMap new_data_map;
  ParseDataMap(serialised_data_map, new_data_map);

  SelfEncryptor self_encryptor(new_data_map, local_store_, get_from_store_);
  EXPECT_TRUE(self_encryptor.Read(&decrypted_[0], kDataSize_, 0));
  EXPECT_NO_THROW(self_encryptor.Close());
  for(uint32_t i(0); i < kDataSize_; ++i)
    EXPECT_EQ(decrypted_[i], original_[i]);
}

TEST_F(EncryptDataMapTest, BEH_EncryptDecryptDataMap) {
  // TODO(Fraser#5#): 2012-01-05 - Test failure cases also.
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));
  EXPECT_NO_THROW(self_encryptor_->Close());
  const Identity kParentId(RandomString(64)), kThisId(RandomString(64));

  asymm::CipherText encrypted_data_map = EncryptDataMap(kParentId, kThisId, data_map_);
  EXPECT_FALSE(encrypted_data_map.string().empty());

  DataMap retrieved_data_map(DecryptDataMap(kParentId, kThisId, encrypted_data_map.string()));
  
  SelfEncryptor self_encryptor(retrieved_data_map, local_store_, get_from_store_);
  EXPECT_TRUE(self_encryptor.Read(&decrypted_[0], kDataSize_, 0));
  EXPECT_NO_THROW(self_encryptor.Close());
  ASSERT_EQ(data_map_.chunks.size(), retrieved_data_map.chunks.size());
  for(uint32_t i(0); i < kDataSize_; ++i)
    EXPECT_EQ(decrypted_[i], original_[i]);
}

TEST_F(EncryptDataMapTest, BEH_DifferentDataMapSameChunk) {
  DataMap data_map_1, data_map_2;
  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, get_from_store_);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, get_from_store_);
    self_encryptor_1.Write(original_.get(), 16 * 1024, 0);
    self_encryptor_2.Write(original_.get(), 16 * 1024, 0);
    self_encryptor_1.Close();
    self_encryptor_2.Close();
  }
  {
    boost::scoped_array<char> result_data;
    result_data.reset(new char[16 * 1024]);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, get_from_store_);
    self_encryptor_2.Read(result_data.get(), 16 * 1024, 0);
    self_encryptor_2.Close();
    for (uint32_t i = 0; i != 16 * 1024; ++i)
      ASSERT_EQ(original_[i], result_data[i]) << "i == " << i;
  }

  boost::scoped_array<char> temp_data(new char[500]);
  memset(temp_data.get(), 'b', 500);
  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, get_from_store_);
    self_encryptor_1.Write(temp_data.get(), 500, 1000);
    self_encryptor_1.Truncate(10 * 1024);
    self_encryptor_1.Close();
  }
  // There's no reference counting in the data store now and the original chunks have been
  // overwritten by this point, so the following fails...
  // {
  //    boost::scoped_array<char> result_data;
  //    result_data.reset(new char[16 * 1024]);
  //    SelfEncryptorPtr self_encryptor_2(new SelfEncryptor(data_map_2,
  //                                                        *client_nfs_,
  //                                                        *data_store_,
  //                                                        num_procs_));
  //    self_encryptor_2->Read(result_data.get(), 16 * 1024, 0);
  //    for (uint32_t i = 0; i != 16 * 1024; ++i)
  //      ASSERT_EQ(original_[i], result_data[i]) << "i == " << i;
  // }
  EXPECT_NO_THROW(self_encryptor_->Close());
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
