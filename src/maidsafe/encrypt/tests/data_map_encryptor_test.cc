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
      : EncryptTestBase(RandomUint32() % (Concurrency() + 1)),
        kDataSize_(1024 * 1024 * 20),
        content_(RandomString(kDataSize_)) {
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


TEST_F(EncryptDataMapTest, BEH_EncryptDecryptDataMap) {
  // TODO(Fraser#5#): 2012-01-05 - Test failure cases also.
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));
  EXPECT_TRUE(self_encryptor_->Flush());
  const Identity kParentId(RandomString(64)), kThisId(RandomString(64));

  asymm::CipherText encrypted_data_map = EncryptDataMap(kParentId, kThisId, data_map_);
  EXPECT_FALSE(encrypted_data_map.string().empty());

  DataMap retrieved_data_map(DecryptDataMap(kParentId, kThisId, encrypted_data_map.string()));
  ASSERT_EQ(data_map_.chunks.size(), retrieved_data_map.chunks.size());
  auto original_itr(data_map_.chunks.begin()), retrieved_itr(retrieved_data_map.chunks.begin());
  std::string original_pre_hash(64, 0), retrieved_pre_hash(64, 0);
  for (; original_itr != data_map_.chunks.end(); ++original_itr, ++retrieved_itr) {
    ASSERT_EQ((*original_itr).hash, (*retrieved_itr).hash);
    memcpy(&original_pre_hash[0], &(*original_itr).pre_hash, 64);
    memcpy(&retrieved_pre_hash[0], &(*retrieved_itr).pre_hash, 64);
    ASSERT_EQ(original_pre_hash, retrieved_pre_hash);
    ASSERT_EQ((*original_itr).size, (*retrieved_itr).size);
  }
}

TEST_F(EncryptDataMapTest, BEH_DifferentDataMapSameChunk) {
  DataMap data_map_1, data_map_2;
  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, get_from_store_);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, get_from_store_);
    self_encryptor_1.Write(original_.get(), 16 * 1024, 0);
    self_encryptor_2.Write(original_.get(), 16 * 1024, 0);
  }
  {
    boost::scoped_array<char> result_data;
    result_data.reset(new char[16 * 1024]);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, get_from_store_);
    self_encryptor_2.Read(result_data.get(), 16 * 1024, 0);
    for (uint32_t i = 0; i != 16 * 1024; ++i)
      ASSERT_EQ(original_[i], result_data[i]) << "i == " << i;
  }

  boost::scoped_array<char> temp_data(new char[500]);
  memset(temp_data.get(), 'b', 500);
  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, get_from_store_);
    self_encryptor_1.Write(temp_data.get(), 500, 1000);
    self_encryptor_1.Truncate(10 * 1024);
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
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
