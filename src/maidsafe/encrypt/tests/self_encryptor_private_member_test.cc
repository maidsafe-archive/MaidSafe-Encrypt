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

class PrivateSelfEncryptorTest : public testing::Test {
 public:
  PrivateSelfEncryptorTest()
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

  virtual ~PrivateSelfEncryptorTest() = default;

 protected:
  virtual void TearDown() { self_encryptor_->closed_ = true; }
  uint64_t size() { return self_encryptor_->file_size_; }
  size_t ChunksSize() { return self_encryptor_->chunks_.size(); }
  uint32_t GetChunkSize(uint32_t chunk_num) { return self_encryptor_->GetChunkSize(chunk_num); }
  uint32_t GetNumChunks() { return self_encryptor_->GetNumChunks(); }
  std::pair<uint64_t, uint64_t> GetStartEndPositions(uint32_t chunk_number) {
    return self_encryptor_->GetStartEndPositions(chunk_number);
  }
  uint32_t GetNextChunkNumber(uint32_t chunk_number) {
    return self_encryptor_->GetNextChunkNumber(chunk_number);
  }
  uint32_t GetPreviousChunkNumber(uint32_t chunk_number) {
    return self_encryptor_->GetPreviousChunkNumber(chunk_number);
  }

  uint32_t GetChunkNumber(uint64_t position) { return self_encryptor_->GetChunkNumber(position); }
  void SetEncryptorSize(uint64_t size) { self_encryptor_->file_size_ = size; }
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  DataBuffer<std::string> local_store_;
  DataMap data_map_;
  std::function<NonEmptyString(const std::string&)> get_from_store_;
  std::unique_ptr<SelfEncryptor> self_encryptor_;
  std::unique_ptr<char[]> original_, decrypted_;
};

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersSmallfileContentOnly) {
  SetEncryptorSize((kMinChunkSize * 3) - 1);
  EXPECT_EQ(GetNumChunks(), 0);
}

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersEqual3MinChunks) {
  SetEncryptorSize(kMinChunkSize * 3);
  EXPECT_EQ(GetNumChunks(), 3);
  EXPECT_EQ(GetChunkSize(0), 1024);
  EXPECT_EQ(GetChunkSize(1), 1024);
  EXPECT_EQ(GetChunkSize(2), 1024);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 2);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, 3 * kMinChunkSize);
}

TEST_F(PrivateSelfEncryptorTest, PRIV_Helpers3MinChunksPlus1) {
  SetEncryptorSize((kMinChunkSize * 3) + 1);
  EXPECT_EQ(GetNumChunks(), 3);
  EXPECT_EQ(GetChunkSize(0), 1024);
  EXPECT_EQ(GetChunkSize(1), 1024);
  EXPECT_EQ(GetChunkSize(2), 1025);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 2);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, 1 + (3 * kMinChunkSize));
}

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersEqual3MaxChunks) {
  SetEncryptorSize(kMaxChunkSize * 3);
  EXPECT_EQ(GetNumChunks(), 3);
  EXPECT_EQ(GetChunkSize(0), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(1), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(2), kMaxChunkSize);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 2);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, 3 * kMaxChunkSize);
}

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersMaxChunksPlus1) {
  SetEncryptorSize((kMaxChunkSize * 3) + 1);
  EXPECT_EQ(GetNumChunks(), 4);
  EXPECT_EQ(GetChunkSize(0), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(1), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(2), kMaxChunkSize - kMinChunkSize);
  EXPECT_EQ(GetChunkSize(3), kMinChunkSize + 1);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 3);
  EXPECT_EQ(GetNextChunkNumber(3), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 3);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetPreviousChunkNumber(3), 2);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, (3 * kMaxChunkSize) - kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).first, (3 * kMaxChunkSize) - kMinChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).second,
            (kMinChunkSize + 1) + ((3 * kMaxChunkSize) - kMinChunkSize));
}

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersEqual3andaHalfMaxChunks) {
  SetEncryptorSize(kMaxChunkSize * 3.5);
  EXPECT_EQ(GetNumChunks(), 4);
  EXPECT_EQ(GetChunkSize(0), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(1), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(2), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(3), kMaxChunkSize / 2);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 3);
  EXPECT_EQ(GetNextChunkNumber(3), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 3);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetPreviousChunkNumber(3), 2);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, 3 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).first, 3 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).second, 3.5 * kMaxChunkSize);
}

TEST_F(PrivateSelfEncryptorTest, PRIV_HelpersEqual5MaxChunks) {
  SetEncryptorSize(kMaxChunkSize * 5);
  EXPECT_EQ(GetNumChunks(), 5);
  EXPECT_EQ(GetChunkSize(0), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(1), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(2), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(3), kMaxChunkSize);
  EXPECT_EQ(GetChunkSize(4), kMaxChunkSize);
  EXPECT_EQ(GetNextChunkNumber(0), 1);
  EXPECT_EQ(GetNextChunkNumber(1), 2);
  EXPECT_EQ(GetNextChunkNumber(2), 3);
  EXPECT_EQ(GetNextChunkNumber(3), 4);
  EXPECT_EQ(GetNextChunkNumber(4), 0);
  EXPECT_EQ(GetPreviousChunkNumber(0), 4);
  EXPECT_EQ(GetPreviousChunkNumber(1), 0);
  EXPECT_EQ(GetPreviousChunkNumber(2), 1);
  EXPECT_EQ(GetPreviousChunkNumber(3), 2);
  EXPECT_EQ(GetPreviousChunkNumber(4), 3);
  EXPECT_EQ(GetStartEndPositions(0).first, 0);
  EXPECT_EQ(GetStartEndPositions(0).second, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).first, kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(1).second, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).first, 2 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(2).second, 3 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).first, 3 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(3).second, 4 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(4).first, 4 * kMaxChunkSize);
  EXPECT_EQ(GetStartEndPositions(4).second, 5 * kMaxChunkSize);
}
}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
