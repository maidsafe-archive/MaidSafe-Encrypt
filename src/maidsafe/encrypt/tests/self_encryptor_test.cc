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
#include "boost/filesystem.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace {

typedef std::pair<uint32_t, uint32_t> SizeAndOffset;
const int g_num_procs(Concurrency());

uint64_t TotalSize(DataMapPtr data_map) {
  uint64_t size(data_map->chunks.empty() ? data_map->content.size() : 0);
  for (auto& elem : data_map->chunks)
    size += (elem).size;
  return size;
}

void GetEncryptionResult(boost::shared_array<byte>* result, boost::shared_array<byte> n1hash,
                         boost::shared_array<byte> n2hash, boost::shared_array<byte> hash,
                         boost::shared_array<byte> chunk, uint32_t chunk_size) {
  boost::scoped_array<byte> pad(
      new byte[(3 * crypto::SHA512::DIGESTSIZE) - crypto::AES256_KeySize - crypto::AES256_IVSize]);
  boost::scoped_array<byte> key(new byte[32]);
  boost::scoped_array<byte> iv(new byte[crypto::AES256_IVSize]);
  boost::scoped_array<byte> postenc(new byte[chunk_size]);
  boost::scoped_array<byte> xor_res(new byte[chunk_size]);

  // set up pad
  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    pad[i] = n1hash[i];
    pad[i + crypto::SHA512::DIGESTSIZE] = hash[i];
  }
  for (int i = 0; i != crypto::AES256_IVSize; ++i) {
    pad[i + (2 * crypto::SHA512::DIGESTSIZE)] =
        n2hash[i + crypto::AES256_KeySize + crypto::AES256_IVSize];
  }
  // get key & IV
  std::copy(n2hash.get(), n2hash.get() + crypto::AES256_KeySize, key.get());
  std::copy(n2hash.get() + crypto::AES256_KeySize,
            n2hash.get() + crypto::AES256_KeySize + crypto::AES256_IVSize, iv.get());

  CryptoPP::Gzip compress(new CryptoPP::MessageQueue(), 6);
  compress.Put2(chunk.get(), chunk_size, -1, true);
  uint32_t compressed_size = static_cast<uint32_t>(compress.MaxRetrievable());
  boost::shared_array<byte> comp_data(new byte[compressed_size]);
  compress.Get(comp_data.get(), compressed_size);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc(key.get(), crypto::AES256_KeySize, iv.get());
  enc.ProcessData(postenc.get(), comp_data.get(), compressed_size);

  for (size_t i = 0; i < compressed_size; ++i) {
    xor_res[i] = postenc[i] ^ pad[i % ((3 * crypto::SHA512::DIGESTSIZE) - crypto::AES256_KeySize -
                                       crypto::AES256_IVSize)];
  }
  CryptoPP::SHA512().CalculateDigest(result->get(), xor_res.get(), compressed_size);
}

}  // unnamed namespace

class BasicOffsetTest : public EncryptTestBase, public testing::TestWithParam<SizeAndOffset> {
 public:
  enum TestFileSize {
    kTiny = 3 * kMinChunkSize,
    kVerySmall = kDefaultChunkSize,
    kSmall = 3 * kDefaultChunkSize,
    kMedium = 10 * kDefaultChunkSize,
    kLarge = 1000 * kDefaultChunkSize,
    kMax = 2147483647
  };

  BasicOffsetTest()
      : EncryptTestBase(RandomUint32() % (Concurrency() + 1)),
        kDataSize_(GetParam().first),
        kOffset_(GetParam().second),
        test_file_size_(kMax) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kOffset_ + kDataSize_]);
    if (kOffset_ + kDataSize_ < kTiny)
      test_file_size_ = kTiny;
    else if (kOffset_ + kDataSize_ < kVerySmall)
      test_file_size_ = kVerySmall;
    else if (kOffset_ + kDataSize_ < kSmall)
      test_file_size_ = kSmall;
    else if (kOffset_ + kDataSize_ < kMedium)
      test_file_size_ = kMedium;
    else
      test_file_size_ = kLarge;
  }

 protected:
  virtual void SetUp() override {
    std::string content(RandomString(kDataSize_));
    std::copy(content.data(), content.data() + kDataSize_, original_.get());
    memset(decrypted_.get(), 1, kDataSize_);
  }

  void TearDown() override {}

  const uint32_t kDataSize_, kOffset_;
  TestFileSize test_file_size_;
};

TEST_P(BasicOffsetTest, BEH_EncryptDecrypt) {
  EXPECT_TRUE(self_encryptor_->Write(original_.get(), kDataSize_, kOffset_));

  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kOffset_ + kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, decrypted_[i]) << "i == " << i;
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[kOffset_ + i]) << "i == " << i;

  decrypted_.reset(new char[kOffset_ + kDataSize_]);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, kOffset_));
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  self_encryptor_.reset(new SelfEncryptor(data_map_, local_store_, nullptr, num_procs_));
  EXPECT_EQ(kOffset_ + kDataSize_, TotalSize(data_map_));
  if (test_file_size_ == kTiny) {
    ASSERT_EQ(kOffset_ + kDataSize_, data_map_->content.size());
    EXPECT_TRUE(data_map_->chunks.empty());
    for (uint32_t i = 0; i != kOffset_; ++i)
      ASSERT_EQ(0, data_map_->content[i]) << "i == " << i;
    for (uint32_t i = 0; i != kDataSize_; ++i)
      ASSERT_EQ(original_[i], data_map_->content[kOffset_ + i]) << "i == " << i;
  } else {
    EXPECT_TRUE(data_map_->content.empty());
    EXPECT_FALSE(data_map_->chunks.empty());
  }

  decrypted_.reset(new char[kOffset_ + kDataSize_]);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kOffset_ + kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, decrypted_[i]) << "i == " << i;
//  for (uint32_t i = 0; i != kDataSize_; ++i)
//    ASSERT_EQ(original_[i], decrypted_[kOffset_ + i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(
    FileSmallerThanMinFileSize, BasicOffsetTest,
    testing::Values(std::make_pair(40, 0), std::make_pair(40, 50), std::make_pair(1024, 0),
                    std::make_pair(3 * kMinChunkSize - 24, 23),
                    std::make_pair(3 * kMinChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(
    FileSmallerThanOneChunk, BasicOffsetTest,
    testing::Values(std::make_pair(3 * kMinChunkSize, 0), std::make_pair(3 * kMinChunkSize - 1, 1),
                    std::make_pair(3 * kMinChunkSize - 1, 1024),
                    std::make_pair(kDefaultChunkSize - 23, 22),
                    std::make_pair(kDefaultChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(
    FileSmallerThanThreeNormalChunks, BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 2 * kDefaultChunkSize - 1), std::make_pair(1, 2 * kDefaultChunkSize),
        std::make_pair(1, 3 * kDefaultChunkSize - 2), std::make_pair(kDefaultChunkSize, 0),
        std::make_pair(kDefaultChunkSize - 1, 1), std::make_pair(kDefaultChunkSize - 1, 1024),
        std::make_pair(kDefaultChunkSize, kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize, kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, 0), std::make_pair(2 * kDefaultChunkSize - 1, 1),
        std::make_pair(2 * kDefaultChunkSize, 0),
        std::make_pair(2 * kDefaultChunkSize - 1, kDefaultChunkSize),
        std::make_pair(3 * kDefaultChunkSize - 23, 22),
        std::make_pair(3 * kDefaultChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(
    FileGreaterThanThreeNormalChunks,  // or equal to
    BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 3 * kDefaultChunkSize - 1), std::make_pair(1, 3 * kDefaultChunkSize),
        std::make_pair(1, 3 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1, 2 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1, 2 * kDefaultChunkSize + 2),
        std::make_pair(kDefaultChunkSize - 1, 2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(kDefaultChunkSize - 1, 2 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1, 2 * kDefaultChunkSize + kMinChunkSize + 2),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize + 2),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize + kMinChunkSize + 1)));

INSTANTIATE_TEST_CASE_P(
    FileGreaterThanTenNormalChunks,  // or equal to
    BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 10 * kDefaultChunkSize - 1), std::make_pair(1, 10 * kDefaultChunkSize),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(10 * kDefaultChunkSize - 1, 0),
        std::make_pair(10 * kDefaultChunkSize - 1, 1),
        std::make_pair(10 * kDefaultChunkSize - 1, 2), std::make_pair(10 * kDefaultChunkSize, 0),
        std::make_pair(10 * kDefaultChunkSize, 1)));

INSTANTIATE_TEST_CASE_P(
    LargeFile, BasicOffsetTest,
    testing::Values(std::make_pair(1, 50 * kDefaultChunkSize),
                    std::make_pair(10 * kDefaultChunkSize, 50 * kDefaultChunkSize),
                    std::make_pair(50 * kDefaultChunkSize + kMinChunkSize, 1)));

class EncryptTest : public EncryptTestBase, public testing::TestWithParam<uint32_t> {
 public:
  EncryptTest()
      : EncryptTestBase((RandomUint32() % (std::max(std::thread::hardware_concurrency(), 2U))) + 1),
        kDataSize_(GetParam()) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kDataSize_]);
  }

 protected:
  virtual void SetUp() override {
    std::string content(RandomString(kDataSize_));
    std::copy(content.data(), content.data() + kDataSize_, original_.get());
    memset(decrypted_.get(), 1, kDataSize_);
  }
  const uint32_t kDataSize_;
};

class SingleBytesTest : public EncryptTest {};

TEST_P(SingleBytesTest, BEH_WriteInOrder) {
  for (uint32_t i = 0; i < kDataSize_; ++i)
    EXPECT_TRUE(self_encryptor_->Write(&original_[i], 1, i));
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_.reset(new SelfEncryptor(data_map_, local_store_, nullptr, num_procs_));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

TEST_P(SingleBytesTest, BEH_WriteAlternatingBytes) {
  for (uint32_t i = 0; i < kDataSize_; i += 2)
    EXPECT_TRUE(self_encryptor_->Write(&original_[i], 1, i));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i) {
    if (i % 2 == 0)
      ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
    else
      ASSERT_EQ(0, decrypted_[i]) << "i == " << i;
  }

  for (uint32_t i = 1; i < kDataSize_; i += 2)
    EXPECT_TRUE(self_encryptor_->Write(&original_[i], 1, i));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_.reset(new SelfEncryptor(data_map_, local_store_, nullptr, num_procs_));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(
    Writing, SingleBytesTest,
    testing::Values(2, kMinChunkSize - 1, kMinChunkSize, kMinChunkSize + 1, 3 * kMinChunkSize - 1,
                    3 * kMinChunkSize, 3 * kMinChunkSize + 1));

class SmallSingleBytesTest : public EncryptTest {};

TEST_P(SmallSingleBytesTest, BEH_WriteRandomOrder) {
  std::vector<int> indices(kDataSize_);
  for (uint32_t i = 0; i < kDataSize_; ++i)
    indices[i] = i;
  srand(RandomUint32());
  std::random_shuffle(indices.begin(), indices.end());

  for (uint32_t i = 0; i < kDataSize_; ++i)
    EXPECT_TRUE(self_encryptor_->Write(&original_[indices[i]], 1, indices[i]));

  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));

  for (uint32_t i = 0; i != kDataSize_; ++i)
    EXPECT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);

  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_.reset(new SelfEncryptor(data_map_, local_store_, nullptr, num_procs_));
  memset(decrypted_.get(), 1, kDataSize_);

  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(
    Writing, SmallSingleBytesTest,
    testing::Values(2, kMinChunkSize - 1, kMinChunkSize, kMinChunkSize + 1, 3 * kMinChunkSize - 1,
                    3 * kMinChunkSize, 3 * kMinChunkSize + 1));

class InProcessTest : public EncryptTest {};

TEST_P(InProcessTest, BEH_ReadInOrder) {
  uint32_t current_write_position(0), current_write_size(0);
  uint32_t current_read_position(0), current_read_size(0);
  while (current_read_position != kDataSize_) {
    current_write_size = std::min(kDefaultChunkSize, kDataSize_ - current_write_position);
    EXPECT_TRUE(self_encryptor_->Write(&original_[current_write_position], current_write_size,
                                       current_write_position));
    while (current_read_position != current_write_position) {
      assert(kDefaultChunkSize > 2);
      current_read_size = std::min(current_write_position - current_read_position,
                                   (RandomUint32() % (kDefaultChunkSize / 3)));
      EXPECT_TRUE(self_encryptor_->Read(&decrypted_[current_read_position], current_read_size,
                                        current_read_position));
      for (uint32_t i = current_read_position; i < current_read_position + current_read_size; ++i)
        ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
      current_read_position += current_read_size;
    }
    current_write_position += current_write_size;
  }

  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(
    Reading, InProcessTest,
    testing::Values(1, kMinChunkSize - 1, kMinChunkSize, kMinChunkSize + 1, 3 * kMinChunkSize - 1,
                    3 * kMinChunkSize, 3 * kMinChunkSize + 1, kDefaultChunkSize - 1,
                    kDefaultChunkSize, kDefaultChunkSize + 1, 3 * kDefaultChunkSize - 1,
                    3 * kDefaultChunkSize, 3 * kDefaultChunkSize + 1,
                    g_num_procs * 3 * kDefaultChunkSize - 1, g_num_procs * 3 * kDefaultChunkSize,
                    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize - 1,
                    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize,
                    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize + 1));

class BasicTest : public EncryptTestBase, public testing::Test {
 public:
  BasicTest()
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

TEST_F(BasicTest, BEH_NewRead) {
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));

  uint32_t read_position(0), index(0);
  const uint32_t kReadSize(4096);
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize, read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // read next small part straight from cache
  read_position += kReadSize;
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize, read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // try to read from end of cache, but request more data than remains
  // will result in cache being refreshed
  index = read_position += (kDefaultChunkSize * 8 - 1000);
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize, read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // try to read from near start of file, no longer in cache
  index = read_position = 5;
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize, read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // use file smaller than the cache size
  DataMapPtr data_map2(new DataMap);
  const uint32_t kDataSize2(kDefaultChunkSize * 5);
  std::string content2(RandomString(kDataSize2));
  boost::scoped_array<char> original2(new char[kDataSize2]);
  std::copy(content2.data(), content2.data() + kDataSize2, original2.get());
  {
    SelfEncryptor self_encryptor(data_map2, local_store_, nullptr, num_procs_);
    EXPECT_TRUE(self_encryptor.Write(original2.get(), kDataSize2, 0));
  }

  // try to read the entire file, will not cache.
  SelfEncryptor self_encryptor(data_map2, local_store_, nullptr, num_procs_);
  boost::scoped_array<char> decrypted2(new char[kDataSize2]);
  memset(decrypted2.get(), 1, kDataSize2);
  EXPECT_TRUE(self_encryptor.Read(decrypted2.get(), kDataSize2, 0));
  for (uint32_t i(0); i != kDataSize2; ++i)
    ASSERT_EQ(original2[i], decrypted2[i]) << "difference at " << i;

  // same small file, many small reads, will cache and read from.
  for (int a(0); a != 10; ++a) {
    EXPECT_TRUE(self_encryptor.Read(decrypted2.get(), 4096, (4096 * a)));
    for (uint32_t i(0); i != kReadSize; ++i) {
      ASSERT_EQ(original2[i + (kReadSize * a)], decrypted2[i]) << "difference at " << i;
    }
  }
}

TEST_F(BasicTest, BEH_WriteRandomSizeRandomPosition) {
  //  create string for input, break into random sized pieces
  //  then write in random order
  std::vector<std::pair<uint64_t, std::string>> broken_data;
  std::string extra("amended");

  uint32_t i(0);
  while (i < kDataSize_) {
    uint32_t size;
    if (kDataSize_ - i < (4096 * 5))
      size = kDataSize_ - i;
    else
      size = RandomUint32() % (4096 * 5);
    std::pair<uint64_t, std::string> piece(i, content_.substr(i, size));
    broken_data.push_back(piece);
    i += size;
  }

  uint64_t last_piece((*broken_data.rbegin()).first);
  srand(RandomUint32());
  std::random_shuffle(broken_data.begin(), broken_data.end());
  auto overlap_itr(broken_data.rbegin());
  if ((*overlap_itr).first == last_piece)
    ++overlap_itr;
  std::pair<uint64_t, std::string> post_overlap((*overlap_itr).first,
                                                ((*overlap_itr).second + extra));
  uint32_t post_position(
      static_cast<uint32_t>((*overlap_itr).first + (*overlap_itr).second.size()));

  uint32_t wtotal(0);
  for (auto& elem : broken_data) {
    EXPECT_TRUE(self_encryptor_->Write((elem).second.data(),
                                       static_cast<uint32_t>((elem).second.size()), (elem).first));
    wtotal += static_cast<uint32_t>(elem.second.size());
  }
  EXPECT_EQ(wtotal, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of " << kDataSize_;
  }
  memset(decrypted_.get(), 1, kDataSize_);
  content_.replace(post_position, 7, extra);
  std::copy(content_.data(), content_.data() + kDataSize_, original_.get());
  EXPECT_TRUE(self_encryptor_->Write(post_overlap.second.data(),
                                     static_cast<uint32_t>(post_overlap.second.size()),
                                     post_overlap.first));
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of " << kDataSize_;
  }
  self_encryptor_->Flush();

  SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
  EXPECT_EQ(kDataSize_, TotalSize(self_encryptor.data_map()));
  EXPECT_TRUE(self_encryptor.data_map()->content.empty());
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor.Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of " << kDataSize_;
  }
}

TEST_F(BasicTest, FUNC_RandomSizedOutOfSequenceWritesWithGapsAndOverlaps) {
  const size_t kParts(20);
  ASSERT_GE(kDataSize_ / kDefaultChunkSize, kParts);
  std::array<std::string, kParts> string_array;
  std::array<uint32_t, kParts> index_array;
  uint32_t total_size(0);

  // Grab randomly-sized pieces of random data at random offsets and shuffle.
  for (uint32_t i = 0; i != kParts; ++i) {
    uint32_t offset(RandomUint32() % (kDataSize_ - kDefaultChunkSize - 2));
    uint32_t size(RandomUint32() % kDefaultChunkSize + 1);
    string_array[i].assign(original_.get() + offset, size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());

  // Clear original_ ready to take modified input data.
  memset(original_.get(), 0, kDataSize_);

  // Write the pieces.  Positions could yield overlaps or gaps.
  for (size_t i(0); i != kParts; ++i) {
    uint32_t piece_size(static_cast<uint32_t>(string_array[index_array[i]].size()));
    uint64_t piece_position(index_array[i] * piece_size);
    total_size = std::max(total_size, static_cast<uint32_t>(piece_position + piece_size));
    EXPECT_TRUE(
        self_encryptor_->Write(string_array[index_array[i]].data(), piece_size, piece_position));

    ASSERT_GE(kDataSize_, total_size);
    EXPECT_EQ(total_size, self_encryptor_->size());
    memcpy(original_.get() + piece_position, string_array[index_array[i]].data(), piece_size);

    decrypted_.reset(new char[total_size]);
    memset(decrypted_.get(), 1, total_size);
    EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), total_size, 0));
    for (uint32_t j(0); j != total_size; ++j) {
      ASSERT_EQ(original_[j], decrypted_[j]) << "difference at " << j << " of " << total_size;
    }
    EXPECT_EQ(total_size, self_encryptor_->size());
  }

  // Read back and check while in process.
  decrypted_.reset(new char[total_size]);
  memset(decrypted_.get(), 1, total_size);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), total_size, 0));
  for (uint32_t i(0); i != total_size; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of " << total_size;
  }
  EXPECT_EQ(total_size, self_encryptor_->size());

  // Read back and check post processing.
  self_encryptor_->Flush();
  EXPECT_EQ(total_size, self_encryptor_->size());
  memset(decrypted_.get(), 1, total_size);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), total_size, 0));
  for (uint32_t i(0); i != total_size; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of " << total_size;
  }
}

TEST_F(BasicTest, BEH_WriteLongAndShort65536SegmentsReadThenRewrite) {
  size_t count(0);
  size_t max_length = kDefaultChunkSize * 3 + kDefaultChunkSize / 3;
  const size_t parts(50), size(65536);
  std::array<std::string, parts> original;

  for (size_t i = 0; i != parts; ++i) {
    if (i % 5 == 0)
      original[i] = RandomString(max_length);
    else
      original[i] = RandomString(size);
  }
  for (size_t i = 0; i != parts; ++i) {
    EXPECT_TRUE(self_encryptor_->Write(original[i].c_str(),
                                       static_cast<uint32_t>(original[i].size()), count));
    count += original[i].size();
  }
  self_encryptor_->Flush();

  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    // Check data_map values again after destruction...
    //    EXPECT_EQ(44, self_encryptor.data_map()->chunks.size());
    EXPECT_EQ(size * 40 + max_length * 10, TotalSize(self_encryptor.data_map()));
    EXPECT_EQ(0, self_encryptor.data_map()->content.size());

    std::array<std::string, parts> recovered;
    for (size_t i = 0; i != parts; ++i) {
      if (i % 5 == 0)
        recovered[i].resize(max_length);
      else
        recovered[i].resize(size);
    }
    count = 0;
    for (size_t i = 0; i != parts; ++i) {
      EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered[i].data()),
                                      static_cast<uint32_t>(recovered[i].size()), count));
      EXPECT_EQ(original[i], recovered[i]);
      count += original[i].size();
    }
  }
  {
    // rewrite
    size_t max_length = kDefaultChunkSize * 3 + 256;
    const size_t parts(70), size(4096);
    std::array<std::string, parts> overwrite, recovered;

    for (size_t i = 0; i != parts; ++i) {
      if (i % 5 == 0) {
        overwrite[i] = RandomString(max_length);
        recovered[i].resize(max_length);
      } else {
        overwrite[i] = RandomString(size);
        recovered[i].resize(size);
      }
    }
    {
      SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
      count = 0;
      for (size_t i = 0; i != parts; ++i) {
        EXPECT_TRUE(self_encryptor.Write(overwrite[i].c_str(),
                                         static_cast<uint32_t>(overwrite[i].size()), count));
        count += overwrite[i].size();
      }
    }
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    count = 0;
    for (size_t i = 0; i != parts; ++i) {
      EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered[i].data()),
                                      static_cast<uint32_t>(recovered[i].size()), count));
      size_t overwrite_size(overwrite[i].size());
      for (size_t j = 0; j != overwrite_size; ++j)
        ASSERT_EQ(overwrite[i][j], recovered[i][j]) << "Failed on string " << i << " at position "
                                                    << j;
      // EXPECT_EQ(overwrite[i], recovered[i]);
      count += overwrite[i].size();
    }
  }
}

TEST_F(BasicTest, BEH_4096ByteOutOfSequenceWritesReadsAndRewrites) {
  // 10 chunks, (1024*256*10-4096)...
  // 639, 4096 byte parts...
  const size_t kSize(4096), kParts((10 * kDefaultChunkSize / kSize) - 1), kGapIndex(30);
  std::array<std::string, kParts> string_array;
  std::array<size_t, kParts> index_array;
  std::string compare(kParts * kSize, 0);
  for (size_t i = 0; i != kParts; ++i) {
    string_array[i] = RandomString(kSize);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  while (index_array[kGapIndex] == kParts - 1)
    std::random_shuffle(index_array.begin(), index_array.end());
  std::string::iterator it(compare.begin());

  for (size_t i = 0; i != kGapIndex; ++i) {
    EXPECT_TRUE(
        self_encryptor_->Write(string_array[index_array[i]].data(), kSize, index_array[i] * kSize));
    compare.replace(it + index_array[i] * kSize, it + index_array[i] * kSize + kSize,
                    string_array[index_array[i]].data(), kSize);
  }
  for (size_t i = kGapIndex + 1; i != kParts; ++i) {
    EXPECT_TRUE(
        self_encryptor_->Write(string_array[index_array[i]].data(), kSize, index_array[i] * kSize));
    compare.replace(it + index_array[i] * kSize, it + index_array[i] * kSize + kSize,
                    string_array[index_array[i]].data(), kSize);
  }
  // write to the gap...
  EXPECT_TRUE(self_encryptor_->Write(string_array[index_array[kGapIndex]].data(), kSize,
                                     index_array[kGapIndex] * kSize + 1025));
  compare.replace(it + index_array[kGapIndex] * kSize + 1025,
                  it + index_array[kGapIndex] * kSize + 1025 + kSize,
                  string_array[index_array[kGapIndex]].data(), kSize);
  // Unknown number of chunks and data map size...
  // No content yet...
  EXPECT_TRUE(self_encryptor_->data_map()->content.empty());
  self_encryptor_->Flush();

  SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, self_encryptor.data_map()->chunks.size());
  EXPECT_EQ(kParts * kSize, TotalSize(self_encryptor.data_map()));
  EXPECT_TRUE(self_encryptor.data_map()->content.empty());

  std::string written;
  written.resize(kSize);
  for (size_t i = 0; i != kParts; ++i) {
    self_encryptor.Read(const_cast<char*>(written.c_str()), kSize, i * kSize);
    EXPECT_EQ(written, compare.substr(i * kSize, kSize));
  }

  for (size_t i = 0; i != kParts; ++i) {
    const uint32_t kOffset(RandomUint32() % string_array[i].size());
    if (i % 20 == 0) {
      self_encryptor.Read(const_cast<char*>(written.c_str()), kSize, i * kSize);
      EXPECT_EQ(written, compare.substr(i * kSize, kSize));
      if (i * kSize >= kOffset) {
        self_encryptor.Write(string_array[i].data(), static_cast<uint32_t>(string_array[i].size()),
                             i * kSize - kOffset);
        compare.replace(it + i * kSize - kOffset, it + i * kSize - kOffset + string_array[i].size(),
                        string_array[i].data(), string_array[i].size());
      } else {
        self_encryptor.Write(string_array[i].data(), static_cast<uint32_t>(string_array[i].size()),
                             i * kSize + kOffset);
        compare.replace(it + i * kSize + kOffset, it + i * kSize + kOffset + string_array[i].size(),
                        string_array[i].data(), string_array[i].size());
      }
    } else if (i % 10 == 0) {
      self_encryptor.Write(string_array[i].data(), static_cast<uint32_t>(string_array[i].size()),
                           i * kSize + kOffset);
      compare.replace(it + i * kSize + kOffset, it + i * kSize + kOffset + string_array[i].size(),
                      string_array[i].data(), string_array[i].size());
      self_encryptor.Read(const_cast<char*>(written.c_str()), kSize, i * kSize);
      EXPECT_EQ(written, compare.substr(i * kSize, kSize));
    } else {
      if (i % 2 == 0) {
        self_encryptor.Write(string_array[i].data(), static_cast<uint32_t>(string_array[i].size()),
                             i * kSize);
        compare.replace(it + i * kSize, it + i * kSize + string_array[i].size(),
                        string_array[i].data(), string_array[i].size());
        self_encryptor.Read(const_cast<char*>(written.c_str()), kSize, i * kSize);
        EXPECT_EQ(written, compare.substr(i * kSize, kSize));
      } else {
        self_encryptor.Read(const_cast<char*>(written.c_str()), kSize, i * kSize);
        EXPECT_EQ(written, compare.substr(i * kSize, kSize));
        self_encryptor.Write(string_array[i].data(), static_cast<uint32_t>(string_array[i].size()),
                             i * kSize);
        compare.replace(it + i * kSize, it + i * kSize + string_array[i].size(),
                        string_array[i].data(), string_array[i].size());
      }
    }
  }
}

TEST_F(BasicTest, BEH_WriteSmallThenAdd) {
  // Write and read small amount
  const uint32_t kSize = (3 * kMinChunkSize) - 2;
  std::string original(RandomString(kSize)), decrypted(kSize, 1);
  EXPECT_EQ(0, self_encryptor_->size());
  EXPECT_TRUE(self_encryptor_->Write(original.data(), kSize, 0));
  EXPECT_EQ(kSize, self_encryptor_->size());
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize, self_encryptor_->size());
  EXPECT_EQ(kSize, TotalSize(data_map_));
  EXPECT_EQ(kSize, data_map_->content.size());
  decrypted.assign(decrypted.size(), 1);

  // Append a single char and read
  char data = 'a';
  EXPECT_TRUE(self_encryptor_->Write(&data, sizeof(data), kSize));
  EXPECT_EQ(kSize + 1, self_encryptor_->size());
  original.append(1, data);
  decrypted.resize(kSize + 1);
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 1, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 1, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 1, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 1, self_encryptor_->size());
  EXPECT_EQ(kSize + 1, TotalSize(data_map_));
  EXPECT_EQ(kSize + 1, data_map_->content.size());

  // Append another single char and read
  EXPECT_TRUE(self_encryptor_->Write(&data, sizeof(data), kSize + 1));
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  original.append(1, data);
  decrypted.resize(kSize + 2);
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  EXPECT_EQ(kSize + 2, TotalSize(data_map_));
  EXPECT_TRUE(data_map_->content.empty());

  // "Right-shift" the data by 1 byte
  EXPECT_TRUE(self_encryptor_->Write(const_cast<char*>(original.data()), kSize + 1, 1));
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  original.replace(original.begin() + 1, original.end(), original.data(), kSize + 1);
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2, self_encryptor_->size());
  EXPECT_EQ(kSize + 2, TotalSize(data_map_));
  EXPECT_TRUE(data_map_->content.empty());

  // Append large block and read
  const uint32_t kNewSize(3 * kDefaultChunkSize);
  std::string new_content(RandomString(kNewSize));
  EXPECT_TRUE(self_encryptor_->Write(const_cast<char*>(new_content.data()), kNewSize, kSize + 2));
  EXPECT_EQ(kSize + 2 + kNewSize, self_encryptor_->size());
  original += new_content;
  decrypted.resize(kSize + 2 + kNewSize);
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2 + kNewSize, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2 + kNewSize, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2 + kNewSize, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2 + kNewSize, self_encryptor_->size());
  EXPECT_EQ(kSize + 2 + kNewSize, TotalSize(data_map_));
  EXPECT_TRUE(data_map_->content.empty());

  // Append a single char and read
  EXPECT_TRUE(self_encryptor_->Write(&data, sizeof(data), kSize + 2 + kNewSize));
  EXPECT_EQ(kSize + 2 + kNewSize + 1, self_encryptor_->size());
  original.append(1, data);
  decrypted.resize(kSize + 2 + kNewSize + 1);
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(
      self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2 + kNewSize + 1, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2 + kNewSize + 1, self_encryptor_->size());
  self_encryptor_->Flush();
  decrypted.assign(decrypted.size(), 1);
  EXPECT_TRUE(
      self_encryptor_->Read(const_cast<char*>(decrypted.data()), kSize + 2 + kNewSize + 1, 0));
  EXPECT_EQ(original, decrypted);
  EXPECT_EQ(kSize + 2 + kNewSize + 1, self_encryptor_->size());
  EXPECT_EQ(kSize + 2 + kNewSize + 1, TotalSize(data_map_));
  EXPECT_TRUE(data_map_->content.empty());
}

TEST_F(BasicTest, BEH_3SmallChunkRewrite) {
  uint32_t size = 153855 * 2 + 153857;
  std::string content(RandomString(size)), recovered(size, 'V');

  EXPECT_TRUE(self_encryptor_->Write(content.data(), size, 0));
  self_encryptor_->Flush();

  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    ASSERT_EQ(TotalSize(data_map_), size);
    EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered.data()), size, 0));
    ASSERT_EQ(content, recovered);
  }
  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    content.erase(content.begin() + 300, content.begin() + 350);
    EXPECT_TRUE(self_encryptor.Write(content.data(), static_cast<uint32_t>(content.size()), 0));
    recovered.assign(size - 50, 'W');
    EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered.data()), size - 50, 0));
    ASSERT_EQ(content, recovered);
    self_encryptor.Flush();
  }
  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    recovered.assign(size - 50, 'X');
    EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered.data()), size - 50, 0));
    ASSERT_EQ(content, recovered);
  }
}

TEST_F(BasicTest, BEH_nKFile) {
  std::string original, temp, recovered;
  for (uint32_t i = 0; i != 15; ++i) {
    for (uint32_t j = 0; j != 100; ++j)
      temp += "a";
    temp += "\r\n";
    original += temp;
    temp = "";
  }
  EXPECT_TRUE(self_encryptor_->Write(original.data(), static_cast<uint32_t>(original.size()), 0));
  EXPECT_TRUE(self_encryptor_->Flush());
  uint32_t start(0), remove(0), add(0), read(0);
  for (uint32_t i = 0; i != 10; ++i) {
    start = RandomUint32() % (original.size() - 150);
    remove = RandomUint32() % 150;
    original = original.erase(start, remove);
  }
  for (uint32_t i = 0; i != 3; ++i) {
    start = RandomUint32() % (original.size() - 1);
    add = RandomUint32() % 150;
    original = original.insert(start, add, ' ');
  }
  EXPECT_TRUE(self_encryptor_->Write(original.data(), static_cast<uint32_t>(original.size()), 0));
  EXPECT_TRUE(self_encryptor_->Truncate(original.size()));
  EXPECT_TRUE(self_encryptor_->Flush());
  start = RandomUint32() % original.size();
  read = static_cast<uint32_t>(original.size()) - start;
  recovered.resize(read);
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(recovered.data()), read, start));
}

TEST_F(BasicTest, BEH_nKFileAppend) {
  std::string original(21485, 'a'), recovered;
  EXPECT_TRUE(self_encryptor_->Write(original.data(), static_cast<uint32_t>(original.size()), 0));
  EXPECT_TRUE(self_encryptor_->Flush());
  self_encryptor_.reset();
  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    EXPECT_TRUE(self_encryptor.Truncate(original.size() + 1));
    EXPECT_TRUE(self_encryptor.Flush());
    original += "a";
    EXPECT_TRUE(self_encryptor.Write(original.data(), static_cast<uint32_t>(original.size()), 0));
    uint32_t read_size(21485 + 1);
    recovered.resize(read_size);
    EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered.data()), read_size, 0));
  }
}

TEST_F(BasicTest, BEH_DeleteStoredChunkFromDisk) {
  boost::system::error_code error_code;
  uint32_t size = 5 * 256 * 1024 + 3;
  std::string original(RandomString(size)), recovered(size, 0);

  EXPECT_TRUE(self_encryptor_->Write(original.data(), static_cast<uint32_t>(original.size()), 0));
  EXPECT_TRUE(self_encryptor_->Flush());
  EXPECT_TRUE(self_encryptor_->Read(const_cast<char*>(recovered.data()),
                                    static_cast<uint32_t>(recovered.size()), 0));

  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(recovered.data()),
                                    static_cast<uint32_t>(recovered.size()), 0));
  }

  local_store_.Delete(data_map_->chunks[0].hash);

  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    EXPECT_FALSE(self_encryptor.Read(const_cast<char*>(recovered.data()),
                                     static_cast<uint32_t>(recovered.size()), 0));
  }
}

TEST_F(BasicTest, BEH_ManualCheckWrite) {
  uint32_t chunk_size(kDefaultChunkSize);
  uint32_t num_chunks(10);
  boost::scoped_array<char> extra(new char[5]);
  for (unsigned char i = 0; i != 5; ++i)
    extra[i] = 49 + i;
  uint32_t extra_size(5);
  uint32_t final_chunk_size(chunk_size + extra_size);
  uint32_t file_size((chunk_size * num_chunks) + extra_size);
  boost::shared_array<char> pre_enc_file(new char[file_size]);
  boost::shared_array<byte> pre_enc_chunk(new byte[chunk_size]);
  boost::shared_array<byte> final_chunk(new byte[final_chunk_size]);
  boost::shared_array<byte> prehash(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> prehash_final(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res_final(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res_C0(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res_C1(new byte[crypto::SHA512::DIGESTSIZE]);

  for (size_t i = 0; i < chunk_size; ++i)
    pre_enc_chunk[i] = 'a';

  for (uint32_t i = 0; i < file_size - extra_size; ++i)
    pre_enc_file[i] = 'a';

  for (uint32_t i = file_size - extra_size; i < file_size; ++i)
    pre_enc_file[i] = extra[i - (file_size - extra_size)];

  // calculate specifics for final chunk
  for (size_t i = 0; i < chunk_size; ++i)
    final_chunk[i] = 'a';
  for (size_t i = chunk_size; i < final_chunk_size; ++i)
    final_chunk[i] = extra[i - chunk_size];

  EXPECT_TRUE(self_encryptor_->Write(pre_enc_file.get(), file_size, 0));
  self_encryptor_->Flush();

  // get pre-encryption hashes
  CryptoPP::SHA512().CalculateDigest(prehash.get(), pre_enc_chunk.get(), chunk_size);
  CryptoPP::SHA512().CalculateDigest(prehash_final.get(), final_chunk.get(), final_chunk_size);

  // calculate result of enc for chunks 2->last-1
  GetEncryptionResult(&enc_res, prehash, prehash, prehash, pre_enc_chunk, chunk_size);
  // calculate result of enc for final chunk
  GetEncryptionResult(&enc_res_final, prehash, prehash, prehash_final, final_chunk,
                      final_chunk_size);
  // calculate result of enc for chunk 0 & 1
  GetEncryptionResult(&enc_res_C0, prehash_final, prehash, prehash, pre_enc_chunk, chunk_size);
  GetEncryptionResult(&enc_res_C1, prehash, prehash_final, prehash, pre_enc_chunk, chunk_size);

  // Check results
  EXPECT_EQ(num_chunks, self_encryptor_->data_map()->chunks.size());
  EXPECT_TRUE(self_encryptor_->data_map()->content.empty());
  EXPECT_EQ(file_size, TotalSize(self_encryptor_->data_map()));
  EXPECT_EQ(file_size, self_encryptor_->size());

  // Prehash checks
  for (uint32_t i = 0; i != num_chunks - 1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
      ASSERT_EQ(prehash[j], self_encryptor_->data_map()->chunks[i].pre_hash[j])
          << "failed at chunk " << i << " pre hash " << j;
    }
  }
  for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(prehash_final[j], self_encryptor_->data_map()->chunks[num_chunks - 1].pre_hash[j])
        << "failed at final chunk pre hash " << j;
  }

  // enc hash checks
  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    ASSERT_EQ(enc_res_C0[i], static_cast<byte>(self_encryptor_->data_map()->chunks[0].hash[i]))
        << "failed at chunk 0 post hash : " << i;
    ASSERT_EQ(enc_res_C1[i], static_cast<byte>(self_encryptor_->data_map()->chunks[1].hash[i]))
        << "failed at chunk 1 post hash : " << i;
    ASSERT_EQ(enc_res_final[i],
              static_cast<byte>(self_encryptor_->data_map()->chunks[num_chunks - 1].hash[i]))
        << "failed at final chunk post hash : " << i;
  }

  for (uint32_t i = 2; i != num_chunks - 1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
      ASSERT_EQ(enc_res[j], static_cast<byte>(self_encryptor_->data_map()->chunks[i].hash[j]))
          << "failed at chunk " << i << " post hash : " << j;
    }
  }
}

TEST_F(BasicTest, BEH_TruncateIncreaseScenario1) {
  const uint32_t kTestDataSize(kDefaultChunkSize * 12);
  const uint32_t kIncrease((RandomUint32() % 4000) + 95);
  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    boost::scoped_array<char> plain_data(new char[kTestDataSize]);
    memset(plain_data.get(), 0, kTestDataSize);

    const uint32_t kWriteLength(4096);
    for (uint32_t i = 0; i < kTestDataSize; i += kWriteLength) {
      std::string plain_text(RandomString(kWriteLength));
      memcpy(plain_data.get() + i, plain_text.c_str(), kWriteLength);
      EXPECT_TRUE(self_encryptor.Write(plain_text.c_str(), kWriteLength, i));
    }

    EXPECT_TRUE(self_encryptor.Truncate(kTestDataSize + kIncrease));

    const uint32_t kReadLength((RandomUint32() % (kIncrease - 100)) + 100);
    boost::scoped_array<char> answer(new char[kReadLength]);
    memset(answer.get(), 1, kReadLength);
    EXPECT_TRUE(self_encryptor.Read(answer.get(), kReadLength, 0));
    EXPECT_EQ(kTestDataSize + kIncrease, self_encryptor.size());
    ASSERT_LE(kReadLength, self_encryptor.size());
    for (uint32_t i = 0; i < kReadLength; ++i) {
      if (i < kTestDataSize) {
        ASSERT_EQ(plain_data[i], answer[i]) << "not match " << i << " from " << kReadLength
                                            << " when total data is " << self_encryptor.size();
      } else {
        ASSERT_EQ(0, answer[i]) << "not match " << i << " from " << kReadLength
                                << " when total data is " << self_encryptor.size();
      }
    }
  }
  SelfEncryptor temp_self_encryptor(data_map_, local_store_, nullptr, num_procs_);
  EXPECT_EQ(kTestDataSize + kIncrease, temp_self_encryptor.size());
}

TEST_F(BasicTest, BEH_TruncateIncreaseScenario2) {
  const size_t kTestDataSize(kDefaultChunkSize * 40);
  {
    SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
    EXPECT_TRUE(self_encryptor.Truncate(100));
    EXPECT_EQ(100, self_encryptor.size());

    boost::scoped_array<char> plain_data(new char[kTestDataSize]);
    memset(plain_data.get(), 0, kTestDataSize);

    EXPECT_TRUE(self_encryptor.Truncate(kTestDataSize));

    uint32_t write_length(4096);
    uint32_t file_size(0);
    for (uint32_t i = 0; i < (kDefaultChunkSize * 3); i += write_length) {
      uint32_t write_position(i);
      std::string plain_text(RandomString(write_length));
      boost::scoped_array<char> content_data(new char[write_length]);
      for (uint32_t i = 0; i < write_length; ++i) {
        plain_data[i + write_position] = plain_text[i];
        content_data[i] = plain_text[i];
      }

      EXPECT_TRUE(self_encryptor.Write(content_data.get(), write_length, write_position));
      file_size = std::max(file_size, write_position + write_length);
    }

    EXPECT_EQ(kTestDataSize, self_encryptor.size());

    uint32_t read_position(0);
    uint32_t read_length(4096);
    boost::scoped_array<char> answer(new char[read_length]);
    EXPECT_TRUE(self_encryptor.Read(answer.get(), read_length, read_position));
    for (size_t i = 0; i < read_length; ++i)
      if ((i + read_position) < self_encryptor.size())
        ASSERT_EQ(plain_data[read_position + i], answer[i])
            << "not match " << i << " from " << read_position << " when total data is "
            << self_encryptor.size();
  }

  SelfEncryptor temp_self_encryptor(data_map_, local_store_, nullptr, num_procs_);
  EXPECT_EQ(kTestDataSize, temp_self_encryptor.size());
}

TEST_F(BasicTest, BEH_TruncateDecrease) {
  const size_t kTestDataSize(300);
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  // The initialization value of truncated data shall be filled here
  memset(plain_data.get(), 0, kTestDataSize);

  uint32_t write_position(0);
  uint32_t write_length(200);
  std::string plain_text(RandomString(write_length));
  boost::scoped_array<char> content_data(new char[write_length]);
  for (size_t i = 0; i < write_length; ++i) {
    plain_data[i + write_position] = plain_text[i];
    content_data[i] = plain_text[i];
  }

  EXPECT_TRUE(self_encryptor_->Write(content_data.get(), write_length, write_position));

  EXPECT_TRUE(self_encryptor_->Truncate(0));
  EXPECT_EQ(0, self_encryptor_->size());

  EXPECT_TRUE(self_encryptor_->Write(content_data.get(), write_length, write_position));

  uint32_t read_position(0);
  uint32_t read_length(200);
  boost::scoped_array<char> answer(new char[read_length]);
  EXPECT_TRUE(self_encryptor_->Read(answer.get(), read_length, read_position));
  for (size_t i = 0; i < read_length; ++i) {
    if ((i + read_position) < self_encryptor_->size())
      ASSERT_EQ(plain_data[read_position + i], answer[i]) << "not match " << i << " from "
                                                          << read_position << " when total data is "
                                                          << self_encryptor_->size();
  }
  self_encryptor_->Flush();
}

TEST_F(BasicTest, FUNC_RandomAccess) {
  uint32_t chunk_size(1024);
  std::vector<uint32_t> num_of_tries;
  std::vector<uint32_t> max_variation;
  max_variation.push_back(1024);
  max_variation.push_back(3072);
  max_variation.push_back(chunk_size);
  max_variation.push_back(3* chunk_size);
  max_variation.push_back(6* chunk_size);
  num_of_tries.push_back(5);
  num_of_tries.push_back(20);
  num_of_tries.push_back(50);
  num_of_tries.push_back(100);
  num_of_tries.push_back(200);

  {
    // the longest length of data is writing to position 6 * chunk_size with
    // a content length of 6 * chunk_size, make the total to be 12 * chunk_size
    const size_t kTestDataSize(chunk_size * 12);
    // In Process random write/read access
    boost::scoped_array<char> plain_data(new char[kTestDataSize]);
    // The initialization value of truncated data shall be filled here
    memset(plain_data.get(), 0, kTestDataSize);

    for (size_t i = 0; i < max_variation.size(); ++i) {
      size_t num_tries = num_of_tries[i];
      size_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        int op_code(RandomUint32() % 2);
        //        LOG(kInfo) << "op code: " << op_code;

        switch (op_code) {
          case 0:  // write
          {
            uint32_t write_position(RandomUint32() % variation);
            uint32_t write_length(RandomUint32() % variation);
            //              LOG(kInfo) << "write_position: " << write_position
            //                         << "\twrite_length: " << write_length;

            std::string plain_text(RandomString(write_length));
            boost::scoped_array<char> content_data(new char[write_length]);
            for (size_t i = 0; i < write_length; ++i) {
              plain_data[i + write_position] = plain_text[i];
              content_data[i] = plain_text[i];
            }

            EXPECT_TRUE(self_encryptor_->Write(content_data.get(), write_length, write_position));
            //              LOG(kInfo) << "current data size is:\t"
            //                         << self_encryptor_->size();
            break;
          }
          case 1:  // read
          {
            uint32_t read_position(RandomUint32() % variation);
            uint32_t read_length(RandomUint32() % variation);
            boost::scoped_array<char> answer(new char[read_length]);
            //              LOG(kInfo) << "read_position: " << read_position
            //                         << "\tread_length: " << read_length;

            // The read method shall accept a reading request that exceeds
            // the current data lenth of the encrypt stream.
            // It shall return part of the content or false if the starting
            // read position exceed the data size
            if (read_position < self_encryptor_->size()) {
              EXPECT_TRUE(self_encryptor_->Read(answer.get(), read_length, read_position));
              // A return value of num_of_bytes succeeded read is required
              for (size_t i = 0; i < read_length; ++i) {
                if ((i + read_position) < self_encryptor_->size())
                  ASSERT_EQ(plain_data[read_position + i], answer[i])
                      << "not match " << i << " from " << read_position << " when total data is "
                      << self_encryptor_->size();
              }
            } else {
              // Should expect a False when reading out-of-range
              EXPECT_TRUE(self_encryptor_->Read(answer.get(), read_length, read_position))
                  << " when trying to read " << read_length << " from " << read_position
                  << " when total data is " << self_encryptor_->size();
            }
            break;
          }
          default:
            break;
        }
      }
    }
    self_encryptor_->Flush();
  }

  {
    // Out Process random write/read access
    DataMapPtr data_map(new DataMap);
    for (size_t i = 0; i < max_variation.size(); ++i) {
      uint32_t num_tries = num_of_tries[i];
      uint32_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        const uint32_t kPosition(RandomUint32() % variation);
        const uint32_t kLength(RandomUint32() % variation);
        //        LOG(kInfo) << i << ", " << j << ":\taccessing at pos: " << kPosition
        //                   << "  \twith data length: " << kLength;
        std::string plain_text(RandomString(kLength));
        {
          SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
          EXPECT_TRUE(self_encryptor.Write(plain_text.data(), kLength, kPosition));
          std::string answer(kLength, 1);
          EXPECT_TRUE(self_encryptor.Read(const_cast<char*>(answer.data()), kLength, kPosition));
          ASSERT_EQ(plain_text, answer);
        }
        boost::scoped_array<char> answer(new char[kLength]);
        memset(answer.get(), 1, kLength);
        {
          SelfEncryptor self_encryptor(data_map_, local_store_, nullptr, num_procs_);
          EXPECT_TRUE(self_encryptor.Read(answer.get(), kLength, kPosition));
        }

        for (size_t k = 0; k < kLength; ++k)
          ASSERT_EQ(plain_text[k], answer[k]) << "not match " << k;
      }
    }
  }
  // The situation combining in-process and out-process access may need to
  // be considered
}

TEST_F(BasicTest, BEH_EncryptDecryptDataMap) {
  // TODO(Fraser#5#): 2012-01-05 - Test failure cases also.
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));
  EXPECT_TRUE(self_encryptor_->Flush());
  const Identity kParentId(RandomString(64)), kThisId(RandomString(64));

  asymm::CipherText encrypted_data_map = EncryptDataMap(kParentId, kThisId, data_map_);
  EXPECT_FALSE(encrypted_data_map.string().empty());

  DataMapPtr retrieved_data_map(new DataMap);

  EXPECT_NO_THROW(
      DecryptDataMap(kParentId, kThisId, encrypted_data_map.string(), retrieved_data_map));
  ASSERT_EQ(data_map_->chunks.size(), retrieved_data_map->chunks.size());
  auto original_itr(data_map_->chunks.begin()), retrieved_itr(retrieved_data_map->chunks.begin());
  std::string original_pre_hash(64, 0), retrieved_pre_hash(64, 0);
  for (; original_itr != data_map_->chunks.end(); ++original_itr, ++retrieved_itr) {
    ASSERT_EQ((*original_itr).hash, (*retrieved_itr).hash);
    memcpy(&original_pre_hash[0], &(*original_itr).pre_hash, 64);
    memcpy(&retrieved_pre_hash[0], &(*retrieved_itr).pre_hash, 64);
    ASSERT_EQ(original_pre_hash, retrieved_pre_hash);
    ASSERT_EQ((*original_itr).pre_hash_state, (*retrieved_itr).pre_hash_state);
    ASSERT_EQ((*original_itr).size, (*retrieved_itr).size);
  }
}

TEST_F(BasicTest, BEH_DifferentDataMapSameChunk) {
  DataMapPtr data_map_1(new DataMap);
  DataMapPtr data_map_2(new DataMap);

  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, nullptr, num_procs_);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, nullptr, num_procs_);
    self_encryptor_1.Write(original_.get(), 16 * 1024, 0);
    self_encryptor_2.Write(original_.get(), 16 * 1024, 0);
  }
  {
    boost::scoped_array<char> result_data;
    result_data.reset(new char[16 * 1024]);
    SelfEncryptor self_encryptor_2(data_map_2, local_store_, nullptr, num_procs_);
    self_encryptor_2.Read(result_data.get(), 16 * 1024, 0);
    for (uint32_t i = 0; i != 16 * 1024; ++i)
      ASSERT_EQ(original_[i], result_data[i]) << "i == " << i;
  }

  boost::scoped_array<char> temp_data(new char[500]);
  memset(temp_data.get(), 'b', 500);
  {
    SelfEncryptor self_encryptor_1(data_map_1, local_store_, nullptr, num_procs_);
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
