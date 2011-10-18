
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

#include <array>
#include <cstdlib>
#include <string>

#ifdef WIN32
#  pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#ifdef WIN32
#  pragma warning(pop)
#endif
#include "boost/scoped_array.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/omp.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"


namespace maidsafe {
namespace encrypt {
namespace test {

namespace {

typedef std::pair<uint32_t, uint32_t> SizeAndOffset;
const int g_num_procs(omp_get_num_procs());

uint64_t TotalSize(DataMapPtr data_map) {
  uint64_t size(data_map->chunks.empty() ? data_map->content.size() : 0);
  for (auto it(data_map->chunks.begin()); it != data_map->chunks.end(); ++it)
    size += (*it).size;
  return size;
}

void GetEncryptionResult(boost::shared_array<byte> *result,
                         boost::shared_array<byte> n1hash,
                         boost::shared_array<byte> n2hash,
                         boost::shared_array<byte> hash,
                         boost::shared_array<byte> chunk,
                         uint32_t chunk_size) {
  boost::scoped_array<byte>pad(new byte[(3 * crypto::SHA512::DIGESTSIZE) -
                                        crypto::AES256_KeySize -
                                        crypto::AES256_IVSize]);
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
            n2hash.get() + crypto::AES256_KeySize + crypto::AES256_IVSize,
            iv.get());

  CryptoPP::Gzip compress(new CryptoPP::MessageQueue(), 6);
  compress.Put2(chunk.get(), chunk_size, -1, true);
  uint32_t compressed_size = static_cast<uint32_t>(compress.MaxRetrievable());
  boost::shared_array<byte> comp_data(new byte[compressed_size]);
  compress.Get(comp_data.get(), compressed_size);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc(
      key.get(), crypto::AES256_KeySize, iv.get());
  enc.ProcessData(postenc.get(), comp_data.get(), compressed_size);

  for (size_t i = 0; i < compressed_size; ++i) {
    xor_res[i] =
        postenc[i] ^ pad[i % ((3 * crypto::SHA512::DIGESTSIZE) -
                              crypto::AES256_KeySize - crypto::AES256_IVSize)];
  }
  CryptoPP::SHA512().CalculateDigest(result->get(),
                                     xor_res.get(),
                                     compressed_size);
}

}  // unnamed namespace



class BasicOffsetTest : public EncryptTestBase,
                        public testing::TestWithParam<SizeAndOffset> {
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
      : EncryptTestBase(5),
        kDataSize_(GetParam().first),
        kOffset_(GetParam().second),
        test_file_size_(kMax) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kOffset_ + kDataSize_]);
    if (kOffset_ + kDataSize_ < kLarge)
      test_file_size_ = kLarge;
    if (kOffset_ + kDataSize_ < kMedium)
      test_file_size_ = kMedium;
    if (kOffset_ + kDataSize_ < kSmall)
      test_file_size_ = kSmall;
    if (kOffset_ + kDataSize_ < kVerySmall)
      test_file_size_ = kVerySmall;
    if (kOffset_ + kDataSize_ < kTiny)
      test_file_size_ = kTiny;
  }

 protected:
  virtual void SetUp() {
    std::string content(RandomString(kDataSize_));
    std::copy(content.data(), content.data() + kDataSize_, original_.get());
    memset(decrypted_.get(), 1, kDataSize_);
  }
  void TearDown() {}

  const uint32_t kDataSize_, kOffset_;
  TestFileSize test_file_size_;
};

TEST_P(BasicOffsetTest, BEH_EncryptDecrypt) {
  EXPECT_TRUE(self_encryptor_->Write(original_.get(), kDataSize_, kOffset_));

  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kOffset_+kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, decrypted_[i]) << "i == " << i;
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[kOffset_ + i]) << "i == " << i;

  decrypted_.reset(new char[kOffset_ + kDataSize_]);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, kOffset_));
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  self_encryptor_.reset(new SelfEncryptor(data_map_, chunk_store_));
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
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kOffset_+kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, decrypted_[i]) << "i == " << i;
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[kOffset_ + i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(FileSmallerThanMinFileSize, BasicOffsetTest,
                        testing::Values(
                            std::make_pair(40, 0),
                            std::make_pair(40, 50),
                            std::make_pair(1024, 0),
                            std::make_pair(3 * kMinChunkSize - 24, 23),
                            std::make_pair(3 * kMinChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(FileSmallerThanOneChunk, BasicOffsetTest,
                        testing::Values(
                            std::make_pair(3 * kMinChunkSize, 0),
                            std::make_pair(3 * kMinChunkSize - 1, 1),
                            std::make_pair(3 * kMinChunkSize - 1, 1024),
                            std::make_pair(kDefaultChunkSize - 23, 22),
                            std::make_pair(kDefaultChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(FileSmallerThanThreeNormalChunks,
    BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 2 * kDefaultChunkSize - 1),
        std::make_pair(1, 2 * kDefaultChunkSize),
        std::make_pair(1, 3 * kDefaultChunkSize - 2),
        std::make_pair(kDefaultChunkSize, 0),
        std::make_pair(kDefaultChunkSize - 1, 1),
        std::make_pair(kDefaultChunkSize - 1, 1024),
        std::make_pair(kDefaultChunkSize, kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize, kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, 0),
        std::make_pair(2 * kDefaultChunkSize - 1, 1),
        std::make_pair(2 * kDefaultChunkSize, 0),
        std::make_pair(2 * kDefaultChunkSize - 1, kDefaultChunkSize),
        std::make_pair(3 * kDefaultChunkSize - 23, 22),
        std::make_pair(3 * kDefaultChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(FileGreaterThanThreeNormalChunks,  // or equal to
    BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 3 * kDefaultChunkSize - 1),
        std::make_pair(1, 3 * kDefaultChunkSize),
        std::make_pair(1, 3 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + 2),
        std::make_pair(kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize + 2),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize - 1, 3 * kDefaultChunkSize + 2),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize, 2 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(kDefaultChunkSize, 3 * kDefaultChunkSize - 1),
        std::make_pair(kDefaultChunkSize, 3 * kDefaultChunkSize),
        std::make_pair(kDefaultChunkSize, 3 * kDefaultChunkSize + 1),
        std::make_pair(kDefaultChunkSize,
                       3 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(kDefaultChunkSize,
                       3 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(kDefaultChunkSize,
                       3 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, kDefaultChunkSize + 2),
        std::make_pair(2 * kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(2 * kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1,
                       2 * kDefaultChunkSize + kMinChunkSize + 2),
        std::make_pair(2 * kDefaultChunkSize - 1, 2 * kDefaultChunkSize),
        std::make_pair(2 * kDefaultChunkSize - 1, 2 * kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, 2 * kDefaultChunkSize + 2),
        std::make_pair(2 * kDefaultChunkSize, kDefaultChunkSize),
        std::make_pair(2 * kDefaultChunkSize, kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize,
                       kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(2 * kDefaultChunkSize,
                       kDefaultChunkSize + kMinChunkSize),
        std::make_pair(2 * kDefaultChunkSize,
                       kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize, 2 * kDefaultChunkSize - 1),
        std::make_pair(2 * kDefaultChunkSize, 2 * kDefaultChunkSize),
        std::make_pair(2 * kDefaultChunkSize, 2 * kDefaultChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(2 * kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(2 * kDefaultChunkSize,
                       2 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(2 * kDefaultChunkSize - 1, 8 * kDefaultChunkSize),
        std::make_pair(2 * kDefaultChunkSize, 8 * kDefaultChunkSize - 1)));

INSTANTIATE_TEST_CASE_P(FileGreaterThanTenNormalChunks,  // or equal to
    BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 10 * kDefaultChunkSize - 1),
        std::make_pair(1, 10 * kDefaultChunkSize),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize - 1),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize),
        std::make_pair(1, 10 * kDefaultChunkSize + kMinChunkSize + 1),
        std::make_pair(10 * kDefaultChunkSize - 1, 0),
        std::make_pair(10 * kDefaultChunkSize - 1, 1),
        std::make_pair(10 * kDefaultChunkSize - 1, 2),
        std::make_pair(10 * kDefaultChunkSize, 0),
        std::make_pair(10 * kDefaultChunkSize, 1),
        std::make_pair(10 * kDefaultChunkSize + kMinChunkSize - 1, 0),
        std::make_pair(10 * kDefaultChunkSize + kMinChunkSize - 1, 1),
        std::make_pair(10 * kDefaultChunkSize + kMinChunkSize, 0),
        std::make_pair(10 * kDefaultChunkSize + kMinChunkSize, 1)));

INSTANTIATE_TEST_CASE_P(LargeFile, BasicOffsetTest,
    testing::Values(
        std::make_pair(1, 50 * kDefaultChunkSize),
        std::make_pair(10 * kDefaultChunkSize, 50 * kDefaultChunkSize),
        std::make_pair(50 * kDefaultChunkSize + kMinChunkSize, 1)));



class EncryptTest : public EncryptTestBase,
                    public testing::TestWithParam<uint32_t> {
 public:
  EncryptTest() : EncryptTestBase(), kDataSize_(GetParam()) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kDataSize_]);
  }
 protected:
  virtual void SetUp() {
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

  self_encryptor_.reset(new SelfEncryptor(data_map_, chunk_store_));
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

  self_encryptor_.reset(new SelfEncryptor(data_map_, chunk_store_));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(Writing, SingleBytesTest,
    testing::Values(2,
                    kMinChunkSize - 1,
                    kMinChunkSize,
                    kMinChunkSize + 1,
                    3 * kMinChunkSize - 1,
                    3 * kMinChunkSize,
                    3 * kMinChunkSize + 1,
                    kDefaultChunkSize - 1,
                    kDefaultChunkSize,
                    kDefaultChunkSize + 1,
                    3 * kDefaultChunkSize - 1,
                    3 * kDefaultChunkSize,
                    3 * kDefaultChunkSize + 1,
                    4 * kDefaultChunkSize - 1,
                    4 * kDefaultChunkSize,
                    4 * kDefaultChunkSize + kMinChunkSize - 1,
                    4 * kDefaultChunkSize + kMinChunkSize,
                    4 * kDefaultChunkSize + kMinChunkSize + 1));



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
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;

  self_encryptor_.reset(new SelfEncryptor(data_map_, chunk_store_));
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i = 0; i < kDataSize_; ++i)
    ASSERT_EQ(original_[i], decrypted_[i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(Writing, SmallSingleBytesTest,
    testing::Values(1,
                    kMinChunkSize - 1,
                    kMinChunkSize,
                    kMinChunkSize + 1,
                    3 * kMinChunkSize - 1,
                    3 * kMinChunkSize,
                    3 * kMinChunkSize + 1,
                    kDefaultChunkSize - 1,
                    kDefaultChunkSize,
                    kDefaultChunkSize + 1));



class InProcessTest : public EncryptTest {};

TEST_P(InProcessTest, BEH_ReadInOrder) {
  uint32_t current_write_position(0), current_write_size(0);
  uint32_t current_read_position(0), current_read_size(0);
  while (current_read_position != kDataSize_) {
    current_write_size = std::min(kDefaultChunkSize,
                                  kDataSize_ - current_write_position);
    EXPECT_TRUE(self_encryptor_->Write(&original_[current_write_position],
                current_write_size, current_write_position));
    while (current_read_position != current_write_position) {
      current_read_size = std::min(
          current_write_position - current_read_position,
          RandomUint32() % (kDefaultChunkSize / 3));
      EXPECT_TRUE(self_encryptor_->Read(&decrypted_[current_read_position],
                  current_read_size, current_read_position));
      for (uint32_t i = current_read_position;
           i < current_read_position + current_read_size; ++i)
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

INSTANTIATE_TEST_CASE_P(Reading, InProcessTest, testing::Values(
    1,
    kMinChunkSize - 1,
    kMinChunkSize,
    kMinChunkSize + 1,
    3 * kMinChunkSize - 1,
    3 * kMinChunkSize,
    3 * kMinChunkSize + 1,
    kDefaultChunkSize - 1,
    kDefaultChunkSize,
    kDefaultChunkSize + 1,
    3 * kDefaultChunkSize - 1,
    3 * kDefaultChunkSize,
    3 * kDefaultChunkSize + 1,
    g_num_procs * 3 * kDefaultChunkSize - 1,
    g_num_procs * 3 * kDefaultChunkSize,
    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize - 1,
    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize,
    g_num_procs * 3 * kDefaultChunkSize + kMinChunkSize + 1));



class BasicTest : public EncryptTestBase, public testing::Test {
 public:
  BasicTest() : EncryptTestBase(),
                kDataSize_(1024 * 1024 * 20),
                content_(RandomString(kDataSize_)) {
    original_.reset(new char[kDataSize_]);
    decrypted_.reset(new char[kDataSize_]);
  }
 protected:
  virtual void SetUp() {
    std::copy(content_.data(), content_.data() + kDataSize_, original_.get());
    memset(decrypted_.get(), 1, kDataSize_);
  }
  const uint32_t kDataSize_;
  std::string content_;
};

TEST_F(BasicTest, BEH_ReadArbitaryPosition) {
  // Read while in process
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));
  uint32_t read_position(0), read_size(0);
  for (int i(0); i != 100; ++i) {
    read_position = RandomUint32() % (kDataSize_ - 1025);
    read_size = (RandomUint32() % 1023) + 1;
    EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], read_size,
                                      read_position));
    for (uint32_t j(read_position); j != read_position + read_size; ++j)
      ASSERT_EQ(original_[j], decrypted_[j]) << "not match " << j;
  }

  // Read post flush
  self_encryptor_->Flush();
  memset(decrypted_.get(), 1, kDataSize_);
  for (int i(0); i != 100; ++i) {
    read_position = RandomUint32() % (kDataSize_ - 1025);
    read_size = (RandomUint32() % 1023) + 1;
    EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], read_size,
                                      read_position));
    for (uint32_t j(read_position); j != read_position + read_size; ++j)
      ASSERT_EQ(original_[j], decrypted_[j]) << "not match " << j;
  }

  // Read with new self_encryptor_
  self_encryptor_.reset(new SelfEncryptor(data_map_, chunk_store_));
  memset(decrypted_.get(), 1, kDataSize_);
  for (int i(0); i != 100; ++i) {
    read_position = RandomUint32() % (kDataSize_ - 1025);
    read_size = (RandomUint32() % 1023) + 1;
    EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], read_size,
                                      read_position));
    for (uint32_t j(read_position); j != read_position + read_size; ++j)
      ASSERT_EQ(original_[j], decrypted_[j]) << "not match " << j;
  }
}

TEST_F(BasicTest, BEH_NewRead) {
  EXPECT_TRUE(self_encryptor_->Write(&original_[0], kDataSize_, 0));

  uint32_t read_position(0), index(0);
  const uint32_t kReadSize(4096);
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize,
                                    read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // read next small part straight from cache
  read_position += kReadSize;
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize,
                                    read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // try to read from end of cache, but request more data than remains
  // will result in cache being refreshed
  read_position += (kDefaultChunkSize * 8 - 1000);
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize,
                                    read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // try to read from near start of file, no longer in cache
  read_position = 5;
  EXPECT_TRUE(self_encryptor_->Read(&decrypted_[read_position], kReadSize,
                                    read_position));
  for (; index != read_position + kReadSize; ++index)
    ASSERT_EQ(original_[index], decrypted_[index]) << "difference at " << index;

  // use file smaller than the cache size
  DataMapPtr data_map2(new DataMap);
  const uint32_t kDataSize2(kDefaultChunkSize * 5);
  std::string content2(RandomString(kDataSize2));
  boost::scoped_array<char> original2(new char[kDataSize2]);
  std::copy(content2.data(), content2.data() + kDataSize2, original2.get());
  {
    SelfEncryptor self_encryptor(data_map2, chunk_store_);
    EXPECT_TRUE(self_encryptor.Write(original2.get(), kDataSize2, 0));
  }

  // try to read the entire file, will not cache.
  SelfEncryptor self_encryptor(data_map2, chunk_store_);
  boost::scoped_array<char> decrypted2(new char[kDataSize2]);
  memset(decrypted2.get(), 1, kDataSize2);
  EXPECT_TRUE(self_encryptor.Read(decrypted2.get(), kDataSize2, 0));
  for (uint32_t i(0); i != kDataSize2; ++i)
    ASSERT_EQ(original2[i], decrypted2[i]) << "difference at " << i;

  // same small file, many small reads, will cache and read from.
  for (int a(0); a != 10; ++a) {
    EXPECT_TRUE(self_encryptor.Read(decrypted2.get(), 4096, (4096 * a)));
    for (uint32_t i(0); i != kReadSize; ++i) {
      ASSERT_EQ(original2[i + (kReadSize * a)], decrypted2[i])
          << "difference at " << i;
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
                                                ((*overlap_itr).second +
                                                extra));
  uint32_t post_position(static_cast<uint32_t>((*overlap_itr).first +
                          (*overlap_itr).second.size()));

  uint32_t wtotal(0);
  for (auto it = broken_data.begin(); it != broken_data.end(); ++it) {
    EXPECT_TRUE(self_encryptor_->Write((*it).second.data(),
                static_cast<uint32_t>((*it).second.size()), (*it).first));
    wtotal += static_cast<uint32_t>(it->second.size());
  }
  EXPECT_EQ(wtotal, kDataSize_);
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of "
                                           << kDataSize_;
  }
  memset(decrypted_.get(), 1, kDataSize_);
  content_.replace(post_position, 7, extra);
  std::copy(content_.data(), content_.data() + kDataSize_, original_.get());
  EXPECT_TRUE(self_encryptor_->Write(post_overlap.second.data(),
              static_cast<uint32_t>(post_overlap.second.size()),
              post_overlap.first));
  EXPECT_TRUE(self_encryptor_->Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of "
                                           << kDataSize_;
  }
  self_encryptor_->Flush();

  SelfEncryptor self_encryptor(data_map_, chunk_store_);
  EXPECT_EQ(kDataSize_, TotalSize(self_encryptor.data_map()));
  EXPECT_TRUE(self_encryptor.data_map()->content.empty());
  memset(decrypted_.get(), 1, kDataSize_);
  EXPECT_TRUE(self_encryptor.Read(decrypted_.get(), kDataSize_, 0));
  for (uint32_t i(0); i != kDataSize_; ++i) {
    ASSERT_EQ(original_[i], decrypted_[i]) << "difference at " << i << " of "
                                           << kDataSize_;
  }
}
/*



TEST(SelfEncryptionTest, BEH_RandomSizedOutOfSequenceWritesWithGaps) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const size_t parts(500);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(RandomUint32() % ((1 << 18) + 1));
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 101; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(),
                  static_cast<uint32_t>(string_array[index_array[i]].size()),
                  index_array[i] * string_array[index_array[i]].size()));
    for (size_t i = 102; i != 233; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(),
                  static_cast<uint32_t>(string_array[index_array[i]].size()),
                  index_array[i] * string_array[index_array[i]].size()));
    for (size_t i = 234; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(),
                  static_cast<uint32_t>(string_array[index_array[i]].size()),
                  index_array[i] * string_array[index_array[i]].size()));
    // No content yet...
    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  // Unknown number of chunks and content details.
}
*/
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
  boost::shared_array<byte> enc_res_final(
      new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res_C0(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::shared_array<byte> enc_res_C1(new byte[crypto::SHA512::DIGESTSIZE]);

  for (size_t i = 0; i < chunk_size; ++i)
    pre_enc_chunk[i] = 'a';

  for (uint32_t i = 0; i < file_size - extra_size ; ++i)
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
  CryptoPP::SHA512().CalculateDigest(prehash.get(), pre_enc_chunk.get(),
                                     chunk_size);
  CryptoPP::SHA512().CalculateDigest(prehash_final.get(), final_chunk.get(),
                                     final_chunk_size);

  // calculate result of enc for chunks 2->last-1
  GetEncryptionResult(&enc_res, prehash, prehash, prehash, pre_enc_chunk,
                      chunk_size);
  // calculate result of enc for final chunk
  GetEncryptionResult(&enc_res_final, prehash, prehash, prehash_final,
                      final_chunk, final_chunk_size);
  // calculate result of enc for chunk 0 & 1
  GetEncryptionResult(&enc_res_C0, prehash_final, prehash, prehash,
                      pre_enc_chunk, chunk_size);
  GetEncryptionResult(&enc_res_C1, prehash, prehash_final, prehash,
                      pre_enc_chunk, chunk_size);

  // Check results
  EXPECT_EQ(num_chunks, self_encryptor_->data_map()->chunks.size());
  EXPECT_TRUE(self_encryptor_->data_map()->content.empty());
  EXPECT_EQ(file_size, TotalSize(self_encryptor_->data_map()));
  EXPECT_EQ(file_size, self_encryptor_->size());

  // Prehash checks
  for (uint32_t i = 0; i!= num_chunks-1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(prehash[j], self_encryptor_->data_map()->chunks[i].pre_hash[j])
      << "failed at chunk " << i << " pre hash " << j;
    }
  }
  for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(prehash_final[j],
              self_encryptor_->data_map()->chunks[num_chunks-1].pre_hash[j])
      << "failed at final chunk pre hash " << j;
  }

  // enc hash checks
  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    ASSERT_EQ(enc_res_C0[i], static_cast<byte>
      (self_encryptor_->data_map()->chunks[0].hash[i]))
      << "failed at chunk 0 post hash : " << i;
    ASSERT_EQ(enc_res_C1[i], static_cast<byte>
      (self_encryptor_->data_map()->chunks[1].hash[i]))
      << "failed at chunk 1 post hash : " << i;
    ASSERT_EQ(enc_res_final[i], static_cast<byte>
      (self_encryptor_->data_map()->chunks[num_chunks-1].hash[i]))
      << "failed at final chunk post hash : " << i;
  }

  for (uint32_t i = 2; i!= num_chunks-1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
      ASSERT_EQ(enc_res[j],
        static_cast<byte>(self_encryptor_->data_map()->chunks[i].hash[j]))
        << "failed at chunk " << i << " post hash : " << j;
    }
  }
}

TEST_F(BasicTest, BEH_RandomAccess) {
  size_t chunk_size(kDefaultChunkSize);
  std::vector<size_t> num_of_tries;
  std::vector<size_t> max_variation;
  max_variation.push_back(1024);
  max_variation.push_back(3072);
  max_variation.push_back(chunk_size);
  max_variation.push_back(3 * chunk_size);
  max_variation.push_back(6 * chunk_size);
  num_of_tries.push_back(5);
  num_of_tries.push_back(20);
  num_of_tries.push_back(50);
  num_of_tries.push_back(100);
  num_of_tries.push_back(200);
  // the longest length of data is writing to position 6 * chunk_size with
  // a content length of 6 * chunk_size, make the total to be 12 * chunk_size
  size_t kTestDataSize(chunk_size * 12);

  {
    // In Process random write/read access
    boost::scoped_array<char>plain_data(new char[kTestDataSize]);
    // The initialization value of truncated data shall be filled here
    for (size_t i = 0; i < kTestDataSize; ++i)
      plain_data[i] = '\0';

    for (size_t i = 0; i < max_variation.size(); ++i) {
      size_t num_tries = num_of_tries[i];
      size_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        int op_code(RandomUint32() % 2);
        DLOG(INFO) << " op code : " << op_code;

        switch (op_code) {
          case 0:  // write
            {
              uint32_t write_position(RandomUint32() % variation);
              uint32_t write_length(RandomUint32() % variation);
              DLOG(INFO) << " write_position : " << write_position
                         << " write_length : " << write_length;

              std::string plain_text(RandomString(write_length));
              boost::scoped_array<char>content_data(new char[write_length]);
              for (size_t i = 0; i < write_length; ++i) {
                plain_data[i + write_position] = plain_text[i];
                content_data[i] = plain_text[i];
              }

              EXPECT_TRUE(self_encryptor_->Write(content_data.get(),
                                                 write_length, write_position));
              DLOG(INFO) << " current data size is : "
                         << self_encryptor_->size();
              break;
            }
          case 1:  // read
            {
              uint32_t read_position(RandomUint32() % variation);
              uint32_t read_length(RandomUint32() % variation);
              boost::scoped_array<char>answer(new char[read_length]);
              DLOG(INFO) << " read_position : " << read_position
                         << " read_length : " << read_length;

              // The read method shall accept a reading request that exceeds
              // the current data lenth of the encrypt stream.
              // It shall return part of the content or false if the starting
              // read position exceed the data size
              if (read_position < self_encryptor_->size()) {
                EXPECT_TRUE(self_encryptor_->Read(answer.get(),
                                                  read_length, read_position));
                // A return value of num_of_bytes succeeded read is required
                for (size_t i = 0; i < read_length; ++i)
                  if ((i + read_position) < self_encryptor_->size())
                    ASSERT_EQ(plain_data[read_position + i], answer[i])
                        << "not match " << i << " from " << read_position
                        << " when total data is " << self_encryptor_->size();
              } else {
                // Should expect a False when reading out-of-range
                EXPECT_TRUE(self_encryptor_->Read(answer.get(),
                                                  read_length, read_position))
                    << " when trying to read " << read_length
                    << " from " << read_position
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
    MemoryChunkStore::HashFunc hash_func
        (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
    std::shared_ptr<MemoryChunkStore> chunk_store
        (new MemoryChunkStore(false, hash_func));
    DataMapPtr data_map(new DataMap);

    for (size_t i = 0; i < max_variation.size(); ++i) {
      size_t num_tries = num_of_tries[i];
      size_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        uint32_t position(RandomUint32() % variation);
        uint32_t length(RandomUint32() % variation);
        DLOG(INFO) << " accesing at postion : " << position
                   << " with data length : " << length;

        std::string plain_text(RandomString(length));
        boost::scoped_array<char>content_data(new char[length]);
        for (size_t i = 0; i < length; ++i)
          content_data[i] = plain_text[i];

        {
          SelfEncryptor selfenc(data_map, chunk_store);
          EXPECT_TRUE(selfenc.Write(content_data.get(), length, position));
        }

        boost::scoped_array<char>answer(new char[length]);
        {
          SelfEncryptor selfenc(data_map, chunk_store);
          EXPECT_TRUE(selfenc.Read(answer.get(), length, position));
        }

        for (size_t i = 0; i < length; ++i)
          ASSERT_EQ(content_data[i], answer[i])
              << "not match " << i;
      }
    }
  }

  // The situation combining in-process and out-process access may need to
  // be considered
}

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe
