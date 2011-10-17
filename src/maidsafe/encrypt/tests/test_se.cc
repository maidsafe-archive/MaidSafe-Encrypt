
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
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/scoped_array.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/log.h"


namespace bptime = boost::posix_time;

namespace maidsafe {
namespace encrypt {
namespace test {

namespace {

typedef std::shared_ptr<MemoryChunkStore> MemoryChunkStorePtr;
typedef std::pair<uint32_t, uint32_t> SizeAndOffset;
MemoryChunkStore::HashFunc g_hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));

uint64_t TotalSize(DataMapPtr data_map) {
  uint64_t size(data_map->chunks.empty() ? data_map->content.size() : 0);
  std::for_each(data_map->chunks.begin(), data_map->chunks.end(),
                [&size] (ChunkDetails chunk) { size += chunk.size; });
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


class BasicSelfEncryptionTest : public testing::TestWithParam<SizeAndOffset> {
 public:
  enum TestFileSize {
    kTiny = 3 * kMinChunkSize,
    kVerySmall = kDefaultChunkSize,
    kSmall = 3 * kDefaultChunkSize,
    kMedium = 10 * kDefaultChunkSize,
    kLarge = 1000 * kDefaultChunkSize,
    kMax = 2147483647
  };
  BasicSelfEncryptionTest()
      : chunk_store_(new MemoryChunkStore(false, g_hash_func)),
        data_map_(new DataMap),
        self_encryptor_(new SelfEncryptor(data_map_, chunk_store_, 5)),
        kDataSize_(GetParam().first),
        kOffset_(GetParam().second),
        original_(new char[kDataSize_]),
        answer_(new char[kOffset_ + kDataSize_]),
        test_file_size_(kMax) {
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
  }
  void TearDown() {}

  MemoryChunkStorePtr chunk_store_;
  DataMapPtr data_map_;
  std::shared_ptr<SelfEncryptor> self_encryptor_;
  const uint32_t kDataSize_, kOffset_;
  boost::scoped_array<char> original_, answer_;
  TestFileSize test_file_size_;
};

TEST_P(BasicSelfEncryptionTest, BEH_EncryptDecrypt) {
  EXPECT_TRUE(self_encryptor_->Write(original_.get(), kDataSize_, kOffset_));

  EXPECT_TRUE(self_encryptor_->Read(answer_.get(), kOffset_ + kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, answer_[i]) << "i == " << i;
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], answer_[kOffset_ + i]) << "i == " << i;

  answer_.reset(new char[kOffset_ + kDataSize_]);
  EXPECT_TRUE(self_encryptor_->Read(answer_.get(), kDataSize_, kOffset_));
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], answer_[i]) << "i == " << i;

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

  answer_.reset(new char[kOffset_ + kDataSize_]);
  EXPECT_TRUE(self_encryptor_->Read(answer_.get(), kOffset_ + kDataSize_, 0));
  for (uint32_t i = 0; i != kOffset_; ++i)
    ASSERT_EQ(0, answer_[i]) << "i == " << i;
  for (uint32_t i = 0; i != kDataSize_; ++i)
    ASSERT_EQ(original_[i], answer_[kOffset_ + i]) << "i == " << i;
}

INSTANTIATE_TEST_CASE_P(FileSmallerThanMinFileSize, BasicSelfEncryptionTest,
                        testing::Values(
                            std::make_pair(40, 0),
                            std::make_pair(40, 50),
                            std::make_pair(1024, 0),
                            std::make_pair(3 * kMinChunkSize - 24, 23),
                            std::make_pair(3 * kMinChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(FileSmallerThanOneChunk, BasicSelfEncryptionTest,
                        testing::Values(
                            std::make_pair(3 * kMinChunkSize, 0),
                            std::make_pair(3 * kMinChunkSize - 1, 1),
                            std::make_pair(3 * kMinChunkSize - 1, 1024),
                            std::make_pair(kDefaultChunkSize - 23, 22),
                            std::make_pair(kDefaultChunkSize - 1, 0)));

INSTANTIATE_TEST_CASE_P(FileSmallerThanThreeNormalChunks,
    BasicSelfEncryptionTest,
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
    BasicSelfEncryptionTest,
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
    BasicSelfEncryptionTest,
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

INSTANTIATE_TEST_CASE_P(LargeFile, BasicSelfEncryptionTest,
    testing::Values(
        std::make_pair(1, 50 * kDefaultChunkSize),
        std::make_pair(10 * kDefaultChunkSize, 50 * kDefaultChunkSize),
        std::make_pair(50 * kDefaultChunkSize + kMinChunkSize, 1)));


class Benchmark : public testing::TestWithParam<uint32_t> {
 public:
  Benchmark() : chunk_store_(new MemoryChunkStore(false, g_hash_func)),
                data_map_(new DataMap),
                self_encryptor_(new SelfEncryptor(data_map_, chunk_store_, 5)),
                kTestDataSize_(1024 * 1024 * 20),
                kPieceSize_(GetParam() ? GetParam() : kTestDataSize_),
                original_(new char[kTestDataSize_]),
                decrypted_(new char[kTestDataSize_]) {}

 protected:
  void PrintResult(const bptime::ptime &start_time,
                   const bptime::ptime &stop_time,
                   bool encrypting,
                   bool compressible) {
    uint64_t duration = (stop_time - start_time).total_microseconds();
    if (duration == 0)
      duration = 1;
    uint64_t rate((static_cast<uint64_t>(kTestDataSize_) * 1000000) / duration);
    std::string encrypted(encrypting ? "Self-encrypted " : "Self-decrypted ");
    std::string comp(compressible ? "compressible" : "incompressible");
    std::cout << encrypted << BytesToBinarySiUnits(kTestDataSize_) << " of "
              << comp << " data in " << BytesToBinarySiUnits(kPieceSize_)
              << " pieces in " << (duration / 1000000.0) << " seconds at a "
              << "speed of " << BytesToBinarySiUnits(rate) << "/s" << std::endl;
  }

  MemoryChunkStorePtr chunk_store_;
  DataMapPtr data_map_;
  std::shared_ptr<SelfEncryptor> self_encryptor_;
  const uint32_t kTestDataSize_, kPieceSize_;
  boost::scoped_array<char> original_, decrypted_;
};

TEST_P(Benchmark, BEH_BenchmarkMemOnly) {
  bool compressible(true);
  for (int z(0); z != 2; ++z) {
    if (compressible) {
      memset(original_.get(), 'a', kTestDataSize_);
    } else {
      memcpy(original_.get(), RandomString(kTestDataSize_).data(),
             kTestDataSize_);
    }

    bptime::ptime start_time(bptime::microsec_clock::universal_time());
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Write(&original_[i], kPieceSize_, i));
    self_encryptor_->Flush();
    bptime::ptime stop_time(bptime::microsec_clock::universal_time());
    PrintResult(start_time, stop_time, true, compressible);

    start_time = bptime::microsec_clock::universal_time();
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Read(&decrypted_[i], kPieceSize_, i));
    stop_time = bptime::microsec_clock::universal_time();
    for (uint32_t i(0); i < kTestDataSize_; ++i)
      ASSERT_EQ(original_[i], decrypted_[i]) << "failed @ count " << i;
    PrintResult(start_time, stop_time, false, compressible);
    compressible = false;
  }
}

INSTANTIATE_TEST_CASE_P(WriteRead, Benchmark, testing::Values(0, 4096, 65536));


TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATime) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // less than 2 MB fails due to test
  const uint32_t kTestDataSize(1024 * 1024 * 2);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 1; ++i) {
    plain_data[i] = 'a';  // plain_text[i];
  }
  plain_data[kTestDataSize - 1] = 'b';
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    // EXPECT_TRUE(selfenc.ReInitialise());
    // extra = sequencer_.Get(current_position_);
    for (uint32_t i = 0; i < kTestDataSize; ++i)  {
      selfenc.Write(&plain_data[i], 1, i);
    }
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(kTestDataSize, TotalSize(data_map));
  EXPECT_TRUE(data_map->content.empty());
  EXPECT_EQ(8, data_map->chunks.size());
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));

//   // check chunks 1 and 2
  for (uint32_t i = 0; i < 524288; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "c0 or c1 failed at count " << i;
// check all other chunks
  for (uint32_t i = 524288; i < kTestDataSize - 1; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "normal chunks failed count :" << i;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATimeOutOfSequenceForward) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(kDefaultChunkSize * 4 + 1025);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 2; ++i)
    plain_data[i] = plain_text[i];

  plain_data[kTestDataSize - 2] = 'a';
  plain_data[kTestDataSize - 1] = 'b';

  uint32_t length = 1;
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    bptime::ptime time = bptime::microsec_clock::universal_time();
    for (uint32_t i = 0; i < kTestDataSize; i += 2)
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    uint64_t duration1 =
        (bptime::microsec_clock::universal_time() -
        time).total_microseconds();
    std::cout << "Even byte_by_byte written taken: " << duration1
              << " microseconds" << std::endl;
    for (uint32_t i = 1; i < kTestDataSize; i += 2)
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    uint64_t duration2 =
        (bptime::microsec_clock::universal_time() -
        time).total_microseconds();
    std::cout << "Odd byte_by_byte written taken: " << duration2 - duration1
              << " microseconds" << std::endl;
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize + 1]);

  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize + 1, 0));

  for (size_t  i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, BEH_WriteOnceRead20) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(1024 * 1024);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 1; ++i) {
//    plain_data[i] = 'a';
    plain_data[i] = plain_text[i];
  }
  plain_data[kTestDataSize - 1] = 'b';
  {
    SelfEncryptor selfenc(data_map, chunk_store);
//   EXPECT_TRUE(selfenc.ReInitialise());
    ASSERT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize, 0));
    // TODO(dirvine) FIXME - wont work till destructor called
    //   ASSERT_TRUE(selfenc.FinaliseWrite());
    // check it works at least once
    boost::scoped_array<char> answer(new char[kTestDataSize]);
    ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
    // In process check !!
    for (int j = 0; j < 20; ++j) {
      boost::scoped_array<char> answer1(new char[kTestDataSize]);
      ASSERT_TRUE(selfenc.Read(answer1.get(), kTestDataSize, 0))
      << "failed at read attempt " << j;
      for (uint32_t  i = 0; i < kTestDataSize; ++i)
        ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
    }
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));

  for (int j = 0; j < 20; ++j) {
    boost::scoped_array<char> answer1(new char[kTestDataSize]);
    ASSERT_TRUE(selfenc.Read(answer1.get(), kTestDataSize, 0))
    << "failed at read attempt " << j;
    for (uint32_t  i = 0; i < kTestDataSize; ++i)
      ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
  }
}

TEST(SelfEncryptionTest, BEH_WriteRandomlyAllDirections) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(1024 * 20);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  std::vector<size_t> vec_data(kTestDataSize);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] =  plain_text[i];
  }

  for (uint32_t i = 0; i < kTestDataSize; ++i)
    vec_data[i] = i;  // vector of seq numbers

  srand(RandomUint32());
  std::random_shuffle(vec_data.begin(), vec_data.end());  // shuffle all about
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    boost::scoped_array<char> answer(new char[kTestDataSize]);
    for (uint32_t i = 0; i < kTestDataSize; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[vec_data[i]], 1, vec_data[i]));

      ASSERT_TRUE(selfenc.Read(&answer[vec_data[i]] , 1, vec_data[i]));
      ASSERT_EQ(plain_data[vec_data[i]], answer[vec_data[i]])
          << "failed in process at round " << i << " position " << vec_data[i];
    }
    // In process check
    ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
    for (uint32_t i = 0; i < kTestDataSize; ++i)
      ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
  }

//   EXPECT_EQ(8, selfenc.data_map()->chunks.size());
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
  for (uint32_t i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_RepeatedRandomCharReadInProcess) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t chunk_size(kDefaultChunkSize);
  const uint32_t kTestDataSize(chunk_size * 6);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);

  for (uint32_t i = 0; i < kTestDataSize - 1; ++i)
    plain_data[i] = plain_text[i];
  plain_data[kTestDataSize - 1] = 'b';
  SelfEncryptor selfenc(data_map, chunk_store);
  // check 2 chunk_size
  for (uint32_t i = 0; i < chunk_size * 2; ++i)
    EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));

  // read some data
  boost::scoped_array<char> testq(new char[chunk_size]);
  for (uint32_t i = 0; i < 10; ++i) {
    EXPECT_TRUE(selfenc.Read(testq.get() + i, 1, i));
    EXPECT_EQ(plain_data[i], testq[i]) << "not read " << i;
  }

  // next 2
  for (uint32_t i = chunk_size * 2; i < chunk_size * 4; ++i)
    EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));

  boost::scoped_array<char> testc0(new char[chunk_size]);
  for (uint32_t i = 0; i < 100; ++i) {
    EXPECT_TRUE(selfenc.Read(&testc0[i], 1, i));
    ASSERT_EQ(testc0[i], plain_data[i]) << "not read " << i;
  }

  boost::scoped_array<char> testc1(new char[chunk_size]);
  for (uint32_t i = 0; i < 100; ++i) {
    EXPECT_TRUE(selfenc.Read(&testc1[i], 1, i +  chunk_size));
    ASSERT_EQ(testc1[i], plain_data[i  + chunk_size]) << "not read " << i;
  }

  // write  out of sequence (should be in sequencer now
  for (uint32_t i = chunk_size * 5; i < (chunk_size * 5) + 10; ++i)
    EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));

  // Check read from Sequencer
  boost::scoped_array<char> testseq(new char[chunk_size]);
  for (uint32_t i = 0; i < 10; ++i) {
    EXPECT_TRUE(selfenc.Read(&testseq[i], 1, i));
    ASSERT_EQ(testseq[i], plain_data[i]) << "not read " << i;
  }

  // write second last chunk
  for (uint32_t i = chunk_size * 4; i < chunk_size * 5; ++i)
    EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));

  for (uint32_t i = (chunk_size * 5) + 10; i < chunk_size * 6; ++i)
    EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));

  selfenc.Flush();
  // read some data - should be in chunks now
  boost::scoped_array<char> testchunks(new char[10]);
  for (uint32_t i = 0; i < 10; ++i) {
    EXPECT_TRUE(selfenc.Read(testchunks.get() + i, 1, i));
    ASSERT_EQ(testchunks[i], plain_data[i]) << "not read " << i;
  }

  EXPECT_EQ(6, selfenc.data_map()->chunks.size());
  EXPECT_TRUE(selfenc.data_map()->content.empty());
  EXPECT_EQ(kTestDataSize, TotalSize(selfenc.data_map()));

  boost::scoped_array<char> answer(new char[kTestDataSize]);
  EXPECT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
  for (uint32_t i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_ReadArbitaryPosition) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t chunk_size(kDefaultChunkSize);
  const uint32_t kTestDataSize(chunk_size * 6);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);

  std::copy(plain_text.begin(), plain_text.end(), plain_data.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize, 0));
  }
  {
    // read some data
    SelfEncryptor selfenc(data_map, chunk_store);
    boost::scoped_array<char> testq(new char[chunk_size * 6]);
    for (size_t i = 0; i < 10; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i;
    }
    for (size_t i = chunk_size - 1; i < chunk_size + 1; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i;
    }
    for (size_t i = chunk_size * 3 - 1; i < chunk_size * 3 + 1; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i;
    }
    for (size_t i = chunk_size * 6 - 1; i < chunk_size * 6; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i))
          << "not read " << i;
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i;
    }

    int position(0);
    int length(chunk_size + 2);
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i;

    position = chunk_size - 1;
    length = chunk_size * 2 + 2;
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i;

    position = chunk_size * 2 - 1;
    length = chunk_size * 3 + 2;
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i;
  }
}

TEST(SelfEncryptionTest, BEH_RandomAccess) {
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
    MemoryChunkStore::HashFunc hash_func
        (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
    std::shared_ptr<MemoryChunkStore> chunk_store
        (new MemoryChunkStore(false, hash_func));
    DataMapPtr data_map(new DataMap);
    SelfEncryptor selfenc(data_map, chunk_store);

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
              uint64_t write_position(RandomUint32() % variation);
              uint32_t write_length(RandomUint32() % variation);
              DLOG(INFO) << " write_position : " << write_position
                         << " write_length : " << write_length;

              std::string plain_text(RandomString(write_length));
              boost::scoped_array<char>content_data(new char[write_length]);
              for (size_t i = 0; i < write_length; ++i) {
                plain_data[i + write_position] = plain_text[i];
                content_data[i] = plain_text[i];
              }

              EXPECT_TRUE(selfenc.Write(content_data.get(),
                                        write_length, write_position));
              DLOG(INFO) << " current data size is : " << selfenc.size();
              break;
            }
          case 1:  // read
            {
              uint64_t read_position(RandomUint32() % variation);
              uint32_t read_length(RandomUint32() % variation);
              boost::scoped_array<char>answer(new char[read_length]);
              DLOG(INFO) << " read_position : " << read_position
                         << " read_length : " << read_length;

              // The read method shall accept a reading request that exceeds
              // the current data lenth of the encrypt stream.
              // It shall return part of the content or false if the starting
              // read position exceed the data size
              if (read_position < selfenc.size()) {
                EXPECT_TRUE(selfenc.Read(answer.get(),
                                         read_length, read_position));
                // A return value of num_of_bytes succeeded read is required
                for (size_t i = 0; i < read_length; ++i)
                  if ((i + read_position) < selfenc.size())
                    ASSERT_EQ(plain_data[read_position + i], answer[i])
                        << "not match " << i << " from " << read_position
                        << " when total data is " << selfenc.size();
              } else {
                // Should expect a False when reading out-of-range
                EXPECT_TRUE(selfenc.Read(answer.get(),
                                          read_length, read_position))
                    << " when trying to read " << read_length
                    << " from " << read_position
                    << " when total data is " << selfenc.size();
              }
              break;
            }
          default:
            break;
        }
      }
    }
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
        uint64_t position(RandomUint32() % variation);
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

TEST(SelfEncryptionTest, BEH_NewRead) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  uint32_t size = kDefaultChunkSize * 10;    // 10 chunks
  uint32_t position = 0;
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff1(new char[size]);
  std::copy(content.data(), content.data() + size, stuff1.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff1.get(), size, 0));
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[size]);
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i)
    ASSERT_EQ(stuff1[i], answer[i]) << "difference at " << i;
  // read next small part straight from cache
  position += 4096;
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i)
    ASSERT_EQ(stuff1[position + i], answer[i]) << "difference at " << i;

  // try to read from end of cache, but request more data than remains
  // will result in cache being refreshed
  position += (kDefaultChunkSize * 8 - 1000);
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i)
    ASSERT_EQ(stuff1[position + i], answer[i]) << "difference at " << i;

  // try to read startish of file, no longer in cache
  position = 5;
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i)
    ASSERT_EQ(stuff1[position + i], answer[i]) << "difference at " << i;

  // use file smaller than the cache size
  MemoryChunkStorePtr chunk_store2(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map2(new DataMap);
  size = kDefaultChunkSize * 5;
  std::string content2(RandomString(size));
  boost::scoped_array<char> stuff2(new char[size]);
  std::copy(content2.data(), content2.data() + size, stuff2.get());
  {
    SelfEncryptor selfenc(data_map2, chunk_store2);
    EXPECT_TRUE(selfenc.Write(stuff2.get(), size, 0));
  }
  // try to read the entire file, will not cache.
  SelfEncryptor selfenc2(data_map2, chunk_store2);
  boost::scoped_array<char> answer2(new char[size]);
  EXPECT_TRUE(selfenc2.Read(answer2.get(), size, 0));
  for (uint32_t i = 0; i < size; ++i)
    ASSERT_EQ(stuff2[i], answer2[i]) << "difference at " << i;

  // same small file, many small reads, will cache and read from.
  for (int a = 0; a < 10; ++a) {
    EXPECT_TRUE(selfenc2.Read(answer2.get(), 4096, (4096 * a)));
    for (int i = 0; i < 4096; ++i)
      ASSERT_EQ(stuff2[i + (4096 * a)], answer2[i]) << "difference at " << i;
  }
}

TEST(SelfEncryptionTest, BEH_WriteRandomSizeRandomPosition) {
  //  create string for input, break into random sized pieces
  //  then write in random order
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t num_chunks(20);
  const uint32_t kFileSize(1024*256*num_chunks);
  std::string plain_text(RandomString(kFileSize));
  std::vector<std::pair<uint64_t, std::string>> broken_data;
  std::string extra("amended");

  uint32_t i(0);
  while (i < kFileSize) {
    uint32_t size;
    if (kFileSize - i < (4096*5))
      size = kFileSize - i;
    else
      size = RandomUint32() % (4096*5);
    std::pair<uint64_t, std::string> piece(i, plain_text.substr(i, size));
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

  boost::scoped_array<char> original(new char[kFileSize]);
  std::copy(plain_text.data(), plain_text.data() + kFileSize, original.get());
  boost::scoped_array<char> answer(new char[kFileSize]);
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    uint32_t wtotal(0);
    for (auto it = broken_data.begin(); it != broken_data.end(); ++it) {
      EXPECT_TRUE(selfenc.Write(it->second.data(),
                                static_cast<uint32_t>(it->second.size()),
                                it->first));
      wtotal += static_cast<uint32_t>(it->second.size());
    }
    EXPECT_EQ(wtotal, kFileSize);
    EXPECT_TRUE(selfenc.Read(answer.get(), kFileSize, 0));
    for (uint32_t i = 0; i < kFileSize; ++i) {
      ASSERT_EQ(original[i], answer[i]) << "difference at " << i << " of "
                                        << kFileSize;
    }
    memset(answer.get(), 0, kFileSize);
    plain_text.replace(post_position, 7, extra);
    std::copy(plain_text.data(), plain_text.data() + kFileSize, original.get());
    EXPECT_TRUE(selfenc.Write(post_overlap.second.data(),
                              static_cast<uint32_t>(post_overlap.second.size()),
                              post_overlap.first));
    EXPECT_TRUE(selfenc.Read(answer.get(), kFileSize, 0));
    for (uint32_t i = 0; i < kFileSize; ++i) {
      ASSERT_EQ(original[i], answer[i]) << "difference at " << i << " of "
                                        << kFileSize;
    }
    memset(answer.get(), 0, kFileSize);
  }

  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(kFileSize, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
  EXPECT_TRUE(selfenc.Read(answer.get(), kFileSize, 0));
  for (uint32_t i = 0; i < kFileSize; ++i) {
    ASSERT_EQ(original[i], answer[i]) << "difference at " << i << " of "
                                      << kFileSize;
  }
}

TEST(SelfEncryptionTest, BEH_10Chunk4096ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 10 chunks, (1024*256*10+1)...
  // 640, 4096 byte parts...
  const size_t parts(640), size(4096);
//  size_t chunks((8 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  char *content(new char[1]);
  content[0] = 'a';
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content, 1, 1024*256*10));
//    EXPECT_EQ(chunks, selfenc.data_map()->chunks.size());
//    EXPECT_EQ(1024*256*chunks, TotalSize(selfenc.data_map()));
//    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10+1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_10Chunk4096ByteOutOfSequenceWritesSmall) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 639, 4096 byte parts...
  const size_t parts(639), size(4096);
//  size_t chunks((10 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(4095));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.data(),
                static_cast<uint32_t>(content.size()), parts * size));
//    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
//    EXPECT_EQ(1024*256*chunks, TotalSize(selfenc.data_map()));
//    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_10Chunk65536ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 10 chunks, (1024*256*10+1)...
  // 40, 65536 byte parts...
  const size_t parts(40), size(65536);
//  size_t chunks((8 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  char *content(new char[1]);
  content[0] = 'a';
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content, 1, 1024*256*10));
//    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
//    EXPECT_EQ(1024*256*chunks, TotalSize(selfenc.data_map()));
//    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10+1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_10Chunk65536ByteOutOfSequenceWritesSmall) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 39, 65536 byte parts...
  const size_t parts(39), size(65536);
//  size_t chunks((10 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(65535));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.data(),
                static_cast<uint32_t>(content.size()), parts * size));
//    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
//    EXPECT_EQ(1024*256*chunks, TotalSize(selfenc.data_map()));
//    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_10Chunk4096ByteOutOfSequenceWritesWithGap) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 639, 4096 byte parts...
  const size_t parts(639), size(4096);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(4095));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 300; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    for (size_t i = 301; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.data(),
                static_cast<uint32_t>(content.size()), parts * size));
    // Unknown number of chunks and data map size...
    // No content yet...
    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_10Chunk65536ByteOutOfSequenceWritesWithGaps) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 39, 65536 byte parts...
  const size_t parts(39), size(65536);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(65535));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  srand(RandomUint32());
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 5; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    for (size_t i = 6; i != 34; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    for (size_t i = 35; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.data(),
                static_cast<uint32_t>(content.size()), parts * size));
    // Unknown number of chunks and data map size...
    // No content yet...
    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, TotalSize(selfenc.data_map()));
  EXPECT_TRUE(selfenc.data_map()->content.empty());
}

TEST(SelfEncryptionTest, BEH_RandomSizedOutOfSequenceWrites) {
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
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].data(),
                  static_cast<uint32_t>(string_array[index_array[i]].size()),
                  index_array[i] * string_array[index_array[i]].size()));
    // No content yet...
    EXPECT_TRUE(selfenc.data_map()->content.empty());
  }
  // Unknown number of chunks and content details.
}

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

TEST(SelfEncryptionManualTest, BEH_ManualCheckWrite) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
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

  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(pre_enc_file.get(), file_size, 0));
  }

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
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(num_chunks,  selfenc.data_map()->chunks.size());
  EXPECT_EQ(0,  selfenc.data_map()->content.size());
  EXPECT_EQ(file_size, TotalSize(selfenc.data_map()));

  // Prehash checks
  for (uint32_t i = 0; i!= num_chunks-1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(prehash[j], selfenc.data_map()->chunks[i].pre_hash[j])
      << "failed at chunk " << i << " pre hash " << j;
    }
  }
  for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(prehash_final[j],
              selfenc.data_map()->chunks[num_chunks-1].pre_hash[j])
      << "failed at final chunk pre hash " << j;
  }

  // enc hash checks
  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    ASSERT_EQ(enc_res_C0[i], static_cast<byte>
      (selfenc.data_map()->chunks[0].hash[i]))
      << "failed at chunk 0 post hash : " << i;
    ASSERT_EQ(enc_res_C1[i], static_cast<byte>
      (selfenc.data_map()->chunks[1].hash[i]))
      << "failed at chunk 1 post hash : " << i;
    ASSERT_EQ(enc_res_final[i], static_cast<byte>
      (selfenc.data_map()->chunks[num_chunks-1].hash[i]))
      << "failed at final chunk post hash : " << i;
  }

  for (uint32_t i = 2; i!= num_chunks-1; ++i) {
    for (int j = 0; j != crypto::SHA512::DIGESTSIZE; ++j) {
    ASSERT_EQ(enc_res[j], static_cast<byte>
      (selfenc.data_map()->chunks[i].hash[j]))
      << "failed at chunk " << i << " post hash : " << j;
    }
  }
}

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe
