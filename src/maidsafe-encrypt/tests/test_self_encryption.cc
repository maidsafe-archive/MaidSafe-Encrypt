/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_self_encryption.cc
 * @brief Tests for the self-encryption engine.
 * @date  2008-09-09
 */

#include <cstdint>
#include <functional>
#include <iostream>  // NOLINT
#include <memory>
#include <sstream>

#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace test_se {

const std::uint32_t kDefaultSelfEncryptionType(
    kHashingSha512 | kCompressionNone | kObfuscationRepeated | kCryptoAes256);

fs::path CreateRandomFile(const fs::path &file_path,
                          const std::uint64_t &file_size) {
  fs::ofstream ofs(file_path, std::ios::binary | std::ios::out |
                              std::ios::trunc);
  if (file_size != 0) {
    size_t string_size = (file_size > 100000) ? 100000 :
                        static_cast<size_t>(file_size);
    std::uint64_t remaining_size = file_size;
    std::string rand_str = RandomString(2 * string_size);
    std::string file_content;
    std::uint64_t start_pos = 0;
    while (remaining_size) {
      srand(17);
      start_pos = rand() % string_size;  // NOLINT (Fraser)
      if (remaining_size < string_size) {
        string_size = static_cast<size_t>(remaining_size);
        file_content = rand_str.substr(0, string_size);
      } else {
        file_content = rand_str.substr(static_cast<size_t>(start_pos),
                                       string_size);
      }
      ofs.write(file_content.c_str(), file_content.size());
      remaining_size -= string_size;
    }
  }
  ofs.close();
  return file_path;
}

std::uint64_t TotalChunkSize(const std::vector<std::uint32_t> &chunk_sizes) {
  std::uint64_t total(0);
  for (size_t i = 0; i < chunk_sizes.size(); ++i)
    total += chunk_sizes[i];
  return total;
}

size_t CountUniqueChunks(std::shared_ptr<DataMap> data_map) {
  std::set<std::string> chunks;
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it)
    chunks.insert(it->hash);
  return chunks.size();
}

bool VerifyChunks(std::shared_ptr<DataMap> data_map,
                  std::shared_ptr<ChunkStore> chunk_store) {
  std::set<std::string> chunks;
  std::uint32_t ref_sum(0);
  bool invalid(false);
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it)
    if (chunks.count(it->hash) == 0) {
      chunks.insert(it->hash);
      ref_sum += chunk_store->Count(it->hash);
      invalid = invalid || !chunk_store->Validate(it->hash);
    }
  return !invalid && ref_sum == data_map->chunks.size();
}

}  // namespace test_se

class SelfEncryptionTest : public testing::Test {
 public:
  SelfEncryptionTest()
      : test_dir_(),
        hash_func_(std::bind(&crypto::Hash<crypto::SHA512>,
                             std::placeholders::_1)) {
    boost::system::error_code ec;
    test_dir_ = boost::filesystem::temp_directory_path(ec) /
        ("maidsafe_TestSE_" + RandomAlphaNumericString(6));
  }
  virtual ~SelfEncryptionTest() {}
 protected:
  void SetUp() {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
    fs::create_directory(test_dir_);
  }
  void TearDown() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  testing::AssertionResult AssertStringsEqual(const char* expr1,
                                              const char* expr2,
                                              std::string s1,
                                              std::string s2) {
    if (s1 == s2)
      return testing::AssertionSuccess();

    const size_t kLineLength(76);

    s1 = EncodeToBase64(s1);
    if (s1.size() > kLineLength)
      s1 = s1.substr(0, kLineLength / 2 - 1) + ".." +
           s1.substr(s1.size() - kLineLength / 2 - 1);

    s2 = EncodeToBase64(s2);
    if (s2.size() > kLineLength)
      s2 = s2.substr(0, kLineLength / 2 - 1) + ".." +
           s2.substr(s2.size() - kLineLength / 2 - 1);

    return testing::AssertionFailure()
        << "Strings " << expr1 << " and " << expr2 << " are not equal: \n  "
        << s1 << "\n  " << s2;
  }

  fs::path test_dir_;
  MemoryChunkStore::HashFunc hash_func_;
};

/*
class SelfEncryptionParamTest
  : public SelfEncryptionTest,
    public testing::WithParamInterface<SelfEncryptionParams> {};
  // TODO(Steve) add sep_ and param output
*/

// TODO(Steve) replace this by the above declaration after upgrade to gtest 1.6
class SelfEncryptionParamTest
  : public testing::TestWithParam<SelfEncryptionParams> {
 public:
  SelfEncryptionParamTest()
      : test_dir_(),
        hash_func_(std::bind(&crypto::Hash<crypto::SHA512>,
                             std::placeholders::_1)),
        sep_(GetParam()) {
    boost::system::error_code ec;
    test_dir_ = boost::filesystem::temp_directory_path(ec) /
        ("maidsafe_TestSE_" + RandomAlphaNumericString(6));
  }
  virtual ~SelfEncryptionParamTest() {}
 protected:
  void SetUp() {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
    fs::create_directory(test_dir_);

    printf("Current SE parameters:\n"
           "  max chunk size            = %d Bytes\n"
           "  max includable chunk size = %d Bytes\n"
           "  max includable data size  = %d bytes\n",
           sep_.max_chunk_size,
           sep_.max_includable_chunk_size,
           sep_.max_includable_data_size);
  }
  void TearDown() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  testing::AssertionResult AssertStringsEqual(const char* expr1,
                                              const char* expr2,
                                              std::string s1,
                                              std::string s2) {
    if (s1 == s2)
      return testing::AssertionSuccess();

    const size_t kLineLength(76);

    s1 = EncodeToBase64(s1);
    if (s1.size() > kLineLength)
      s1 = s1.substr(0, kLineLength / 2 - 1) + ".." +
           s1.substr(s1.size() - kLineLength / 2 - 1);

    s2 = EncodeToBase64(s2);
    if (s2.size() > kLineLength)
      s2 = s2.substr(0, kLineLength / 2 - 1) + ".." +
           s2.substr(s2.size() - kLineLength / 2 - 1);

    return testing::AssertionFailure()
        << "Strings " << expr1 << " and " << expr2 << " are not equal: \n  "
        << s1 << "\n  " << s2;
  }

  fs::path test_dir_;
  MemoryChunkStore::HashFunc hash_func_;
  const SelfEncryptionParams sep_;
};

// TODO(Steve) replace this by the above declaration after upgrade to gtest 1.6
class SelfEncryptionBenchmarkTest
  : public testing::TestWithParam<SelfEncryptionParams> {
 public:
  SelfEncryptionBenchmarkTest()
      : test_dir_(),
        sep_(GetParam()) {
    boost::system::error_code ec;
    test_dir_ = boost::filesystem::temp_directory_path(ec) /
        ("maidsafe_TestSE_" + RandomAlphaNumericString(6));
  }
  virtual ~SelfEncryptionBenchmarkTest() {}
 protected:
  void SetUp() {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
    fs::create_directory(test_dir_);

    printf("Current SE parameters:\n"
           "  max chunk size            = %d Bytes\n"
           "  max includable chunk size = %d Bytes\n"
           "  max includable data size  = %d bytes\n",
           sep_.max_chunk_size,
           sep_.max_includable_chunk_size,
           sep_.max_includable_data_size);
  }
  void TearDown() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }

  fs::path test_dir_;
  const SelfEncryptionParams sep_;
};

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_Serialisation) {
  DataMap data_map;
  {
    data_map.content = "abcdefg";
    data_map.size = 12345;
    ChunkDetails chunk;
    chunk.hash = "test123";
    chunk.size = 10000;
    data_map.chunks.push_back(chunk);
    chunk.hash = "test456";
    chunk.size = 2345;
    data_map.chunks.push_back(chunk);
  }
  std::stringstream ser_data_map;
  {  // serialise DataMap to string stream
    boost::archive::text_oarchive oa(ser_data_map);
    oa << data_map;
  }
  {
    DataMap restored_data_map;
    boost::archive::text_iarchive ia(ser_data_map);
    ia >> restored_data_map;
    EXPECT_EQ(data_map.content, restored_data_map.content);
    EXPECT_EQ(data_map.size, restored_data_map.size);
    EXPECT_EQ(data_map.chunks.size(), restored_data_map.chunks.size());
    EXPECT_EQ(data_map.chunks[0].hash, restored_data_map.chunks[0].hash);
    EXPECT_EQ(data_map.chunks[0].size, restored_data_map.chunks[0].size);
    EXPECT_EQ(data_map.chunks[1].hash, restored_data_map.chunks[1].hash);
    EXPECT_EQ(data_map.chunks[1].size, restored_data_map.chunks[1].size);
  }
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_IsCompressedFile) {
  EXPECT_TRUE(utils::IsCompressedFile("test.7z"));
  EXPECT_TRUE(utils::IsCompressedFile("test.jpg"));
  EXPECT_TRUE(utils::IsCompressedFile("test.JPG"));
  EXPECT_TRUE(utils::IsCompressedFile("test.txt.rar"));
  EXPECT_TRUE(utils::IsCompressedFile("test.ZiP"));
  EXPECT_FALSE(utils::IsCompressedFile("test.txt"));
  EXPECT_FALSE(utils::IsCompressedFile("test.jpg.txt"));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_CheckCompressibility) {
  // TODO(Steve) add more compression types

  // no data
  std::string sample;
  EXPECT_FALSE(utils::CheckCompressibility(sample, kCompressionGzip));

  //  make compressible string
  sample = std::string(kCompressionSampleSize, 'x');
  EXPECT_TRUE(utils::CheckCompressibility(sample, kCompressionGzip));

  //  make incompressible string
  sample = RandomString(kCompressionSampleSize);
  EXPECT_FALSE(utils::CheckCompressibility(sample, kCompressionGzip));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ResizeObfuscationHash) {
  std::string output;
  EXPECT_FALSE(utils::ResizeObfuscationHash("abc", 10, NULL));
  EXPECT_FALSE(utils::ResizeObfuscationHash("", 10, &output));
  EXPECT_TRUE(output.empty());
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 0, &output));
  EXPECT_TRUE(output.empty());
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 1, &output));
  EXPECT_EQ("a", output);
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 3, &output));
  EXPECT_EQ("abc", output);
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 4, &output));
  EXPECT_EQ("abca", output);
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 9, &output));
  EXPECT_EQ("abcabcabc", output);
  EXPECT_TRUE(utils::ResizeObfuscationHash("abc", 11, &output));
  EXPECT_EQ("abcabcabcab", output);
  EXPECT_TRUE(utils::ResizeObfuscationHash("a", 5, &output));
  EXPECT_EQ("aaaaa", output);

  SelfEncryptionParams sep;
  const std::string kInput(RandomString(64));
  const int kRepetitions(25000);
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  for (int i = 0; i < kRepetitions; ++i) {
    output.clear();
    utils::ResizeObfuscationHash(kInput, sep.max_chunk_size, &output);
  }
  std::uint64_t duration =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  printf("Resized hash to %u Bytes %d times in %.2f ms.\n",
         sep.max_chunk_size, kRepetitions, duration / 1000.0);
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptChunk) {
  std::string content(RandomString(3000 + RandomUint32() % 1000));
  std::string hash1(RandomString(64)), hash2(RandomString(64));
  ASSERT_NE(hash1, hash2);

  // TODO(Steve) parametrise SE type

  EXPECT_EQ("", utils::SelfEncryptChunk("", hash1, hash2,
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfEncryptChunk(content, "", hash2,
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfEncryptChunk(content, hash1, "",
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfEncryptChunk(content, hash1, hash2, 0));

  EXPECT_EQ("", utils::SelfDecryptChunk("", hash1, hash2,
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfDecryptChunk(content, "", hash2,
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfDecryptChunk(content, hash1, "",
                                        test_se::kDefaultSelfEncryptionType));
  EXPECT_EQ("", utils::SelfDecryptChunk(content, hash1, hash2, 0));

  EXPECT_PRED_FORMAT2(AssertStringsEqual, content, utils::SelfDecryptChunk(
      utils::SelfEncryptChunk(content, hash1, hash2,
                              test_se::kDefaultSelfEncryptionType),
      hash1, hash2, test_se::kDefaultSelfEncryptionType));

  EXPECT_NE(content, utils::SelfDecryptChunk(
      utils::SelfEncryptChunk(content, hash1, hash2,
                              test_se::kDefaultSelfEncryptionType),
      hash2, hash1, test_se::kDefaultSelfEncryptionType));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptStreamInvalid) {
  // Invalid calls
  SelfEncryptionParams sep;
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::shared_ptr<std::istringstream> istream(new std::istringstream("test"));
  EXPECT_EQ(kNullPointer, SelfEncrypt(istream, false, sep,
                                      std::shared_ptr<DataMap>(), chunk_store));
  EXPECT_EQ(kNullPointer, SelfEncrypt(istream, false, sep, data_map,
                                      std::shared_ptr<ChunkStore>()));
  EXPECT_EQ(kNullPointer, SelfEncrypt(std::shared_ptr<std::istringstream>(),
                                      false, sep, data_map, chunk_store));
  EXPECT_EQ(kNullPointer, SelfDecrypt(data_map, chunk_store,
                                      std::shared_ptr<std::ostringstream>()));
  std::shared_ptr<std::ostringstream> ostream(new std::ostringstream);
  EXPECT_EQ(kNullPointer,
            SelfDecrypt(std::shared_ptr<DataMap>(), chunk_store, ostream));
  EXPECT_EQ(kNullPointer,
            SelfDecrypt(data_map, std::shared_ptr<ChunkStore>(), ostream));
  sep = SelfEncryptionParams(0, 0, kMinChunks - 1);
  EXPECT_EQ(kInvalidInput,
            SelfEncrypt(istream, false, sep, data_map, chunk_store));
  sep = SelfEncryptionParams(1, 0, 0);
  EXPECT_EQ(kInvalidInput,
            SelfEncrypt(istream, false, sep, data_map, chunk_store));
  sep = SelfEncryptionParams(1, 10, 10);
  EXPECT_EQ(kInvalidInput,
            SelfEncrypt(istream, false, sep, data_map, chunk_store));
  sep = SelfEncryptionParams(10, 0, 10 * kMinChunks + 1);
  EXPECT_EQ(kInvalidInput,
            SelfEncrypt(istream, false, sep, data_map, chunk_store));
  sep = SelfEncryptionParams(10, 10, 10 * kMinChunks);
  EXPECT_EQ(kInvalidInput,
            SelfEncrypt(istream, false, sep, data_map, chunk_store));
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamTinyData) {
  {  // Only one byte of data
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::shared_ptr<std::istringstream> stream_in(
        new std::istringstream(RandomString(1)));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, false, sep_, data_map,
                                    chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(),
                        stream_out->str());
  }
  {  // Smallest amount of data to allow chunking
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::shared_ptr<std::istringstream> stream_in(
        new std::istringstream(RandomString(kMinChunks)));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, false, sep_, data_map,
                                    chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(),
                        stream_out->str());
  }
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamFullInclude) {
  // Little data, should end up completely in DM
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  if (sep_.max_includable_data_size == 0)
    return;
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(sep_.max_includable_data_size)));
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  EXPECT_EQ(0, data_map->chunks.size());
//   EXPECT_EQ(test_se::kDefaultSelfEncryptionType,
//             data_map->self_encryption_type);
  EXPECT_EQ(sep_.max_includable_data_size, data_map->size);
  EXPECT_EQ(sep_.max_includable_data_size, data_map->content.size());
  EXPECT_EQ(hash_in, crypto::Hash<crypto::SHA512>(data_map->content));
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamNoInclude) {
  // Data just big enough to chunk
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(sep_.max_includable_data_size + 1)));
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  EXPECT_LE(kMinChunks, data_map->chunks.size());
  EXPECT_EQ(test_se::kDefaultSelfEncryptionType,
            data_map->self_encryption_type);
  EXPECT_EQ(sep_.max_includable_data_size + 1, data_map->size);
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamLastInclude) {
  // Last chunk ends up in DM
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  if (sep_.max_includable_chunk_size == 0)
    return;
  std::uint64_t data_size(kMinChunks * sep_.max_chunk_size +
                          sep_.max_includable_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_EQ(kMinChunks, data_map->chunks.size());
  EXPECT_EQ(test_se::kDefaultSelfEncryptionType,
            data_map->self_encryption_type);
  EXPECT_EQ(data_size, data_map->size);
  EXPECT_FALSE(data_map->content.empty());
  std::uint64_t total_size(0);
  for (auto it = data_map->chunks.begin(); it < data_map->chunks.end(); ++it) {
    EXPECT_FALSE(it->hash.empty());
    EXPECT_TRUE(chunk_store->Validate(it->hash));
    EXPECT_EQ(it->size, chunk_store->Size(it->hash));
    EXPECT_EQ(sep_.max_chunk_size, it->size);
    EXPECT_FALSE(it->pre_hash.empty());
    EXPECT_EQ(it->size, it->pre_size);  // no compression
    total_size += it->pre_size;
  }
  EXPECT_EQ(data_size, total_size + data_map->content.size());
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out))
      << "Data size: " << data_size;
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamNoCapacity) {
  // ChunkStore with too little capacity
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  chunk_store->SetCapacity(sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString((kMinChunks + 1) * sep_.max_chunk_size)));
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kEncryptError,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  EXPECT_LE(1, data_map->chunks.size());
  EXPECT_EQ(1, chunk_store->Count());
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamPattern) {
  // Check with different sequences of repeating chunks
  if (sep_.max_chunk_size < 4)
    return;  // collisions far too likely
  if (sep_.max_includable_data_size == kMinChunks * sep_.max_chunk_size)
    return;  // need at least 3 actual chunks
  ASSERT_EQ(3, kMinChunks);  // chunk depends on following 2 chunks
  std::string chunk_a(RandomString(sep_.max_chunk_size));
  std::string chunk_b(chunk_a);
  while (chunk_b == chunk_a)
    chunk_b = RandomString(sep_.max_chunk_size);
  std::string chunk_c(chunk_a);
  while (chunk_c == chunk_a || chunk_c == chunk_b)
    chunk_c = RandomString(sep_.max_chunk_size);

  for (int i = 0; i <= 18; ++i) {
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::shared_ptr<std::istringstream> stream_in(new std::istringstream);
    size_t expected_chunks(0);
    printf("--- case %d ---\n", i);
    switch (i) {
      case 0:  // abc
        stream_in->str(chunk_a + chunk_b + chunk_c);
        expected_chunks = 3;
        break;
      case 1:  // aaa
        stream_in->str(chunk_a + chunk_a + chunk_a);
        expected_chunks = 1;
        break;
      case 2:  // aaaa
        stream_in->str(chunk_a + chunk_a + chunk_a + chunk_a);
        expected_chunks = 1;
        break;
      case 3:  // baaa
        stream_in->str(chunk_b + chunk_a + chunk_a + chunk_a);
        expected_chunks = 4;
        break;
      case 4:  // abaa
        stream_in->str(chunk_a + chunk_b + chunk_a + chunk_a);
        expected_chunks = 4;
        break;
      case 5:  // aaba
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a);
        expected_chunks = 4;
        break;
      case 6:  // aaab
        stream_in->str(chunk_a + chunk_a + chunk_a + chunk_b);
        expected_chunks = 4;
        break;
      case 7:  // baaaa
        stream_in->str(chunk_b + chunk_a + chunk_a + chunk_a + chunk_a);
        expected_chunks = 4;
        break;
      case 8:  // abaaa
        stream_in->str(chunk_a + chunk_b + chunk_a + chunk_a + chunk_a);
        expected_chunks = 4;
        break;
      case 9:  // aabaa
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a + chunk_a);
        expected_chunks = 4;
        break;
      case 10:  // aaaba
        stream_in->str(chunk_a + chunk_a + chunk_a + chunk_b + chunk_a);
        expected_chunks = 4;
        break;
      case 11:  // aaaab
        stream_in->str(chunk_a + chunk_a + chunk_a + chunk_a + chunk_b);
        expected_chunks = 4;
        break;
      case 12:  // baaab
        stream_in->str(chunk_b + chunk_a + chunk_a + chunk_a + chunk_b);
        expected_chunks = 5;
        break;
      case 13:  // aaabc
        stream_in->str(chunk_a + chunk_a + chunk_a + chunk_b + chunk_c);
        expected_chunks = 5;
        break;
      case 14:  // aabaab
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a + chunk_a +
                      chunk_b);
        expected_chunks = 3;
        break;
      case 15:  // aabaac
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a + chunk_a +
                      chunk_c);
        expected_chunks = 6;
        break;
      case 16:  // aabaacaac
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a + chunk_a +
                      chunk_c + chunk_a + chunk_a + chunk_c);
        expected_chunks = 6;
        break;
      case 17:  // aabaacaab
        stream_in->str(chunk_a + chunk_a + chunk_b + chunk_a + chunk_a +
                      chunk_c + chunk_a + chunk_a + chunk_b);
        expected_chunks = 6;
        break;
      case 18:  // abaca
        stream_in->str(chunk_a + chunk_b + chunk_a + chunk_c + chunk_a);
        expected_chunks = 5;
        break;
    }
    EXPECT_EQ(kSuccess,
              SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
    EXPECT_EQ(expected_chunks, test_se::CountUniqueChunks(data_map));
    EXPECT_EQ(expected_chunks, chunk_store->Count());
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str())
        << "Case " << i;
  }
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamDedup) {
  // Check de-duplication (identical chunks except for last one)
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  const size_t kChunkCount(5 * kMinChunks);
  std::string chunk_content(RandomString(sep_.max_chunk_size));
  std::string last_chunk_content(chunk_content);
  while (last_chunk_content == chunk_content)
    last_chunk_content = RandomString(sep_.max_chunk_size);
  std::string chunk_hash(crypto::Hash<crypto::SHA512>(chunk_content));
  std::string last_chunk_hash(crypto::Hash<crypto::SHA512>(last_chunk_content));
  ASSERT_NE(chunk_hash, last_chunk_hash);

  std::string data_content;
  for (size_t i = 0; i < kChunkCount - 1; ++i)
    data_content.append(chunk_content);
  data_content.append(last_chunk_content);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      data_content));
  ASSERT_EQ(kChunkCount * sep_.max_chunk_size, stream_in->str().size());
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  EXPECT_EQ(kChunkCount, data_map->chunks.size());
  EXPECT_EQ(test_se::kDefaultSelfEncryptionType,
            data_map->self_encryption_type);
  EXPECT_EQ(kChunkCount * sep_.max_chunk_size, data_map->size);
  EXPECT_TRUE(data_map->content.empty());

  std::uint64_t total_size(0);
  std::string post_enc_hash;
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_FALSE(data_map->chunks[i].hash.empty());
    if (i == 0)
      post_enc_hash = data_map->chunks[i].hash;
    else if (i < data_map->chunks.size() - kMinChunks)
      EXPECT_EQ(post_enc_hash, data_map->chunks[i].hash);
    else
      EXPECT_NE(post_enc_hash, data_map->chunks[i].hash);
    EXPECT_EQ(sep_.max_chunk_size, data_map->chunks[i].size);
    if (i < data_map->chunks.size() - 1)
      EXPECT_EQ(chunk_hash, data_map->chunks[i].pre_hash);
    else
      EXPECT_EQ(last_chunk_hash, data_map->chunks[i].pre_hash);
    EXPECT_EQ(data_map->chunks[i].size, data_map->chunks[i].pre_size);  // uncpr
    total_size += data_map->chunks[i].pre_size;
  }

  EXPECT_EQ(kChunkCount * sep_.max_chunk_size, total_size);
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamCharacters) {
  // Try all possible characters
  // NOTE Test is needed because streams tend to choke on certain characters.
  for (int i = 0; i < 256; ++i) {
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size(RandomUint32() % sep_.max_includable_data_size + 1);
    std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
        std::string(data_size, static_cast<char>(i))));
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, false, sep_, data_map,
                                    chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out))
        << "Character: " << i << "\nData size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(),
                        stream_out->str());
  }
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamDelChunk) {
  // First chunk is deleted
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::uint64_t data_size((kMinChunks + 1) * sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  ASSERT_EQ(kMinChunks + 1, data_map->chunks.size());
  EXPECT_TRUE(chunk_store->Delete(data_map->chunks[0].hash));
  std::vector<std::string> missing_chunks;
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_FALSE(test_se::VerifyChunks(data_map, chunk_store));
  ASSERT_EQ(1, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks.front());
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, chunk_store, stream_out));
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamResizeChunk) {
  // First chunk is changed in size (and contents)
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::uint64_t data_size((kMinChunks + 1) * sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  ASSERT_EQ(kMinChunks + 1, data_map->chunks.size());
  EXPECT_TRUE(chunk_store->Delete(data_map->chunks[0].hash));
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[0].hash,
                                RandomString(data_map->chunks[0].size + 7)));
  EXPECT_FALSE(test_se::VerifyChunks(data_map, chunk_store));
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, chunk_store, stream_out));
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptStreamCorruptChunk) {
  // First chunk is changed only in contents
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::uint64_t data_size((kMinChunks + 1) * sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  std::string random(stream_in->str());
  while (random == stream_in->str())
    random = RandomString(data_size);
  EXPECT_EQ(kSuccess,
            SelfEncrypt(stream_in, false, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  ASSERT_EQ(kMinChunks + 1, data_map->chunks.size());
  EXPECT_TRUE(chunk_store->Delete(data_map->chunks[0].hash));
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[0].hash, random));
  EXPECT_FALSE(test_se::VerifyChunks(data_map, chunk_store));
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, chunk_store, stream_out));
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptString) {
  {  // Invalid calls
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kNullPointer,
              SelfEncrypt("test", false, sep_, std::shared_ptr<DataMap>(),
                          chunk_store));
    EXPECT_EQ(kNullPointer, SelfEncrypt("test", false, sep_, data_map,
                                        std::shared_ptr<ChunkStore>()));
    std::string s;
    EXPECT_EQ(kNullPointer, SelfDecrypt(data_map, chunk_store,
                                        static_cast<std::string*>(NULL)));
    EXPECT_EQ(kNullPointer,
              SelfDecrypt(std::shared_ptr<DataMap>(), chunk_store, &s));
    EXPECT_EQ(kNullPointer,
              SelfDecrypt(data_map, std::shared_ptr<ChunkStore>(), &s));
  }
  {  // Empty data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kSuccess,
              SelfEncrypt("", false, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::string string_out;
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, &string_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual, "", string_out);
  }
  {  // Small data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size(kMinChunks);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess,
              SelfEncrypt(string_in, false, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::string string_out;
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, &string_out))
        << "Data size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual, string_in, string_out);
  }
  {  // Random data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) *
                            sep_.max_chunk_size + kMinChunks +
                            RandomUint32() % sep_.max_chunk_size);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess,
              SelfEncrypt(string_in, false, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::string string_out;
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, &string_out))
        << "Data size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual, string_in, string_out);
  }
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptFile) {
  fs::path path_in(test_dir_ / "SelfEncryptFilesTestIn.dat");
  fs::path path_out(test_dir_ / "SelfEncryptFilesTestOut.dat");

  {  // Invalid calls
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kIoError,
              SelfEncrypt(path_in, sep_, data_map, chunk_store));
    test_se::CreateRandomFile(path_in, 1);
    EXPECT_EQ(kNullPointer,
              SelfEncrypt(path_in, sep_, std::shared_ptr<DataMap>(),
                          chunk_store));
    EXPECT_EQ(kNullPointer, SelfEncrypt(path_in, sep_, data_map,
                                        std::shared_ptr<ChunkStore>()));
    EXPECT_EQ(kNullPointer, SelfDecrypt(std::shared_ptr<DataMap>(), chunk_store,
                                        true, path_out));
    EXPECT_EQ(kNullPointer, SelfDecrypt(data_map, std::shared_ptr<ChunkStore>(),
                                        true, path_out));
  }
  {  // Empty data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    test_se::CreateRandomFile(path_in, 0);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out));
    EXPECT_TRUE(fs::exists(path_out));
    ASSERT_EQ(0, fs::file_size(path_out));
  }
  {  // Small data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size(kMinChunks);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out))
        << "Data size: " << data_size;
    EXPECT_TRUE(fs::exists(path_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual,
                        crypto::HashFile<crypto::SHA512>(path_in),
                        crypto::HashFile<crypto::SHA512>(path_out));
  }
  {  // Random data test
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) *
                            sep_.max_chunk_size + kMinChunks +
                            RandomUint32() % sep_.max_chunk_size);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out))
        << "Data size: " << data_size;
    EXPECT_TRUE(fs::exists(path_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual,
                        crypto::HashFile<crypto::SHA512>(path_in),
                        crypto::HashFile<crypto::SHA512>(path_out));
  }
  {  // Try restoring existing file
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kFileAlreadyExists,
              SelfDecrypt(data_map, chunk_store, false, path_out));
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out));
  }
}

TEST_P(SelfEncryptionParamTest, BEH_ENCRYPT_SelfEnDecryptMixed) {
  {  // String input, file output
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) *
                            sep_.max_chunk_size + kMinChunks +
                            RandomUint32() % sep_.max_chunk_size);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess,
              SelfEncrypt(string_in, false, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    fs::path path_out(test_dir_ / "SelfEncryptFilesTestOut.dat");
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out))
        << "Data size: " << data_size;
    EXPECT_TRUE(fs::exists(path_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual,
                        crypto::Hash<crypto::SHA512>(string_in),
                        crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // File input, string output
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) *
                            sep_.max_chunk_size + kMinChunks +
                            RandomUint32() % sep_.max_chunk_size);
    fs::path path_in(test_dir_ / "SelfEncryptFilesTestIn.dat");
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::string string_out;
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, &string_out))
        << "Data size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual,
                        crypto::HashFile<crypto::SHA512>(path_in),
                        crypto::Hash<crypto::SHA512>(string_out));
  }
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ChunksExist) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  EXPECT_FALSE(ChunksExist(std::shared_ptr<DataMap>(), chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, std::shared_ptr<ChunkStore>(), NULL));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  std::vector<std::string> missing_chunks;
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
  missing_chunks.push_back("test chunk name");
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
  }
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  ASSERT_EQ(2, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks[0]);
  EXPECT_EQ(data_map->chunks[1].hash, missing_chunks[1]);
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[1].hash, RandomString(123)));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  ASSERT_EQ(1, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks[0]);
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[0].hash, RandomString(123)));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_DeleteChunks) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  EXPECT_FALSE(DeleteChunks(std::shared_ptr<DataMap>(), chunk_store));
  EXPECT_FALSE(DeleteChunks(data_map, std::shared_ptr<ChunkStore>()));
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
  }
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_TRUE(data_map->chunks.empty());

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    EXPECT_TRUE(chunk_store->Store(crypto::Hash<crypto::SHA512>("chunk3"),
                                   "foo"));
  }
  EXPECT_EQ(3, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_EQ(1, chunk_store->Count());
  EXPECT_TRUE(data_map->chunks.empty());
  chunk_store->Clear();

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "foo"));
  }
  EXPECT_EQ(2, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_EQ(1, chunk_store->Count());
  EXPECT_TRUE(data_map->chunks.empty());
  chunk_store->Clear();

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "foo"));
  }
  EXPECT_EQ(2, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_TRUE(chunk_store->Empty());
  EXPECT_TRUE(data_map->chunks.empty());
}

TEST_F(SelfEncryptionTest, DISABLED_BEH_ENCRYPT_Compression) {
  // TODO(Steve) Test if compression can be toggled, it's noticable in sizes,
  //             and resulting chunk sizes are constant except for the last one.
  FAIL() << "Not implemented yet.";
}

INSTANTIATE_TEST_CASE_P(VarChunkSizes, SelfEncryptionParamTest, testing::Values(
    SelfEncryptionParams(1, 0, kMinChunks - 1),  // 1 Byte
    SelfEncryptionParams(1 << 8, 0, (1 << 8) * kMinChunks),  // 256 B, 3 chk inc
    SelfEncryptionParams(1 << 8, 1 << 5, 1 << 7),  // 256 Bytes
    SelfEncryptionParams(1 << 18, 1 << 8, 1 << 10)  // 256 KiB (default)
));

TEST_P(SelfEncryptionBenchmarkTest, FUNC_ENCRYPT_Benchmark) {
  const size_t kRunCount(16);
  for (size_t run = 0; run < kRunCount; ++run) {
    size_t repetitions(0);
    size_t data_size(64 << run);
    if (data_size <= (1 << 12))
      repetitions = 1000;
    else if (data_size <= (1 << 15))
      repetitions = 100;
    else
      repetitions = 10;

    printf("Timing Self-encryption of %d strings à %d bytes (run %d/%d)...\n",
           repetitions, data_size, run + 1, kRunCount);

    std::vector<std::shared_ptr<std::istringstream>> contents;
    std::vector<std::shared_ptr<DataMap>> data_maps;
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true,
        std::bind(&crypto::HashFile<crypto::SHA512>, std::placeholders::_1)));
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::istringstream> stream_ptr(
          new std::istringstream(RandomString(data_size)));
      contents.push_back(stream_ptr);
      std::shared_ptr<DataMap> data_map_ptr(new DataMap);
      data_maps.push_back(data_map_ptr);
    }
    ASSERT_EQ(repetitions, contents.size());
    ASSERT_EQ(repetitions, data_maps.size());

    boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
    for (size_t i = 0; i < repetitions; ++i)
      SelfEncrypt(contents[i], false, sep_, data_maps[i], chunk_store);
    std::uint64_t duration =
        (boost::posix_time::microsec_clock::universal_time() -
         time).total_microseconds();
    if (duration == 0)
      duration = 1;
    printf("Self-encrypted %d strings à %d bytes in %.2f seconds "
           "(%.3f MB/s).\n", repetitions, data_size, duration / 1000000.0,
           (repetitions * data_size) / duration / 1.048576);

    std::vector<std::shared_ptr<std::ostringstream>> dec_contents;
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::ostringstream> stream_ptr(new std::ostringstream);
      dec_contents.push_back(stream_ptr);
    }
    ASSERT_EQ(repetitions, dec_contents.size());

    time = boost::posix_time::microsec_clock::universal_time();
    for (size_t i = 0; i < repetitions; ++i)
      SelfDecrypt(data_maps[i], chunk_store, dec_contents[i]);
    duration = (boost::posix_time::microsec_clock::universal_time() -
                time).total_microseconds();
    if (duration == 0)
      duration = 1;

    printf("Self-decrypted %d strings à %d bytes in %.2f seconds "
           "(%.3f MB/s).\n", repetitions, data_size, duration / 1000000.0,
           (repetitions * data_size) / duration / 1.048576);

//     for (size_t i = 0; i < repetitions; ++i)
    size_t idx(RandomUint32() % repetitions);
    EXPECT_EQ(contents[idx]->str(), dec_contents[idx]->str());
  }
}

INSTANTIATE_TEST_CASE_P(ChunkSize, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in chunk_size
    SelfEncryptionParams(1 << 8, 0, kMinChunks - 1),  // 256 Bytes
    SelfEncryptionParams(1 << 10, 0, kMinChunks - 1),  // 1 KiB
    SelfEncryptionParams(1 << 12, 0, kMinChunks - 1),  // 4 KiB
    SelfEncryptionParams(1 << 14, 0, kMinChunks - 1),  // 16 KiB
    SelfEncryptionParams(1 << 16, 0, kMinChunks - 1),  // 64 KiB
    SelfEncryptionParams(1 << 17, 0, kMinChunks - 1),  // 128 KiB
    SelfEncryptionParams(1 << 18, 0, kMinChunks - 1),  // 256 KiB (default)
    SelfEncryptionParams(1 << 19, 0, kMinChunks - 1),  // 512 KiB
    SelfEncryptionParams(1 << 20, 0, kMinChunks - 1),  // 1 MiB
    SelfEncryptionParams(1 << 21, 0, kMinChunks - 1)  // 2 MiB
));

INSTANTIATE_TEST_CASE_P(IncData, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in max_includable_data_size
    SelfEncryptionParams(1 << 18, 0, 1 << 6),  // 64 Bytes
    SelfEncryptionParams(1 << 18, 0, 1 << 8),  // 256 Bytes
    SelfEncryptionParams(1 << 18, 0, 1 << 10),  // 1 KiB (default)
    SelfEncryptionParams(1 << 18, 0, 1 << 12),  // 4 KiB
    SelfEncryptionParams(1 << 18, 0, 1 << 14),  // 16 KiB
    SelfEncryptionParams(1 << 18, 0, 1 << 16)  // 64 KiB
));

INSTANTIATE_TEST_CASE_P(IncChunk, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in max_includable_chunk_size
    SelfEncryptionParams(1 << 18, 1 << 6, 1 << 8),  // 64 Bytes
    SelfEncryptionParams(1 << 18, 1 << 8, 1 << 10),  // 256 Bytes (default)
    SelfEncryptionParams(1 << 18, 1 << 10, 1 << 12),  // 1 KiB
    SelfEncryptionParams(1 << 18, 1 << 12, 1 << 14),  // 4 KiB
    SelfEncryptionParams(1 << 18, 1 << 14, 1 << 16),  // 16 KiB
    SelfEncryptionParams(1 << 18, 1 << 16, 1 << 18)  // 64 KiB
));

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
