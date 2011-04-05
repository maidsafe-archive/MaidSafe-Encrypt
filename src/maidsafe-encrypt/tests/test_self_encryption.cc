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
 * @brief Tests for the self-encryption convenience functions.
 * @date  2008-09-09
 */

#include <cstdint>
#include <functional>
#include <iostream>  // NOLINT
#include <memory>
#include <sstream>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption.h"

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

TEST_F(SelfEncryptionTest, BEH_SelfEnDecryptStreamInvalid) {
  // Invalid calls
  SelfEncryptionParams sep;
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::shared_ptr<std::istringstream> istream(new std::istringstream("test"));
  EXPECT_EQ(kNullPointer,
            SelfEncrypt(istream, sep, std::shared_ptr<DataMap>(), chunk_store));
  EXPECT_EQ(kNullPointer,
            SelfEncrypt(istream, sep, data_map, std::shared_ptr<ChunkStore>()));
  EXPECT_EQ(kNullPointer,
            SelfEncrypt(std::shared_ptr<std::istringstream>(), sep, data_map,
                        chunk_store));
  EXPECT_EQ(kNullPointer,
            SelfDecrypt(data_map, chunk_store,
                        std::shared_ptr<std::ostringstream>()));
  std::shared_ptr<std::ostringstream> ostream(new std::ostringstream);
  EXPECT_EQ(kNullPointer,
            SelfDecrypt(std::shared_ptr<DataMap>(), chunk_store, ostream));
  EXPECT_EQ(kNullPointer,
            SelfDecrypt(data_map, std::shared_ptr<ChunkStore>(), ostream));
  sep = SelfEncryptionParams(0, 0, 0);
  EXPECT_EQ(kInvalidInput, SelfEncrypt(istream, sep, data_map, chunk_store));
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamTinyData) {
  {  // Only one byte of data
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::shared_ptr<std::istringstream> stream_in(
        new std::istringstream(RandomString(1)));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(),
                        stream_out->str());
  }
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamFullInclude) {
  // Little data, should end up completely in DM
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  if (sep_.max_includable_data_size == 0)
    return;
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(sep_.max_includable_data_size)));
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamNoInclude) {
  // Data just big enough to chunk
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(sep_.max_includable_data_size + 1)));
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamLastInclude) {
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
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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
    EXPECT_EQ(sep_.max_chunk_size, it->pre_size);
    EXPECT_FALSE(it->pre_hash.empty());
    total_size += it->pre_size;
  }
  EXPECT_EQ(data_size, total_size + data_map->content.size());
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out))
      << "Data size: " << data_size;
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamNoCapacity) {
  // ChunkStore with too little capacity
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  chunk_store->SetCapacity(1);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString((kMinChunks + 1) * sep_.max_chunk_size)));
  std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in->str());
  EXPECT_EQ(kEncryptError, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamPattern) {
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
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamDedup) {
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
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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
    EXPECT_EQ(sep_.max_chunk_size, data_map->chunks[i].pre_size);
    if (i < data_map->chunks.size() - 1)
      EXPECT_EQ(chunk_hash, data_map->chunks[i].pre_hash);
    else
      EXPECT_EQ(last_chunk_hash, data_map->chunks[i].pre_hash);
    total_size += data_map->chunks[i].pre_size;
  }

  EXPECT_EQ(kChunkCount * sep_.max_chunk_size, total_size);
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out));
  ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(), stream_out->str());
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamCharacters) {
  // Try all possible characters
  // NOTE Test is needed because streams tend to choke on certain characters.
  for (int i = 0; i < 256; ++i) {
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size(RandomUint32() % sep_.max_includable_data_size + 1);
    std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
        std::string(data_size, static_cast<char>(i))));
    EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, stream_out))
        << "Character: " << i << "\nData size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual, stream_in->str(),
                        stream_out->str());
  }
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamDelChunk) {
  // First chunk is deleted
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::uint64_t data_size((kMinChunks + 1) * sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  ASSERT_EQ(kMinChunks + 1, data_map->chunks.size());
  while (chunk_store->Has(data_map->chunks[0].hash))
    EXPECT_TRUE(chunk_store->Delete(data_map->chunks[0].hash));
  std::vector<std::string> missing_chunks;
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_FALSE(test_se::VerifyChunks(data_map, chunk_store));
  ASSERT_LE(1, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks.front());
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, chunk_store, stream_out));
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamResizeChunk) {
  // First chunk is changed in size (and contents)
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::uint64_t data_size((kMinChunks + 1) * sep_.max_chunk_size);
  std::shared_ptr<std::istringstream> stream_in(new std::istringstream(
      RandomString(data_size)));
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
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

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptStreamCorruptChunk) {
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
  EXPECT_EQ(kSuccess, SelfEncrypt(stream_in, sep_, data_map, chunk_store));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
  ASSERT_EQ(kMinChunks + 1, data_map->chunks.size());
  EXPECT_TRUE(chunk_store->Delete(data_map->chunks[0].hash));
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[0].hash, random));
  EXPECT_FALSE(test_se::VerifyChunks(data_map, chunk_store));
  std::shared_ptr<std::ostringstream> stream_out(new std::ostringstream);
  ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, chunk_store, stream_out));
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptString) {
  {  // Invalid calls
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kNullPointer,
              SelfEncrypt(std::string("test"), sep_, std::shared_ptr<DataMap>(),
                          chunk_store));
    EXPECT_EQ(kNullPointer, SelfEncrypt(std::string("test"), sep_, data_map,
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
              SelfEncrypt(std::string(), sep_, data_map, chunk_store));
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
    EXPECT_EQ(kSuccess, SelfEncrypt(string_in, sep_, data_map, chunk_store));
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
    EXPECT_EQ(kSuccess, SelfEncrypt(string_in, sep_, data_map, chunk_store));
    EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
    EXPECT_TRUE(test_se::VerifyChunks(data_map, chunk_store));
    std::string string_out;
    EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, &string_out))
        << "Data size: " << data_size;
    ASSERT_PRED_FORMAT2(AssertStringsEqual, string_in, string_out);
  }
}

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptFile) {
  fs::path path_in(test_dir_ / "SelfEncryptFilesTestIn.dat");
  fs::path path_out(test_dir_ / "SelfEncryptFilesTestOut.dat");

  {  // Invalid calls
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    EXPECT_EQ(kIoError, SelfEncrypt(path_in, sep_, data_map, chunk_store));
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

TEST_P(SelfEncryptionParamTest, BEH_SelfEnDecryptMixed) {
  {  // String input, file output
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) *
                            sep_.max_chunk_size + kMinChunks +
                            RandomUint32() % sep_.max_chunk_size);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(string_in, sep_, data_map, chunk_store));
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

TEST_F(SelfEncryptionTest, BEH_ChunksExist) {
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

TEST_F(SelfEncryptionTest, BEH_DeleteChunks) {
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

INSTANTIATE_TEST_CASE_P(VarChunkSizes, SelfEncryptionParamTest, testing::Values(
    SelfEncryptionParams(1, 0, kMinChunks - 1),  // 1 Byte
    SelfEncryptionParams(1 << 8, 0, (1 << 8) * kMinChunks),  // 256 B, 3 chk inc
    SelfEncryptionParams(1 << 8, 1 << 5, 1 << 7),  // 256 Bytes
    SelfEncryptionParams(1 << 18, 1 << 8, 1 << 10)  // 256 KiB (default)
));

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
