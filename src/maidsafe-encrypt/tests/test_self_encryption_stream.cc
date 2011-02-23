/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_self_encryption_stream.cc
 * @brief Tests for the self-encryption streaming interface.
 * @date  2011-02-19
 */

#include <cstdint>
#include <iostream>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "gtest/gtest.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption_stream.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace test_ses {

// TODO(Fraser#5#): Replace with fs::temp_directory_path() from boost 1.45
fs::path TempDir() {
#if defined(PD_WIN32)
  fs::path temp_dir("");
  if (std::getenv("TEMP"))
    temp_dir = std::getenv("TEMP");
  else if (std::getenv("TMP"))
    temp_dir = std::getenv("TMP");
#elif defined(P_tmpdir)
  fs::path temp_dir(P_tmpdir);
#else
  fs::path temp_dir("");
  if (std::getenv("TMPDIR")) {
    temp_dir = std::getenv("TMPDIR");
  } else {
    temp_dir = fs::path("/tmp");
    try {
      if (!fs::exists(temp_dir))
        temp_dir.clear();
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In TempDir: %s\n", e.what());
#endif
      temp_dir.clear();
    }
  }
#endif
  size_t last_char = temp_dir.string().size() - 1;
  if (temp_dir.string()[last_char] == '/' ||
      temp_dir.string()[last_char] == '\\') {
    std::string temp_str = temp_dir.string();
    temp_str.resize(last_char);
    temp_dir = fs::path(temp_str);
  }
  return temp_dir;
}

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

}  // namespace test_ses

class SelfEncryptionStreamTest : public testing::Test {
 public:
  SelfEncryptionStreamTest()
      : kRootDir_(test_ses::TempDir() /
            ("maidsafe_TestSES_" + RandomAlphaNumericString(6))),
        kChunksDir_(kRootDir_ / "Chunks") {}
  ~SelfEncryptionStreamTest() {}
 protected:
  void SetUp() {
    if (fs::exists(kRootDir_))
      fs::remove_all(kRootDir_);
    fs::create_directories(kChunksDir_);
  }
  void TearDown() {
    try {
      if (fs::exists(kRootDir_))
        fs::remove_all(kRootDir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  const fs::path kRootDir_, kChunksDir_;
};

TEST_F(SelfEncryptionStreamTest, BEH_ENCRYPT_DeviceInit) {
  DataMap data_map;
  {
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    EXPECT_EQ(kChunksDir_, sed.chunk_dir_);
    EXPECT_EQ(0, sed.total_size_);
  }
  data_map.content = RandomString(123);
  {
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    EXPECT_EQ(123, sed.total_size_);
  }
  for (int i = 1; i <= 5; ++i) {
    ChunkDetails chunk;
    chunk.pre_size = i * 100;
    data_map.chunks.push_back(chunk);
  }
  {
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    EXPECT_EQ(1500, sed.total_size_);
  }
}

TEST_F(SelfEncryptionStreamTest, BEH_ENCRYPT_DeviceRead) {
  {
    DataMap data_map;
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    std::string content(10, 0);
    EXPECT_EQ(-1, sed.read(&(content[0]), 10));
    EXPECT_EQ(-1, sed.read(&(content[0]), 0));
  }
  {  // unencrypted whole content in DataMap
    DataMap data_map;
    data_map.content = RandomString(100);

    SelfEncryptionDevice sed(data_map, kChunksDir_);
    std::string content1(data_map.content.size(), 0);
    EXPECT_EQ(data_map.content.size(),
              sed.read(&(content1[0]), data_map.content.size()));
    EXPECT_EQ(data_map.content, content1);
    EXPECT_EQ(-1, sed.read(&(content1[0]), data_map.content.size()));
    EXPECT_EQ(data_map.content, content1);
    std::string content2(data_map.content.size(), 0);
    EXPECT_EQ(data_map.content.size() - 10, sed.seek(-10, std::ios_base::end));
    EXPECT_EQ(10, sed.read(&(content2[0]), data_map.content.size()));
    EXPECT_EQ(data_map.content.substr(data_map.content.size() - 10),
              content2.substr(0, 10));
    std::string content3(data_map.content.size(), 0);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(10, sed.read(&(content3[0]), 10));
    EXPECT_EQ(data_map.content.substr(0, 10), content3.substr(0, 10));
  }
  {  // unencrypted chunk in DataMap
    DataMap data_map;
    ChunkDetails chunk;
    chunk.content = RandomString(100);
    chunk.pre_hash = crypto::Hash<crypto::SHA512>(chunk.content);
    chunk.pre_size = chunk.content.size();
    chunk.size = chunk.content.size();
    data_map.chunks.push_back(chunk);

    SelfEncryptionDevice sed(data_map, kChunksDir_);
    std::string content1(chunk.content.size(), 0);
    EXPECT_EQ(chunk.content.size(),
              sed.read(&(content1[0]), chunk.content.size()));
    EXPECT_EQ(chunk.content, content1);
    EXPECT_EQ(-1, sed.read(&(content1[0]), chunk.content.size()));
    EXPECT_EQ(chunk.content, content1);
    std::string content2(chunk.content.size(), 0);
    EXPECT_EQ(chunk.content.size() - 10, sed.seek(-10, std::ios_base::end));
    EXPECT_EQ(10, sed.read(&(content2[0]), chunk.content.size()));
    EXPECT_EQ(chunk.content.substr(chunk.content.size() - 10),
              content2.substr(0, 10));
    std::string content3(chunk.content.size(), 0);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(10, sed.read(&(content3[0]), 10));
    EXPECT_EQ(chunk.content.substr(0, 10), content3.substr(0, 10));
  }
  {  // single chunk in file
    DataMap data_map;
    std::string content_orig(RandomString(100));
    std::string hash_orig(crypto::Hash<crypto::SHA512>(content_orig));
    std::string content_enc(utils::SelfEncryptChunk(content_orig, hash_orig,
                                                    hash_orig));
    std::string hash_enc(crypto::Hash<crypto::SHA512>(content_enc));
    fs::path chunk_path(kChunksDir_ / EncodeToHex(hash_enc));
    EXPECT_TRUE(utils::WriteFile(chunk_path, content_enc));
    ChunkDetails chunk;
    chunk.pre_hash = hash_orig;
    chunk.pre_size = content_orig.size();
    chunk.hash = hash_enc;
    chunk.size = content_enc.size();
    data_map.chunks.push_back(chunk);

    SelfEncryptionDevice sed(data_map, kChunksDir_);
    std::string content1(content_orig.size(), 0);
    EXPECT_EQ(content_orig.size(),
              sed.read(&(content1[0]), content_orig.size()));
    EXPECT_EQ(content_orig, content1);
    std::string content2(content_orig.size(), 0);
    test_ses::CreateRandomFile(chunk_path, 123);
    EXPECT_EQ(-1, sed.read(&(content2[0]), content_orig.size()));
    EXPECT_TRUE(fs::remove(chunk_path));
    EXPECT_EQ(-1, sed.read(&(content2[0]), content_orig.size()));
  }
  { // read across borders of multiple chunks
    const size_t kChunkCount(5);
    const size_t kChunkSize(10);
    DataMap data_map;
    std::vector<std::string> content_orig;

    for (size_t i = 0; i < kChunkCount; ++i) {
      ChunkDetails chunk;
      content_orig.push_back(std::string(kChunkSize,
                                         'a' + static_cast<char>(i)));
      chunk.pre_hash = crypto::Hash<crypto::SHA512>(content_orig.back());
      chunk.pre_size = content_orig.back().size();
      data_map.chunks.push_back(chunk);
    }

    for (size_t i = 0; i < kChunkCount; ++i) {
      std::string content_enc(utils::SelfEncryptChunk(
          content_orig[i], data_map.chunks[(i + 1) % kChunkCount].pre_hash,
          data_map.chunks[(i + 2) % kChunkCount].pre_hash));
      std::string hash_enc(crypto::Hash<crypto::SHA512>(content_enc));
      data_map.chunks[i].hash = hash_enc;
      data_map.chunks[i].size = content_enc.size();
      EXPECT_TRUE(utils::WriteFile(kChunksDir_ / EncodeToHex(hash_enc),
                                   content_enc));
    }

    SelfEncryptionDevice sed(data_map, kChunksDir_);

    // read and check each character in the stream
    for (size_t i = 0; i < kChunkCount * kChunkSize; ++i) {
      char c(0);
      EXPECT_EQ(1, sed.read(&c, 1));
      EXPECT_EQ('a' + static_cast<char>(i / kChunkSize), c);
    }

    // read and check each chunk
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    for (size_t i = 0; i < kChunkCount; ++i) {
      std::string content(kChunkSize, 0);
      EXPECT_EQ(kChunkSize, sed.read(&(content[0]), kChunkSize));
      EXPECT_EQ(std::string(kChunkSize, 'a' + static_cast<char>(i)), content);
    }

    // read half of one chunk and half of the next
    EXPECT_EQ(kChunkSize / 2, sed.seek(kChunkSize / 2, std::ios_base::beg));
    for (size_t i = 0; i < kChunkCount - 1; ++i) {
      std::string content(kChunkSize, 0);
      EXPECT_EQ(kChunkSize, sed.read(&(content[0]), kChunkSize));
      EXPECT_EQ(std::string(kChunkSize / 2, 'a' + static_cast<char>(i)).
                append(kChunkSize / 2, 'b' + static_cast<char>(i)), content);
    }

    std::string expected_content;
    for (size_t i = 0; i < kChunkCount; ++i)
      expected_content.append(kChunkSize, 'a' + static_cast<char>(i));

    // read the whole file
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    std::string content(kChunkCount * kChunkSize, 0);
    EXPECT_EQ(content.size(), sed.read(&(content[0]), content.size()));
    EXPECT_EQ(expected_content, content);

    // read the whole file except first and last byte
    EXPECT_EQ(1, sed.seek(1, std::ios_base::beg));
    content.resize(kChunkCount * kChunkSize - 2);
    EXPECT_EQ(content.size(), sed.read(&(content[0]), content.size()));
    EXPECT_EQ(expected_content.substr(1, content.size()), content);
  }
}

TEST_F(SelfEncryptionStreamTest, BEH_ENCRYPT_DeviceSeek) {
  DataMap data_map;
  {
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
  }
  for (int i = 1; i <= 5; ++i) {
    ChunkDetails chunk;
    chunk.pre_size = i * 100;
    data_map.chunks.push_back(chunk);
  }
  {
    SelfEncryptionDevice sed(data_map, kChunksDir_);
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(123, sed.seek(123, std::ios_base::beg));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(1500, sed.seek(1500, std::ios_base::beg));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1501, std::ios_base::beg));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(123, sed.seek(123, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(246, sed.seek(123, std::ios_base::cur));
    EXPECT_EQ(246, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1400, std::ios_base::cur));
    EXPECT_EQ(246, sed.offset_);
    EXPECT_EQ(123, sed.seek(-123, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-124, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(0, sed.seek(-123, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(-1, sed.seek(1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(1500, sed.seek(0, std::ios_base::end));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(500, sed.seek(-1000, std::ios_base::end));
    EXPECT_EQ(500, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1501, std::ios_base::end));
    EXPECT_EQ(500, sed.offset_);
    EXPECT_EQ(0, sed.seek(-1500, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
  }
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
