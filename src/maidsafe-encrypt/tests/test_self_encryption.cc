/*******************************************************************************
 *  Copyright 2008 maidsafe.net limited                                        *
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
#include <iostream>
#include <memory>
#include <sstream>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace test_se {

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

}  // namespace test_se

class SelfEncryptionTest : public testing::Test {
 public:
  SelfEncryptionTest()
      : kRootDir_(test_se::TempDir() /
            ("maidsafe_TestSE_" + RandomAlphaNumericString(6))),
        kFilesDir_(kRootDir_ / "Files"),
        kChunksDir_(kRootDir_ / "Chunks") {}
  ~SelfEncryptionTest() {}
 protected:
  void SetUp() {
    if (fs::exists(kRootDir_))
      fs::remove_all(kRootDir_);
    fs::create_directories(kFilesDir_);
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
  const fs::path kRootDir_, kFilesDir_, kChunksDir_;
};

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ReasonableConfig) {
  EXPECT_LE(3, kMinChunks) << "Obfuscation requires at least 3 chunks.";
  EXPECT_LT(kMinChunks * kMaxIncludableChunkSize, kMaxIncludableDataSize) <<
      "Can't include more chunks in DataMap than the allowed total data size.";
  EXPECT_LT(kMaxIncludableChunkSize, kMaxChunkSize) <<
      "Can't include every chunk in the DataMap.";
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
  std::stringstream stream;

  //  make compressible string
  for (int i = 0; i < 1000; ++i)
    stream << "repeated text ";
  stream.seekg(stream.tellp() / 2);
  EXPECT_TRUE(utils::CheckCompressibility(&stream));

  //  make incompressible string
  stream.str("small text");
  stream.seekg(0);
  EXPECT_FALSE(utils::CheckCompressibility(&stream));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_CalculateChunkSizes) {
  std::vector<std::uint32_t> chunk_sizes;
  std::uint64_t data_size(0);
  EXPECT_FALSE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(0, chunk_sizes.size());

  chunk_sizes.clear();
  data_size = kMaxIncludableDataSize;
  EXPECT_FALSE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(0, chunk_sizes.size());

  chunk_sizes.clear();
  data_size = kMaxDataSize + 1;
  EXPECT_FALSE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(0, chunk_sizes.size());

  chunk_sizes.clear();
  data_size = kMaxIncludableDataSize + 1;
  EXPECT_TRUE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(kMinChunks, chunk_sizes.size());
  EXPECT_EQ(data_size, test_se::TotalChunkSize(chunk_sizes));

  chunk_sizes.clear();
  data_size = kMaxChunkSize * kMinChunks - 1;
  EXPECT_TRUE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(kMinChunks, chunk_sizes.size());
  EXPECT_EQ(data_size, test_se::TotalChunkSize(chunk_sizes));

  chunk_sizes.clear();
  data_size = kMaxChunkSize * kMinChunks;
  EXPECT_TRUE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(kMinChunks, chunk_sizes.size());
  for (size_t i = 0; i < chunk_sizes.size(); ++i)
    EXPECT_EQ(kMaxChunkSize, chunk_sizes[i]);
  EXPECT_EQ(data_size, test_se::TotalChunkSize(chunk_sizes));

  chunk_sizes.clear();
  std::uint64_t base(RandomUint32() % 6 + 4),
                extra(RandomUint32() % kMaxChunkSize);
  data_size = base * kMaxChunkSize + extra;
  EXPECT_TRUE(utils::CalculateChunkSizes(data_size, &chunk_sizes));
  EXPECT_EQ(base + 1, chunk_sizes.size());
  for (size_t i = 0; i < chunk_sizes.size(); ++i)
    if (i < chunk_sizes.size() - 1)
      EXPECT_EQ(kMaxChunkSize, chunk_sizes[i]);
    else
      EXPECT_EQ(extra, chunk_sizes[i]);
  EXPECT_EQ(data_size, test_se::TotalChunkSize(chunk_sizes));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ResizeObfuscationHash) {
  std::string input("abc");
  std::string hash = crypto::Hash<crypto::SHA512>(input);
  EXPECT_EQ(EncodeToHex(hash),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  std::string amended_hash("Rubbish");
  EXPECT_TRUE(utils::ResizeObfuscationHash(input, 65, &amended_hash));
  char appended(55);
  EXPECT_EQ(amended_hash, hash + appended);
  EXPECT_TRUE(utils::ResizeObfuscationHash(input, 10, &amended_hash));
  EXPECT_EQ(std::string("\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41"),
            amended_hash);
  EXPECT_TRUE(utils::ResizeObfuscationHash(input, 200, &amended_hash));
  EXPECT_EQ(std::string("\x91\xee\x3b\x36\xd\x3e\x5e\xe\xd\xe"),
            amended_hash.substr(190, 10));
  EXPECT_FALSE(utils::ResizeObfuscationHash(hash, 10, NULL));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ReadFile) {
  fs::path file_path(kChunksDir_ / "test.dat");
  std::string file_content;
  EXPECT_FALSE(utils::ReadFile(file_path, NULL));
  EXPECT_FALSE(utils::ReadFile(file_path, &file_content));
  EXPECT_TRUE(file_content.empty());
  test_se::CreateRandomFile(file_path, 3000 + RandomUint32() % 1000);
  EXPECT_TRUE(utils::ReadFile(file_path, &file_content));
  EXPECT_EQ(fs::file_size(file_path), file_content.size());
  EXPECT_EQ(crypto::HashFile<crypto::SHA512>(file_path),
            crypto::Hash<crypto::SHA512>(file_content));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_WriteFile) {
  fs::path file_path(kChunksDir_ / "test.dat");
  std::string file_content;
  EXPECT_FALSE(fs::exists(file_path));
  EXPECT_TRUE(utils::WriteFile(file_path, file_content));
  EXPECT_TRUE(fs::exists(file_path));
  EXPECT_EQ(0, fs::file_size(file_path));
  file_content = RandomString(3000 + RandomUint32() % 1000);
  EXPECT_TRUE(utils::WriteFile(file_path, file_content));
  EXPECT_EQ(crypto::Hash<crypto::SHA512>(file_content),
            crypto::HashFile<crypto::SHA512>(file_path));
  EXPECT_TRUE(utils::WriteFile(file_path, "moo"));
  EXPECT_TRUE(utils::ReadFile(file_path, &file_content));
  EXPECT_EQ("moo", file_content);
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptChunk) {
  std::string content(RandomString(3000 + RandomUint32() % 1000));
  std::string hash1(RandomString(64)), hash2(RandomString(64));

  EXPECT_EQ(content, utils::SelfDecryptChunk(
      utils::SelfEncryptChunk(content, hash1, hash2), hash1, hash2));

  EXPECT_NE(content, utils::SelfDecryptChunk(
      utils::SelfEncryptChunk(content, hash1, hash2), hash2, hash1));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptStream) {
  {  // Invalid calls
    DataMap data_map;
    std::istringstream stream;
    EXPECT_EQ(kInvalidInput,
              SelfEncrypt(&stream, kChunksDir_, false, &data_map));
    stream.str("test");
    EXPECT_EQ(kNullPointer,
              SelfEncrypt(&stream, kChunksDir_, false, NULL));
    EXPECT_EQ(kNullPointer,
              SelfEncrypt(NULL, kChunksDir_, false, &data_map));
  }

  {  // Little data, should end up completely in DM
    DataMap data_map;
    std::istringstream stream_in(RandomString(kMaxIncludableDataSize));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in.str());
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_EQ(0, data_map.chunks.size());
    EXPECT_EQ(kNoCompression, data_map.compression_type);
    EXPECT_EQ(kMaxIncludableDataSize, data_map.content.size());
    EXPECT_EQ(hash_in, crypto::Hash<crypto::SHA512>(data_map.content));
    std::ostringstream stream_out;
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, &stream_out));
    EXPECT_EQ(stream_in.str(), stream_out.str());
  }

  {  // Data just big enough to chunk
    DataMap data_map;
    std::istringstream stream_in(RandomString(kMaxIncludableDataSize + 1));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in.str());
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_EQ(kMinChunks, data_map.chunks.size());
    EXPECT_EQ(kNoCompression, data_map.compression_type);
    EXPECT_TRUE(data_map.content.empty());
    std::uint64_t total_size(0);
    for (auto it = data_map.chunks.begin(); it < data_map.chunks.end(); ++it) {
      EXPECT_FALSE(it->hash.empty());
      fs::path chunk_path(kChunksDir_ / EncodeToHex(it->hash));
      EXPECT_TRUE(fs::exists(chunk_path));
      EXPECT_TRUE(it->content.empty());
      EXPECT_EQ(it->size, fs::file_size(chunk_path));
      EXPECT_GE(kMaxChunkSize, it->size);
      EXPECT_EQ(it->hash, crypto::HashFile<crypto::SHA512>(chunk_path));
      EXPECT_FALSE(it->pre_hash.empty());
      EXPECT_EQ(it->size, it->pre_size);  // no compression
      total_size += it->pre_size;
    }
    EXPECT_EQ(kMaxIncludableDataSize + 1, total_size);
    std::ostringstream stream_out;
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, &stream_out));
    EXPECT_EQ(stream_in.str(), stream_out.str());
  }

  {  // Last chunk ends up in DM
    DataMap data_map;
    std::uint64_t data_size(kMinChunks * kMaxChunkSize +
                            kMaxIncludableChunkSize);
    std::istringstream stream_in(RandomString(data_size));
    std::string hash_in = crypto::Hash<crypto::SHA512>(stream_in.str());
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_EQ(kMinChunks + 1, data_map.chunks.size());
    EXPECT_EQ(kNoCompression, data_map.compression_type);
    EXPECT_TRUE(data_map.content.empty());
    std::uint64_t total_size(0);
    std::uint32_t i(0);
    for (auto it = data_map.chunks.begin(); it < data_map.chunks.end(); ++it) {
      if (i < kMinChunks) {
        // chunk is a file
        EXPECT_FALSE(it->hash.empty());
        fs::path chunk_path(kChunksDir_ / EncodeToHex(it->hash));
        EXPECT_TRUE(fs::exists(chunk_path));
        EXPECT_TRUE(it->content.empty());
        EXPECT_EQ(it->size, fs::file_size(chunk_path));
        EXPECT_EQ(kMaxChunkSize, it->size);
        EXPECT_EQ(it->hash, crypto::HashFile<crypto::SHA512>(chunk_path));
        EXPECT_FALSE(it->pre_hash.empty());
        EXPECT_EQ(it->size, it->pre_size);  // no compression
        total_size += it->pre_size;
      } else {
        // chunk is included in DataMap
        EXPECT_TRUE(it->hash.empty());
        EXPECT_FALSE(it->content.empty());
        EXPECT_EQ(kMaxIncludableChunkSize, it->content.size());
        EXPECT_EQ(it->size, it->content.size());
        EXPECT_EQ(it->pre_size, it->content.size());  // no compression
        EXPECT_EQ(it->pre_hash, crypto::Hash<crypto::SHA512>(it->content));
        total_size += it->content.size();
      }
      ++i;
    }
    EXPECT_EQ(data_size, total_size);
    std::ostringstream stream_out;
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, &stream_out));
    EXPECT_EQ(stream_in.str(), stream_out.str());
  }

  {  // First chunk is deleted
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    std::istringstream stream_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    EXPECT_TRUE(fs::remove(kChunksDir_ / EncodeToHex(data_map.chunks[0].hash)));
    std::ostringstream stream_out;
    ASSERT_EQ(kFilesystemError,
              SelfDecrypt(data_map, kChunksDir_, &stream_out));
  }

  {  // First chunk is changed in size (and contents)
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    std::istringstream stream_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    test_se::CreateRandomFile(
        kChunksDir_ / EncodeToHex(data_map.chunks[0].hash),
        data_map.chunks[0].size / 2);
    std::ostringstream stream_out;
    ASSERT_EQ(kIoError, SelfDecrypt(data_map, kChunksDir_, &stream_out));
  }

  {  // First chunk is changed only in contents
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    std::istringstream stream_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(&stream_in, kChunksDir_, false, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    test_se::CreateRandomFile(
        kChunksDir_ / EncodeToHex(data_map.chunks[0].hash),
        data_map.chunks[0].size);
    std::ostringstream stream_out;
    ASSERT_EQ(kDecryptError, SelfDecrypt(data_map, kChunksDir_, &stream_out));
  }
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptString) {
  {  // Invalid calls
    DataMap data_map;
    EXPECT_EQ(kInvalidInput, SelfEncrypt("", kChunksDir_, false, &data_map));
    EXPECT_EQ(kNullPointer, SelfEncrypt("test", kChunksDir_, false, NULL));
  }

  {  // Random data test
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(string_in, kChunksDir_, false, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    std::string string_out;
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, &string_out));
    ASSERT_EQ(string_in, string_out);
  }
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptFile) {
  fs::path path_in(kFilesDir_ / "SelfEncryptFilesTestIn.dat");
  fs::path path_out(kFilesDir_ / "SelfEncryptFilesTestOut.dat");

  {  // Invalid calls
    DataMap data_map;
    EXPECT_EQ(kInvalidInput, SelfEncrypt(path_in, kChunksDir_, &data_map));
    test_se::CreateRandomFile(path_in, 0);
    EXPECT_EQ(kInvalidInput, SelfEncrypt(path_in, kChunksDir_, &data_map));
    test_se::CreateRandomFile(path_in, 1);
    EXPECT_EQ(kNullPointer, SelfEncrypt(path_in, kChunksDir_, NULL));
  }

  {  // Random data test
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, kChunksDir_, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, true, path_out));
    EXPECT_TRUE(fs::exists(path_out));
    EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path_in),
              crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // Try restoring existing file
    DataMap data_map;
    EXPECT_EQ(kFileAlreadyExists,
              SelfDecrypt(data_map, kChunksDir_, false, path_out));
  }
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptMixed) {
  {  // String input, file output
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    std::string string_in(RandomString(data_size));
    EXPECT_EQ(kSuccess, SelfEncrypt(string_in, kChunksDir_, false, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    fs::path path_out(kFilesDir_ / "SelfEncryptFilesTestOut.dat");
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, true, path_out));
    EXPECT_TRUE(fs::exists(path_out));
    EXPECT_EQ(crypto::Hash<crypto::SHA512>(string_in),
              crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // File input, string output
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    fs::path path_in(kFilesDir_ / "SelfEncryptFilesTestIn.dat");
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncrypt(path_in, kChunksDir_, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    std::string string_out;
    ASSERT_EQ(kSuccess, SelfDecrypt(data_map, kChunksDir_, &string_out));
    EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path_in),
              crypto::Hash<crypto::SHA512>(string_out));
  }
}

TEST_F(SelfEncryptionTest, DISABLED_BEH_ENCRYPT_Compression) {
  // TODO Test if compression can be toggled, if it's noticable in sizes, and
  //      if the resulting chunk sizes are constant except for the last one.
  FAIL() << "Not implemented yet.";
}

TEST_F(SelfEncryptionTest, DISABLED_FUNC_ENCRYPT_Benchmark) {
  const size_t kRunCount(17);
  for (size_t run = 0; run < kRunCount; ++run) {
    size_t repetitions((1 << 15) >> std::min(size_t(11), run));
    size_t data_size(64 << run);

    printf("Timing Self-encryption of %d strings à %d bytes (run %d/%d)...\n",
           repetitions, data_size, run + 1, kRunCount);

    std::vector<std::shared_ptr<std::istringstream>> contents;
    std::vector<DataMap> data_maps;
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::istringstream> stream_ptr(
          new std::istringstream(RandomString(data_size)));
      contents.push_back(stream_ptr);
    }
    ASSERT_EQ(repetitions, contents.size());
    data_maps.resize(repetitions);

    boost::timer timer;
    for (size_t i = 0; i < repetitions; ++i)
      SelfEncrypt(contents[i].get(), kChunksDir_, false, &(data_maps[i]));
    double encryption_time(timer.elapsed());
    printf("Self-encrypted %d strings à %d bytes in %.2f seconds "
          "(%.3f MB/s).\n", repetitions, data_size, encryption_time,
          (repetitions * data_size) / encryption_time / 1048576.0);

    std::vector<std::shared_ptr<std::ostringstream>> dec_contents;
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::ostringstream> stream_ptr(new std::ostringstream);
      dec_contents.push_back(stream_ptr);
    }
    ASSERT_EQ(repetitions, dec_contents.size());

    timer.restart();
    for (size_t i = 0; i < repetitions; ++i)
      SelfDecrypt(data_maps[i], kChunksDir_, dec_contents[i].get());
    double decryption_time(timer.elapsed());
    printf("Self-decrypted %d strings à %d bytes in %.2f seconds "
          "(%.3f MB/s).\n", repetitions, data_size, decryption_time,
          (repetitions * data_size) / decryption_time / 1048576.0);

    for (size_t i = 0; i < repetitions; ++i)
      EXPECT_EQ(contents[i]->str(), dec_contents[i]->str());
  }
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
