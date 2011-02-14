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

#include <memory>
#include <cstdint>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem3;

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
  typedef std::shared_ptr<DataIOHandler> DataIoHandlerPtr;
  typedef std::shared_ptr<std::string> StringPtr;

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
  //  make compressible .txt file
  fs::path path1(kFilesDir_ / "compressible.txt");
  fs::ofstream ofs1;
  ofs1.open(path1);
  for (int i = 0; i < 1000; ++i)
    ofs1 << "repeated text ";
  ofs1.close();

  //  make incompressible .txt file
  fs::path path2(kFilesDir_ / "incompressible.txt");
  fs::ofstream ofs2;
  ofs2.open(path2);
  ofs2 << "small text";
  ofs2.close();

  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));
  DataIoHandlerPtr input_handler2(new FileIOHandler(path2, true));
  EXPECT_TRUE(utils::CheckCompressibility(input_handler1));
  EXPECT_FALSE(utils::CheckCompressibility(input_handler2));
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
  for (int i = 0; i < chunk_sizes.size(); ++i)
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

/*
TEST_F(SelfEncryptionTest, BEH_ENCRYPT_GeneratePreEncryptionHashes) {
  fs::path path1(kInputDir_ / "GeneratePreEncryptionHashesTest01.txt");
  fs::ofstream ofs1;
  ofs1.open(path1);
  ofs1 << "abc";
  ofs1 << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijkl"
          "mnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  ofs1 << "abc";
  ofs1.close();
  protobuf::DataMap data_map;
  data_map.add_chunk_size(3);
  data_map.add_chunk_size(112);
  data_map.add_chunk_size(3);

  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));
  EXPECT_TRUE(utils::GeneratePreEncryptionHashes(input_handler1, &data_map));
  EXPECT_EQ(3, data_map.chunk_name_size());
  EXPECT_EQ(EncodeToHex(data_map.chunk_name(0)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  EXPECT_EQ(EncodeToHex(data_map.chunk_name(1)),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
        "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  EXPECT_EQ(EncodeToHex(data_map.chunk_name(2)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}
*/

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

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEnDecryptFile) {
  fs::path path_in(kFilesDir_ / "SelfEncryptFilesTestIn.dat");
  fs::path path_out(kFilesDir_ / "SelfEncryptFilesTestOut.dat");

  {  // Invalid calls
    DataMap data_map;
    EXPECT_EQ(kInvalidInput, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    test_se::CreateRandomFile(path_in, 0);
    EXPECT_EQ(kInvalidInput, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    test_se::CreateRandomFile(path_in, 1);
    EXPECT_EQ(kNullPointer, SelfEncryptFile(path_in, kChunksDir_, NULL));
  }

  {  // Small file, should end up completely in DM
    DataMap data_map;
    test_se::CreateRandomFile(path_in, kMaxIncludableDataSize);
    std::string hash_in = crypto::HashFile<crypto::SHA512>(path_in);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_EQ(0, data_map.chunks.size());
    EXPECT_EQ(hash_in, data_map.data_hash);
    if (data_map.compression_type == kNoCompression) {
      EXPECT_EQ(kMaxIncludableDataSize, data_map.content.size());
      EXPECT_EQ(hash_in, crypto::Hash<crypto::SHA512>(data_map.content));
    }
    ASSERT_EQ(kSuccess,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
    EXPECT_EQ(hash_in, crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // File just big enough to chunk
    DataMap data_map;
    test_se::CreateRandomFile(path_in, kMaxIncludableDataSize + 1);
    std::string hash_in = crypto::HashFile<crypto::SHA512>(path_in);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_EQ(kMinChunks, data_map.chunks.size());
    EXPECT_EQ(hash_in, data_map.data_hash);
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
      total_size += it->pre_size;
    }
    EXPECT_EQ(kMaxIncludableDataSize + 1, total_size);
    ASSERT_EQ(kSuccess,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
    EXPECT_EQ(kMaxIncludableDataSize + 1, fs::file_size(path_out));
    EXPECT_EQ(hash_in, crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // Last chunk ends up in DM
    DataMap data_map;
    std::uint64_t data_size(kMinChunks * kMaxChunkSize +
                            kMaxIncludableChunkSize);
    test_se::CreateRandomFile(path_in, data_size);
    std::string hash_in = crypto::HashFile<crypto::SHA512>(path_in);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_EQ(kMinChunks + 1, data_map.chunks.size());
    EXPECT_EQ(hash_in, data_map.data_hash);
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
        if (data_map.compression_type == kNoCompression)
          EXPECT_EQ(it->pre_size, it->size);
        total_size += it->pre_size;
      } else {
        // chunk is included in DataMap
        EXPECT_TRUE(it->hash.empty());
        EXPECT_FALSE(it->content.empty());
        EXPECT_EQ(kMaxIncludableChunkSize, it->content.size());
        EXPECT_EQ(it->size, it->content.size());
        if (data_map.compression_type == kNoCompression) {
          EXPECT_EQ(it->pre_size, it->content.size());
          EXPECT_EQ(it->pre_hash, crypto::Hash<crypto::SHA512>(it->content));
        }
        total_size += it->content.size();
      }
      ++i;
    }
    EXPECT_EQ(data_size, total_size);
    ASSERT_EQ(kSuccess,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
    EXPECT_EQ(hash_in, crypto::HashFile<crypto::SHA512>(path_out));
  }

  {  // Try restoring existing file
    DataMap data_map;
    EXPECT_EQ(kFileAlreadyExists,
              SelfDecryptToFile(data_map, kChunksDir_, false, path_out));
  }

  {  // First chunk is deleted
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    EXPECT_TRUE(fs::remove(kChunksDir_ / EncodeToHex(data_map.chunks[0].hash)));
    ASSERT_EQ(kFilesystemError,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
  }

  {  // First chunk is changed in size (and contents)
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    test_se::CreateRandomFile(
        kChunksDir_ / EncodeToHex(data_map.chunks[0].hash),
        data_map.chunks[0].size / 2);
    ASSERT_EQ(kIoError,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
  }

  {  // First chunk is changed only in contents
    DataMap data_map;
    std::uint64_t data_size((RandomUint32() % kMinChunks + 1) * kMaxChunkSize +
                            RandomUint32() % kMaxIncludableChunkSize);
    test_se::CreateRandomFile(path_in, data_size);
    EXPECT_EQ(kSuccess, SelfEncryptFile(path_in, kChunksDir_, &data_map));
    EXPECT_LE(kMinChunks, data_map.chunks.size());
    test_se::CreateRandomFile(
        kChunksDir_ / EncodeToHex(data_map.chunks[0].hash),
        data_map.chunks[0].size);
    ASSERT_EQ(kDecryptError,
              SelfDecryptToFile(data_map, kChunksDir_, true, path_out));
  }
}

TEST_F(SelfEncryptionTest, DISABLED_BEH_ENCRYPT_SelfEnDecryptString) {
  FAIL();
}

TEST_F(SelfEncryptionTest, DISABLED_BEH_ENCRYPT_SelfEnDecryptMixed) {
  FAIL();
}

TEST_F(SelfEncryptionTest, DISABLED_BEH_ENCRYPT_Benchmark) {
  FAIL();
//   const size_t kRunCount(2); //17);
//   for (size_t run = 0; run < kRunCount; ++run) {
//     size_t repetitions(1); //(1 << 15) >> std::min(size_t(11), run));
//     size_t data_size(64 << run);
//
//     printf("Timing Self-encryption of %d strings à %d bytes (run %d/%d)...\n",
//           repetitions, data_size, run + 1, kRunCount);
//
//     std::vector<std::shared_ptr<std::string>> contents;
//     std::vector<protobuf::DataMap> data_maps;
//     std::vector<DataIoHandlerPtr> io_handlers;
//     std::vector<std::map<std::string, fs::path>> chunk_maps;
//     for (size_t i = 0; i < repetitions; ++i) {
//       StringPtr content(new std::string(RandomString(data_size)));
//       contents.push_back(content);
//       protobuf::DataMap data_map;
//       data_map.set_file_hash(crypto::Hash<crypto::SHA512>(*(contents.back())));
//       data_maps.push_back(data_map);
//       DataIoHandlerPtr io_handler(new StringIOHandler(contents.back(), true));
//       io_handlers.push_back(io_handler);
//       std::map<std::string, fs::path> chunk_map;
//       chunk_maps.push_back(chunk_map);
//     }
//     ASSERT_EQ(repetitions, contents.size());
//     ASSERT_EQ(repetitions, data_maps.size());
//     ASSERT_EQ(repetitions, io_handlers.size());
//     ASSERT_EQ(repetitions, chunk_maps.size());
//
//     boost::timer timer;
//     for (size_t i = 0; i < repetitions; ++i)
//       utils::EncryptContent(io_handlers[i], kOutputDir_, &(data_maps[i]),
//                             &(chunk_maps[i]));
//     double encryption_time(timer.elapsed());
//     printf("Self-encrypted %d strings à %d bytes in %.2f seconds "
//           "(%.3f MB/s).\n", repetitions, data_size, encryption_time,
//           (repetitions * data_size) / encryption_time / 1048576.0);
//
//     std::vector<std::shared_ptr<std::string>> dec_contents;
//     std::vector<std::vector<fs::path>> chunk_paths;
//     for (size_t i = 0; i < repetitions; ++i) {
//       chunk_paths.push_back(MapToVector(chunk_maps[i]));
//       StringPtr content(new std::string);
//       dec_contents.push_back(content);
//       io_handlers[i].reset(new StringIOHandler(dec_contents.back(), false));
//     }
//     ASSERT_EQ(repetitions, chunk_paths.size());
//     ASSERT_EQ(repetitions, dec_contents.size());
//
//     timer.restart();
//     for (size_t i = 0; i < repetitions; ++i)
//       utils::DecryptContent(data_maps[i], chunk_paths[i], 0, io_handlers[i]);
//     double decryption_time(timer.elapsed());
//     printf("Self-decrypted %d strings à %d bytes in %.2f seconds "
//           "(%.3f MB/s).\n", repetitions, data_size, decryption_time,
//           (repetitions * data_size) / decryption_time / 1048576.0);
//
//     for (size_t i = 0; i < repetitions; ++i)
//       EXPECT_EQ(*(contents[i]), *(dec_contents[i]));
//   }
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
