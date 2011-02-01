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
#include "gtest/gtest.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/data_map.pb.h"
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
                         const std::uint64_t &filesize) {
  fs::ofstream ofs(file_path, std::ios::binary | std::ios::out |
                              std::ios::trunc);
  if (filesize != 0) {
    size_t stringsize = (filesize > 100000) ? 100000 :
                        static_cast<size_t>(filesize);
    std::uint64_t remainingsize = filesize;
    std::string rand_str = RandomString(2 * stringsize);
    std::string file_content;
    std::uint64_t start_pos = 0;
    while (remainingsize) {
      srand(17);
      start_pos = rand() % stringsize;  // NOLINT (Fraser)
      if (remainingsize < stringsize) {
        stringsize = static_cast<size_t>(remainingsize);
        file_content = rand_str.substr(0, stringsize);
      } else {
        file_content = rand_str.substr(static_cast<size_t>(start_pos),
                                       stringsize);
      }
      ofs.write(file_content.c_str(), file_content.size());
      remainingsize -= stringsize;
    }
  }
  ofs.close();
  return file_path;
}

}  // namespace test_se

class SelfEncryptionTest : public testing::Test {
 public:
  SelfEncryptionTest()
      : kRootDir_(test_se::TempDir() /
            ("maidsafe_TestSE_" + RandomAlphaNumericString(6))),
        kInputDir_(kRootDir_ / "Inputs"),
        kOutputDir_(kRootDir_ / "Outputs") {}
  ~SelfEncryptionTest() {}
 protected:
  typedef std::shared_ptr<DataIOHandler> DataIoHandlerPtr;
  typedef std::shared_ptr<std::string> StringPtr;
  void SetUp() {
    if (fs::exists(kRootDir_))
      fs::remove_all(kRootDir_);
    fs::create_directories(kInputDir_);
    fs::create_directories(kOutputDir_);
//    done_chunks_.clear();
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
  const fs::path kRootDir_, kInputDir_, kOutputDir_;
//  std::set<std::string> done_chunks_;
};

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_CheckEntry) {
  fs::path file_path(kInputDir_ / "CheckEntryTest01.txt");
  DataIoHandlerPtr input_handler(new FileIOHandler(file_path, true));
  test_se::CreateRandomFile(file_path, 0);
  EXPECT_EQ(kInputTooSmall, utils::CheckEntry(input_handler));
  fs::remove(file_path);

  test_se::CreateRandomFile(file_path, 1);
  EXPECT_EQ(kInputTooSmall, utils::CheckEntry(input_handler));
  fs::remove(file_path);

  test_se::CreateRandomFile(file_path, 2);
  EXPECT_EQ(kSuccess, utils::CheckEntry(input_handler));
  fs::remove(file_path);

  test_se::CreateRandomFile(file_path, 1234567);
  EXPECT_EQ(kSuccess, utils::CheckEntry(input_handler));
  fs::remove(file_path);
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_CheckCompressibility) {
  //  make compressible .txt file
  fs::path path1(kInputDir_ / "compressible.txt");
  fs::ofstream ofs1;
  ofs1.open(path1);
  for (int i = 0; i < 1000; ++i)
    ofs1 << "repeated text ";
  ofs1.close();

  //  make incompressible .txt file
  fs::path path2(kInputDir_ / "incompressible.txt");
  fs::ofstream ofs2;
  ofs2.open(path2);
  ofs2 << "small text";
  ofs2.close();

  //  make compressible file, but with extension for incompressible file
  fs::path path3(kInputDir_ / "incompressible.7z");
  fs::ofstream ofs3;
  ofs3.open(path3);
  for (int i = 0; i < 1000; ++i)
    ofs3 << "repeated text ";
  ofs3.close();

  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));
  DataIoHandlerPtr input_handler2(new FileIOHandler(path2, true));
  DataIoHandlerPtr input_handler3(new FileIOHandler(path3, true));
  EXPECT_TRUE(utils::CheckCompressibility(input_handler1));
  EXPECT_FALSE(utils::CheckCompressibility(input_handler2));
  EXPECT_FALSE(utils::CheckCompressibility(input_handler3));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_ChunkAddition) {
  EXPECT_EQ(-8, utils::ChunkAddition('0'));
  EXPECT_EQ(-7, utils::ChunkAddition('1'));
  EXPECT_EQ(-6, utils::ChunkAddition('2'));
  EXPECT_EQ(-5, utils::ChunkAddition('3'));
  EXPECT_EQ(-4, utils::ChunkAddition('4'));
  EXPECT_EQ(-3, utils::ChunkAddition('5'));
  EXPECT_EQ(-2, utils::ChunkAddition('6'));
  EXPECT_EQ(-1, utils::ChunkAddition('7'));
  EXPECT_EQ(0, utils::ChunkAddition('8'));
  EXPECT_EQ(1, utils::ChunkAddition('9'));
  EXPECT_EQ(2, utils::ChunkAddition('a'));
  EXPECT_EQ(3, utils::ChunkAddition('b'));
  EXPECT_EQ(4, utils::ChunkAddition('c'));
  EXPECT_EQ(5, utils::ChunkAddition('d'));
  EXPECT_EQ(6, utils::ChunkAddition('e'));
  EXPECT_EQ(7, utils::ChunkAddition('f'));
  EXPECT_EQ(2, utils::ChunkAddition('A'));
  EXPECT_EQ(3, utils::ChunkAddition('B'));
  EXPECT_EQ(4, utils::ChunkAddition('C'));
  EXPECT_EQ(5, utils::ChunkAddition('D'));
  EXPECT_EQ(6, utils::ChunkAddition('E'));
  EXPECT_EQ(7, utils::ChunkAddition('F'));
  EXPECT_EQ(0, utils::ChunkAddition('g'));
  EXPECT_EQ(0, utils::ChunkAddition(' '));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_CalculateChunkSizes) {
  // make file of size larger than (max no of chunks) * (default chunk size)
  fs::path test_file1(kInputDir_ / "CalculateChunkSizesTest01.txt");
  std::uint64_t file_size1 = kDefaultChunkSize * kMaxChunks * 2;
  fs::path path1(test_se::CreateRandomFile(test_file1, file_size1));
  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));

  // make file of size exactly (max no of chunks) * (default chunk size)
  fs::path test_file2(kInputDir_ / "CalculateChunkSizesTest02.txt");
  std::uint64_t file_size2 = kDefaultChunkSize * kMaxChunks;
  fs::path path2(test_se::CreateRandomFile(test_file2, file_size2));
  DataIoHandlerPtr input_handler2(new FileIOHandler(path2, true));

  // make file of size between (max no of chunks) * (default chunk size)
  // & (min no of chunks) * (default chunk size)
  fs::path test_file3(kInputDir_ / "CalculateChunkSizesTest03.txt");
  std::uint64_t file_size3 = kDefaultChunkSize * (kMaxChunks+kMinChunks)/2;
  fs::path path3(test_se::CreateRandomFile(test_file3, file_size3));
  DataIoHandlerPtr input_handler3(new FileIOHandler(path3, true));

  //  make file of size smaller than (min no of chunks) * (default chunk size)
  fs::path test_file4(kInputDir_ / "CalculateChunkSizesTest04.txt");
  std::uint64_t file_size4 = kDefaultChunkSize * kMinChunks/2;
  fs::path path4(test_se::CreateRandomFile(test_file4, file_size4));
  DataIoHandlerPtr input_handler4(new FileIOHandler(path4, true));

  //  make file of size 4 bytes
  fs::path test_file5(kInputDir_ / "CalculateChunkSizesTest05.txt");
  std::uint64_t file_size5 = 4;
  fs::path path5(test_se::CreateRandomFile(test_file5, file_size5));
  DataIoHandlerPtr input_handler5(new FileIOHandler(path5, true));

  //  set file hash so that each chunk size is unaltered
  protobuf::DataMap data_map;
  std::string file_hash("8888888888888888888888888888888888888888");
  std::uint16_t chunk_count(0);
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler1, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  std::uint64_t chunk_size_total(0);
  for (int i = 0; i < chunk_count; ++i) {
    EXPECT_EQ(file_size1 / kMaxChunks, data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_EQ(file_size1, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler2, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count; ++i) {
    EXPECT_EQ(kDefaultChunkSize, data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_EQ(file_size2, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler3, &data_map,
                                         &chunk_count));
  // std::cout << "File Size: " << file_size3 << std::endl;
  // std::cout << "Default: " << kDefaultChunkSize << "\tChunk[0]: "
  // << data_map.chunk_size(0) << std::endl;
  for (int i = 1; i < chunk_count - 1; ++i) {
    // std::cout << "Default: " << kDefaultChunkSize << "\tChunk[" << i << "]:
    //  " << data_map.chunk_size(i) << std::endl;
    EXPECT_EQ(data_map.chunk_size(i - 1), data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  // std::cout << "Default: " << kDefaultChunkSize << "\tChunk["
  // << chunk_count - 1;
  // std::cout << "]: " << data_map.chunk_size(chunk_count - 1) << std::endl;
  EXPECT_TRUE(data_map.chunk_size(0) > kDefaultChunkSize);
  chunk_size_total += data_map.chunk_size(0);
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size3, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler4, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMinChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count; ++i) {
    EXPECT_TRUE(data_map.chunk_size(i) < kDefaultChunkSize);
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_EQ(file_size4, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler5, &data_map,
                                         &chunk_count));
  EXPECT_EQ(data_map.chunk_size_size(), 3);
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  EXPECT_EQ(1U, data_map.chunk_size(0));
  EXPECT_EQ(1U, data_map.chunk_size(1));
  EXPECT_EQ(2U, data_map.chunk_size(2));
  data_map.Clear();

  //  set file hash so that each chunk size is increased
  file_hash = "ffffffffffffffffffffffffffffffffffffffff";
  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler1, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count - 1; ++i) {
    EXPECT_TRUE((file_size1 / kMaxChunks) < data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_GT(data_map.chunk_size(chunk_count - 1), 0);
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size1, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler2, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count - 1; ++i) {
    EXPECT_TRUE((file_size2 / kMaxChunks) < data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_GT(data_map.chunk_size(chunk_count - 1), 0);
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size2, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler3, &data_map,
                                         &chunk_count));
  for (int i = 1; i < chunk_count - 1; ++i) {
    // std::cout << "Default: " << kDefaultChunkSize << "\tChunk[" << i << "]:
    // " << data_map.chunk_size(i) << std::endl;
    EXPECT_EQ(data_map.chunk_size(i - 1), data_map.chunk_size(i));
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_GT(data_map.chunk_size(0), kDefaultChunkSize);
  EXPECT_GT(data_map.chunk_size(chunk_count - 1), 0);
  chunk_size_total += data_map.chunk_size(0);
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size3, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler4, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMinChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count; ++i) {
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_GT(data_map.chunk_size(chunk_count - 1), 0);
  EXPECT_EQ(file_size4, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler5, &data_map,
                                         &chunk_count));
  EXPECT_EQ(data_map.chunk_size_size(), 3);
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  EXPECT_EQ(1U, data_map.chunk_size(0));
  EXPECT_EQ(1U, data_map.chunk_size(1));
  EXPECT_EQ(2U, data_map.chunk_size(2));
  data_map.Clear();

  //  set file hash so that each chunk size is reduced
  file_hash = "0000000000000000000000000000000000000000";
  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler1, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count - 1; ++i) {
    EXPECT_GT((file_size1 / kMaxChunks), data_map.chunk_size(i));
    EXPECT_GT(data_map.chunk_size(i), 0);
    chunk_size_total += data_map.chunk_size(i);
  }
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size1, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler2, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMaxChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count - 1; ++i) {
    EXPECT_GT((file_size2 / kMaxChunks), data_map.chunk_size(i));
    EXPECT_GT(data_map.chunk_size(i), 0);
    chunk_size_total += data_map.chunk_size(i);
  }
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size2, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler3, &data_map,
                                         &chunk_count));
  for (int i = 1; i < chunk_count-1; ++i) {
    // std::cout << "Default: " << kDefaultChunkSize << "\tChunk[" << i << "]:
    //  " << data_map.chunk_size(i) << std::endl;
    EXPECT_EQ(data_map.chunk_size(i - 1), data_map.chunk_size(i));
    EXPECT_GT(data_map.chunk_size(i), 0);
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_GT(data_map.chunk_size(chunk_count - 1), data_map.chunk_size(0));
  chunk_size_total += data_map.chunk_size(0);
  chunk_size_total += data_map.chunk_size(chunk_count - 1);
  EXPECT_EQ(file_size3, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler4, &data_map,
                                         &chunk_count));
  EXPECT_EQ(kMinChunks, data_map.chunk_size_size());
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  for (int i = 0; i < chunk_count; ++i) {
    EXPECT_GT(data_map.chunk_size(i), 0);
    chunk_size_total += data_map.chunk_size(i);
  }
  EXPECT_EQ(file_size4, chunk_size_total);
  data_map.Clear();

  chunk_size_total = 0;
  EXPECT_TRUE(utils::CalculateChunkSizes(file_hash, input_handler5, &data_map,
                                         &chunk_count));
  EXPECT_EQ(data_map.chunk_size_size(), 3);
  EXPECT_EQ(data_map.chunk_size_size(), chunk_count);
  EXPECT_EQ(1U, data_map.chunk_size(0));
  EXPECT_EQ(1U, data_map.chunk_size(1));
  EXPECT_EQ(2U, data_map.chunk_size(2));
  data_map.Clear();
}

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

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEncryptFiles) {
  fs::path path1(kInputDir_ / "SelfEncryptFilesTest01.txt");
  fs::path path2(kInputDir_ / "SelfEncryptFilesTest02.txt");
  fs::path path3(kInputDir_ / "SelfEncryptFilesTest03.txt");
  fs::path path4(kInputDir_ / "SelfEncryptFilesTest04.txt");
  fs::path path5(kInputDir_ / "SelfEncryptFilesTest05.txt");
  test_se::CreateRandomFile(path1, 0);  // empty file
  test_se::CreateRandomFile(path2, 2);  // smallest possible encryptable file
  test_se::CreateRandomFile(path3, 4);  // special small file
  test_se::CreateRandomFile(path4, 24);  // small file
  test_se::CreateRandomFile(path5, 1024);  // regular file
  protobuf::DataMap data_map1, data_map2, data_map3, data_map4, data_map5;
  data_map1.set_file_hash(crypto::HashFile<crypto::SHA512>(path1));
  data_map2.set_file_hash(crypto::HashFile<crypto::SHA512>(path2));
  data_map3.set_file_hash(crypto::HashFile<crypto::SHA512>(path3));
  data_map4.set_file_hash(crypto::HashFile<crypto::SHA512>(path4));
  data_map5.set_file_hash(crypto::HashFile<crypto::SHA512>(path5));
  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));
  DataIoHandlerPtr input_handler2(new FileIOHandler(path2, true));
  DataIoHandlerPtr input_handler3(new FileIOHandler(path3, true));
  DataIoHandlerPtr input_handler4(new FileIOHandler(path4, true));
  DataIoHandlerPtr input_handler5(new FileIOHandler(path5, true));
  std::map<std::string, fs::path> done_chunks;

  EXPECT_NE(kSuccess, utils::EncryptContent(input_handler1, kOutputDir_,
                                            &data_map1, &done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler2, kOutputDir_,
                                            &data_map2, &done_chunks));
  EXPECT_EQ(3, data_map2.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler3, kOutputDir_,
                                            &data_map3, &done_chunks));
  EXPECT_EQ(3, data_map3.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler4, kOutputDir_,
                                            &data_map4, &done_chunks));
  EXPECT_EQ(3, data_map4.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler5, kOutputDir_,
                                            &data_map5, &done_chunks));
  EXPECT_EQ(3, data_map5.chunk_name_size());
}

std::vector<fs::path> MapToVector(const std::map<std::string, fs::path> &in) {
  std::vector<fs::path> out;
  std::map<std::string, fs::path>::const_iterator it = in.begin();
  while (it != in.end())
    out.push_back((*it++).second);
  return out;
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_DecryptFile) {
  fs::path path1(kInputDir_ / "DecryptFileTest01.txt");
  fs::path path2(kInputDir_ / "DecryptFileTest02.txt");
  fs::path path3(kInputDir_ / "DecryptFileTest03.txt");
  fs::path path4(kInputDir_ / "DecryptFileTest04.txt");
  test_se::CreateRandomFile(path1, 2);
  test_se::CreateRandomFile(path2, 4);
  test_se::CreateRandomFile(path3, 24);
  test_se::CreateRandomFile(path4, 1024);
  protobuf::DataMap data_map1, data_map2, data_map3, data_map4;
  data_map1.set_file_hash(crypto::HashFile<crypto::SHA512>(path1));
  data_map2.set_file_hash(crypto::HashFile<crypto::SHA512>(path2));
  data_map3.set_file_hash(crypto::HashFile<crypto::SHA512>(path3));
  data_map4.set_file_hash(crypto::HashFile<crypto::SHA512>(path4));
  DataIoHandlerPtr input_handler1(new FileIOHandler(path1, true));
  DataIoHandlerPtr input_handler2(new FileIOHandler(path2, true));
  DataIoHandlerPtr input_handler3(new FileIOHandler(path3, true));
  DataIoHandlerPtr input_handler4(new FileIOHandler(path4, true));
  std::map<std::string, fs::path> done_chunks;

  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler1, kOutputDir_,
                                            &data_map1, &done_chunks));
  std::vector<fs::path> chunk_paths1(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler2, kOutputDir_,
                                            &data_map2, &done_chunks));
  std::vector<fs::path> chunk_paths2(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler3, kOutputDir_,
                                            &data_map3, &done_chunks));
  std::vector<fs::path> chunk_paths3(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler4, kOutputDir_,
                                            &data_map4, &done_chunks));
  std::vector<fs::path> chunk_paths4(MapToVector(done_chunks));

  fs::path decrypted1(kOutputDir_ / "DecryptFileTest01.txt");
  fs::path decrypted2(kOutputDir_ / "DecryptFileTest02.txt");
  fs::path decrypted3(kOutputDir_ / "DecryptFileTest03.txt");
  fs::path decrypted4(kOutputDir_ / "DecryptFileTest04.txt");
  DataIoHandlerPtr output_handler1(new FileIOHandler(decrypted1, false));
  DataIoHandlerPtr output_handler2(new FileIOHandler(decrypted2, false));
  DataIoHandlerPtr output_handler3(new FileIOHandler(decrypted3, false));
  DataIoHandlerPtr output_handler4(new FileIOHandler(decrypted4, false));

  EXPECT_EQ(kOffsetError, utils::DecryptContent(data_map1, chunk_paths1, 1,
                                                output_handler1));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map1, chunk_paths1, 0,
                                            output_handler1));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map2, chunk_paths2, 0,
                                            output_handler2));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map3, chunk_paths3, 0,
                                            output_handler3));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map4, chunk_paths4, 0,
                                            output_handler4));

  EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path1),
            crypto::HashFile<crypto::SHA512>(decrypted1));
  EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path2),
            crypto::HashFile<crypto::SHA512>(decrypted2));
  EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path3),
            crypto::HashFile<crypto::SHA512>(decrypted3));
  EXPECT_EQ(crypto::HashFile<crypto::SHA512>(path4),
            crypto::HashFile<crypto::SHA512>(decrypted4));
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfEncryptStrings) {
  StringPtr str1(new std::string(RandomString(0)));
  StringPtr str2(new std::string(RandomString(2)));
  StringPtr str3(new std::string(RandomString(4)));
  StringPtr str4(new std::string(RandomString(24)));
  StringPtr str5(new std::string(RandomString(1024)));
  protobuf::DataMap data_map1, data_map2, data_map3, data_map4, data_map5;
  data_map1.set_file_hash(crypto::Hash<crypto::SHA512>(*str1));
  data_map2.set_file_hash(crypto::Hash<crypto::SHA512>(*str2));
  data_map3.set_file_hash(crypto::Hash<crypto::SHA512>(*str3));
  data_map4.set_file_hash(crypto::Hash<crypto::SHA512>(*str4));
  data_map5.set_file_hash(crypto::Hash<crypto::SHA512>(*str5));
  DataIoHandlerPtr input_handler1(new StringIOHandler(str1, true));
  DataIoHandlerPtr input_handler2(new StringIOHandler(str2, true));
  DataIoHandlerPtr input_handler3(new StringIOHandler(str3, true));
  DataIoHandlerPtr input_handler4(new StringIOHandler(str4, true));
  DataIoHandlerPtr input_handler5(new StringIOHandler(str5, true));
  std::map<std::string, fs::path> done_chunks;

  EXPECT_NE(kSuccess, utils::EncryptContent(input_handler1, kOutputDir_,
                                            &data_map1, &done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler2, kOutputDir_,
                                            &data_map2, &done_chunks));
  EXPECT_EQ(3, data_map2.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler3, kOutputDir_,
                                            &data_map3, &done_chunks));
  EXPECT_EQ(3, data_map3.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler4, kOutputDir_,
                                            &data_map4, &done_chunks));
  EXPECT_EQ(3, data_map4.chunk_name_size());
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler5, kOutputDir_,
                                            &data_map5, &done_chunks));
  EXPECT_EQ(3, data_map5.chunk_name_size());
}

TEST_F(SelfEncryptionTest, BEH_ENCRYPT_SelfDecryptString) {
  StringPtr str1(new std::string(RandomString(2)));
  StringPtr str2(new std::string(RandomString(4)));
  StringPtr str3(new std::string(RandomString(24)));
  StringPtr str4(new std::string(RandomString(1024)));
  protobuf::DataMap data_map1, data_map2, data_map3, data_map4;
  data_map1.set_file_hash(crypto::Hash<crypto::SHA512>(*str1));
  data_map2.set_file_hash(crypto::Hash<crypto::SHA512>(*str2));
  data_map3.set_file_hash(crypto::Hash<crypto::SHA512>(*str3));
  data_map4.set_file_hash(crypto::Hash<crypto::SHA512>(*str4));
  DataIoHandlerPtr input_handler1(new StringIOHandler(str1, true));
  DataIoHandlerPtr input_handler2(new StringIOHandler(str2, true));
  DataIoHandlerPtr input_handler3(new StringIOHandler(str3, true));
  DataIoHandlerPtr input_handler4(new StringIOHandler(str4, true));
  std::map<std::string, fs::path> done_chunks;

  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler1, kOutputDir_,
                                            &data_map1, &done_chunks));
  std::vector<fs::path> chunk_paths1(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler2, kOutputDir_,
                                            &data_map2, &done_chunks));
  std::vector<fs::path> chunk_paths2(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler3, kOutputDir_,
                                            &data_map3, &done_chunks));
  std::vector<fs::path> chunk_paths3(MapToVector(done_chunks));
  EXPECT_EQ(kSuccess, utils::EncryptContent(input_handler4, kOutputDir_,
                                            &data_map4, &done_chunks));
  std::vector<fs::path> chunk_paths4(MapToVector(done_chunks));

  StringPtr dec1(new std::string);
  StringPtr dec2(new std::string);
  StringPtr dec3(new std::string);
  StringPtr dec4(new std::string);
  DataIoHandlerPtr output_handler1(new StringIOHandler(dec1, false));
  DataIoHandlerPtr output_handler2(new StringIOHandler(dec2, false));
  DataIoHandlerPtr output_handler3(new StringIOHandler(dec3, false));
  DataIoHandlerPtr output_handler4(new StringIOHandler(dec4, false));

  EXPECT_EQ(kOffsetError, utils::DecryptContent(data_map1, chunk_paths1, 1,
                                                output_handler1));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map1, chunk_paths1, 0,
                                            output_handler1));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map2, chunk_paths2, 0,
                                            output_handler2));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map3, chunk_paths3, 0,
                                            output_handler3));
  EXPECT_EQ(kSuccess, utils::DecryptContent(data_map4, chunk_paths4, 0,
                                            output_handler4));

  EXPECT_EQ(*str1, *dec1);
  EXPECT_EQ(*str2, *dec2);
  EXPECT_EQ(*str3, *dec3);
  EXPECT_EQ(*str4, *dec4);
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
