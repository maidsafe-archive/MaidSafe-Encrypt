/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Self-encrypts/self-decrypts test
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       Team www.maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <gtest/gtest.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/base/utils.h>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/dataiohandler.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/datamaps.pb.h"
#include "tests/maidsafe/cached_keys.h"

namespace fs = boost::filesystem;

namespace test_se {

std::string CreateRandomFile(const std::string &filename, const int &filesize) {
  fs::path file_path(file_system::MaidsafeHomeDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()) / filename);
  fs::ofstream ofs;
  ofs.open(file_path);
  if (filesize != 0) {
    int stringsize = filesize;
    if (filesize > 100000)
      stringsize = 100000;
    int remainingsize = filesize;
    std::string rand_str = base::RandomAlphaNumericString(2 * stringsize);
    std::string file_content;
    int start_pos = 0;
    while (remainingsize) {
      srand(17);
      start_pos = rand() % stringsize;  // NOLINT (Fraser)
      if (remainingsize < stringsize) {
        stringsize = remainingsize;
        file_content = rand_str.substr(0, stringsize);
      } else {
        file_content = rand_str.substr(start_pos, stringsize);
      }
      ofs << file_content;
      remainingsize -= stringsize;
    }
  }
  ofs.close();
  return file_path.string();
}

}  // namespace test_se

namespace maidsafe {

class SelfEncryptionTest : public testing::Test {
 public:
  SelfEncryptionTest()
      : test_root_dir_(file_system::TempDir() /
            ("maidsafe_TestSE_" + base::RandomAlphaNumericString(6))),
        ss(SessionSingleton::getInstance()),
        client_chunkstore_(),
        ms_home_path_(),
        keys_() {}
  ~SelfEncryptionTest() {}
 protected:
  void SetUp() {
//    done_chunks_.clear();
    ss->ResetSession();
    ss->SetUsername("user1");
    ss->SetPin(base::IntToString(base::RandomUint32()));
    ss->SetPassword("password1");
    ss->SetSessionName(false);
    ss->SetRootDbKey("whatever");
    try {
      if (fs::exists(file_system::MaidsafeDir(ss->SessionName())))
        fs::remove_all(file_system::MaidsafeDir(ss->SessionName()));
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
    client_chunkstore_ = boost::shared_ptr<ChunkStore>(
        new ChunkStore(test_root_dir_.string(), 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    ASSERT_EQ(0, file_system::Mount(ss->SessionName(), ss->DefConLevel()));
    ms_home_path_ = file_system::MaidsafeHomeDir(ss->SessionName());
  }
  void TearDown() {
    try {
      if (fs::exists(file_system::MaidsafeDir(ss->SessionName())))
        fs::remove_all(file_system::MaidsafeDir(ss->SessionName()));
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  fs::path test_root_dir_;
  SessionSingleton *ss;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  fs::path ms_home_path_;
  std::vector<crypto::RsaKeyPair> keys_;
//  std::set<std::string> done_chunks_;
 private:
  explicit SelfEncryptionTest(const maidsafe::SelfEncryptionTest&);
  SelfEncryptionTest &operator=(const maidsafe::SelfEncryptionTest&);
};

TEST_F(SelfEncryptionTest, BEH_MAID_CheckEntry) {
  boost::shared_ptr<DataIOHandler> iohandler;
  fs::path file_path(ms_home_path_);
  std::string file = "test01.txt";
  file_path = file_path/file;
  iohandler.reset(new FileIOHandler);
  SelfEncryption se(client_chunkstore_);

  iohandler->SetData(file_path.string(), false);
  test_se::CreateRandomFile(file, 0);
  ASSERT_EQ(-1, se.CheckEntry(iohandler));
  fs::remove(file_path);

  iohandler->SetData(file_path.string(), false);
  test_se::CreateRandomFile(file, 1);
  ASSERT_EQ(-1, se.CheckEntry(iohandler));
  fs::remove(file_path);

  iohandler->SetData(file_path.string(), false);
  test_se::CreateRandomFile(file, 2);
  ASSERT_EQ(0, se.CheckEntry(iohandler));
  fs::remove(file_path);

  iohandler->SetData(file_path.string(), false);
  test_se::CreateRandomFile(file, 1234567);
  ASSERT_EQ(0, se.CheckEntry(iohandler));
  // fs::remove(file_path);
}

TEST_F(SelfEncryptionTest, BEH_MAID_CreateProcessDirectory) {
  fs::path process_path("");
  SelfEncryption se(client_chunkstore_);
  se.file_hash_ = "TheFileHash";
  ASSERT_TRUE(se.CreateProcessDirectory(&process_path));
  fs::path processing_path = file_system::TempDir() / "TheFileH";
  ASSERT_EQ(processing_path.string(), process_path.string());
  ASSERT_TRUE(fs::exists(process_path));
  // add dir to this, then rerun CreateProcessDirectory to
  // check all contents are deleted
  processing_path /= "NewDir";
  fs::create_directory(processing_path);
  ASSERT_TRUE(fs::exists(processing_path));
  ASSERT_TRUE(se.CreateProcessDirectory(&process_path));
  ASSERT_TRUE(fs::exists(process_path));
  ASSERT_FALSE(fs::exists(processing_path));

  try {
    fs::remove_all(process_path);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
}

TEST_F(SelfEncryptionTest, BEH_MAID_CheckCompressibility) {
  boost::shared_ptr<DataIOHandler> iohandler;
  iohandler.reset(new FileIOHandler);
  //  make compressible .txt file
  fs::path path1 = ms_home_path_;
  path1 /= "compressible.txt";
  fs::ofstream ofs1;
  ofs1.open(path1);
  for (int i = 0; i < 1000; i++)
    ofs1 << "repeated text ";
  ofs1.close();

  //  make incompressible .txt file
  fs::path path2 = ms_home_path_;
  path2 /= "incompressible.txt";
  fs::ofstream ofs2;
  ofs2.open(path2);
  ofs2 << "small text";
  ofs2.close();

  //  make compressible file, but with extension for incompressible file
  fs::path path3 = ms_home_path_;
  path3 /= "incompressible.7z";
  fs::ofstream ofs3;
  ofs3.open(path3);
  for (int i = 0; i < 1000; i++)
    ofs3 << "repeated text ";
  ofs3.close();

  SelfEncryption se(client_chunkstore_);
  iohandler->SetData(path1.string(), true);
  ASSERT_TRUE(se.CheckCompressibility(path1.string(), iohandler));
  iohandler->SetData(path2.string(), true);
  ASSERT_FALSE(se.CheckCompressibility(path2.string(), iohandler));
  iohandler->SetData(path3.string(), true);
  ASSERT_FALSE(se.CheckCompressibility(path3.string(), iohandler));
}

TEST_F(SelfEncryptionTest, BEH_MAID_ChunkAddition) {
  SelfEncryption se(client_chunkstore_);
  ASSERT_EQ(-8, se.ChunkAddition('0'));
  ASSERT_EQ(-7, se.ChunkAddition('1'));
  ASSERT_EQ(-6, se.ChunkAddition('2'));
  ASSERT_EQ(-5, se.ChunkAddition('3'));
  ASSERT_EQ(-4, se.ChunkAddition('4'));
  ASSERT_EQ(-3, se.ChunkAddition('5'));
  ASSERT_EQ(-2, se.ChunkAddition('6'));
  ASSERT_EQ(-1, se.ChunkAddition('7'));
  ASSERT_EQ(0, se.ChunkAddition('8'));
  ASSERT_EQ(1, se.ChunkAddition('9'));
  ASSERT_EQ(2, se.ChunkAddition('a'));
  ASSERT_EQ(3, se.ChunkAddition('b'));
  ASSERT_EQ(4, se.ChunkAddition('c'));
  ASSERT_EQ(5, se.ChunkAddition('d'));
  ASSERT_EQ(6, se.ChunkAddition('e'));
  ASSERT_EQ(7, se.ChunkAddition('f'));
  ASSERT_EQ(2, se.ChunkAddition('A'));
  ASSERT_EQ(3, se.ChunkAddition('B'));
  ASSERT_EQ(4, se.ChunkAddition('C'));
  ASSERT_EQ(5, se.ChunkAddition('D'));
  ASSERT_EQ(6, se.ChunkAddition('E'));
  ASSERT_EQ(7, se.ChunkAddition('F'));
  ASSERT_EQ(0, se.ChunkAddition('g'));
  ASSERT_EQ(0, se.ChunkAddition(' '));
}

TEST_F(SelfEncryptionTest, BEH_MAID_CalculateChunkSizes) {
  boost::shared_ptr<DataIOHandler> iohandler;
  iohandler.reset(new FileIOHandler);
  fs::path file_path(ms_home_path_);

  SelfEncryption se(client_chunkstore_);
  boost::uint16_t min_chunks = se.min_chunks_;
  boost::uint16_t max_chunks = se.max_chunks_;
  boost::uint64_t default_chunk_size_ = se.default_chunk_size_;

  // make file of size larger than (max no of chunks)*(default chunk size)
  std::string test_file1 = "test01.txt";
  boost::uint64_t file_size1 = default_chunk_size_*max_chunks*2;
  fs::path path1(test_se::CreateRandomFile(test_file1, file_size1), fs::native);

  // make file of size exactly (max no of chunks)*(default chunk size)
  std::string test_file2 = "test02.txt";
  boost::uint64_t file_size2 = default_chunk_size_*max_chunks;
  fs::path path2(test_se::CreateRandomFile(test_file2, file_size2), fs::native);

  // make file of size between (max no of chunks)*(default chunk size)
  // & (min no of chunks)*(default chunk size)
  std::string test_file3 = "test03.txt";
  boost::uint64_t file_size3 = default_chunk_size_*(max_chunks+min_chunks)/2;
  fs::path path3(test_se::CreateRandomFile(test_file3, file_size3), fs::native);

  //  make file of size smaller than (min no of chunks)*(default chunk size)
  std::string test_file4 = "test04.txt";
  boost::uint64_t file_size4 = default_chunk_size_*min_chunks/2;
  fs::path path4(test_se::CreateRandomFile(test_file4, file_size4), fs::native);

  //  make file of size 4 bytes
  std::string test_file5 = "test05.txt";
  boost::uint64_t file_size5 = 4;
  fs::path path5(test_se::CreateRandomFile(test_file5, file_size5), fs::native);

  //  set file hash so that each chunk size is unaltered
  DataMap dm;
  se.file_hash_ = "8888888888888888888888888888888888888888";
  boost::uint64_t chunk_size_total = 0;
  iohandler->SetData(path1.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size(); i++) {
    ASSERT_EQ(file_size1/max_chunks, dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_EQ(file_size1, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path2.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size(); i++) {
    ASSERT_EQ(default_chunk_size_, dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_EQ(file_size2, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path3.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  // std::cout << "File Size: " << file_size3 << std::endl;
  // std::cout << "Default: " << default_chunk_size_ << "\tChunk[0]: "
  // << dm.chunk_size(0) << std::endl;
  for (int i = 1; i < dm.chunk_size_size()-1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]:
    //  " << dm.chunk_size(i) << std::endl;
    ASSERT_EQ(dm.chunk_size(i-1), dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  // std::cout << "Default: " << default_chunk_size_ << "\tChunk["
  // << dm.chunk_size_size()-1;
  // std::cout << "]: " << dm.chunk_size(dm.chunk_size_size()-1) << std::endl;
  ASSERT_TRUE(dm.chunk_size(0)>default_chunk_size_);
  chunk_size_total += static_cast<int>(dm.chunk_size(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size3, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path4.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(min_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size(); i++) {
    ASSERT_TRUE(dm.chunk_size(i) < default_chunk_size_);
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_EQ(file_size4, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path5.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(dm.chunk_size_size(), 3);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm.chunk_size(0));
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm.chunk_size(1));
  ASSERT_EQ(static_cast<boost::uint32_t>(2), dm.chunk_size(2));
  dm.Clear();

  //  set file hash so that each chunk size is increased
  se.file_hash_ = "ffffffffffffffffffffffffffffffffffffffff";
  chunk_size_total = 0;
  iohandler->SetData(path1.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size() - 1; i++) {
    ASSERT_TRUE((file_size1 / max_chunks) < dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_GT(dm.chunk_size(dm.chunk_size_size()-1),
            static_cast<boost::uint32_t>(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size1, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path2.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size()-1; i++) {
    ASSERT_TRUE((file_size2 / max_chunks) < dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_GT(dm.chunk_size(dm.chunk_size_size()-1),
            static_cast<boost::uint32_t>(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size2, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path3.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  for (int i = 1; i < dm.chunk_size_size() - 1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]:
    // " << dm.chunk_size(i) << std::endl;
    ASSERT_EQ(dm.chunk_size(i-1), dm.chunk_size(i));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_GT(dm.chunk_size(0), default_chunk_size_);
  ASSERT_GT(dm.chunk_size(dm.chunk_size_size()-1),
            static_cast<boost::uint32_t>(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size3, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path4.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(min_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size(); i++) {
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_GT(dm.chunk_size(dm.chunk_size_size()-1),
            static_cast<boost::uint32_t>(0));
  ASSERT_EQ(file_size4, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path5.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(dm.chunk_size_size(), 3);
  ASSERT_EQ(size_t(1), dm.chunk_size(0));
  ASSERT_EQ(size_t(1), dm.chunk_size(1));
  ASSERT_EQ(size_t(2), dm.chunk_size(2));
  dm.Clear();

  //  set file hash so that each chunk size is reduced
  se.file_hash_ = "0000000000000000000000000000000000000000";
  chunk_size_total = 0;
  iohandler->SetData(path1.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size()-1; i++) {
    ASSERT_GT((file_size1/max_chunks), dm.chunk_size(i));
    ASSERT_GT(dm.chunk_size(i), static_cast<boost::uint32_t>(0));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size1, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path2.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(max_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size()-1; i++) {
    ASSERT_GT((file_size2 / max_chunks), dm.chunk_size(i));
    ASSERT_GT(dm.chunk_size(i), static_cast<boost::uint32_t>(0));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size2, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path3.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  for (int i = 1; i < dm.chunk_size_size()-1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]:
    //  " << dm.chunk_size(i) << std::endl;
    ASSERT_EQ(dm.chunk_size(i-1), dm.chunk_size(i));
    ASSERT_GT(dm.chunk_size(i), static_cast<boost::uint32_t>(0));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_GT(dm.chunk_size(dm.chunk_size_size()-1), dm.chunk_size(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(0));
  chunk_size_total += static_cast<int>(dm.chunk_size(dm.chunk_size_size()-1));
  ASSERT_EQ(file_size3, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path4.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(min_chunks, dm.chunk_size_size());
  for (int i = 0; i < dm.chunk_size_size(); i++) {
    ASSERT_GT(dm.chunk_size(i), static_cast<boost::uint32_t>(0));
    chunk_size_total += static_cast<int>(dm.chunk_size(i));
  }
  ASSERT_EQ(file_size4, chunk_size_total);
  dm.Clear();

  chunk_size_total = 0;
  iohandler->SetData(path5.string(), false);
  ASSERT_TRUE(se.CalculateChunkSizes(iohandler, &dm));
  ASSERT_EQ(dm.chunk_size_size(), 3);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm.chunk_size(0));
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm.chunk_size(1));
  ASSERT_EQ(static_cast<boost::uint32_t>(2), dm.chunk_size(2));
  dm.Clear();
}

TEST_F(SelfEncryptionTest, BEH_MAID_HashFile) {
  SelfEncryption se(client_chunkstore_);
  fs::path ms_home(ms_home_path_);

  fs::path path1 = ms_home;
  path1 /= "test01.txt";
  fs::ofstream ofs1;
  ofs1.open(path1);
  ofs1 << "abc";
  ofs1.close();

  fs::path path2 = ms_home;
  path2 /= "test02.txt";
  fs::ofstream ofs2;
  ofs2.open(path2);
  ofs2 << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijkl"
          "mnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  ofs2.close();
  ASSERT_EQ(base::EncodeToHex(se.SHA512(path1)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(base::EncodeToHex(se.SHA512(path2)),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
        "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST_F(SelfEncryptionTest, BEH_MAID_HashString) {
  SelfEncryption se(client_chunkstore_);
  ASSERT_EQ(base::EncodeToHex(se.SHA512(static_cast<std::string>("abc"))),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(base::EncodeToHex(se.SHA512(static_cast<std::string>("abcdefghbcdef"
        "ghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklm"
        "nopqrlmnopqrsmnopqrstnopqrstu"))),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
        "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST_F(SelfEncryptionTest, BEH_MAID_GeneratePreEncHashes) {
  boost::shared_ptr<DataIOHandler> iohandler;
  iohandler.reset(new FileIOHandler);
  SelfEncryption se(client_chunkstore_);
  fs::path ms_home(ms_home_path_);

  fs::path path1 = ms_home;
  path1 /= "test01.txt";
  fs::ofstream ofs1;
  ofs1.open(path1);
  ofs1 << "abc";
  ofs1 << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijkl"
          "mnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  ofs1 << "abc";
  ofs1.close();
  DataMap dm;
  dm.add_chunk_size(3);
  dm.add_chunk_size(112);
  dm.add_chunk_size(3);
  se.chunk_count_ = 3;

  iohandler->SetData(path1.string(), true);
  ASSERT_TRUE(se.GeneratePreEncHashes(iohandler, &dm));
  ASSERT_EQ(3, dm.chunk_name_size());
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(0)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(1)),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
        "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(2)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

  // Modify default chunklet size so that pre-encryption hashes are generated
  // from only first 2 chars of each chunk.
  boost::uint16_t *new_default_chunklet_size_ =
    const_cast<boost::uint16_t*>(&se.default_chunklet_size_);
  *new_default_chunklet_size_ = 2;
  dm.clear_chunk_name();
  iohandler->SetData(path1.string(), true);
  ASSERT_TRUE(se.GeneratePreEncHashes(iohandler, &dm));
  ASSERT_EQ(3, dm.chunk_name_size());
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(0)),
        "2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf"
        "12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d");
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(1)),
        "2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf"
        "12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d");
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(2)),
        "2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf"
        "12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d");
}

TEST_F(SelfEncryptionTest, BEH_MAID_HashUnique) {
  SelfEncryption se(client_chunkstore_);
  std::string hash = se.SHA512(static_cast<std::string>("abc"));
  DataMap dm;
  dm.add_chunk_name(hash);
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(0)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_TRUE(se.HashUnique(dm, true, &hash));
  dm.add_chunk_name(hash);
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(1)),
        "9fddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
        "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca4");
  ASSERT_TRUE(se.HashUnique(dm, true, &hash));
  dm.add_chunk_name(hash);
  ASSERT_EQ(base::EncodeToHex(dm.chunk_name(2)),
        "a49fddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21"
        "92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54c");
  hash = se.SHA512(static_cast<std::string>("ab"));
  std::string hashafter = hash;
  ASSERT_TRUE(se.HashUnique(dm, true, &hashafter));
  ASSERT_EQ(hash, hashafter);
}

TEST_F(SelfEncryptionTest, BEH_MAID_ResizeObfuscationHash) {
  SelfEncryption se(client_chunkstore_);
  std::string hash = se.SHA512(static_cast<std::string>("abc"));
  ASSERT_EQ(base::EncodeToHex(hash),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
        "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  std::string amended_hash;
  ASSERT_TRUE(se.ResizeObfuscationHash(base::EncodeToHex(hash), 129,
              &amended_hash));
  ASSERT_EQ(amended_hash, base::EncodeToHex(hash)+"d");
  ASSERT_TRUE(se.ResizeObfuscationHash(base::EncodeToHex(hash), 10,
              &amended_hash));
  ASSERT_EQ(amended_hash, "ddaf35a193");
  ASSERT_TRUE(se.ResizeObfuscationHash(base::EncodeToHex(hash), 1280,
              &amended_hash));
  ASSERT_EQ(amended_hash, base::EncodeToHex(
            hash+hash+hash+hash+hash+hash+hash+hash+hash+hash));
}

TEST_F(SelfEncryptionTest, BEH_MAID_SelfEncryptFiles) {
  std::string test_file1("test01.txt");
  std::string test_file2("test02.txt");
  std::string test_file3("test03.txt");
  std::string test_file4("test04.txt");
  std::string test_file5("test05.txt");
  // empty file
  fs::path path1(test_se::CreateRandomFile(test_file1, 0), fs::native);
  // smallest possible encryptable file
  fs::path path2(test_se::CreateRandomFile(test_file2, 2), fs::native);
  // special small file
  fs::path path3(test_se::CreateRandomFile(test_file3, 4), fs::native);
  // small file
  fs::path path4(test_se::CreateRandomFile(test_file4, 24), fs::native);
  // regular file
  fs::path path5(test_se::CreateRandomFile(test_file5, 1024), fs::native);
  DataMap dm1, dm2, dm3, dm4, dm5;

  SelfEncryption se(client_chunkstore_);
  dm1.set_file_hash(se.SHA512(path1));
  dm2.set_file_hash(se.SHA512(path2));
  dm3.set_file_hash(se.SHA512(path3));
  dm4.set_file_hash(se.SHA512(path4));
  dm5.set_file_hash(se.SHA512(path5));
  ASSERT_LT(se.Encrypt(path1.string(), false, &dm1/*, &done_chunks_*/), 0);
  ASSERT_EQ(0, se.Encrypt(path2.string(), false, &dm2/*, &done_chunks_*/));
  ASSERT_EQ(3, dm2.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(path3.string(), false, &dm3/*, &done_chunks_*/));
  ASSERT_EQ(3, dm3.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(path4.string(), false, &dm4/*, &done_chunks_*/));
  ASSERT_EQ(3, dm4.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(path5.string(), false, &dm5/*, &done_chunks_*/));
  ASSERT_EQ(3, dm5.chunk_name_size());
}

TEST_F(SelfEncryptionTest, BEH_MAID_DecryptFile) {
  std::string test_file1("test01.txt");
  std::string test_file2("test02.txt");
  std::string test_file3("test03.txt");
  std::string test_file4("test04.txt");
  // smallest possible encryptable file
  fs::path path1(test_se::CreateRandomFile(test_file1, 2), fs::native);
  // special small file
  fs::path path2(test_se::CreateRandomFile(test_file2, 4), fs::native);
  // small file
  fs::path path3(test_se::CreateRandomFile(test_file3, 24), fs::native);
  // regular file
  fs::path path4(test_se::CreateRandomFile(test_file4, 1024), fs::native);
  DataMap dm1, dm2, dm3, dm4;

  SelfEncryption se(client_chunkstore_);
  dm1.set_file_hash(se.SHA512(path1));
  dm2.set_file_hash(se.SHA512(path2));
  dm3.set_file_hash(se.SHA512(path3));
  dm4.set_file_hash(se.SHA512(path4));
  ASSERT_EQ(0, se.Encrypt(path1.string(), false, &dm1/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(path2.string(), false, &dm2/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(path3.string(), false, &dm3/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(path4.string(), false, &dm4/*, &done_chunks_*/));

  fs::path decrypted1(path1.string()+".decrypted", fs::native);
  fs::path decrypted2(path2.string()+".decrypted", fs::native);
  fs::path decrypted3(path3.string()+".decrypted", fs::native);
  fs::path decrypted4(path4.string()+".decrypted", fs::native);

  ASSERT_EQ(0, se.Decrypt(dm1, decrypted1.string(), 0, false));
  ASSERT_EQ(0, se.Decrypt(dm2, decrypted2.string(), 0, false));
  ASSERT_EQ(0, se.Decrypt(dm3, decrypted3.string(), 0, false));
  ASSERT_EQ(0, se.Decrypt(dm4, decrypted4.string(), 0, false));

  ASSERT_EQ(se.SHA512(path1), se.SHA512(decrypted1));
  ASSERT_EQ(se.SHA512(path2), se.SHA512(decrypted2));
  ASSERT_EQ(se.SHA512(path3), se.SHA512(decrypted3));
  ASSERT_EQ(se.SHA512(path4), se.SHA512(decrypted4));
}

TEST_F(SelfEncryptionTest, BEH_MAID_SelfEncryptStrings) {
  std::string str1(base::RandomString(0));
  std::string str2(base::RandomString(2));
  std::string str3(base::RandomString(4));
  std::string str4(base::RandomString(24));
  std::string str5(base::RandomString(1024));
  DataMap dm1, dm2, dm3, dm4, dm5;

  SelfEncryption se(client_chunkstore_);
  dm1.set_file_hash(se.SHA512(str1));
  dm2.set_file_hash(se.SHA512(str2));
  dm3.set_file_hash(se.SHA512(str3));
  dm4.set_file_hash(se.SHA512(str4));
  dm5.set_file_hash(se.SHA512(str5));
  ASSERT_LT(se.Encrypt(str1, true, &dm1/*, &done_chunks_*/), 0);
  ASSERT_EQ(0, se.Encrypt(str2, true, &dm2/*, &done_chunks_*/));
  ASSERT_EQ(3, dm2.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(str3, true, &dm3/*, &done_chunks_*/));
  ASSERT_EQ(3, dm3.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(str4, true, &dm4/*, &done_chunks_*/));
  ASSERT_EQ(3, dm4.chunk_name_size());
  ASSERT_EQ(0, se.Encrypt(str5, true, &dm5/*, &done_chunks_*/));
  ASSERT_EQ(3, dm5.chunk_name_size());
}

TEST_F(SelfEncryptionTest, BEH_MAID_SelfDecryptString) {
  std::string str1(base::RandomString(2));
  std::string str2(base::RandomString(4));
  std::string str3(base::RandomString(24));
  std::string str4(base::RandomString(1024));
  DataMap dm1, dm2, dm3, dm4;

  SelfEncryption se(client_chunkstore_);
  dm1.set_file_hash(se.SHA512(str1));
  dm2.set_file_hash(se.SHA512(str2));
  dm3.set_file_hash(se.SHA512(str3));
  dm4.set_file_hash(se.SHA512(str4));
  ASSERT_EQ(0, se.Encrypt(str1, true, &dm1/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(str2, true, &dm2/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(str3, true, &dm3/*, &done_chunks_*/));
  ASSERT_EQ(0, se.Encrypt(str4, true, &dm4/*, &done_chunks_*/));

  std::string dec1, dec2, dec3, dec4;

  ASSERT_EQ(0, se.Decrypt(dm1, 0, &dec1));
  ASSERT_EQ(0, se.Decrypt(dm2, 0, &dec2));
  ASSERT_EQ(0, se.Decrypt(dm3, 0, &dec3));
  ASSERT_EQ(0, se.Decrypt(dm4, 0, &dec4));

  ASSERT_EQ(str1, dec1);
  ASSERT_EQ(str2, dec2);
  ASSERT_EQ(str3, dec3);
  ASSERT_EQ(str4, dec4);
}

TEST_F(SelfEncryptionTest, BEH_MAID_EncryptDecryptStringSerDA) {
  DataAtlas da;
  crypto::Crypto co;
  std::vector<PacketType> types;
  types.push_back(ANMID);
  types.push_back(ANSMID);
  types.push_back(ANTMID);
  types.push_back(MAID);
  da.set_root_db_key(co.Hash("db_key", "", crypto::STRING_STRING, false));
  cached_keys::MakeKeys(types.size(), &keys_);
  for (unsigned int i = 0; i < types.size(); ++i) {
    Key *k = da.add_keys();
    k->set_type(types[i]);
    k->set_private_key(keys_.at(i).private_key());
    k->set_public_key(keys_.at(i).public_key());
    k->set_public_key_signature(co.AsymSign(keys_.at(i).public_key(), "",
        keys_.at(i).private_key(), crypto::STRING_STRING));
    k->set_id(co.Hash(keys_.at(i).public_key() + k->public_key_signature(), "",
        crypto::STRING_STRING, false));
  }
  std::string ser_da;
  ASSERT_TRUE(da.SerializeToString(&ser_da));
  DataMap dm1;

  SelfEncryption se(client_chunkstore_);

  dm1.set_file_hash(se.SHA512(ser_da));
  ASSERT_EQ(0, se.Encrypt(ser_da, true, &dm1/*, &done_chunks_*/));

  std::string dec_str;
  ASSERT_EQ(0, se.Decrypt(dm1, 0, &dec_str));
  EXPECT_EQ(se.SHA512(ser_da), se.SHA512(dec_str));
  EXPECT_EQ(ser_da.size(), dec_str.size());
  EXPECT_EQ(ser_da, dec_str);
  da.Clear();
  EXPECT_TRUE(da.ParseFromString(ser_da));
  da.Clear();
  EXPECT_TRUE(da.ParseFromString(dec_str));
//  fs::remove(fpath);
}

TEST_F(SelfEncryptionTest, BEH_MAID_EncryptDecryptFileSerDA) {
  DataAtlas da;
  crypto::Crypto co;
  std::vector<PacketType> types;
  types.push_back(ANMID);
  types.push_back(ANSMID);
  types.push_back(ANTMID);
  types.push_back(MAID);
  da.set_root_db_key(co.Hash("db_key", "", crypto::STRING_STRING, false));
  cached_keys::MakeKeys(types.size(), &keys_);
  for (unsigned int i = 0; i < types.size(); ++i) {
    Key *k = da.add_keys();
    k->set_type(types[i]);
    k->set_private_key(keys_.at(i).private_key());
    k->set_public_key(keys_.at(i).public_key());
    k->set_public_key_signature(co.AsymSign(keys_.at(i).public_key(), "",
        keys_.at(i).private_key(), crypto::STRING_STRING));
    k->set_id(co.Hash(keys_.at(i).public_key() + k->public_key_signature(), "",
                      crypto::STRING_STRING, false));
  }
  std::string filename("ser_da");
  std::fstream output(filename.c_str(),
                      std::ios::out | std::ios::trunc | std::ios::binary);
  ASSERT_TRUE(da.SerializeToOstream(&output));
  output.close();

  fs::path filepath(filename, fs::native);
  DataMap dm;

  SelfEncryption se(client_chunkstore_);
  dm.set_file_hash(se.SHA512(filepath));
  ASSERT_EQ(0, se.Encrypt(filepath.string(), false, &dm/*, &done_chunks_*/));

  fs::path decfilepath(filename + "dec", fs::native);
  ASSERT_EQ(0, se.Decrypt(dm, decfilepath.string(), 0, false));

  EXPECT_EQ(se.SHA512(filepath), se.SHA512(decfilepath));

  std::ifstream input1(filepath.string().c_str(),
                       std::ios::in | std::ios::binary);
  da.Clear();
  EXPECT_TRUE(da.ParseFromIstream(&input1));
  input1.close();
  std::ifstream input2(decfilepath.string().c_str(),
                       std::ios::in | std::ios::binary);
  da.Clear();
  EXPECT_TRUE(da.ParseFromIstream(&input2));
  input2.close();
  fs::remove(filepath);
  fs::remove(decfilepath);
}

/*
//TEST_F(SelfEncryptionTest, BEH_MAID_EncryptAndCheckDoneChunks) {
//  std::string test_file1("test01.txt");
//  std::string test_file2("test02.txt");
//
//  fs::path path1(test_se::CreateRandomFile(test_file1, 999), fs::native);
//  fs::path path2(file_system::MaidsafeHomeDir(
//                     maidsafe::SessionSingleton::getInstance()->SessionName()) /
//                 test_file2);
//  try {
//    fs::copy_file(path1, path2);
//  }
//  catch(const std::exception &e) {
//    FAIL() << e.what();
//  }
//
//  DataMap dm1, dm2;
//  SelfEncryption se(client_chunkstore_);
//  dm1.set_file_hash(se.SHA512(path1));
//  dm2.set_file_hash(se.SHA512(path2));
//  ASSERT_EQ(se.Encrypt(path1.string(), false, &dm1, &done_chunks_), 0);
//  ASSERT_TRUE(done_chunks_.empty());
//  ASSERT_EQ(se.Encrypt(path2.string(), false, &dm2, &done_chunks_), 0);
//  ASSERT_EQ(size_t(3), done_chunks_.size());
//  std::set<std::string>::iterator it;
//  for (int n = 0; n < dm2.encrypted_chunk_name_size(); ++n) {
//    ASSERT_EQ(dm1.encrypted_chunk_name(n), dm2.encrypted_chunk_name(n));
//    it = done_chunks_.find(dm2.encrypted_chunk_name(n));
//    if (it == done_chunks_.end())
//      FAIL() << "Chunk missing " << n;
//  }
//}
*/

}  // namespace maidsafe
