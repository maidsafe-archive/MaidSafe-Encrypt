#include "maidsafe/utils.h"
#include "maidsafe/client/selfencryption.h"

#include <stdint.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <gtest/gtest.h>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe-dht.h"
#include "fs/filesystem.h"

namespace fs=boost::filesystem;

std::string CreateRandomFile(const std::string &filename_, const int &filesize_) {
  std::string file_content = base::RandomString(filesize_);
  file_system::FileSystem fsys_;
  fs::path file_path(fsys_.MaidsafeHomeDir());
  file_path = file_path/filename_;
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  return file_path.string();
};

namespace maidsafe{

class TestSelfEncryption : public testing::Test {
public:
TestSelfEncryption() : ss() {}
protected:
  void SetUp() {
    ss = SessionSingleton::getInstance();
    ss->SetUsername("user1");
    ss->SetPin("1234");
    ss->SetPassword("password1");
    ss->SetSessionName(false);
    ss->SetRootDbKey("whatever");
    file_system::FileSystem fsys_;
    fsys_.Mount();
  }
  void TearDown() {
    try {
      file_system::FileSystem fsys_;
      fs::remove_all(fsys_.MaidsafeHomeDir());
    }
    catch(std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  SessionSingleton *ss;
private:
TestSelfEncryption(const maidsafe::TestSelfEncryption&);
TestSelfEncryption &operator=(const maidsafe::TestSelfEncryption&);
};


TEST_F(TestSelfEncryption, FUNC_MAID_CheckEntry) {
  std::string test_file1_ = "test01.txt";
  std::string test_file2_ = "test02.txt";
  std::string test_file3_ = "test03.txt";
  std::string test_file4_ = "test04.txt";
  fs::path path1_(CreateRandomFile(test_file1_, 0), fs::native);
  fs::path path2_(CreateRandomFile(test_file2_, 1), fs::native);
  fs::path path3_(CreateRandomFile(test_file3_, 2), fs::native);
  fs::path path4_(CreateRandomFile(test_file4_, 1234567), fs::native);
  SelfEncryption se_;
  ASSERT_EQ(-1, se_.CheckEntry(path1_));
  ASSERT_EQ(-1, se_.CheckEntry(path2_));
  ASSERT_EQ(0, se_.CheckEntry(path3_));
  ASSERT_EQ(0, se_.CheckEntry(path4_));
}


TEST_F(TestSelfEncryption, BEH_MAID_CreateProcessDirectory) {
  fs::path process_path_("");
  SelfEncryption se_;
  se_.file_hash_ = "TheFileHash";
  ASSERT_TRUE(se_.CreateProcessDirectory(&process_path_));
  file_system::FileSystem fsys_;
  fs::path processing_path_(fsys_.ProcessDir(), fs::native);
  processing_path_ /= "TheFileH";
  ASSERT_EQ(processing_path_.string(), process_path_.string());
  ASSERT_TRUE(fs::exists(process_path_));
  //  add dir to this, then rerun CreateProcessDirectory to check all contents are deleted
  processing_path_ /= "NewDir";
  fs::create_directory(processing_path_);
  ASSERT_TRUE(fs::exists(processing_path_));
  ASSERT_TRUE(se_.CreateProcessDirectory(&process_path_));
  ASSERT_TRUE(fs::exists(process_path_));
  ASSERT_FALSE(fs::exists(processing_path_));

  try {
    fs::remove_all(process_path_);
  }
  catch (std::exception e_) {
    printf("%s\n", e_.what());
  }
}


TEST_F(TestSelfEncryption, BEH_MAID_CheckCompressibility) {
  file_system::FileSystem fsys_;
  fs::path ms_home_(fsys_.MaidsafeHomeDir());
  //  make compressible .txt file
  fs::path path1_ = ms_home_;
  path1_ /= "compressible.txt";
  fs::ofstream ofs1_;
  ofs1_.open(path1_);
  for (int i=0; i<1000; i++)
    ofs1_ << "repeated text ";
  ofs1_.close();
  //  make incompressible .txt file
  fs::path path2_ = ms_home_;
  path2_ /= "incompressible.txt";
  fs::ofstream ofs2_;
  ofs2_.open(path2_);
  ofs2_ << "small text";
  ofs2_.close();
  //  make compressible file, but with extension for incompressible file
  fs::path path3_ = ms_home_;
  path3_ /= "incompressible.7z";
  fs::ofstream ofs3_;
  ofs3_.open(path3_);
  for (int i=0; i<1000; i++)
    ofs3_ << "repeated text ";
  ofs3_.close();

  SelfEncryption se_;
  ASSERT_TRUE(se_.CheckCompressibility(path1_));
  ASSERT_FALSE(se_.CheckCompressibility(path2_));
  ASSERT_FALSE(se_.CheckCompressibility(path3_));
}


TEST_F(TestSelfEncryption, BEH_MAID_ChunkAddition) {
  SelfEncryption se_;
  ASSERT_EQ(-8, se_.ChunkAddition('0'));
  ASSERT_EQ(-7, se_.ChunkAddition('1'));
  ASSERT_EQ(-6, se_.ChunkAddition('2'));
  ASSERT_EQ(-5, se_.ChunkAddition('3'));
  ASSERT_EQ(-4, se_.ChunkAddition('4'));
  ASSERT_EQ(-3, se_.ChunkAddition('5'));
  ASSERT_EQ(-2, se_.ChunkAddition('6'));
  ASSERT_EQ(-1, se_.ChunkAddition('7'));
  ASSERT_EQ(0, se_.ChunkAddition('8'));
  ASSERT_EQ(1, se_.ChunkAddition('9'));
  ASSERT_EQ(2, se_.ChunkAddition('a'));
  ASSERT_EQ(3, se_.ChunkAddition('b'));
  ASSERT_EQ(4, se_.ChunkAddition('c'));
  ASSERT_EQ(5, se_.ChunkAddition('d'));
  ASSERT_EQ(6, se_.ChunkAddition('e'));
  ASSERT_EQ(7, se_.ChunkAddition('f'));
  ASSERT_EQ(2, se_.ChunkAddition('A'));
  ASSERT_EQ(3, se_.ChunkAddition('B'));
  ASSERT_EQ(4, se_.ChunkAddition('C'));
  ASSERT_EQ(5, se_.ChunkAddition('D'));
  ASSERT_EQ(6, se_.ChunkAddition('E'));
  ASSERT_EQ(7, se_.ChunkAddition('F'));
  ASSERT_EQ(0, se_.ChunkAddition('g'));
  ASSERT_EQ(0, se_.ChunkAddition(' '));
}


TEST_F(TestSelfEncryption, FUNC_MAID_CalculateChunkSizes) {
  SelfEncryption se_;
  uint16_t min_chunks_ = se_.min_chunks_;
  uint16_t max_chunks_ = se_.max_chunks_;
  uint64_t default_chunk_size_ = se_.default_chunk_size_;

  //  make file of size larger than (max no of chunks)*(default chunk size)
  std::string test_file1_ = "test01.txt";
  uint64_t file_size1_ = default_chunk_size_*max_chunks_*2;
  fs::path path1_(CreateRandomFile(test_file1_, file_size1_), fs::native);

  //  make file of size exactly (max no of chunks)*(default chunk size)
  std::string test_file2_ = "test02.txt";
  uint64_t file_size2_ = default_chunk_size_*max_chunks_;
  fs::path path2_(CreateRandomFile(test_file2_, file_size2_), fs::native);

  //  make file of size between (max no of chunks)*(default chunk size) & (min no of chunks)*(default chunk size)
  std::string test_file3_ = "test03.txt";
  uint64_t file_size3_ = default_chunk_size_*(max_chunks_+min_chunks_)/2;
  fs::path path3_(CreateRandomFile(test_file3_, file_size3_), fs::native);

  //  make file of size smaller than (min no of chunks)*(default chunk size)
  std::string test_file4_ = "test04.txt";
  uint64_t file_size4_ = default_chunk_size_*min_chunks_/2;
  fs::path path4_(CreateRandomFile(test_file4_, file_size4_), fs::native);

  //  make file of size 4 bytes
  std::string test_file5_ = "test05.txt";
  uint64_t file_size5_ = 4;
  fs::path path5_(CreateRandomFile(test_file5_, file_size5_), fs::native);

  //  set file hash so that each chunk size is unaltered
  DataMap dm_;
  se_.file_hash_ = "8888888888888888888888888888888888888888";
  uint64_t chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path1_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size(); i++) {
    ASSERT_EQ(file_size1_/max_chunks_, dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_EQ(file_size1_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path2_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size(); i++) {
    ASSERT_EQ(default_chunk_size_, dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_EQ(file_size2_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path3_, &dm_));
  // std::cout << "File Size: " << file_size3_ << std::endl;
  // std::cout << "Default: " << default_chunk_size_ << "\tChunk[0]: " << dm_.chunk_size(0) << std::endl;
  for (int i=1; i<dm_.chunk_size_size()-1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]: " << dm_.chunk_size(i) << std::endl;
    ASSERT_EQ(dm_.chunk_size(i-1), dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << dm_.chunk_size_size()-1;
  // std::cout << "]: " << dm_.chunk_size(dm_.chunk_size_size()-1) << std::endl;
  ASSERT_TRUE(dm_.chunk_size(0)>default_chunk_size_);
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(0));
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size3_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path4_, &dm_));
  ASSERT_EQ(min_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size(); i++) {
    ASSERT_TRUE(dm_.chunk_size(i)<default_chunk_size_);
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_EQ(file_size4_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path5_, &dm_));
  ASSERT_TRUE(dm_.chunk_size_size() == 3);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm_.chunk_size(0));
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm_.chunk_size(1));
  ASSERT_EQ(static_cast<boost::uint32_t>(2), dm_.chunk_size(2));
  dm_.Clear();

  //  set file hash so that each chunk size is increased
  se_.file_hash_ = "ffffffffffffffffffffffffffffffffffffffff";
  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path1_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size()-1; i++) {
    ASSERT_TRUE((file_size1_/max_chunks_)<dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_TRUE(dm_.chunk_size(dm_.chunk_size_size()-1)>0);
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size1_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path2_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size()-1; i++) {
    ASSERT_TRUE((file_size2_/max_chunks_)<dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_TRUE(dm_.chunk_size(dm_.chunk_size_size()-1)>0);
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size2_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path3_, &dm_));
  for (int i=1; i<dm_.chunk_size_size()-1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]: " << dm_.chunk_size(i) << std::endl;
    ASSERT_EQ(dm_.chunk_size(i-1), dm_.chunk_size(i));
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_TRUE(dm_.chunk_size(0)>default_chunk_size_);
  ASSERT_TRUE(dm_.chunk_size(dm_.chunk_size_size()-1)>0);
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(0));
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size3_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path4_, &dm_));
  ASSERT_EQ(min_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size(); i++) {
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_TRUE(dm_.chunk_size(dm_.chunk_size_size()-1)>0);
  ASSERT_EQ(file_size4_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path5_, &dm_));
  ASSERT_TRUE(dm_.chunk_size_size() == 3);
  ASSERT_EQ(static_cast<unsigned int>(1), dm_.chunk_size(0));
  ASSERT_EQ(static_cast<unsigned int>(1), dm_.chunk_size(1));
  ASSERT_EQ(static_cast<unsigned int>(2), dm_.chunk_size(2));
  dm_.Clear();

  //  set file hash so that each chunk size is reduced
  se_.file_hash_ = "0000000000000000000000000000000000000000";
  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path1_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size()-1; i++) {
    ASSERT_TRUE((file_size1_/max_chunks_)>dm_.chunk_size(i));
    ASSERT_TRUE(dm_.chunk_size(i)>0);
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size1_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path2_, &dm_));
  ASSERT_EQ(max_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size()-1; i++) {
    ASSERT_TRUE((file_size2_/max_chunks_)>dm_.chunk_size(i));
    ASSERT_TRUE(dm_.chunk_size(i)>0);
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size2_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path3_, &dm_));
  for (int i=1; i<dm_.chunk_size_size()-1; i++) {
    // std::cout << "Default: " << default_chunk_size_ << "\tChunk[" << i << "]: " << dm_.chunk_size(i) << std::endl;
    ASSERT_EQ(dm_.chunk_size(i-1), dm_.chunk_size(i));
    ASSERT_TRUE(dm_.chunk_size(i)>0);
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_TRUE(dm_.chunk_size(dm_.chunk_size_size()-1)>dm_.chunk_size(0));
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(0));
  chunk_size_total_ += static_cast<int>(dm_.chunk_size(dm_.chunk_size_size()-1));
  ASSERT_EQ(file_size3_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path4_, &dm_));
  ASSERT_EQ(min_chunks_, dm_.chunk_size_size());
  for (int i=0; i<dm_.chunk_size_size(); i++) {
    ASSERT_TRUE(dm_.chunk_size(i)>0);
    chunk_size_total_ += static_cast<int>(dm_.chunk_size(i));
  }
  ASSERT_EQ(file_size4_, chunk_size_total_);
  dm_.Clear();

  chunk_size_total_=0;
  ASSERT_TRUE(se_.CalculateChunkSizes(path5_, &dm_));
  ASSERT_TRUE(dm_.chunk_size_size() == 3);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm_.chunk_size(0));
  ASSERT_EQ(static_cast<boost::uint32_t>(1), dm_.chunk_size(1));
  ASSERT_EQ(static_cast<boost::uint32_t>(2), dm_.chunk_size(2));
  dm_.Clear();
}


TEST_F(TestSelfEncryption, BEH_MAID_HashFile) {
  SelfEncryption se_;
  file_system::FileSystem fsys_;
  fs::path ms_home_(fsys_.MaidsafeHomeDir());

  fs::path path1_ = ms_home_;
  path1_ /= "test01.txt";
  fs::ofstream ofs1_;
  ofs1_.open(path1_);
  ofs1_ << "abc";
  ofs1_.close();

  fs::path path2_ = ms_home_;
  path2_ /= "test02.txt";
  fs::ofstream ofs2_;
  ofs2_.open(path2_);
  ofs2_ << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  ofs2_.close();
  ASSERT_EQ(se_.SHA512(path1_),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(se_.SHA512(path2_),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}


TEST_F(TestSelfEncryption, BEH_MAID_HashString) {
  SelfEncryption se_;
  ASSERT_EQ(se_.SHA512(static_cast<std::string>("abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(se_.SHA512(static_cast<std::string>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}


TEST_F(TestSelfEncryption, FUNC_MAID_GeneratePreEncHashes) {
  SelfEncryption se_;
  file_system::FileSystem fsys_;
  fs::path ms_home_(fsys_.MaidsafeHomeDir());

  fs::path path1_ = ms_home_;
  path1_ /= "test01.txt";
  fs::ofstream ofs1_;
  ofs1_.open(path1_);
  ofs1_ << "abc";
  ofs1_ << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  ofs1_ << "abc";
  ofs1_.close();

  DataMap dm_;
  dm_.add_chunk_size(3);
  dm_.add_chunk_size(112);
  dm_.add_chunk_size(3);
  se_.chunk_count_ = 3;

  ASSERT_TRUE(se_.GeneratePreEncHashes(path1_, &dm_));
  ASSERT_EQ(3, dm_.chunk_name_size());
  ASSERT_EQ(dm_.chunk_name(0),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(dm_.chunk_name(1),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  ASSERT_EQ(dm_.chunk_name(2),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}


TEST_F(TestSelfEncryption, FUNC_MAID_HashUnique) {
  SelfEncryption se_;
  std::string hash_ = se_.SHA512(static_cast<std::string>("abc"));
  DataMap dm_;
  dm_.add_chunk_name(hash_);
  ASSERT_EQ(dm_.chunk_name(0),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_TRUE(se_.HashUnique(dm_, true, &hash_));
  dm_.add_chunk_name(hash_);
  ASSERT_EQ(dm_.chunk_name(1),
        "fddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49");
  ASSERT_TRUE(se_.HashUnique(dm_, true, &hash_));
  dm_.add_chunk_name(hash_);
  ASSERT_EQ(dm_.chunk_name(2),
        "9fddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca4");
  hash_ = se_.SHA512(static_cast<std::string>("ab"));
  std::string hash_after_ = hash_;
  ASSERT_TRUE(se_.HashUnique(dm_, true, &hash_after_));
  ASSERT_EQ(hash_, hash_after_);
}


TEST_F(TestSelfEncryption, FUNC_MAID_ResizeObfuscationHash) {
  SelfEncryption se_;
  std::string hash_ = se_.SHA512(static_cast<std::string>("abc"));
  ASSERT_EQ(hash_,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  std::string amended_hash_;
  ASSERT_TRUE(se_.ResizeObfuscationHash(hash_, 129, &amended_hash_));
  ASSERT_EQ(amended_hash_, hash_+"d");
  ASSERT_TRUE(se_.ResizeObfuscationHash(hash_, 10, &amended_hash_));
  ASSERT_EQ(amended_hash_, "ddaf35a193");
  ASSERT_TRUE(se_.ResizeObfuscationHash(hash_, 1280, &amended_hash_));
  ASSERT_EQ(amended_hash_, hash_+hash_+hash_+hash_+hash_+hash_+hash_+hash_+hash_+hash_);
}


TEST_F(TestSelfEncryption, FUNC_MAID_EncryptFile) {
  std::string test_file1_ = "test01.txt";
  std::string test_file2_ = "test02.txt";
  std::string test_file3_ = "test03.txt";
  std::string test_file4_ = "test04.txt";
  std::string test_file5_ = "test05.txt";
  fs::path path1_(CreateRandomFile(test_file1_, 0), fs::native); //  empty file
  fs::path path2_(CreateRandomFile(test_file2_, 2), fs::native); //  smallest possible encryptable file
  fs::path path3_(CreateRandomFile(test_file3_, 4), fs::native); //  special small file
  fs::path path4_(CreateRandomFile(test_file4_, 24), fs::native); //  small file
  fs::path path5_(CreateRandomFile(test_file5_, 1024), fs::native); //  regular file
  DataMap dm1_, dm2_, dm3_, dm4_, dm5_;

  SelfEncryption se_;
  dm1_.set_file_hash(se_.SHA512(path1_));
  dm2_.set_file_hash(se_.SHA512(path2_));
  dm3_.set_file_hash(se_.SHA512(path3_));
  dm4_.set_file_hash(se_.SHA512(path4_));
  dm5_.set_file_hash(se_.SHA512(path5_));
  ASSERT_TRUE(se_.Encrypt(path1_.string(), &dm1_)<0);
  ASSERT_EQ(0, se_.Encrypt(path2_.string(), &dm2_));
  ASSERT_EQ(3, dm2_.chunk_name_size());
  ASSERT_EQ(0, se_.Encrypt(path3_.string(), &dm3_));
  ASSERT_EQ(3, dm3_.chunk_name_size());
  ASSERT_EQ(0, se_.Encrypt(path4_.string(), &dm4_));
  ASSERT_EQ(3, dm4_.chunk_name_size());
  ASSERT_EQ(0, se_.Encrypt(path5_.string(), &dm5_));
  ASSERT_EQ(3, dm5_.chunk_name_size());
}


TEST_F(TestSelfEncryption, FUNC_MAID_DecryptFile) {
  std::string test_file1_ = "test01.txt";
  std::string test_file2_ = "test02.txt";
  std::string test_file3_ = "test03.txt";
  std::string test_file4_ = "test04.txt";
  fs::path path1_(CreateRandomFile(test_file1_, 2), fs::native); //  smallest possible encryptable file
  fs::path path2_(CreateRandomFile(test_file2_, 4), fs::native); //  special small file
  fs::path path3_(CreateRandomFile(test_file3_, 24), fs::native); //  small file
  fs::path path4_(CreateRandomFile(test_file4_, 1024), fs::native); //  regular file
  DataMap dm1_, dm2_, dm3_, dm4_;

  SelfEncryption se_;
  dm1_.set_file_hash(se_.SHA512(path1_));
  dm2_.set_file_hash(se_.SHA512(path2_));
  dm3_.set_file_hash(se_.SHA512(path3_));
  dm4_.set_file_hash(se_.SHA512(path4_));
  ASSERT_EQ(0, se_.Encrypt(path1_.string(), &dm1_));
  ASSERT_EQ(0, se_.Encrypt(path2_.string(), &dm2_));
  ASSERT_EQ(0, se_.Encrypt(path3_.string(), &dm3_));
  ASSERT_EQ(0, se_.Encrypt(path4_.string(), &dm4_));

  fs::path decrypted1_(path1_.string()+".decrypted", fs::native);
  fs::path decrypted2_(path2_.string()+".decrypted", fs::native);
  fs::path decrypted3_(path3_.string()+".decrypted", fs::native);
  fs::path decrypted4_(path4_.string()+".decrypted", fs::native);

  ASSERT_EQ(0, se_.Decrypt(dm1_, decrypted1_.string(), 0, false));
  ASSERT_EQ(0, se_.Decrypt(dm2_, decrypted2_.string(), 0, false));
  ASSERT_EQ(0, se_.Decrypt(dm3_, decrypted3_.string(), 0, false));
  ASSERT_EQ(0, se_.Decrypt(dm4_, decrypted4_.string(), 0, false));

  ASSERT_EQ(se_.SHA512(path1_), se_.SHA512(decrypted1_));
  ASSERT_EQ(se_.SHA512(path2_), se_.SHA512(decrypted2_));
  ASSERT_EQ(se_.SHA512(path3_), se_.SHA512(decrypted3_));
  ASSERT_EQ(se_.SHA512(path4_), se_.SHA512(decrypted4_));
}

}
