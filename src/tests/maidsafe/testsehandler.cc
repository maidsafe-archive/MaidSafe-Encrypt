/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Tests functionality of Self Encryption Handler
* Version:      1.0
* Created:      2009-07-08-03.06.29
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/sehandler.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "tests/maidsafe/cached_keys.h"

namespace fs = boost::filesystem;

namespace test_seh {

std::string CreateRandomFile(const std::string &filename,
                             int size = (1024)) {
  std::string file_content = base::RandomString(size);
  fs::path file_path(file_system::MaidsafeHomeDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()) / filename);
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  return file_path.string();
};

class FakeCallback {
 public:
  FakeCallback() : result("") {}
  void CallbackFunc(const std::string &res) {
    result = res;
  }
  void Reset() {
    result = "";
  }
  std::string result;
};

void wait_for_result_seh(const FakeCallback &cb, boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
};
}  // namespace test_seh

namespace maidsafe {

class SEHandlerTest : public testing::Test {
 protected:
  SEHandlerTest() : test_root_dir_(file_system::TempDir() /
                        ("maidsafe_TestSEH_" + base::RandomString(6))),
                    client_chunkstore_(),
                    cb(),
                    db_str1_(),
                    db_str2_(),
                    ss_(SessionSingleton::getInstance()),
                    keys_() {}
  ~SEHandlerTest() {}
  void SetUp() {
    ss_->SetUsername("user1");
    ss_->SetPin("1234");
    ss_->SetPassword("password1");
    ss_->SetSessionName(false);
    ss_->SetRootDbKey("whatever");
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
      if (fs::exists(file_system::MaidsafeDir(ss_->SessionName())))
        fs::remove_all(file_system::MaidsafeDir(ss_->SessionName()));
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
    boost::shared_ptr<LocalStoreManager>
        sm(new LocalStoreManager(client_chunkstore_));
    cb.Reset();
    sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
    boost::mutex mutex;
    wait_for_result_seh(cb, &mutex);
    GenericResponse result;
    if ((!result.ParseFromString(cb.result)) ||
        (result.result() == kNack)) {
      FAIL();
      return;
    }
    cached_keys::MakeKeys(3, &keys_);
    ss_->AddKey(PMID, "PMID", keys_.at(0).private_key(),
        keys_.at(0).public_key(), "");
    ss_->AddKey(MAID, "MAID", keys_.at(1).private_key(),
        keys_.at(1).public_key(), "");
    ss_->AddKey(MPID, "Me", keys_.at(2).private_key(),
        keys_.at(2).public_key(), "");
    ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));
    boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
    boost::scoped_ptr<SEHandler> seh(new SEHandler());
    seh->Init(sm, client_chunkstore_);
    if (dah->Init(true) )
      FAIL();

     //  set up default root subdirs
    for (int i = 0; i < kRootSubdirSize; i++) {
      MetaDataMap mdm;
      std::string ser_mdm, key;
      mdm.set_id(-2);
      mdm.set_display_name(base::TidyPath(kRootSubdir[i][0]));
      mdm.set_type(EMPTY_DIRECTORY);
      mdm.set_stats("");
      mdm.set_tag("");
      mdm.set_file_size_high(0);
      mdm.set_file_size_low(0);
      boost::uint32_t current_time = base::get_epoch_time();
      mdm.set_creation_time(current_time);
      mdm.SerializeToString(&ser_mdm);
      if (kRootSubdir[i][1].empty())
        seh->GenerateUniqueKey(&key);
      else
        key = kRootSubdir[i][1];
      fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
          kRootSubdir[i][0]);
      dah->AddElement(base::TidyPath(kRootSubdir[i][0]),
          ser_mdm, "", key, true);
    }

// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//    //set up Anon share subdir
//    fs::path subdir_(kSharesSubdir[1][0], fs::native);
//    std::string subdir_name_ = subdir_.filename();
//    MetaDataMap mdm_;
//    std::string ser_mdm_, key_;
//    mdm_.set_id(-2);
//    mdm_.set_display_name(subdir_name_);
//    mdm_.set_type(EMPTY_DIRECTORY);
//    mdm_.set_stats("");
//    mdm_.set_tag("");
//    mdm_.set_file_size_high(0);
//    mdm_.set_file_size_low(0);
//    boost::uint32_t current_time_ = base::get_epoch_time();
//    mdm_.set_creation_time(current_time_);
//    mdm_.SerializeToString(&ser_mdm_);
//    key_ = kSharesSubdir[1][1];
//    dah->AddElement(base::TidyPath(kSharesSubdir[1][0]),
//      ser_mdm_, "", key_, true);
//
    dah->GetDbPath(base::TidyPath(kRootSubdir[0][0]), CREATE, &db_str1_);
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//    dah->GetDbPath(base::TidyPath(kSharesSubdir[1][0]), CREATE, &db_str2_);
    cb.Reset();
  }
  void TearDown() {
    cb.Reset();
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
      if (fs::exists(file_system::MaidsafeDir(ss_->SessionName())))
        fs::remove_all(file_system::MaidsafeDir(ss_->SessionName()));
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  fs::path test_root_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  test_seh::FakeCallback cb;
  std::string db_str1_, db_str2_;
  SessionSingleton *ss_;
  std::vector<crypto::RsaKeyPair> keys_;
 private:
  SEHandlerTest(const SEHandlerTest&);
  SEHandlerTest &operator=(const SEHandlerTest&);
};

TEST_F(SEHandlerTest, BEH_MAID_Check_Entry) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0], fs::native);
  fs::path rel_path1 = rel_path / "file1";
  fs::path rel_path2 = rel_path / "file2";
  fs::path rel_path3 = rel_path / "file3";
  fs::path rel_path4 = rel_path / "file4.LNK";
  fs::path rel_path5 = rel_path / "file5";
  fs::path rel_path6 = rel_path / "Dir";
  fs::path rel_path7 = rel_path6 / "EmptyDir";
  std::string name_too_long = "";
  for (int i = 0; i < 20; i++)
    name_too_long += "NameTooLong";
  fs::path rel_path8 = rel_path / name_too_long;
  fs::path rel_path9 = rel_path / "file9";
  std::string rel_str1 = base::TidyPath(rel_path1.string());
  std::string rel_str2 = base::TidyPath(rel_path2.string());
  std::string rel_str3 = base::TidyPath(rel_path3.string());
  std::string rel_str4 = base::TidyPath(rel_path4.string());
  std::string rel_str5 = base::TidyPath(rel_path5.string());
  std::string rel_str6 = base::TidyPath(rel_path6.string());
  std::string rel_str7 = base::TidyPath(rel_path7.string());
  std::string rel_str8 = base::TidyPath(rel_path8.string());
  std::string rel_str9 = base::TidyPath(rel_path9.string());
  boost::uint64_t size1 = 0;
  boost::uint64_t size2 = kMinRegularFileSize - 1;
  boost::uint64_t size3 = kMinRegularFileSize;
  boost::uint64_t size4 = 5;
  boost::uint64_t size5 = 5;
  boost::uint64_t size6 = 0;
  boost::uint64_t size7 = 0;
  boost::uint64_t size8 = 0;
  boost::uint64_t size9 = 0;
  fs::path full_path1(test_seh::CreateRandomFile(rel_str1, size1));
  fs::path full_path2(test_seh::CreateRandomFile(rel_str2, size2));
  fs::path full_path3(test_seh::CreateRandomFile(rel_str3, size3));
  fs::path full_path4(test_seh::CreateRandomFile(rel_str4, size4));
  fs::path full_path5(test_seh::CreateRandomFile(rel_str5, size5));
  fs::path full_path6(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      rel_str6);
  fs::path full_path7(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      rel_str7);
  fs::create_directories(full_path7);
  fs::path full_path8 = test_seh::CreateRandomFile(rel_str8, size8);
  fs::path full_path9 = test_seh::CreateRandomFile(rel_str9, size9);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string hash1(co.Hash(full_path1.string(), "", crypto::FILE_STRING,
      false));
  std::string hash2(co.Hash(full_path2.string(), "", crypto::FILE_STRING,
      false));
  std::string hash3(co.Hash(full_path3.string(), "", crypto::FILE_STRING,
      false));
  std::string hash6, hash7, hash8;
  std::string hash9(co.Hash(full_path9.string(), "", crypto::FILE_STRING,
      false));
  fs::path before(full_path9);
  fs::path after(full_path9.parent_path() / base::EncodeToHex(hash9));
  fs::rename(before, after);
  full_path9 = after;
  boost::uint64_t returned_size1(9), returned_size2(9), returned_size3(9);
  boost::uint64_t returned_size6(9), returned_size7(9), returned_size8(9);
  boost::uint64_t returned_size9(9);
  std::string returned_hash1("A"), returned_hash2("A"), returned_hash3("A");
  std::string returned_hash6("A"), returned_hash7("A"), returned_hash8("A");
  std::string returned_hash9("A");
  ASSERT_EQ(EMPTY_FILE,
            seh->CheckEntry(full_path1, &returned_size1, &returned_hash1));
  ASSERT_EQ(size1, returned_size1);
  ASSERT_EQ(hash1, returned_hash1);
  ASSERT_EQ(SMALL_FILE,
            seh->CheckEntry(full_path2, &returned_size2, &returned_hash2));
  ASSERT_EQ(size2, returned_size2);
  ASSERT_EQ(hash2, returned_hash2);
  ASSERT_EQ(REGULAR_FILE,
            seh->CheckEntry(full_path3, &returned_size3, &returned_hash3));
  ASSERT_EQ(size3, returned_size3);
  ASSERT_EQ(hash3, returned_hash3);
  ASSERT_EQ(EMPTY_DIRECTORY,
            seh->CheckEntry(full_path6, &returned_size6, &returned_hash6));
  ASSERT_EQ(size6, returned_size6);
  ASSERT_EQ(hash6, returned_hash6);
  ASSERT_EQ(EMPTY_DIRECTORY,
            seh->CheckEntry(full_path7, &returned_size7, &returned_hash7));
  ASSERT_EQ(size7, returned_size7);
  ASSERT_EQ(hash7, returned_hash7);
  ASSERT_EQ(NOT_FOR_PROCESSING,
            seh->CheckEntry(full_path8, &returned_size8, &returned_hash8));
  ASSERT_EQ(size8, returned_size8);
  ASSERT_EQ(hash8, returned_hash8);
  ASSERT_EQ(MAIDSAFE_CHUNK,
            seh->CheckEntry(full_path9, &returned_size9, &returned_hash9));
  ASSERT_EQ(size9, returned_size9);
  ASSERT_TRUE(returned_hash9.empty());
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptFile) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str);
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  std::string ser_dm;
  ASSERT_EQ(0, dah->GetDataMap(rel_str, &ser_dm));
  ASSERT_FALSE(ser_dm.empty());
  DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm->KeyUnique(dm.encrypted_chunk_name(i), false));
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptString) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);


  std::string data(base::RandomString(1024)), ser_dm;
  int result = seh->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  maidsafe::DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm->KeyUnique(dm.encrypted_chunk_name(i), false));
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithChunksPrevLoaded) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);


  std::string data(base::RandomString(19891/*1024*/)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  std::string dec_string;
  result = seh->DecryptString(ser_dm, &dec_string);
  ASSERT_EQ(0, result);
  ASSERT_EQ(data, dec_string);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithLoadChunks) {
  ss_->SetDefConLevel(kDefCon2);
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  std::string data(base::RandomString(1024)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh->EncryptString(data, &ser_dm);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  // All dirs are removed on fsys_.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  fs::path db_dir_original = file_system::DbDir(ss_->SessionName());
  std::string db_dir_new = "./W";
  try {
    fs::remove_all(db_dir_new);
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));

  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      kRootSubdir[0][0]);
  try {
    fs::remove_all(db_dir_original);
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  std::string dec_string;
  result = seh->DecryptString(ser_dm, &dec_string);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);

  ASSERT_EQ(data, dec_string);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithChunksPrevLoaded) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  hash_before = se.SHA512(fs::path(full_str));
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);
  fs::remove(full_str);
  ASSERT_FALSE(fs::exists(full_str));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
//  printf("1 - trying to decrypt: %s\n", rel_str.c_str());
  result = seh->DecryptFile(rel_str);
//  printf("2\n");
  ASSERT_EQ(0, result);
//  printf("3 - trying to assert exists: %s\n", full_str.c_str());
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithLoadChunks) {
  ss_->SetDefConLevel(kDefCon2);
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = base::TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  fs::path full_path(full_str, fs::native);
  hash_before = se.SHA512(full_path);
  int result = seh->EncryptFile(rel_str, PRIVATE, "");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  // All dirs are removed on fsys.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  fs::path db_dir_original = file_system::DbDir(ss_->SessionName());
  std::string db_dir_new = "./W";
  try {
    fs::remove_all(db_dir_new);
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));
  ASSERT_FALSE(fs::exists(full_str));
  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      kRootSubdir[0][0]);
  try {
    fs::remove_all(db_dir_original);
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  result = seh->DecryptFile(rel_str);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

//  TEST_F(SEHandlerTest, FUNC_MAID_Decrypt_FailedToLoadChunk) {
//   boost::shared_ptr<LocalStoreManager> sm_(new LocalStoreManager(rec_mutex));
//    sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
//    boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), rec_mutex));
//    boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());
//
//    fs::path rel_path_(kRootSubdir[0][0]);
//    rel_path /= "file1";
//    std::string rel_str = base::TidyPath(rel_path_.string());
//
//    std::string full_str = test_seh::CreateRandomFile(rel_str_);
//    std::string hash_before_, hash_after_;
//    SelfEncryption se_;
//    fs::path full_path_(full_str_, fs::native);
//    hash_before = se_.SHA512(full_path_);
//    int result = seh->EncryptFile(rel_str_, PRIVATE, "");
//    boost::this_thread::sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, result);
//    file_system::FileSystem fsys_;
//    try {
//      fs::remove_all(fsys_.MaidsafeHomeDir());
//      //  NB we can't remove DbDir (which contains dir's db files)
//      //  unless a proper logout/login is run
//      fs::remove_all(fsys_.ProcessDir());
//      for (char c = '0'; c <= '9'; c_++) {
//        std::stringstream out_;
//        out << c_;
//        std::string f = file_system::ApplicationDataDir() +
//                        "/client/" + out_.str();
//        fs::remove_all(f);
//        printf("Removing %s\n", f.c_str());
//      }
//      for (char c = 'a'; c <= 'f'; c_++) {
//        std::stringstream out_;
//        out << c_;
//        std::string f = file_system::ApplicationDataDir() +
//                        "client/" + out_.str();
//        fs::remove_all(f);
//        printf("Removing %s\n", f.c_str());
//      }
//    }
//    catch(std::exception& e) {
//      printf("%s\n", e.what());
//    }
//    ASSERT_FALSE(fs::exists(full_str_));
//
//    std::string ser_dm;
//    ASSERT_EQ(0, dah->GetDataMap(rel_str_, &ser_dm));
//    DataMap dm;
//    ASSERT_TRUE(dm.ParseFromString(ser_dm));
//    fs::path chunk_path("");
//    chunk_path = se_.GetChunkPath(dm.encrypted_chunk_name(2));
//    printf("Removing %s\n", chunk_path.string().c_str());
//    fs::remove(chunk_path);
//
//    fsys_.Mount();
//    fs::create_directories(fsys_.MaidsafeHomeDir() + kRootSubdir[0][0]);
//
//    result = seh->DecryptFile(rel_str_);
//    boost::this_thread::sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, result);
//    ASSERT_FALSE(fs::exists(full_str_));
//    sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1),
//              true);
//    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
//  }

TEST_F(SEHandlerTest, BEH_MAID_EncryptAndDecryptPrivateDb) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path db_path(db_str1_, fs::native);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string key = co.Hash("somekey", "", crypto::STRING_STRING, false);
//  std::string key;
//  ASSERT_EQ(0, seh->GenerateUniqueKey(&key));
//  dah->GetDirKey(kRootSubdir[0][0], &key);
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = co.Hash(db_str1_, "", crypto::FILE_STRING, false);
  DataMap dm;
  std::string ser_dm;
  dm.SerializeToString(&ser_dm);

  // Create the entry
  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE, key,
            "", true, &dm));
//  ASSERT_EQ("", ser_dm);

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));

  // Deleting the details of the DB
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
  ASSERT_EQ(0,
    seh->RemoveKeyFromUptodateDms(base::TidyPath(kRootSubdir[0][0]))) <<
    "Didn't find the key in the map of DMs.";

  // Test decryption with no record of the directory DB ser_dm
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(SEHandlerTest, DISABLED_BEH_MAID_EncryptAndDecryptAnonDb) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  boost::scoped_ptr<SEHandler> seh(new SEHandler());
  seh->Init(sm, client_chunkstore_);

  fs::path db_path(db_str2_, fs::native);
  std::string key = "testkey";
  ASSERT_TRUE(fs::exists(db_path));
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string hash_before = co.Hash(db_str2_, "", crypto::FILE_STRING, false);
  std::string ser_dm;
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, key, "", false, &ser_dm));
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
//  ASSERT_EQ(0,
//    seh->RemoveKeyFromUptodateDms(base::TidyPath(kSharesSubdir[1][0]))) <<
//    "Didn't find the key in the map of DMs.";
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, ser_dm, key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str2_, "", crypto::FILE_STRING, false));
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, "", key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str2_, "", crypto::FILE_STRING, false));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
  sm->Close(boost::bind(&test_seh::FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

}  // namespace maidsafe
