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
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/sehandler.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

std::string CreateRandomFile(const std::string &filename,
    int size_ = (1024)) {
  std::string file_content = base::RandomString(size_);
  file_system::FileSystem fsys_;
  fs::path file_path(fsys_.MaidsafeHomeDir());
  file_path = file_path / filename;
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

namespace maidsafe {

class TestSEHandler : public testing::Test {
 protected:
  TestSEHandler() : sm(),
                    client_chunkstore_(),
                    cb(),
                    db_str1_(""),
                    db_str2_("")  {
    try {
      if (fs::exists("KademilaDb.db"))
        fs::remove(fs::path("KademilaDb.db"));
      if (fs::exists("StoreChunks"))
        fs::remove_all("StoreChunks");
      if (fs::exists("./TestSEH"))
        fs::remove_all("./TestSEH");
      if (fs::exists("KademilaDb.db"))
        printf("Kademila.db still there.\n");
      if (fs::exists("StoreChunks"))
        printf("StoreChunks still there.\n");
      if (fs::exists("./TestSEH"))
        printf("./TestSEH still there.\n");
      file_system::FileSystem fsys_;
      if (fs::exists(fsys_.MaidsafeDir()))
        fs::remove_all(fsys_.MaidsafeDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  ~TestSEHandler() {
    fs::path db("MaidDataAtlas.db");
    try {
      if (fs::exists(db))
        fs::remove(db);
      file_system::FileSystem fsys_;
      fs::remove_all(fsys_.MaidsafeDir());
      fs::remove_all("./TestSEH");
      fs::remove_all("StoreChunks");
      fs::path kaddb("KademilaDb.db");
      fs::remove(kaddb);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  void SetUp() {
    client_chunkstore_ =
        boost::shared_ptr<ChunkStore>(new ChunkStore("./TestSEH", 0, 0));
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    boost::shared_ptr<LocalStoreManager>
        sm(new LocalStoreManager(client_chunkstore_));
    cb.Reset();
    sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    boost::mutex mutex;
    wait_for_result_seh(cb, &mutex);
    GenericResponse result;
    if ((!result.ParseFromString(cb.result)) ||
        (result.result() == kNack)) {
      FAIL();
      return;
    }
    SessionSingleton::getInstance()->SetUsername("user1");
    SessionSingleton::getInstance()->SetPin("1234");
    SessionSingleton::getInstance()->SetPassword("password1");
    SessionSingleton::getInstance()->SetSessionName(false);
    SessionSingleton::getInstance()->SetRootDbKey("whatever");
    crypto::RsaKeyPair rsa_kp;
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(PMID, "PMID", rsa_kp.private_key(),
                                            rsa_kp.public_key(), "");
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(MAID, "MAID", rsa_kp.private_key(),
                                            rsa_kp.public_key(), "");
    rsa_kp.GenerateKeys(kRsaKeySize);
    SessionSingleton::getInstance()->AddKey(MPID, "Me", rsa_kp.private_key(),
        rsa_kp.public_key(), "");
    file_system::FileSystem fsys_;
    fsys_.Mount();
    boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());
    boost::scoped_ptr<SEHandler>seh_(new SEHandler(sm.get(),
                                     client_chunkstore_));
    if (dah->Init(true) )
      FAIL();

     //  set up default root subdirs
    for (int i = 0; i < kRootSubdirSize; i++) {
      MetaDataMap mdm_;
      std::string ser_mdm_, key_;
      mdm_.set_id(-2);
      mdm_.set_display_name(base::TidyPath(kRootSubdir[i][0]));
      mdm_.set_type(EMPTY_DIRECTORY);
      mdm_.set_stats("");
      mdm_.set_tag("");
      mdm_.set_file_size_high(0);
      mdm_.set_file_size_low(0);
      boost::uint32_t current_time_ = base::get_epoch_time();
      mdm_.set_creation_time(current_time_);
      mdm_.SerializeToString(&ser_mdm_);
      if (kRootSubdir[i][1] == "")
        seh_->GenerateUniqueKey(PRIVATE, "", 0, &key_);
      else
        key_ = kRootSubdir[i][1];
      fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[i][0]);
      dah->AddElement(base::TidyPath(kRootSubdir[i][0]),
        ser_mdm_, "", key_, true);
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
  }
  boost::shared_ptr<LocalStoreManager> sm;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  FakeCallback cb;
  std::string db_str1_;
  std::string db_str2_;
 private:
  TestSEHandler(const TestSEHandler&);
  TestSEHandler &operator=(const TestSEHandler&);
};


TEST_F(TestSEHandler, FUNC_MAID_Check_Entry) {
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm.get(), client_chunkstore_));
  boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());

  fs::path rel_path_(kRootSubdir[0][0], fs::native);
  fs::path rel_path1_ = rel_path_ / "file1";
  fs::path rel_path2_ = rel_path_ / "file2";
  fs::path rel_path3_ = rel_path_ / "file3";
  fs::path rel_path4_ = rel_path_ / "file4.LNK";
  fs::path rel_path5_ = rel_path_ / "file5";
  fs::path rel_path6_ = rel_path_ / "Dir";
  fs::path rel_path7_ = rel_path6_ / "EmptyDir";
  std::string name_too_long_ = "";
  for (int i = 0; i < 20; i++)
    name_too_long_ += "NameTooLong";
  fs::path rel_path8_ = rel_path_ / name_too_long_;
  std::string rel_str1_ = base::TidyPath(rel_path1_.string());
  std::string rel_str2_ = base::TidyPath(rel_path2_.string());
  std::string rel_str3_ = base::TidyPath(rel_path3_.string());
  std::string rel_str4_ = base::TidyPath(rel_path4_.string());
  std::string rel_str5_ = base::TidyPath(rel_path5_.string());
  std::string rel_str6_ = base::TidyPath(rel_path6_.string());
  std::string rel_str7_ = base::TidyPath(rel_path7_.string());
  std::string rel_str8_ = base::TidyPath(rel_path8_.string());
  int size1_ = 0;
  int size2_ = kMinRegularFileSize - 1;
  int size3_ = kMinRegularFileSize;
  int size4_ = 5;
  int size5_ = 5;
  int size6_ = 0;
  int size7_ = 0;
  int size8_ = 5;
  std::string full_str1_ = CreateRandomFile(rel_str1_, size1_);
  std::string full_str2_ = CreateRandomFile(rel_str2_, size2_);
  std::string full_str3_ = CreateRandomFile(rel_str3_, size3_);
  std::string full_str4_ = CreateRandomFile(rel_str4_, size4_);
  std::string full_str5_ = CreateRandomFile(rel_str5_, size5_);
  file_system::FileSystem fsys_;
  fs::path full_path6_(fsys_.MaidsafeHomeDir(), fs::native);
  full_path6_ /= rel_str6_;
  fs::path full_path7_(fsys_.MaidsafeHomeDir(), fs::native);
  full_path7_ /= rel_str7_;
  fs::create_directories(full_path7_);
  std::string full_str6_ = full_path6_.string();
  std::string full_str7_ = full_path7_.string();
  std::string full_str8_ = CreateRandomFile(rel_str8_, size8_);
  uint64_t returned_size1_, returned_size2_, returned_size3_;
  uint64_t returned_size6_, returned_size7_, returned_size8_;
  ASSERT_TRUE(EMPTY_FILE == seh->CheckEntry(full_str1_, &returned_size1_));
  ASSERT_EQ(size1_, static_cast<int>(returned_size1_));
  ASSERT_TRUE(SMALL_FILE == seh->CheckEntry(full_str2_, &returned_size2_));
  ASSERT_EQ(size2_, static_cast<int>(returned_size2_));
  ASSERT_TRUE(REGULAR_FILE == seh->CheckEntry(full_str3_, &returned_size3_));
  ASSERT_EQ(size3_, static_cast<int>(returned_size3_));
  ASSERT_TRUE(EMPTY_DIRECTORY == seh->CheckEntry(full_str6_, &returned_size6_));
  ASSERT_EQ(size6_, static_cast<int>(returned_size6_));
  ASSERT_TRUE(EMPTY_DIRECTORY == seh->CheckEntry(full_str7_, &returned_size7_));
  ASSERT_EQ(size7_, static_cast<int>(returned_size7_));
  ASSERT_TRUE(NOT_FOR_PROCESSING == seh->CheckEntry(full_str8_,
                                                    &returned_size8_));
}

TEST_F(TestSEHandler, FUNC_MAID_EncryptFile) {
  boost::scoped_ptr<LocalStoreManager>
      sm_(new LocalStoreManager(client_chunkstore_));
  sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), client_chunkstore_));
  boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());

  fs::path rel_path_(kRootSubdir[0][0]);
  rel_path_ /= "file1";
  std::string rel_str_ = base::TidyPath(rel_path_.string());

  std::string full_str_ = CreateRandomFile(rel_str_);
  int result = seh->EncryptFile(rel_str_, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  std::string ser_dm_;
  ASSERT_EQ(0, dah->GetDataMap(rel_str_, &ser_dm_));
  DataMap dm_;
  ASSERT_TRUE(dm_.ParseFromString(ser_dm_));

  for (int i = 0; i < dm_.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm_.encrypted_chunk_name(i), false));
  sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(TestSEHandler, FUNC_MAID_DecryptFile_ChunksPrevLoaded) {
  boost::scoped_ptr<LocalStoreManager>
      sm_(new LocalStoreManager(client_chunkstore_));
  sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), client_chunkstore_));
  boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());

  fs::path rel_path_(kRootSubdir[0][0]);
  rel_path_ /= "file1";
  std::string rel_str_ = base::TidyPath(rel_path_.string());

  std::string full_str_ = CreateRandomFile(rel_str_);
  std::string hash_before_, hash_after_;
  SelfEncryption se_(client_chunkstore_);
  hash_before_ = se_.SHA512(fs::path(full_str_));
  int result = seh->EncryptFile(rel_str_, PRIVATE, "");
  ASSERT_EQ(0, result);
  fs::remove(full_str_);
  ASSERT_FALSE(fs::exists(full_str_));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
//  printf("1 - trying to decrypt: %s\n", rel_str_.c_str());
  result = seh->DecryptFile(rel_str_);
//  printf("2\n");
  ASSERT_EQ(0, result);
//  printf("3 - trying to assert exists: %s\n", full_str_.c_str());
  ASSERT_TRUE(fs::exists(full_str_));
  hash_after_ = se_.SHA512(fs::path(full_str_));
  ASSERT_EQ(hash_before_, hash_after_);
  sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(TestSEHandler, FUNC_MAID_DecryptFile_LoadChunks) {
  SessionSingleton::getInstance()->SetDefConLevel(DEFCON2);
  boost::scoped_ptr<LocalStoreManager>
      sm_(new LocalStoreManager(client_chunkstore_));
  sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), client_chunkstore_));
  boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());

  fs::path rel_path_(kRootSubdir[0][0]);
  rel_path_ /= "file1";
  std::string rel_str_ = base::TidyPath(rel_path_.string());

  std::string full_str_ = CreateRandomFile(rel_str_);
  std::string hash_before_, hash_after_;
  SelfEncryption se_(client_chunkstore_);
  fs::path full_path_(full_str_, fs::native);
  hash_before_ = se_.SHA512(full_path_);
  int result = seh->EncryptFile(rel_str_, PRIVATE, "");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  file_system::FileSystem fsys_;
  // All dirs are removed on fsys_.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  std::string db_dir_original = fsys_.DbDir();
  std::string db_dir_new = "./W";
  try {
    fs::remove_all(db_dir_new);
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  fsys_.Mount();
  ASSERT_FALSE(fs::exists(full_str_));
  fs::create_directories(fsys_.MaidsafeHomeDir() + kRootSubdir[0][0]);
  try {
    fs::remove_all(db_dir_original);
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  result = seh->DecryptFile(rel_str_);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str_));
  hash_after_ = se_.SHA512(fs::path(full_str_));
  ASSERT_EQ(hash_before_, hash_after_);
  sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

//  TEST_F(TestSEHandler, FUNC_MAID_Decrypt_FailedToLoadChunk) {
//   boost::scoped_ptr<LocalStoreManager> sm_(new LocalStoreManager(rec_mutex));
//    sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
//    boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), rec_mutex));
//    boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());
//
//    fs::path rel_path_(kRootSubdir[0][0]);
//    rel_path_ /= "file1";
//    std::string rel_str_ = base::TidyPath(rel_path_.string());
//
//    std::string full_str_ = CreateRandomFile(rel_str_);
//    std::string hash_before_, hash_after_;
//    SelfEncryption se_;
//    fs::path full_path_(full_str_, fs::native);
//    hash_before_ = se_.SHA512(full_path_);
//    int result = seh->EncryptFile(rel_str_, PRIVATE, "");
//    boost::this_thread::sleep(boost::posix_time::seconds(1));
//    ASSERT_EQ(0, result);
//    file_system::FileSystem fsys_;
//    try {
//      fs::remove_all(fsys_.MaidsafeHomeDir());
//      //  NB we can't remove DbDir (which contains dir's db files)
//      //  unless a proper logout/login is run
//      fs::remove_all(fsys_.ProcessDir());
//      for (char c_ = '0'; c_ <= '9'; c_++) {
//        std::stringstream out_;
//        out_ << c_;
//        std::string f = fsys_.ApplicationDataDir() + "/client/" + out_.str();
//        fs::remove_all(f);
//        printf("Removing %s\n", f.c_str());
//      }
//      for (char c_ = 'a'; c_ <= 'f'; c_++) {
//        std::stringstream out_;
//        out_ << c_;
//        std::string f = fsys_.ApplicationDataDir() + "client/" + out_.str();
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
//    sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
//    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
//  }

TEST_F(TestSEHandler, BEH_MAID_EncryptAndDecryptPrivateDb) {
  boost::scoped_ptr<LocalStoreManager>
      sm_(new LocalStoreManager(client_chunkstore_));
  sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), client_chunkstore_));
  boost::scoped_ptr<DataAtlasHandler>dah(new DataAtlasHandler());
  file_system::FileSystem fsys_;
  fs::path db_path_(db_str1_, fs::native);
  std::string key_(seh->SHA512("somekey", false));
//  std::string key_("");
//  ASSERT_EQ(0, seh->GenerateUniqueKey(PRIVATE, "", 0, &key_));
//  dah->GetDirKey(kRootSubdir[0][0], &key_);
  ASSERT_TRUE(fs::exists(db_path_));
  std::string hash_before_ = seh->SHA512(db_str1_, true);
  DataMap dm;
  std::string ser_dm_;
  dm.SerializeToString(&ser_dm_);

  // Create the entry
  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kRootSubdir[0][0]),
    PRIVATE, key_, "", true, &dm));
//  ASSERT_EQ("", ser_dm_);

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]),
    PRIVATE, ser_dm_, key_, "", true, false));
  ASSERT_TRUE(fs::exists(db_path_));
  ASSERT_EQ(hash_before_, seh->SHA512(db_str1_, true));

  // Deleting the details of the DB
  fs::remove(db_path_);
  ASSERT_FALSE(fs::exists(db_path_));
  ASSERT_EQ(0,
    seh->RemoveKeyFromUptodateDms(base::TidyPath(kRootSubdir[0][0]))) <<
    "Didn't find the key in the map of DMs.";

  // Test decryption with no record of the directory DB ser_dm
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]),
    PRIVATE, ser_dm_, key_, "", true, false));
  ASSERT_TRUE(fs::exists(db_path_));
  ASSERT_EQ(hash_before_, seh->SHA512(db_str1_, true));

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kRootSubdir[0][0]),
    PRIVATE, ser_dm_, key_, "", true, false));
  ASSERT_TRUE(fs::exists(db_path_));
  ASSERT_EQ(hash_before_, seh->SHA512(db_str1_, true));

  fs::path key_path_(fsys_.MaidsafeDir(), fs::native);
  key_path_ /= key_;
  fs::remove(key_path_);
  sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}

TEST_F(TestSEHandler, DISABLED_BEH_MAID_EncryptAndDecryptAnonDb) {
  boost::scoped_ptr<LocalStoreManager>
      sm_(new LocalStoreManager(client_chunkstore_));
  sm_->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<SEHandler>seh(new SEHandler(sm_.get(), client_chunkstore_));
  file_system::FileSystem fsys_;
  fs::path db_path_(db_str2_, fs::native);
  std::string key_ = "testkey";
  ASSERT_TRUE(fs::exists(db_path_));
  std::string hash_before_ = seh->SHA512(db_str2_, true);
  std::string ser_dm_;
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  ASSERT_EQ(0, seh->EncryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, key_, "", false, &ser_dm_));
  fs::remove(db_path_);
  ASSERT_FALSE(fs::exists(db_path_));
//  ASSERT_EQ(0,
//    seh->RemoveKeyFromUptodateDms(base::TidyPath(kSharesSubdir[1][0]))) <<
//    "Didn't find the key in the map of DMs.";
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, ser_dm_, key_, "", false, false));
  ASSERT_TRUE(fs::exists(db_path_));
  ASSERT_EQ(hash_before_, seh->SHA512(db_str2_, true));
//  ASSERT_EQ(0, seh->DecryptDb(base::TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, "", key_, "", false, false));
  ASSERT_TRUE(fs::exists(db_path_));
  ASSERT_EQ(hash_before_, seh->SHA512(db_str2_, true));
  fs::path key_path_(fsys_.MaidsafeDir(), fs::native);
  key_path_ /= key_;
  fs::remove(key_path_);
  sm_->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1), true);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
}
}
