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
#include <limits.h>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/returncodes.h"
#include "maidsafe/pdutils.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/sehandler.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/testcallback.h"

namespace fs = boost::filesystem;

namespace test_seh {

static const boost::uint8_t K(4);

std::string CreateRandomFile(const std::string &filename,
                             const boost::uint64_t &filesize) {
  int file_size = static_cast<int>(filesize);
  if (filesize > INT_MAX)
    file_size = INT_MAX;
  std::string file_content = base::RandomString(file_size);
  fs::path file_path(file_system::MaidsafeHomeDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()) / filename);
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  return file_path.string();
}

void ModifyUpToDateDms(ModificationType modification_type,
                       const boost::uint16_t &test_size,
                       const std::vector<std::string> &keys,
                       const std::vector<std::string> &enc_dms,
                       boost::shared_ptr<maidsafe::SEHandler> seh) {
  switch (modification_type) {
    case kAdd:
      for (boost::uint16_t i = 0; i < test_size; ++i)
        seh->AddToUpToDateDms(keys.at(i), enc_dms.at(i));
      break;
    case kGet:
      for (boost::uint16_t i = 0; i < test_size; ++i)
        seh->GetFromUpToDateDms(keys.at(i));
      break;
    case kRemove:
      for (boost::uint16_t i = 0; i < test_size; ++i)
        seh->RemoveFromUpToDateDms(keys.at(i));
      break;
    default:
      break;
  }
}

}  // namespace test_seh

namespace maidsafe {

namespace test {

class SEHandlerTest : public testing::Test {
 protected:
  SEHandlerTest() : test_root_dir_(file_system::TempDir() /
                        ("maidsafe_TestSEH_" + base::RandomString(6))),
                    client_chunkstore_(),
                    cb_(),
                    db_str1_(),
                    db_str2_(),
                    ss_(SessionSingleton::getInstance()),
                    keys_(),
                    sm_(),
                    dah_(new DataAtlasHandler()),
                    seh_(new SEHandler()) {}
  ~SEHandlerTest() {}
  void SetUp() {
    ss_->SetUsername("user1");
    ss_->SetPin("1234");
    ss_->SetPassword("password1");
    ss_->SetSessionName(false);
    ss_->SetRootDbKey("whatever");
    ASSERT_TRUE(file_system::RemoveDir(test_root_dir_, 5));
    ASSERT_TRUE(file_system::RemoveDir(file_system::LocalStoreManagerDir(), 5));
    ASSERT_TRUE(file_system::RemoveDir(
        file_system::MaidsafeDir(ss_->SessionName()), 5));
    client_chunkstore_ = boost::shared_ptr<ChunkStore>(
        new ChunkStore(test_root_dir_.string(), 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    sm_.reset(new LocalStoreManager(client_chunkstore_, test_seh::K,
                                    test_root_dir_));
    cb_.Reset();
    sm_->Init(boost::bind(&test::CallbackObject::ReturnCodeCallback, &cb_, _1),
              0);
    if (cb_.WaitForReturnCodeResult() != kSuccess) {
      FAIL();
      return;
    }
    cached_keys::MakeKeys(3, &keys_);
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    std::string pmid_sig = co.AsymSign(keys_.at(0).public_key(), "",
        keys_.at(1).private_key(), crypto::STRING_STRING);
    std::string pmid = co.Hash(keys_.at(0).public_key() + pmid_sig, "",
                               crypto::STRING_STRING, false);
    ss_->AddKey(PMID, pmid, keys_.at(0).private_key(), keys_.at(0).public_key(),
                pmid_sig);
    ss_->AddKey(MAID, "MAID", keys_.at(1).private_key(),
                keys_.at(1).public_key(), "");
    ss_->AddKey(MPID, "Me", keys_.at(2).private_key(),
                keys_.at(2).public_key(), "");
    ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));
    seh_->Init(sm_, client_chunkstore_);
    if (dah_->Init(true) )
      FAIL();

     //  set up default root subdirs
    for (int i = 0; i < kRootSubdirSize; i++) {
      MetaDataMap mdm;
      std::string ser_mdm, key;
      mdm.set_id(-2);
      mdm.set_display_name(TidyPath(kRootSubdir[i][0]));
      mdm.set_type(EMPTY_DIRECTORY);
      mdm.set_stats("");
      mdm.set_tag("");
      mdm.set_file_size_high(0);
      mdm.set_file_size_low(0);
      boost::uint32_t current_time = base::GetEpochTime();
      mdm.set_creation_time(current_time);
      mdm.SerializeToString(&ser_mdm);
      if (kRootSubdir[i][1].empty())
        seh_->GenerateUniqueKey(&key);
      else
        key = kRootSubdir[i][1];
      fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
          kRootSubdir[i][0]);
      dah_->AddElement(TidyPath(kRootSubdir[i][0]),
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
//    boost::uint32_t current_time_ = base::GetEpochTime();
//    mdm_.set_creation_time(current_time_);
//    mdm_.SerializeToString(&ser_mdm_);
//    key_ = kSharesSubdir[1][1];
//    dah_->AddElement(TidyPath(kSharesSubdir[1][0]),
//      ser_mdm_, "", key_, true);
//
    dah_->GetDbPath(TidyPath(kRootSubdir[0][0]), CREATE, &db_str1_);
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//    dah_->GetDbPath(TidyPath(kSharesSubdir[1][0]), CREATE, &db_str2_);
    cb_.Reset();
  }
  void TearDown() {
    cb_.Reset();
    sm_->Close(boost::bind(&test::CallbackObject::ReturnCodeCallback, &cb_, _1),
               true);
    ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
    ASSERT_TRUE(file_system::RemoveDir(test_root_dir_, 5));
    ASSERT_TRUE(file_system::RemoveDir(file_system::LocalStoreManagerDir(), 5));
    ASSERT_TRUE(file_system::RemoveDir(
        file_system::MaidsafeDir(ss_->SessionName()), 5));
  }
  fs::path test_root_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  test::CallbackObject cb_;
  std::string db_str1_, db_str2_;
  SessionSingleton *ss_;
  std::vector<crypto::RsaKeyPair> keys_;
  boost::shared_ptr<LocalStoreManager> sm_;
  boost::shared_ptr<DataAtlasHandler> dah_;
  boost::shared_ptr<SEHandler> seh_;
 private:
  SEHandlerTest(const SEHandlerTest&);
  SEHandlerTest &operator=(const SEHandlerTest&);
};

TEST_F(SEHandlerTest, BEH_MAID_Check_Entry) {
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
  std::string rel_str1 = TidyPath(rel_path1.string());
  std::string rel_str2 = TidyPath(rel_path2.string());
  std::string rel_str3 = TidyPath(rel_path3.string());
  std::string rel_str4 = TidyPath(rel_path4.string());
  std::string rel_str5 = TidyPath(rel_path5.string());
  std::string rel_str6 = TidyPath(rel_path6.string());
  std::string rel_str7 = TidyPath(rel_path7.string());
  std::string rel_str8 = TidyPath(rel_path8.string());
  std::string rel_str9 = TidyPath(rel_path9.string());
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
            seh_->CheckEntry(full_path1, &returned_size1, &returned_hash1));
  ASSERT_EQ(size1, returned_size1);
  ASSERT_EQ(hash1, returned_hash1);
  ASSERT_EQ(SMALL_FILE,
            seh_->CheckEntry(full_path2, &returned_size2, &returned_hash2));
  ASSERT_EQ(size2, returned_size2);
  ASSERT_EQ(hash2, returned_hash2);
  ASSERT_EQ(REGULAR_FILE,
            seh_->CheckEntry(full_path3, &returned_size3, &returned_hash3));
  ASSERT_EQ(size3, returned_size3);
  ASSERT_EQ(hash3, returned_hash3);
  ASSERT_EQ(EMPTY_DIRECTORY,
            seh_->CheckEntry(full_path6, &returned_size6, &returned_hash6));
  ASSERT_EQ(size6, returned_size6);
  ASSERT_EQ(hash6, returned_hash6);
  ASSERT_EQ(EMPTY_DIRECTORY,
            seh_->CheckEntry(full_path7, &returned_size7, &returned_hash7));
  ASSERT_EQ(size7, returned_size7);
  ASSERT_EQ(hash7, returned_hash7);
  ASSERT_EQ(NOT_FOR_PROCESSING,
            seh_->CheckEntry(full_path8, &returned_size8, &returned_hash8));
  ASSERT_EQ(size8, returned_size8);
  ASSERT_EQ(hash8, returned_hash8);
  ASSERT_EQ(MAIDSAFE_CHUNK,
            seh_->CheckEntry(full_path9, &returned_size9, &returned_hash9));
  ASSERT_EQ(size9, returned_size9);
  ASSERT_TRUE(returned_hash9.empty());
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptFile) {
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 1024);
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  std::string ser_dm;
  ASSERT_EQ(0, dah_->GetDataMap(rel_str, &ser_dm));
  ASSERT_FALSE(ser_dm.empty());
  DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptString) {
  std::string data(base::RandomString(1024)), ser_dm;
  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Check the chunks are stored
  maidsafe::DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithChunksPrevLoaded) {
  std::string data(base::RandomString(19891/*1024*/)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  std::string dec_string;
  result = seh_->DecryptString(ser_dm, &dec_string);
  ASSERT_EQ(0, result);
  ASSERT_EQ(data, dec_string);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithLoadChunks) {
  std::string data(base::RandomString(1024)), ser_dm;

  SelfEncryption se(client_chunkstore_);
  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);
  // All dirs are removed on fsys_.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  fs::path db_dir_original = file_system::DbDir(ss_->SessionName());
  std::string db_dir_new = "./W";
  ASSERT_TRUE(file_system::RemoveDir(db_dir_new, 5));
  try {
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));

  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      kRootSubdir[0][0]);
  ASSERT_TRUE(file_system::RemoveDir(db_dir_original, 5));
  try {
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  std::string dec_string;
  result = seh_->DecryptString(ser_dm, &dec_string);
  ASSERT_EQ(0, result);

  ASSERT_EQ(data, dec_string);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithChunksPrevLoaded) {
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 1024);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  hash_before = se.SHA512(fs::path(full_str));
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);
  fs::remove(full_str);
  ASSERT_FALSE(fs::exists(full_str));

  result = seh_->DecryptFile(rel_str);
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithLoadChunks) {
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 1024);
  std::string hash_before, hash_after;
  SelfEncryption se(client_chunkstore_);
  fs::path full_path(full_str, fs::native);
  hash_before = se.SHA512(full_path);
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);
  // All dirs are removed on fsys.Mount() below.  We need to temporarily rename
  // DbDir (which contains dir's db files) to avoid deletion.
  fs::path db_dir_original = file_system::DbDir(ss_->SessionName());
  std::string db_dir_new = "./W";
  ASSERT_TRUE(file_system::RemoveDir(db_dir_new, 5));
  try {
    fs::rename(db_dir_original, db_dir_new);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));
  ASSERT_FALSE(fs::exists(full_str));
  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      kRootSubdir[0][0]);
  ASSERT_TRUE(file_system::RemoveDir(db_dir_original, 5));
  try {
    fs::rename(db_dir_new, db_dir_original);
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  result = seh_->DecryptFile(rel_str);
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = se.SHA512(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptAndDecryptPrivateDb) {
  fs::path db_path(db_str1_, fs::native);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string key = co.Hash("somekey", "", crypto::STRING_STRING, false);
//  std::string key;
//  ASSERT_EQ(0, seh_->GenerateUniqueKey(&key));
//  dah_->GetDirKey(kRootSubdir[0][0], &key);
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = co.Hash(db_str1_, "", crypto::FILE_STRING, false);
  DataMap dm;

  // Create the entry
  ASSERT_EQ(0, seh_->EncryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE, key,
            "", true, &dm));
//  ASSERT_EQ("", ser_dm);

  std::string ser_dm;
  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));

  // Deleting the details of the DB
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
  ASSERT_EQ(0, seh_->RemoveFromUpToDateDms(key)) <<
      "Didn't find the key in the map of DMs.";

  // Test decryption with no record of the directory DB ser_dm
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
            ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str1_, "", crypto::FILE_STRING, false));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
}

TEST_F(SEHandlerTest, DISABLED_BEH_MAID_EncryptAndDecryptAnonDb) {
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
//  ASSERT_EQ(0, seh_->EncryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, key, "", false, &ser_dm));
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
//  ASSERT_EQ(0,
//    seh_->RemoveKeyFromUptodateDms(TidyPath(kSharesSubdir[1][0]))) <<
//    "Didn't find the key in the map of DMs.";
//  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, ser_dm, key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str2_, "", crypto::FILE_STRING, false));
//  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, "", key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, co.Hash(db_str2_, "", crypto::FILE_STRING, false));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
}

TEST_F(SEHandlerTest, BEH_MAID_UpToDateDatamapsSingleThread) {
  const boost::uint16_t kTestSize(100);
  const boost::uint16_t kTestIndex(base::RandomUint32() % kTestSize);
  std::vector<std::string> keys(kTestSize, ""), enc_dms(kTestSize, "");
  for (boost::uint16_t i = 0; i < kTestSize; ++i) {
    keys.at(i) = base::RandomString(64);
    enc_dms.at(i) = base::RandomString(200);
  }
  std::string test_key(keys.at(kTestIndex));
  std::string test_enc_dm_before(keys.at(kTestIndex));
  std::string test_enc_dm_after(keys.at(kTestIndex));
  while (test_enc_dm_after == test_enc_dm_before)
    test_enc_dm_after = base::RandomString(200);

  // Add keys that don't equal the test key (usually all except one)
  for (boost::uint16_t i = 0; i < kTestSize; ++i) {
    if (keys.at(i) != test_key)
      seh_->AddToUpToDateDms(keys.at(i), enc_dms.at(i));
  }
  size_t map_size = seh_->up_to_date_datamaps_.size();

  // Check trying to retrieve enc_dm returns empty string
  ASSERT_TRUE(seh_->GetFromUpToDateDms(test_key).empty());
  ASSERT_EQ(map_size, seh_->up_to_date_datamaps_.size());

  // Check trying to remove non-existant enc_dm fails
  ASSERT_EQ(kEncryptionDmNotInMap, seh_->RemoveFromUpToDateDms(test_key));
  ASSERT_EQ(map_size, seh_->up_to_date_datamaps_.size());

  // Check initial addition returns empty string
  ASSERT_TRUE(seh_->AddToUpToDateDms(test_key, test_enc_dm_before).empty());
  ASSERT_EQ(map_size + 1, seh_->up_to_date_datamaps_.size());

  // Check we can retrieve enc_dm
  ASSERT_EQ(test_enc_dm_before, seh_->GetFromUpToDateDms(test_key));
  ASSERT_EQ(map_size + 1, seh_->up_to_date_datamaps_.size());

  // Check subsequent addition returns previous enc_dm
  ASSERT_EQ(test_enc_dm_before,
            seh_->AddToUpToDateDms(test_key, test_enc_dm_after));
  ASSERT_EQ(map_size + 1, seh_->up_to_date_datamaps_.size());

  // Check we can retrieve updated enc_dm
  ASSERT_EQ(test_enc_dm_after, seh_->GetFromUpToDateDms(test_key));
  ASSERT_EQ(map_size + 1, seh_->up_to_date_datamaps_.size());

  // Check we can remove enc_dm
  ASSERT_EQ(kSuccess, seh_->RemoveFromUpToDateDms(test_key));
  ASSERT_TRUE(seh_->GetFromUpToDateDms(test_key).empty());
  ASSERT_EQ(map_size, seh_->up_to_date_datamaps_.size());
}

TEST_F(SEHandlerTest, BEH_MAID_UpToDateDatamapsMultiThread) {
  const boost::uint16_t kTestSize(100);
  std::vector<std::string> keys(kTestSize, ""), enc_dms(kTestSize, "");
  for (boost::uint16_t i = 0; i < kTestSize; ++i) {
    keys.at(i) = base::RandomString(64);
    enc_dms.at(i) = base::RandomString(200);
    seh_->AddToUpToDateDms(keys.at(i), enc_dms.at(i));
  }
  boost::thread thr1(&test_seh::ModifyUpToDateDms, test_seh::kAdd, kTestSize,
                     keys, enc_dms, seh_);
  boost::thread thr2(&test_seh::ModifyUpToDateDms, test_seh::kGet, kTestSize,
                     keys, enc_dms, seh_);
  boost::thread thr3(&test_seh::ModifyUpToDateDms, test_seh::kRemove, kTestSize,
                     keys, enc_dms, seh_);
  thr1.join();
  thr2.join();
  thr3.join();
}

}  // namespace test

}  // namespace maidsafe
