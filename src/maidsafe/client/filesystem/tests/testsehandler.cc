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
#include <gtest/gtest.h>
#include <maidsafe/encrypt/selfencryption.h>

#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/client/filesystem/dataatlashandler.h"
#include "maidsafe/client/filesystem/sehandler.h"
#include "maidsafe/client/clientutils.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/sharedtest/cachepassport.h"
#include "maidsafe/sharedtest/testcallback.h"

namespace fs = boost::filesystem;

namespace test_seh {

static const boost::uint8_t K(4);

std::string CreateSetFile(const std::string &filename,
                          const std::string &file_content) {
  fs::path file_path(file_system::MaidsafeHomeDir(
      maidsafe::SessionSingleton::getInstance()->SessionName()) / filename);
  fs::ofstream ofs;
  ofs.open(file_path, std::ofstream::binary | std::ofstream::ate);
  ofs.write(file_content.data(), file_content.size());
  ofs.close();
  return file_path.string();
}

std::string CreateRandomFile(const std::string &filename,
                             const boost::uint64_t &filesize) {
  int file_size = static_cast<int>(filesize);
  if (filesize > INT_MAX)
    file_size = INT_MAX;
  std::string file_content = base::RandomAlphaNumericString(file_size);
  return CreateSetFile(filename, file_content);
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

void FileUpdate(const std::string &file, int percentage, int *result,
                boost::mutex *mutex) {
  boost::mutex::scoped_lock loch_lyon(*mutex);
  printf("%s - %d%%\n", file.c_str(), percentage);
  *result = percentage;
}

void MultipleFileUpdate(
    const std::string &file, int percentage,
    std::vector<boost::tuple<std::string, std::string, int> > *fileage,
    boost::mutex *mutex, bool *done, int *received_chunks) {
  boost::mutex::scoped_lock loch_lyon(*mutex);
  printf("MultipleFileUpdate - %s (%d)\n", file.c_str(), percentage);
  if (percentage == 100) {
    ++(*received_chunks);
  }

  size_t finished(0);
  for (size_t n = 0; n < fileage->size(); ++n) {
    if (file == fileage->at(n).get<0>()) {
      fileage->at(n).get<2>() = percentage;
    }
    if (fileage->at(n).get<2>() == 100 || fileage->at(n).get<2>() == -1)
      ++finished;
  }

  if (finished == fileage->size())
    *done = true;
}

void MultipleEqualFileUpdate(
    const std::string &file, int, boost::mutex *mutex, int *received_chunks) {
  boost::mutex::scoped_lock loch_lyon(*mutex);
  ++(*received_chunks);
  printf("MultipleEqualFileUpdate - %d - %s\n", *received_chunks, file.c_str());
}

void SamePathDifferentContent(const std::string &, int percentage,
                              int *result, boost::mutex *mutex) {
  boost::mutex::scoped_lock loch_lyon(*mutex);
  if (percentage == 100)
    ++(*result);
}

}  // namespace test_seh

namespace maidsafe {

namespace test {

class SEHandlerTest : public testing::Test {
 protected:
  SEHandlerTest() : test_root_dir_(file_system::TempDir() / ("maidsafe_TestSEH_"
                                   + base::RandomAlphaNumericString(6))),
                    client_chunkstore_(), cb_(), db_str1_(), db_str2_(),
                    ss_(SessionSingleton::getInstance()), keys_(), sm_(),
                    dah_(), seh_() {}

  ~SEHandlerTest() {}

  void SetUp() {
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss_->passport_ = passport;
    ss_->ResetSession();
    ss_->CreateTestPackets("PublicName");
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
    sm_.reset(new LocalStoreManager(client_chunkstore_, test_seh::K,
                                    test_root_dir_));
    sm_->Init(boost::bind(&test::CallbackObject::ReturnCodeCallback, &cb_, _1),
              0);
    if (cb_.WaitForReturnCodeResult() != kSuccess) {
      FAIL();
      return;
    }
    ASSERT_EQ(0, file_system::Mount(ss_->SessionName(), ss_->DefConLevel()));
    dah_.reset(new DataAtlasHandler());
    seh_.reset(new SEHandler());
    seh_->Init(sm_, client_chunkstore_);
    if (dah_->Init(true))
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
      mdm.set_creation_time(base::GetEpochTime());
      mdm.SerializeToString(&ser_mdm);
      if (kRootSubdir[i][1].empty())
        seh_->GenerateUniqueKey(&key);
      else
        key = kRootSubdir[i][1];
      fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
                                                          kRootSubdir[i][0]);
      dah_->AddElement(TidyPath(kRootSubdir[i][0]), ser_mdm, "", key, true);
    }
    dah_->GetDbPath(TidyPath(kRootSubdir[0][0]), CREATE, &db_str1_);
    cb_.Reset();
  }

  void TearDown() {
    cb_.Reset();
    sm_->Close(boost::bind(&test::CallbackObject::ReturnCodeCallback, &cb_, _1),
               true);
    if (cb_.WaitForReturnCodeResult() == kSuccess) {}
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
  test::CallbackObject cb_;
  std::string db_str1_, db_str2_;
  SessionSingleton *ss_;
  std::vector<crypto::RsaKeyPair> keys_;
  boost::shared_ptr<LocalStoreManager> sm_;
  boost::scoped_ptr<DataAtlasHandler> dah_;
  boost::scoped_ptr<SEHandler> seh_;

 private:
  SEHandlerTest(const SEHandlerTest&);
  SEHandlerTest &operator=(const SEHandlerTest&);
};

TEST_F(SEHandlerTest, BEH_MAID_Check_Entry) {
  fs::path rel_path(kRootSubdir[0][0]);
  fs::path rel_path1 = rel_path / "file1";
  fs::path rel_path2 = rel_path / "file2";
  fs::path rel_path3 = rel_path / "file3";
  fs::path rel_path4 = rel_path / "file4.LNK";
  fs::path rel_path5 = rel_path / "file5";
  fs::path rel_path6 = rel_path / "Dir";
  fs::path rel_path7 = rel_path6 / "EmptyDir";
  std::string name_too_long("T");
  name_too_long.append(kMaxPath - 5, 'o');
  name_too_long.append(" Long");
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
  std::string hash1(SHA512File(full_path1));
  std::string hash2(SHA512File(full_path2));
  std::string hash3(SHA512File(full_path3));
  std::string hash6, hash7, hash8;
  std::string hash9(SHA512File(full_path9));
  fs::path before(full_path9);
  fs::path after(full_path9.parent_path() / base::EncodeToHex(hash9));
  try {
    fs::rename(before, after);
  }
  catch(const std::exception &e) {
    printf("In SEHandlerTest, BEH_MAID_Check_Entry: %s\n", e.what());
  }
  full_path9 = after;
  boost::uint64_t returned_size1(9), returned_size2(9), returned_size3(9),
                  returned_size6(9), returned_size7(9), returned_size8(9),
                  returned_size9(9);
  std::string returned_hash1("A"), returned_hash2("A"), returned_hash3("A"),
              returned_hash6("A"), returned_hash7("A"), returned_hash8("A"),
              returned_hash9("A");
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
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 9999);
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();

  // Check the chunks are stored
  std::string ser_dm;
  ASSERT_EQ(0, dah_->GetDataMap(rel_str, &ser_dm));
  ASSERT_FALSE(ser_dm.empty());
  encrypt::DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptString) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  std::string data(base::RandomString(1024)), ser_dm;
  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();

  // Check the chunks are stored
  encrypt::DataMap dm;
  ASSERT_TRUE(dm.ParseFromString(ser_dm));

  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithChunksPrevLoaded) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));
  std::string data(base::RandomString(19891)), ser_dm;

  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();

  std::string dec_string;
  result = seh_->DecryptString(ser_dm, &dec_string);
  ASSERT_EQ(0, result);
  ASSERT_EQ(data, dec_string);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptStringWithLoadChunks) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  ss_->SetDefConLevel(kDefCon2);
  std::string data(base::RandomString(1024)), ser_dm;

  int result = seh_->EncryptString(data, &ser_dm);
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);

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
  result = seh_->DecryptString(ser_dm, &dec_string);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);

  ASSERT_EQ(data, dec_string);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithChunksPrevLoaded) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str(test_seh::CreateRandomFile(rel_str, 1026));
  std::string hash_before, hash_after;
  hash_before = SHA512File(fs::path(full_str));
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();

  fs::remove(full_str);
  ASSERT_FALSE(fs::exists(full_str));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = seh_->DecryptFile(rel_str);
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = SHA512File(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
}

TEST_F(SEHandlerTest, BEH_MAID_DecryptWithLoadChunks) {
  ss_->SetDefConLevel(kDefCon2);
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 256 * 1024);
  std::string hash_before, hash_after;
  fs::path full_path(full_str);
  hash_before = SHA512File(full_path);
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();

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
  result = seh_->DecryptFile(rel_str);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(0, result);
  ASSERT_TRUE(fs::exists(full_str));
  hash_after = SHA512File(fs::path(full_str));
  ASSERT_EQ(hash_before, hash_after);
}

TEST_F(SEHandlerTest, BEH_MAID_EncryptAndDecryptPrivateDb) {
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                     _2, &res, &m));

  fs::path db_path(db_str1_);
  std::string key = SHA512String("somekey");
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = SHA512File(db_path);

  // Create the entry
  encrypt::DataMap dm;
  ASSERT_EQ(0, seh_->EncryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE, key,
                               "", true, &dm));

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  ASSERT_EQ(100, res2);
  c.disconnect();
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));

  // Test decryption with the directory DB ser_dm in the map
  std::string ser_dm;
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
                               ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, SHA512File(db_path));

  // Deleting the details of the DB
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
  ASSERT_EQ(0, seh_->RemoveFromUpToDateDms(key))
            << "Didn't find the key in the map of DMs.";

  // Test decryption with no record of the directory DB ser_dm
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
                               ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, SHA512File(db_path));

  // Test decryption with the directory DB ser_dm in the map
  ASSERT_EQ(0, seh_->DecryptDb(TidyPath(kRootSubdir[0][0]), PRIVATE,
                               ser_dm, key, "", true, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, SHA512File(db_path));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
}

TEST_F(SEHandlerTest, DISABLED_BEH_MAID_EncryptAndDecryptAnonDb) {
  fs::path db_path(db_str2_);
  std::string key = "testkey";
  ASSERT_TRUE(fs::exists(db_path));
  std::string hash_before = SHA512File(db_path);
  std::string ser_dm;
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  ASSERT_EQ(0, seh->EncryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, key, "", false, &ser_dm));
  fs::remove(db_path);
  ASSERT_FALSE(fs::exists(db_path));
//  ASSERT_EQ(0,
//    seh->RemoveKeyFromUptodateDms(TidyPath(kSharesSubdir[1][0]))) <<
//    "Didn't find the key in the map of DMs.";
//  ASSERT_EQ(0, seh->DecryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, ser_dm, key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, SHA512File(db_path));
//  ASSERT_EQ(0, seh->DecryptDb(TidyPath(kSharesSubdir[1][0]),
//    ANONYMOUS, "", key, "", false, false));
  ASSERT_TRUE(fs::exists(db_path));
  ASSERT_EQ(hash_before, SHA512File(db_path));
  fs::remove(file_system::MaidsafeDir(ss_->SessionName()) / key);
}

TEST_F(SEHandlerTest, BEH_MAID_FailureOfChunkEncryptingFile) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(boost::bind(&test_seh::FileUpdate, _1,
                                                    _2, &res, &m));
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_entry(TidyPath(rel_path.string()));
  std::string full_str = test_seh::CreateRandomFile(rel_entry, 66666);

  boost::uint64_t file_size(0);
  std::string file_hash;
  ItemType item_type = seh_->CheckEntry(full_str, &file_size, &file_hash);
  encrypt::DataMap dm, dm_retrieved;
  std::string ser_dm_retrieved, ser_dm, ser_mdm, dir_key;
  if (dah_->GetDataMap(rel_entry, &ser_dm_retrieved) == kSuccess)
    dm_retrieved.ParseFromString(ser_dm_retrieved);

  int removee(-1);
//  std::set<std::string> done_chunks;
  if (ser_dm_retrieved.empty() || dm_retrieved.file_hash() != file_hash) {
    dm.set_file_hash(file_hash);
    ASSERT_EQ(kSuccess, encrypt::SelfEncryptFile(full_str,
              file_system::TempDir(), &dm/*, &done_chunks*/));
    ASSERT_EQ(kSuccess, seh_->AddChunksToChunkstore(dm));
    int chunkage = dm.chunk_name_size();
    removee = base::RandomUint32() % chunkage;
    std::string a(dm.encrypted_chunk_name(removee));
#ifdef DEBUG
//    printf("ENCRYPTED ALL CHUNKS. SIZE: %d - REMOVEE: %d - CHUNK: %s\n",
//           chunkage, removee, base::EncodeToHex(a).substr(0, 10).c_str());
#endif

    // delete one of the chunks
    try {
      ChunkType type = client_chunkstore_->chunk_type(a);
      fs::path chunk_path(client_chunkstore_->GetChunkPath(a, type, false));
      if (fs::exists(chunk_path)) {
        fs::remove_all(chunk_path);
//        printf("Deleted chunk %s\n", chunk_path.string().c_str());
      }
    }
    catch(const std::exception &e) {
      FAIL() << "Couldn't erase chunk - " << e.what();
    }
//    printf("Before seh->StoreChunks\n");
    seh_->StoreChunks(dm, PRIVATE, "", rel_entry);
//    printf("After seh->StoreChunks\n");
    dm.SerializeToString(&ser_dm);
  }

  ASSERT_TRUE(seh_->ProcessMetaData(rel_entry, item_type, file_hash, file_size,
                                    &ser_mdm));
  ASSERT_EQ(kSuccess, dah_->AddElement(rel_entry, ser_mdm, ser_dm, dir_key,
                                       true));

  // Wait for signal that file has been succesfully uploaded
  while (!(res2 == -1 || res2 == 100)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }

  ASSERT_EQ(-1, res2);
  c.disconnect();
  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i) {
    if (i == removee)
      ASSERT_TRUE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
    else
      ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
  }
}

TEST_F(SEHandlerTest, BEH_MAID_MultipleFileEncryption) {
  // Create the files
  std::vector<boost::tuple<std::string, std::string, int> > fileage;
  std::vector<std::string> filenames;
  fs::path root_path(kRootSubdir[0][0]);
  int total_files(20);
  boost::mutex m;
  printf("Start\n");
  for (int n = 0; n < total_files; ++n) {
    std::string filename("file" + base::IntToString(n));
    fs::path rel_path = root_path / fs::path(filename);
    std::string rel_str = TidyPath(rel_path.string());
    filenames.push_back(rel_str);
    std::string full_str = test_seh::CreateRandomFile(rel_str, 999);
    fileage.push_back(boost::tuple<std::string, std::string, int>(
                                   rel_str,     full_str,    -2));
  }
  printf("Files created\n");

  // Connect to SEH signal
  bool done(false), done2(done);
  int received_chunks(1);
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(
          boost::bind(&test_seh::MultipleFileUpdate, _1, _2, &fileage, &m,
                      &done, &received_chunks));
  printf("Connected\n");
  for (int a = 0; a < total_files; ++a) {
    int result = seh_->EncryptFile(filenames[a], PRIVATE, "");
    ASSERT_EQ(0, result);
  }

  printf("EncryptFile run and about to wait\n");
  while (!done2) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_muick(m);
      done2 = done;
    }
  }
  printf("Done waiting\n");

  for (int y = 0; y < total_files; ++y) {
    ASSERT_EQ(100, fileage[y].get<2>());
  }
  printf("Checked results\n");
}

TEST_F(SEHandlerTest, BEH_MAID_MultipleEqualFiles) {
  // Create the files
  std::vector<std::string> filenames;
  fs::path root_path(kRootSubdir[0][0]);
  int total_files(20);
  boost::mutex m;
//  printf("Start\n");

  std::string file_content = base::RandomString(999);
  for (int n = 0; n < total_files; ++n) {
//    printf("%d\n", n);
    std::string filename("file" + base::IntToString(n));
    fs::path rel_path = root_path / fs::path(filename);
    std::string rel_str = TidyPath(rel_path.string());
    std::string full_str = test_seh::CreateSetFile(rel_str, file_content);
    filenames.push_back(rel_str);
  }
//  printf("Files created %d\n", filenames.size());

  // Connect to SEH signal
  int received_chunks(0), received_chunks2(received_chunks);
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(
          boost::bind(&test_seh::MultipleEqualFileUpdate, _1, _2, &m,
                      &received_chunks));
//  printf("Connected\n");
  for (int a = 0; a < total_files; ++a) {
    int result = seh_->EncryptFile(filenames[a], PRIVATE, "");
    ASSERT_EQ(0, result);
  }

//  printf("EncryptFile run and about to wait: %d\n", (total_files) * 3);
  while (received_chunks2 != (total_files) * 3) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_muick(m);
      received_chunks2 = received_chunks;
    }
  }
//  printf("Done waiting\n");
}

TEST_F(SEHandlerTest, BEH_MAID_FailureSteppedMultipleEqualFiles) {
  std::vector<boost::tuple<std::string, std::string, int> > fileage;
  std::vector<std::string> filenames, fullnames;
  std::vector<encrypt::DataMap> dms;
  fs::path root_path(kRootSubdir[0][0]);
  int total_files(20);
  boost::mutex m;
  printf("Start\n");

  std::string file_content = base::RandomString(999);
  for (int n = 0; n < total_files; ++n) {
    std::string filename("file" + base::IntToString(n));
    fs::path rel_path = root_path / fs::path(filename);
    std::string rel_str = TidyPath(rel_path.string());
    std::string full_str = test_seh::CreateSetFile(rel_str, file_content);
    filenames.push_back(rel_str);
    fullnames.push_back(full_str);
    fileage.push_back(
        boost::tuple<std::string, std::string, int>(rel_str, full_str, -2));
  }
  printf("Files created %d\n", filenames.size());

//  std::set<std::string> done_chunks;
  for (int a = 0; a < total_files; ++a) {
    boost::uint64_t file_size(0);
    std::string file_hash;
    ItemType item_type = seh_->CheckEntry(fullnames[a], &file_size, &file_hash);
    encrypt::DataMap dm, dm_retrieved;
    std::string ser_dm_retrieved, ser_dm, ser_mdm, dir_key;
    if (dah_->GetDataMap(filenames[a], &ser_dm_retrieved) == kSuccess)
      dm_retrieved.ParseFromString(ser_dm_retrieved);

    if (ser_dm_retrieved.empty() || dm_retrieved.file_hash() != file_hash) {
      dm.set_file_hash(file_hash);
      ASSERT_EQ(kSuccess, encrypt::SelfEncryptFile(fullnames[a],
                          file_system::TempDir(), &dm/*, &done_chunks*/));
      ASSERT_EQ(kSuccess, seh_->AddChunksToChunkstore(dm));
      dm.SerializeToString(&ser_dm);
    }
    dms.push_back(dm);

    ASSERT_TRUE(seh_->ProcessMetaData(filenames[a], item_type, file_hash,
                                      file_size, &ser_mdm));
    ASSERT_EQ(kSuccess, dah_->AddElement(filenames[a], ser_mdm, ser_dm, dir_key,
                                         true));
  }

  // delete one of the chunks
  int file_dm(total_files/2);
  int chunkage = dms[file_dm].chunk_name_size();
  int removee = base::RandomUint32() % chunkage;
  std::string enc_removee(dms[file_dm].encrypted_chunk_name(removee));
  try {
    ChunkType type = client_chunkstore_->chunk_type(enc_removee);
    fs::path chunk_path(client_chunkstore_->GetChunkPath(enc_removee, type,
                                                         false));
    if (fs::exists(chunk_path)) {
      fs::remove_all(chunk_path);
//      printf("Deleted chunk %s\n", chunk_path.string().c_str());
    }
  }
  catch(const std::exception &e) {
    FAIL() << "Couldn't erase chunk - " << e.what();
  }

  bool done(false), done2(done);
  int received_chunks(1);
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(
          boost::bind(&test_seh::MultipleFileUpdate, _1, _2, &fileage, &m,
                      &done, &received_chunks));

//  printf("Before seh->StoreChunks\n");
  for (int y = 0; y < total_files; ++y) {
    seh_->ChunksToMultiIndex(dms[y], "", filenames[y]);
  }
//  printf("After seh->StoreChunks\n");
  ASSERT_EQ(size_t(total_files * chunkage), seh_->pending_chunks_.size());

  for (int y = 0; y < total_files; ++y) {
    seh_->StoreChunksToNetwork(dms[y], PRIVATE, "");
  }

  printf("\n\nEncryptFile run and about to wait\n");
  while (!done2) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_muick(m);
      done2 = done;
    }
  }
  printf("Done waiting\n");

  for (int e = 0; e < total_files; ++e) {
    ASSERT_EQ(-1, fileage[e].get<2>()) << e;
  }
  printf("Checked results\n");
}

TEST_F(SEHandlerTest, BEH_MAID_OneFileModifiedAndSavedAgain) {
  // Connect to SEH signal
  int res(0), res2(res);
  boost::mutex m;
  boost::signals2::connection c =
      seh_->ConnectToOnFileNetworkStatus(
          boost::bind(&test_seh::SamePathDifferentContent, _1, _2, &res, &m));

  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "file1";
  std::string rel_str = TidyPath(rel_path.string());

  std::string full_str = test_seh::CreateRandomFile(rel_str, 9999);
  int result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  full_str = test_seh::CreateRandomFile(rel_str, 33333);
  result = seh_->EncryptFile(rel_str, PRIVATE, "");
  ASSERT_EQ(0, result);

  // Wait for signal that file has been succesfully uploaded
  while (res2 != 2) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_tulla(m);
      res2 = res;
    }
  }
  c.disconnect();

  // Check the chunks are stored
//  std::string ser_dm;
//  ASSERT_EQ(0, dah_->GetDataMap(rel_str, &ser_dm));
//  ASSERT_FALSE(ser_dm.empty());
//  DataMap dm;
//  ASSERT_TRUE(dm.ParseFromString(ser_dm));
//
//  for (int i = 0; i < dm.encrypted_chunk_name_size(); ++i)
//    ASSERT_FALSE(sm_->KeyUnique(dm.encrypted_chunk_name(i), false));
}

}  // namespace test

}  // namespace maidsafe

