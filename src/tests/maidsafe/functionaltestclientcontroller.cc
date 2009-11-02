/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional tests for Client Controller operations
* Version:      1.0
* Created:      2009-01-29-02.29.46
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


#include <boost/bind.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>

#include <list>
#include <map>
#include <vector>

#include "tests/maidsafe/localvaults.h"
#include "maidsafe/crypto.h"
#include "maidsafe/utils.h"
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"


namespace fs = boost::filesystem;

namespace cc_test {

static std::vector< boost::shared_ptr<maidsafe_vault::PDVault> > pdvaults_;
static const int kNetworkSize_ = 16;
static const int kTestK_ = 4;
static bool initialised_ = false;

class FakeCallback {
 public:
  FakeCallback() : result_("") {}
  void CallbackFunc(const std::string &result) {
    result_ = result;
  }
  void Wait(int duration) {
    boost::posix_time::milliseconds timeout(duration);
    boost::posix_time::milliseconds count(0);
    boost::posix_time::milliseconds increment(10);
    while (result_ == "" && count < timeout) {
      count += increment;
      boost::this_thread::sleep(increment);
    }
  }
  std::string result() { return result_; }
 private:
  std::string result_;
};

bool CheckUserExists(maidsafe::ClientController *cc,
                     const std::string &username,
                     const std::string &pin,
                     int duration) {
  FakeCallback cb;
  int result = cc->CheckUserExists(username, pin, maidsafe::DEFCON3);
  cb.Wait(10000);
  if (maidsafe::kUserExists != result)
    return false;
  boost::posix_time::milliseconds timeout(duration);
  boost::posix_time::milliseconds count(0);
  boost::posix_time::milliseconds increment(10);
  maidsafe::GetResponse load_res;
  while (kAck != load_res.result() && count < timeout) {
    load_res.ParseFromString(cb.result());
    count += increment;
    boost::this_thread::sleep(increment);
  }
  return kAck == load_res.result();
}
}  // namespace cc_test

namespace maidsafe {

class FunctionalClientControllerTest : public testing::Test {
 protected:
  FunctionalClientControllerTest()
      : cc(),
        authentication(),
        ss(),
        chunkstore_(new ChunkStore("./TestCC", 0, 0)),
        se(chunkstore_),
        dir1_(""),
        dir2_(""),
        final_dir_(),
        vcp_() {}
  void SetUp() {
    int count(0);
    while (!chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    cc = ClientController::getInstance();
    if (!cc_test::initialised_) {
      ASSERT_TRUE(cc->JoinKademlia());
      ASSERT_TRUE(cc->Init());
    }
  }
  void TearDown() {
//    boost::this_thread::sleep(boost::posix_time::seconds(10));
//    cc->CloseConnection();
    try {
      if (final_dir_ != "" && fs::exists(final_dir_))
        fs::remove_all(final_dir_);
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }
  ClientController *cc;
  Authentication *authentication;
  SessionSingleton *ss;
  boost::shared_ptr<ChunkStore> chunkstore_;
  SelfEncryption se;
  std::string dir1_, dir2_, final_dir_;
  VaultConfigParameters vcp_;
 private:
  FunctionalClientControllerTest(const FunctionalClientControllerTest&);
  FunctionalClientControllerTest &operator=
      (const FunctionalClientControllerTest&);
};

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerLoginSequence) {
  std::string username = "User1";
  std::string pin = "1234";
  std::string password = "The beagle has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
                      boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
                      boost::this_thread::sleep(boost::posix_time::seconds(10));

  ASSERT_FALSE(cc_test::CheckUserExists(cc, "juan.smer", pin, 10000));
  printf("Can't log in with fake details.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerChangeDetails) {
  std::string username = "User2";
  std::string pin = "2345";
  std::string password = "The axolotl has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed username.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, "juan.smer", pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");
  file_system::FileSystem fsys_;
  dir1_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ(password, ss->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed pin.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, "juan.smer", "2207", 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");
  dir2_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ("elpasguor", ss->Password());
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("Changed password.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, "juan.smer", "2207", 10000));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ("elpasguor", ss->Password());
  printf("Logged in. New u/p/w.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, "juan.smer", "2207", 10000));
  ASSERT_FALSE(cc->ValidateUser(password))
    << "old details still work, damn it, damn the devil to hell";
  ss->ResetSession();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Can't log in with old u/p/w.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerCreatePubUsername) {
  std::string username = "User3";
  std::string pin = "3456";
  std::string password = "The fanjeeta has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_FALSE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Public Username already created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerLeaveNetwork) {
  std::string username = "User4";
  std::string pin = "4567";
  std::string password = "The chubster has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->LeaveMaidsafeNetwork());
  printf("Left maidsafe ='(.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  printf("User no longer exists.\n");

  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created again.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerBackupFile) {
  std::string username = "User5";
  std::string pin = "5678";
  std::string password = "The limping dog has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  file_system::FileSystem fsys_;
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path_(kRootSubdir[0][0]);
  rel_path_ /= "testencryption.txt";
  std::string rel_str_ = base::TidyPath(rel_path_.string());

  fs::path full_path_(fsys_.MaidsafeHomeDir());
  full_path_ /= rel_path_;
  fs::ofstream testfile(full_path_.string().c_str());
  testfile << base::RandomString(1024*1024);
  testfile.close();
  std::string hash_original_file = se.SHA512(full_path_);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc->write(rel_str_));
    printf("File backed up in ");
  }

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");

  if (fs::exists(full_path_))
      fs::remove(full_path_);

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User logged in.\n");
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);

  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc->read(rel_str_));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = se.SHA512(full_path_);
  ASSERT_EQ(hash_original_file, hash_dec_file);

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");
}

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerUserAuthorisation) {
  std::string username = "User6";
  std::string pin = "6789";
  std::string password = "The deleted folder has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.nalga"));
  ASSERT_EQ("el.mambo.nalga", ss->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.nalga", ss->PublicUsername());
  printf("Logged in.\n");

  std::set<std::string> auth_users;
  std::string users[3] = {"esssmer", "es tu", "padre"};
  for (int n = 0; n < 3 ; ++n)
    auth_users.insert(users[n]);

  ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
  std::set<std::string> local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[0] || *p == users[1] || *p == users[2])
      << "User missing";
  printf("Authorised 3 users.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.nalga", ss->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[0] || *p == users[1] || *p == users[2])
      << "User missing";
  printf("Authorised users still there.\n");

  std::set<std::string> deauth_users;
  deauth_users.insert(users[0]);
  ASSERT_TRUE(cc->DeauthoriseUsers(deauth_users));
  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[1] || *p == users[2]) << "User missing";
  printf("Deauthorised a user.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.nalga", ss->PublicUsername());
  printf("Logged in.\n");

  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p) {
    bool b_ = (*p == users[1] || *p == users[2]);
    ASSERT_TRUE(b_) << "User missing";
  }
  printf("2 authorised users.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

//  TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerShares) {
//    ss = SessionSingleton::getInstance();
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Preconditions fulfilled.\n");
//
//    ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
//    ASSERT_EQ(username, ss->Username());
//    ASSERT_EQ(pin, ss->Pin());
//    ASSERT_EQ(password, ss->Password());
//    printf("User created.\n");
//
//    ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
//    ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
//    printf("Public Username created.\n");
//
//    std::set<std::string> auth_users;
//    std::string users[3] = {"el.dan.liiiiiisto", "es tu", "padre"};
//    for (int n=0; n<3 ; n++)
//      auth_users.insert(users[n]);
//
//    ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
//    std::set<std::string> local_set = ss->AuthorisedUsers();
//    for (std::set<std::string>::iterator p = local_set.begin();
//         p != local_set.end();
//         ++p)
//      ASSERT_TRUE(*p==users[0] || *p==users[1] || *p==users[2])
//        << "User missing";
//    printf("Authorised 3 users.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    ASSERT_TRUE(cc->CreateUser("smer","7777","palofeo", vcp_));
//    ASSERT_TRUE(ss->Username() == "smer");
//    ASSERT_TRUE(ss->Pin() == "7777");
//    ASSERT_TRUE(ss->Password() == "palofeo");
//    printf("User created.\n");
//
//    ASSERT_TRUE(cc->CreatePublicUsername("el.dan.liiiiiisto"));
//    ASSERT_TRUE(ss->PublicUsername() == "el.dan.liiiiiisto");
//    printf("Public Username created.\n");
//
//    std::string path = file_system::FileSystem::getInstance()->HomeDir() +
//                       "/testencryption.txt";
//    fs::path path_(path);
//    fs::ofstream testfile(path.c_str());
//    testfile << base::RandomString(1024*1024);
//    testfile.close();
//    std::string hash_original_file = se.SHA512(path_);
//    ASSERT_TRUE(cc->BackupElement(path));
//    while(ss->SelfEncrypting())
//      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
//    OutputProcessedJobs(cc);
//    printf("File backed up.\n");
//
//    std::vector<std::string> paths, share_users;
//    std::string ms_path = path;
//    ms_path.erase(0,
//                  file_system::FileSystem::getInstance()->HomeDir().size());
//    paths.push_back(ms_path);
//    share_users.push_back("el.mambo.tonnnnnto");
//    ASSERT_TRUE(cc->CreateShare(paths,share_users,"fotos puercas"));
//    printf("Created share.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    ASSERT_TRUE(cc->Start(username, pin, password));
//    ASSERT_EQ(username, ss->Username());
//    ASSERT_EQ(pin, ss->Pin());
//    ASSERT_EQ(password, ss->Password());
//    printf("User logged in.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    if (fs::exists(path))
//      fs::remove(fs::path(path));
//  }

TEST_F(FunctionalClientControllerTest, FUNC_MAID_ControllerFuseFunctions) {
  std::string username = "User7";
  std::string pin = "7890";
  std::string password = "The pint of lager has landed on the floor.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  ASSERT_FALSE(cc_test::CheckUserExists(cc, username, pin, 10000));
  ASSERT_TRUE(cc->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  file_system::FileSystem fsys_;
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path_(kRootSubdir[0][0]);
  fs::path testfile[15];
  fs::path homedir(fsys_.HomeDir());
  fs::path mshomedir(fsys_.MaidsafeHomeDir());
  // fs::path newdir = homedir / "NewDir";
  // fs::path msnewdir = mshomedir / "NewDir";
  fs::path my_files(base::TidyPath(kRootSubdir[0][0]));
  fs::path startdir = my_files / "NewDir";

  testfile[0] = startdir;
  testfile[1] = startdir / "file0";
  testfile[2] = startdir / "file1";
  testfile[3] = startdir / "file2";
  testfile[4] = startdir / "file3";

  fs::path insidenewdir = startdir / "insidenewdir";
  testfile[5] = insidenewdir;
  testfile[6] = insidenewdir / "file4";
  testfile[7] = insidenewdir / "file5";
  testfile[8] = insidenewdir / "file6";

  fs::path quitedeepinsidenewdir = insidenewdir / "quitedeepinsidenewdir";
  testfile[9] = quitedeepinsidenewdir;
  fs::path deepinsidenewdir = quitedeepinsidenewdir / "deepinsidenewdir";
  testfile[10] = deepinsidenewdir;
  testfile[11] = deepinsidenewdir / "file7";
  testfile[12] = deepinsidenewdir / "file8";

  fs::path reallydeepinsidenewdir = deepinsidenewdir / "reallydeepinsidenewdir";
  testfile[13] = reallydeepinsidenewdir;
  testfile[14] = reallydeepinsidenewdir / "file9";

  std::string temp_path, temp_path1;

  printf("Creating directories and files.\n");
  for (int n = 0; n < 15; ++n) {
    temp_path = testfile[n].string();
    if (n == 0 || n == 5 || n == 9 || n == 10 || n == 13) {
      fs::create_directory(mshomedir.string()+"/"+temp_path);
      ASSERT_EQ(0, cc->mkdir(temp_path));
    } else {
      std::string full_ = mshomedir.string()+"/"+temp_path;
      fs::ofstream testfile(full_.c_str());
      testfile.close();
      ASSERT_EQ(0, cc->mknod(temp_path));
    }
    // printf("Creating element [%i]: %s\n", i, temp_path);
  }

  fs::path newdirtest2_ = insidenewdir / "testdir1/dansdir";
  temp_path = newdirtest2_.string();
  ASSERT_NE(0, cc->mkdir(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible directory.\n");
  fs::path newfiletest3_ = insidenewdir / "testdir/lapuercota.jpg";
  temp_path = newfiletest3_.string();
  ASSERT_NE(0, cc->mknod(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible file.\n");

  temp_path = testfile[1].string();
  fs::path temp_b_path = insidenewdir / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc->rename(temp_path, temp_path1)) << "file rename failed";
  // printf("Renamed file " << temp_path << " to " << temp_path1 << std::endl;
  printf("Renamed file.\n");

  temp_path = testfile[10].string();
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc->rename(temp_path, temp_path1)) << "directory rename failed";
  // printf("Renamed dir %s to %s\n", temp_path.c_str(), temp_path1.c_str());
  printf("Renamed directory.\n");
  testfile[10] = temp_b_path.string();

  temp_path = testfile[2].string();
  temp_b_path = insidenewdir / "nonexistant" / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc->rename(temp_path, temp_path1))
    << "impossible file rename failed";
  printf("Didn't rename existant file to impossible one.\n");

  temp_path = testfile[13].string();
  temp_b_path = deepinsidenewdir /
                "nonexistant" /
                "renamed_reallydeepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc->rename(temp_path, temp_path1))
    << "impossible directory rename failed";
  printf("Didn't rename existant directory to impossible one.\n");

  temp_path = testfile[13].string();
  ASSERT_NE(0, cc->rmdir(temp_path)) << "remove non-empty directory failed";
  printf("Doesn't remove non-empty directory.\n");

  temp_b_path = quitedeepinsidenewdir /
                "renamed_deepinsidenewdir" /
                "reallydeepinsidenewdir" /
                "file9";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  // printf("Removed file " << temp_path << std::endl;
  printf("Removed file.\n");

  temp_b_path = temp_b_path.parent_path();
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->rmdir(temp_path)) << "remove directory failed";
  // printf("Removed directory " << temp_path << std::endl;
  printf("Removed directory.\n");

  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file8";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file7";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove stupid dir failed";
  // printf("Recursively removed directory %s and its content.\n",
  //        temp_path.c_str());
  printf("Recursively removed directory and its content.\n");

  std::string o_path = testfile[8].string();
  fs::path ppp = startdir / "file6";
  std::string n_path = ppp.string();
  ASSERT_EQ(0, cc->link(o_path, n_path));
  printf("\nCopied file %s to %s\n", o_path.c_str(), n_path.c_str());
  o_path = testfile[9].string();
  fs::path ppp1 = startdir / "dirA";
  n_path = ppp1.string();
  ASSERT_EQ(0, cc->cpdir(o_path, n_path));
  // printf("Copied directory %s to %s\n", o_path, n_path);
  printf("Copied directory.\n");

  temp_b_path = startdir;
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->utime(temp_path));
  // printf("\nChanged the last modification time to directory %s\n",
  //        temp_path);
  printf("Changed the last modification time to directory.\n");

  // ASSERT_EQ(0, cc->statfs());
  // printf("Got the FS stats.\n\n");

  final_dir_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");
}

}  // namespace maidsafe

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(new localvaults::Env(cc_test::kNetworkSize_,
      cc_test::kTestK_, &cc_test::pdvaults_));
  return RUN_ALL_TESTS();
}
