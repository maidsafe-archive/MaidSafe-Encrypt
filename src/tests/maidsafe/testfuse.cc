/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Tests for FUSE/Dokan
* Version:      1.0
* Created:      2009-02-02-00.49.35
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

#include <gtest/gtest.h>

#if defined __WIN32__
  #include <windef.h>
  #include <shellapi.h>
#endif

#include <set>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"

#include "base/config.h"
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/sessionsingleton.h"

#if defined MAIDSAFE_WIN32
  #include "fs/w_fuse/fswin.h"
  namespace fs_w_fuse {
#elif defined MAIDSAFE_POSIX
  #include "fs/l_fuse/fslinux.h"
  namespace fs_l_fuse {
#elif defined MAIDSAFE_APPLE
  #include "fs/m_fuse/fsmac.h"
  namespace fs_m_fuse {
#endif

namespace fs = boost::filesystem;

class FakeCallback {
 public:
  FakeCallback() : result_(""){}
  void CallbackFunc(const std::string &res_) {
    result_ = res_;
  }
  void Reset() {
    result_ = "";
  }
  std::string result_;
};

class FunctionalFuseTest : public testing::Test {
 public:
 FunctionalFuseTest() : cc_(), ss_(), username1_(""),
 username2_(""), public_username1_(""), public_username2_(""),
 pin_(""), password_(""), dir1_(""), dir2_(""), final_dir_(""),
 cb_(),
   #if defined MAIDSAFE_POSIX
    fsl_(),
  #elif defined MAIDSAFE_APPLE
    fsm_(),
  #endif


 logout_(false) {}
 protected:
  void SetUp() {
//    int Fraser(10000), Dan(-3);
//    ASSERT_GT(Dan, Fraser);
  }

  void TearDown() {
  }

  maidsafe::ClientController *cc_;
  maidsafe::SessionSingleton *ss_;
  std::string username1_;
  std::string username2_;
  std::string public_username1_;
  std::string public_username2_;
  std::string pin_;
  std::string password_;
  std::string dir1_, dir2_, final_dir_;
  FakeCallback cb_;
  #if defined MAIDSAFE_POSIX
    fs_l_fuse::FSLinux fsl_;
  #elif defined MAIDSAFE_APPLE
    fs_l_fuse::FSLinux fsm_;
    // fs_m_fuse::FSMac fsm_;
  #endif
  bool logout_;
  private:
  FunctionalFuseTest(const FunctionalFuseTest&);
  FunctionalFuseTest &operator=(const FunctionalFuseTest&);
};

static bool logged_in_;
static std::vector<fs::path> test_file_;
static std::vector<std::string> pre_hash_;

bool CreateRandomFile(const std::string &filename,
                      const uint32_t &size,
                      std::string *hash) {
  std::string file_content_ = base::RandomString(size);
  file_system::FileSystem fsys_;
  fs::ofstream ofs_;
  try {
    ofs_.open(filename);
    ofs_ << file_content_;
    ofs_.close();
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
    return false;
  }
  bool success_ = false;
  try {
    success_ = (fs::exists(filename) && (fs::file_size(filename) == size));
    fs::path file_path_(filename);
    maidsafe::SelfEncryption se_;
    *hash = se_.SHA512(file_path_);
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
    return false;
  }
  return success_;
};

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_RepeatedMount) {
  try {
    if (fs::exists("KademilaDb.db"))
      fs::remove(fs::path("KademilaDb.db"));
    if (fs::exists("StoreChunks"))
      fs::remove_all("StoreChunks");
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
  }
  username1_ = "user1";
  pin_ = "1234";
  password_ = "password1";
  cc_ = maidsafe::ClientController::getInstance();
  ss_ = maidsafe::SessionSingleton::getInstance();
  cc_->JoinKademlia();
  cc_->Init();
  // check session reset OK
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  maidsafe::exitcode result_ = cc_->CheckUserExists(
                                        username1_,
                                        pin_,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb_,
                                            _1),
                                        maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::NON_EXISTING_USER, result_);
  // create user and logout
  ASSERT_TRUE(cc_->CreateUser(username1_, pin_, password_));
  ASSERT_TRUE(cc_->Logout());
  for (int i = 0; i < 10; ++i) {
    // login
    result_ = cc_->CheckUserExists(username1_,
                                   pin_,
                                   boost::bind(&FakeCallback::CallbackFunc,
                                               &cb_,
                                               _1),
                                   maidsafe::DEFCON2);
    ASSERT_EQ(maidsafe::USER_EXISTS, result_);
    base::sleep(5);
  std::list<std::string> list;
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
    ss_->SetMounted(0);
    #if defined MAIDSAFE_WIN32
      Mount(cc_->DriveLetter());
      fs::path mount_path_("M:\\", fs::native);
    #elif defined MAIDSAFE_POSIX
      file_system::FileSystem fsys_;
      std::string mount_point_ = fsys_.MaidsafeFuseDir();
      fs::path mount_path_(mount_point_, fs::native);
      std::string debug_mode_("-d");
      fsl_.Mount(mount_point_, debug_mode_);
    #elif defined MAIDSAFE_APPLE
      file_system::FileSystem fsys_;
      std::string mount_point_ = fsys_.MaidsafeFuseDir();
      fs::path mount_path_(mount_point_, fs::native);
      std::string debug_mode_("-d");
      fsm_.Mount(mount_point_, debug_mode_);
    #endif
    base::sleep(5);
    ASSERT_EQ(0, ss_->Mounted());
    logged_in_ = true;
    printf("Logged in.\n");
    base::sleep(5);
    // read root dir
//    mount_path_ = fs::path("M:\\My Files", fs::native);
//    fs::directory_iterator end_itr_;
//    for (fs::directory_iterator itr_(mount_path_); itr_ != end_itr_; ++itr_) {
//      printf("%s\n", itr_->path().string().c_str());
//    }
    ASSERT_TRUE(fs::exists(mount_path_));
    // logout
    bool logout_ = false;
    #ifdef MAIDSAFE_WIN32
      SHELLEXECUTEINFO shell_info_;
      memset(&shell_info_, 0, sizeof(shell_info_));
      shell_info_.cbSize = sizeof(shell_info_);
      shell_info_.hwnd = NULL;
      shell_info_.lpVerb = L"open";
      shell_info_.lpFile = L"dokanctl";
      shell_info_.lpParameters = L" /u M";
      shell_info_.nShow = SW_HIDE;
      shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
      logout_ = ShellExecuteEx(&shell_info_);
      if (logout_)
        WaitForSingleObject(shell_info_.hProcess, INFINITE);
      base::sleep(0.5);
      logout_ = true;
    #else
      fsl_.UnMount();
      logout_ = true;
    #endif
    ASSERT_TRUE(logout_);
    logout_ = cc_->Logout();
    ASSERT_TRUE(logout_);
    printf("Logged out (%i)\n--------------------------------------\n\n", i+1);
  }
  base::sleep(5);
  cc_->CloseConnection();
  base::sleep(5);
  try {
    if (fs::exists("KademilaDb.db")) {
      printf("Deleting KademilaDb.db\n");
      fs::remove(fs::path("KademilaDb.db"));
    }
    if (fs::exists("StoreChunks")) {
      printf("Deleting StoreChunks\n");
      fs::remove_all(fs::path("StoreChunks"));
    }
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e_) {
    printf("Error: %s\n", e_.what());
  }
  logged_in_ = false;
}

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_StoreFilesAndDirs) {
  // try to logout in case previous test failed
  cc_ = maidsafe::ClientController::getInstance();
  ss_ = maidsafe::SessionSingleton::getInstance();
  if (logged_in_) {
    try {
      printf("At test start, trying to unmount m:\n");
//      bool logout_ = false;
      #ifdef MAIDSAFE_WIN32
        SHELLEXECUTEINFO shell_info_;
        memset(&shell_info_, 0, sizeof(shell_info_));
        shell_info_.cbSize = sizeof(shell_info_);
        shell_info_.hwnd = NULL;
        shell_info_.lpVerb = L"open";
        shell_info_.lpFile = L"dokanctl";
        shell_info_.lpParameters = L" /u M";
        shell_info_.nShow = SW_HIDE;
        shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
        logout_ = ShellExecuteEx(&shell_info_);
        if (logout_)
          WaitForSingleObject(shell_info_.hProcess, INFINITE);
        base::sleep(0.5);
      #else
        fsl_.UnMount();
      #endif
      cc_->Logout();
      logged_in_ = false;
    }
     catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }
  try {
    if (fs::exists("KademilaDb.db")) {
      printf("Deleting KademilaDb.db\n");
      fs::remove(fs::path("KademilaDb.db"));
    }
    if (fs::exists("StoreChunks")) {
      printf("Deleting StoreChunks\n");
      fs::remove_all(fs::path("StoreChunks"));
    }
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
  }
  username1_ = "user1";
  pin_ = "1234";
  password_ = "password1";
  cc_->JoinKademlia();
  cc_->Init();
  // check session reset OK
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  maidsafe::exitcode result_ = cc_->CheckUserExists(
                                        username1_,
                                        pin_,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb_,
                                            _1),
                                        maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::NON_EXISTING_USER, result_);
  // create user and logout
  ASSERT_TRUE(cc_->CreateUser(username1_, pin_, password_));
  ASSERT_TRUE(cc_->Logout());
  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  std::list<std::string> list;
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
    fs::path mount_path_("m:\\", fs::native);
  #elif defined MAIDSAFE_POSIX
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // try to write file to root dir
  fs::path test_path_(mount_path_);
  test_path_ /= "test.txt";
  std::string hash_("");
  ASSERT_FALSE(CreateRandomFile(test_path_.string(), 1, &hash_));

  // write files and dirs to "/My Files" dir
  #if defined MAIDSAFE_WIN32
    std::string win_root_(mount_path_.string());
    win_root_ = base::TidyPath(win_root_);
    fs::path root_(win_root_);
  #else
    fs::path root_(mount_path_);
  #endif
  fs::path test_root_(root_);
  test_root_ /= kRootSubdir[0][0];
  fs::path test_dir_0_(test_root_);
  test_dir_0_ /= "TestDir0";
  fs::path test_dir_1_(test_dir_0_);
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    test_file_.push_back(test_root_);
  test_file_[0] /= "test0.txt";
  test_file_[1] /= "test1.txt";
  test_file_[2] /= "test2.txt";
  test_file_.push_back(test_dir_0_);
  test_file_.push_back(test_dir_1_);
  test_file_[3] /= "test3.txt";  // /My Files/TestDir0/test3.txt
  test_file_[4] /= "test4.txt";  // /My Files/TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    pre_hash_.push_back("");
  bool success_ = false;
  try {
    fs::create_directory(test_dir_0_.string());
    fs::create_directory(test_dir_1_.string());
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", test_file_[0].string().c_str());
  success_ = CreateRandomFile(test_file_[0].string(), 2, &pre_hash_[0]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[1].string(), 10, &pre_hash_[1]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[2].string(), 100, &pre_hash_[2]);
  base::sleep(10);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[3].string(), 100, &pre_hash_[3]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[4].string(), 100, &pre_hash_[4]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  maidsafe::SelfEncryption se_;
  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
    base::sleep(5);
  }
//  test_root_ = root_;
//
//  // write files and dirs to "/Shares/Public" dir
//  test_root_ /= kSharesSubdir[1][0];
//  test_dir_0_ = test_root_;
//  test_dir_0_ /= "TestDir0";
//  test_dir_1_ = test_dir_0_;
//  test_dir_1_ /= "TestDir1";
//  for (int i = 0; i < 3; ++i)
//    test_file_.push_back(test_root_);
//  test_file_[5] /= "test0.txt";
//  test_file_[6] /= "test1.txt";
//  test_file_[7] /= "test2.txt";
//  test_file_.push_back(test_dir_0_);
//  test_file_.push_back(test_dir_1_);
//  test_file_[8] /= "test3.txt";  // Shares/Public/TestDir0/test3.txt
//  test_file_[9] /= "test4.txt";  // Shares/Public/TestDir0/TestDir1/test4.txt
//  for (int i = 0; i < 5; ++i)
//    pre_hash_.push_back("");
//  success_ = false;
//  try {
//    fs::create_directory(test_dir_0_.string());
//    fs::create_directory(test_dir_1_.string());
//    base::sleep(30);
//    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  base::sleep(30);
//  ASSERT_TRUE(success_);
//  printf("Trying to create %s\n", test_file_[5].string().c_str());
//  success_ = CreateRandomFile(test_file_[5].string(), 2, &pre_hash_[5]);
//  base::sleep(5);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[6].string(), 10, &pre_hash_[6]);
//  base::sleep(5);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[7].string(), 100, &pre_hash_[7]);
//  base::sleep(10);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[8].string(), 100, &pre_hash_[8]);
//  base::sleep(60);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[9].string(), 100, &pre_hash_[9]);
//  base::sleep(60);
//  ASSERT_TRUE(success_);
//  for (int i = 5; i < 10; ++i) {
//    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
//    base::sleep(5);
//  }
  test_root_ = root_;

  // write files and dirs to "/Shares/Anonymous" dir
  test_root_ /= kSharesSubdir[1][0];  // /Shares/Anonymous/
  test_dir_0_ = test_root_;
  test_dir_0_ /= "TestDir0";
  test_dir_1_ = test_dir_0_;
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    test_file_.push_back(test_root_);
  test_file_[10] /= "test0.txt";
  test_file_[11] /= "test1.txt";
  test_file_[12] /= "test2.txt";
  test_file_.push_back(test_dir_0_);
  test_file_.push_back(test_dir_1_);
  test_file_[13] /= "test3.txt";  // /Shares/Anonymous/TestDir0/test3.txt
  test_file_[14] /= "test4.txt";  // /Shares/Anon.../TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    pre_hash_.push_back("");
  success_ = false;
  try {
    fs::create_directory(test_dir_0_.string());
    fs::create_directory(test_dir_1_.string());
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  base::sleep(30);
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", test_file_[10].string().c_str());
  success_ = CreateRandomFile(test_file_[10].string(), 2, &pre_hash_[10]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[11].string(), 10, &pre_hash_[11]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[12].string(), 100, &pre_hash_[12]);
  base::sleep(10);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[13].string(), 100, &pre_hash_[13]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[14].string(), 100, &pre_hash_[14]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  for (int i = 10; i < 15; ++i) {
    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
    base::sleep(5);
  }
  test_root_ = root_;

  // try to write files and dirs to "/Shares/Private" dir
  test_root_ /= kSharesSubdir[0][0];  // /Shares/Private/
  fs::path test_dir_(test_root_);
  test_dir_ /= "TestDir";
  fs::path test_txt_(test_root_);
  test_txt_ /= "test.txt";
  success_ = false;
  try {
    printf("Trying to create %s\n", test_dir_.string().c_str());
    fs::create_directory(test_dir_.string());
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  try {
    printf("Checking dir's existence.\n");
    success_ = (fs::exists(test_dir_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  base::sleep(30);
  ASSERT_FALSE(success_);
  printf("Trying to create %s\n", test_txt_.string().c_str());
  std::string file_hash_("");
  success_ = CreateRandomFile(test_txt_.string(), 2, &file_hash_);
  base::sleep(10);
  ASSERT_FALSE(success_);

  // logout
  bool logout_ = false;
  #ifdef MAIDSAFE_WIN32
    SHELLEXECUTEINFO shell_info_;
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  try {
    if (fs::exists("KademilaDb.db"))
      fs::remove(fs::path("KademilaDb.db"));
    if (fs::exists("StoreChunks"))
      fs::remove_all("StoreChunks");
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e_) {
    printf("Error: %s\n", e_.what());
  }
  logged_in_ = false;
  test_file_.clear();
  pre_hash_.clear();
}

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_Rename_Dir) {
//  cc_ = maidsafe::ClientController::getInstance();
//  ss_ = maidsafe::SessionSingleton::getInstance();
//  if (logged_in_) {
//    try {
//      bool logout_ = false;
//      #ifdef MAIDSAFE_WIN32
//        SHELLEXECUTEINFO shell_info_;
//        memset(&shell_info_, 0, sizeof(shell_info_));
//        shell_info_.cbSize = sizeof(shell_info_);
//        shell_info_.hwnd = NULL;
//        shell_info_.lpVerb = L"open";
//        shell_info_.lpFile = L"dokanctl";
//        shell_info_.lpParameters = L" /u M";
//        shell_info_.nShow = SW_HIDE;
//        shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
//        logout_ = ShellExecuteEx(&shell_info_);
//        if (logout_)
//          WaitForSingleObject(shell_info_.hProcess, INFINITE);
//        base::sleep(0.5);
//      #else
//        fsl_.UnMount();
//      #endif
//      cc_->Logout();
//      if (fs::exists("KademilaDb.db"))
//        fs::remove(fs::path("KademilaDb.db"));
//      if (fs::exists("StoreChunks"))
//        fs::remove_all("StoreChunks");
//      if (fs::exists("KademilaDb.db"))
//        printf("Kademila.db still there\n");
//      if (fs::exists("StoreChunks"))
//        printf("StoreChunks still there\n");
//      logged_in_ = false;
//    }
//    catch(const std::exception &e) {
//      printf("Error: %s\n", e.what());
//    }
//  }
//  username1_ = "user1";
//  pin_ = "1234";
//  password_ = "password1";
//  cc_->JoinKademlia();
//  cc_->Init();
//  // check session reset OK
//  ASSERT_EQ("", ss_->Username());
//  ASSERT_EQ("", ss_->Pin());
//  ASSERT_EQ("", ss_->Password());
//  maidsafe::exitcode result_ = cc_->CheckUserExists(
//                                        username1_,
//                                        pin_,
//                                        boost::bind(
//                                            &FakeCallback::CallbackFunc,
//                                            &cb_,
//                                            _1),
//                                        maidsafe::DEFCON2);
//  ASSERT_EQ(maidsafe::NON_EXISTING_USER, result_);
//  // create user and logout
//  ASSERT_TRUE(cc_->CreateUser(username1_, pin_, password_));
//  ASSERT_TRUE(cc_->Logout());
//  // login
//  result_ = cc_->CheckUserExists(username1_,
//                                 pin_,
//                                 boost::bind(&FakeCallback::CallbackFunc,
//                                             &cb_,
//                                             _1),
//                                 maidsafe::DEFCON2);
//  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
//  base::sleep(5);
//  std::list<dht::entry> list;
//  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
//  ss_->SetMounted(0);
//  #if defined MAIDSAFE_WIN32
//    Mount(cc_->DriveLetter());
//    fs::path mount_path_("m:", fs::native);
//  #elif defined MAIDSAFE_POSIX
//    file_system::FileSystem fsys_;
//    std::string mount_point_ = fsys_.MaidsafeFuseDir();
//    fs::path mount_path_(mount_point_, fs::native);
//    std::string debug_mode_("-d");
//    fsl_.Mount(mount_point_, debug_mode_);
//  #elif defined MAIDSAFE_APPLE
//    file_system::FileSystem fsys_;
//    std::string mount_point_ = fsys_.MaidsafeFuseDir();
//    fs::path mount_path_(mount_point_, fs::native);
//    std::string debug_mode_("-d");
//    fsm_.Mount(mount_point_, debug_mode_);
//  #endif
//  base::sleep(5);
//  ASSERT_EQ(0, ss_->Mounted());
//  logged_in_ = true;
//  printf("Logged in.\n");
//  base::sleep(5);
//
//  // write files and dirs to "/My Files" dir
//  #if defined MAIDSAFE_WIN32
//    std::string win_root_(mount_path_.string());
//    win_root_ = base::TidyPath(win_root_);
//    fs::path root_(win_root_);
//  #else
//    fs::path root_(mount_path_);
//  #endif
//  fs::path test_root_(root_);
//  test_root_ /= kRootSubdir[0][0];
//  fs::path test_dir_0_(test_root_);
//  test_dir_0_ /= "untitled folder";
//  fs::path test_dir_0_renamed(test_root_);
//  test_dir_0_renamed /= "renamed dir";
//  bool renamation = false;
//  bool success_ = false;
//  try {
//    fs::create_directory(test_dir_0_.string());
//    success_ = fs::exists(test_dir_0_);
//    fs::rename(test_dir_0_.string(), test_dir_0_renamed.string());
//    renamation = (!fs::exists(test_dir_0_) && fs::exists(test_dir_0_renamed));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  base::sleep(30);
//  ASSERT_TRUE(success_);
//  ASSERT_TRUE(renamation);
//
//  fs::path fileillo(test_dir_0_renamed / "summat.txt");
//  success_ = CreateRandomFile(fileillo.string(), 100, &pre_hash_[2]);
//  base::sleep(10);

// DO NOT ERASE. HAD TO COMMIT TO GENERATE BUILD.
  SUCCEED();
}

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_RepeatStoreFilesAndDirs) {
  cc_ = maidsafe::ClientController::getInstance();
  ss_ = maidsafe::SessionSingleton::getInstance();
  // try to logout in case previous test failed
  if (logged_in_) {
    try {
//      bool logout_ = false;
      #ifdef MAIDSAFE_WIN32
        SHELLEXECUTEINFO shell_info_;
        memset(&shell_info_, 0, sizeof(shell_info_));
        shell_info_.cbSize = sizeof(shell_info_);
        shell_info_.hwnd = NULL;
        shell_info_.lpVerb = L"open";
        shell_info_.lpFile = L"dokanctl";
        shell_info_.lpParameters = L" /u M";
        shell_info_.nShow = SW_HIDE;
        shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
        logout_ = ShellExecuteEx(&shell_info_);
        if (logout_)
          WaitForSingleObject(shell_info_.hProcess, INFINITE);
        base::sleep(0.5);
      #else
        fsl_.UnMount();
      #endif
      cc_->Logout();
      logged_in_ = false;
    }
     catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }
  try {
    if (fs::exists("KademilaDb.db"))
      fs::remove(fs::path("KademilaDb.db"));
    if (fs::exists("StoreChunks"))
      fs::remove_all("StoreChunks");
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e) {
    printf("Error: %s\n", e.what());
  }
  username1_ = "user1";
  public_username1_ = "XXXXX";
  pin_ = "1234";
  password_ = "password1";
  cc_->JoinKademlia();
  cc_->Init();
  // check session reset OK
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  maidsafe::exitcode result_ = cc_->CheckUserExists(
                                        username1_,
                                        pin_,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb_,
                                            _1),
                                        maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::NON_EXISTING_USER, result_);
  // create user and logout
  ASSERT_TRUE(cc_->CreateUser(username1_, pin_, password_));
  ASSERT_TRUE(cc_->Logout());
  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  std::list<std::string> list;
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
    fs::path mount_path_("m:", fs::native);
  #elif defined MAIDSAFE_POSIX
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // try to write file to root dir
  fs::path test_path_(mount_path_);
  test_path_ /= "test.txt";
  std::string hash_("");
  ASSERT_FALSE(CreateRandomFile(test_path_.string(), 1, &hash_));

  // write files and dirs to "/My Files" dir
  #if defined MAIDSAFE_WIN32
    std::string win_root_(mount_path_.string());
    win_root_ = base::TidyPath(win_root_);
    fs::path root_(win_root_);
  #else
    fs::path root_(mount_path_);
  #endif
  fs::path test_root_(root_);
  test_root_ /= kRootSubdir[0][0];
  fs::path test_dir_0_(test_root_);
  test_dir_0_ /= "TestDir0";
  fs::path test_dir_1_(test_dir_0_);
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    test_file_.push_back(test_root_);
  test_file_[0] /= "test0.txt";
  test_file_[1] /= "test1.txt";
  test_file_[2] /= "test2.txt";
  test_file_.push_back(test_dir_0_);
  test_file_.push_back(test_dir_1_);
  test_file_[3] /= "test3.txt";  // /My Files/TestDir0/test3.txt
  test_file_[4] /= "test4.txt";  // /My Files/TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    pre_hash_.push_back("");
  bool success_ = false;
  try {
    fs::create_directory(test_dir_0_.string());
    fs::create_directory(test_dir_1_.string());
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  base::sleep(30);
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", test_file_[0].string().c_str());
  success_ = CreateRandomFile(test_file_[0].string(), 2, &pre_hash_[0]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[1].string(), 10, &pre_hash_[1]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[2].string(), 100, &pre_hash_[2]);
  base::sleep(10);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[3].string(), 100, &pre_hash_[3]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[4].string(), 100, &pre_hash_[4]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  maidsafe::SelfEncryption se_;
  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
    base::sleep(5);
  }
//  test_root_ = root_;
//
//  // write files and dirs to "/Shares/Public" dir
//  test_root_ /= kSharesSubdir[1][0];
//  test_dir_0_ = test_root_;
//  test_dir_0_ /= "TestDir0";
//  test_dir_1_ = test_dir_0_;
//  test_dir_1_ /= "TestDir1";
//  for (int i = 0; i < 3; ++i)
//    test_file_.push_back(test_root_);
//  test_file_[5] /= "test0.txt";
//  test_file_[6] /= "test1.txt";
//  test_file_[7] /= "test2.txt";
//  test_file_.push_back(test_dir_0_);
//  test_file_.push_back(test_dir_1_);
//  test_file_[8] /= "test3.txt";  // Shares/Public/TestDir0/test3.txt
//  test_file_[9] /= "test4.txt";  // Shares/Public/TestDir0/TestDir1/test4.txt
//  for (int i = 0; i < 5; ++i)
//    pre_hash_.push_back("");
//  success_ = false;
//  try {
//    fs::create_directory(test_dir_0_.string());
//    fs::create_directory(test_dir_1_.string());
//    base::sleep(30);
//    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  base::sleep(30);
//  ASSERT_TRUE(success_);
//  printf("Trying to create %s\n", test_file_[5].string().c_str());
//  success_ = CreateRandomFile(test_file_[5].string(), 2, &pre_hash_[5]);
//  base::sleep(5);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[6].string(), 10, &pre_hash_[6]);
//  base::sleep(5);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[7].string(), 100, &pre_hash_[7]);
//  base::sleep(10);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[8].string(), 100, &pre_hash_[8]);
//  base::sleep(60);
//  ASSERT_TRUE(success_);
//  success_ = CreateRandomFile(test_file_[9].string(), 100, &pre_hash_[9]);
//  base::sleep(60);
//  ASSERT_TRUE(success_);
//  for (int i = 5; i < 10; ++i) {
//    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
//    base::sleep(5);
//  }
  test_root_ = root_;

  // write files and dirs to "/Shares/Anonymous" dir
  test_root_ /= kSharesSubdir[1][0];  // /Shares/Anonymous/
  test_dir_0_ = test_root_;
  test_dir_0_ /= "TestDir0";
  test_dir_1_ = test_dir_0_;
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    test_file_.push_back(test_root_);
  test_file_[10] /= "test0.txt";
  test_file_[11] /= "test1.txt";
  test_file_[12] /= "test2.txt";
  test_file_.push_back(test_dir_0_);
  test_file_.push_back(test_dir_1_);
  test_file_[13] /= "test3.txt";  // /Shares/Anonymous/TestDir0/test3.txt
  test_file_[14] /= "test4.txt";  // /Shares/Anon.../TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    pre_hash_.push_back("");
  success_ = false;
  try {
    fs::create_directory(test_dir_0_.string());
    fs::create_directory(test_dir_1_.string());
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  base::sleep(30);
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", test_file_[10].string().c_str());
  success_ = CreateRandomFile(test_file_[10].string(), 2, &pre_hash_[10]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[11].string(), 10, &pre_hash_[11]);
  base::sleep(5);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[12].string(), 100, &pre_hash_[12]);
  base::sleep(10);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[13].string(), 100, &pre_hash_[13]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  success_ = CreateRandomFile(test_file_[14].string(), 100, &pre_hash_[14]);
  base::sleep(60);
  ASSERT_TRUE(success_);
  for (int i = 10; i < 15; ++i) {
    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
    base::sleep(5);
  }
  test_root_ = root_;

  // try to write files and dirs to "/Shares/Private" dir
  test_root_ /= kSharesSubdir[0][0];  // /Shares/Private/
  fs::path test_dir_(test_root_);
  test_dir_ /= "TestDir";
  fs::path test_txt_(test_root_);
  test_txt_ /= "test.txt";
  success_ = false;
  try {
    fs::create_directory(test_dir_.string());
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  try {
    printf("Checking dir's existence.\n");
    success_ = (fs::exists(test_dir_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  base::sleep(30);
  ASSERT_FALSE(success_);
  printf("Trying to create %s\n", test_txt_.string().c_str());
  std::string file_hash_("");
  success_ = CreateRandomFile(test_txt_.string(), 2, &file_hash_);
  base::sleep(10);
  ASSERT_FALSE(success_);

  // logout
  bool logout_ = false;
  #ifdef MAIDSAFE_WIN32
    SHELLEXECUTEINFO shell_info_;
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");

  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  list.clear();
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
  #elif defined MAIDSAFE_POSIX
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // TODO(Fraser#5#): Create private share and save files and dirs to it

  // logout
  logout_ = false;
  #ifdef MAIDSAFE_WIN32
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");

  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  list.clear();
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
  #elif defined MAIDSAFE_POSIX
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // ensure all previous files are still there
  for (int i = 0; i < 15; ++i) {
    printf("Checking file %i\n", i);
    printf("pre_hash[%i] = %s\n", i, pre_hash_[i].c_str());
    printf("se_.SHA512(test_file_[%i]) = %s\n",
           i,
           se_.SHA512(test_file_[i]).c_str());
    ASSERT_EQ(pre_hash_[i], se_.SHA512(test_file_[i]));
    base::sleep(5);
  }
  // TODO(Fraser#5#): ensure private shared files are still there

  // Create public username for user 1
  ASSERT_TRUE(cc_->CreatePublicUsername(public_username1_));

  // logout
  logout_ = false;
  #ifdef MAIDSAFE_WIN32
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  logged_in_ = false;
}

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_CheckNewUserDirs) {
  cc_ = maidsafe::ClientController::getInstance();
  ss_ = maidsafe::SessionSingleton::getInstance();
  // try to logout in case previous test failed
  if (logged_in_) {
    try {
//      bool logout_ = false;
      #ifdef MAIDSAFE_WIN32
        SHELLEXECUTEINFO shell_info_;
        memset(&shell_info_, 0, sizeof(shell_info_));
        shell_info_.cbSize = sizeof(shell_info_);
        shell_info_.hwnd = NULL;
        shell_info_.lpVerb = L"open";
        shell_info_.lpFile = L"dokanctl";
        shell_info_.lpParameters = L" /u M";
        shell_info_.nShow = SW_HIDE;
        shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
        logout_ = ShellExecuteEx(&shell_info_);
        if (logout_)
          WaitForSingleObject(shell_info_.hProcess, INFINITE);
        base::sleep(0.5);
      #else
        fsl_.UnMount();
      #endif
      cc_->Logout();
      logged_in_ = false;
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }
  username2_ = "user2";
  public_username1_ = "XXXXX";
  public_username2_ = "YYYYY";
  pin_ = "1234";
  password_ = "password1";
  cc_->JoinKademlia();
  cc_->Init();
  // check session reset OK
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  maidsafe::exitcode result_ = cc_->CheckUserExists(
                                        username2_,
                                        pin_,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb_,
                                            _1),
                                        maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::NON_EXISTING_USER, result_);
  // create user and logout
  ASSERT_TRUE(cc_->CreateUser(username2_, pin_, password_));
  ASSERT_TRUE(cc_->Logout());
  // login as user 2
  result_ = cc_->CheckUserExists(username2_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  std::list<std::string> list;
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
    fs::path mount_path_("m:", fs::native);
  #elif defined MAIDSAFE_POSIX
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // check "My Files" and "Shares/Private" are empty
  #if defined MAIDSAFE_WIN32
    std::string win_root_(mount_path_.string());
    win_root_ = base::TidyPath(win_root_);
    fs::path root_(win_root_);
  #else
    fs::path root_(mount_path_);
  #endif
  fs::path test_root_(root_);
  test_root_ /= kRootSubdir[0][0];
  fs::directory_iterator end_itr_;
  int file_count_(0);
  for (fs::directory_iterator itr_(test_root_); itr_ != end_itr_; ++itr_) {
    ++file_count_;
  }
  printf("In My Files, file count = %i\n", file_count_);
  ASSERT_EQ(0, file_count_);
  test_root_ = root_;
  test_root_ /= kSharesSubdir[0][0];
  for (fs::directory_iterator itr_(test_root_); itr_ != end_itr_; ++itr_) {
    ++file_count_;
  }
  printf("In Shares/Private, file count = %i\n", file_count_);
  ASSERT_EQ(0, file_count_);

  // check previously-added files exist in "/Shares/Public" dir
  maidsafe::SelfEncryption se_;
//  test_root_ = root_;
//  test_root_ /= kSharesSubdir[1][0];
//  file_count_ = 0;
//  for (fs::directory_iterator itr_(test_root_); itr_ != end_itr_; ++itr_) {
//    try {
//      if (fs::is_regular_file(itr_->status())) {
//        for (int i = 5; i < 10; ++i) {
//          if (itr_->path().filename() == test_file_[i].filename()) {
//            ++file_count_;
//            ASSERT_EQ(pre_hash_[i], se_.SHA512(itr_->path()));
//            break;
//          }
//        }
//      }
//    }
//    catch(const std::exception &e_) {
//      printf("%s - %s\n", itr_->path().filename().c_str(), e_.what());
//    }
//  }
//  // ASSERT_EQ(5, file_count_);
//  ASSERT_EQ(0, file_count_);  // TODO(Fraser#5#): Uncommnt line above & del this
//
  // check previously-added files exist in "/Shares/Anonymous" dir
  test_root_ = root_;
  test_root_ /= kSharesSubdir[1][0];
  file_count_ = 0;
  for (fs::directory_iterator itr_(test_root_); itr_ != end_itr_; ++itr_) {
    try {
      if (fs::is_regular_file(itr_->status())) {
        for (int i = 10; i < 15; ++i) {
          if (itr_->path().filename() == test_file_[i].filename()) {
            ++file_count_;
            ASSERT_EQ(pre_hash_[i], se_.SHA512(itr_->path()));
            break;
          }
        }
      }
    }
    catch(const std::exception &e_) {
      printf("%s - %s\n", itr_->path().filename().c_str(), e_.what());
    }
  }
  ASSERT_EQ(5, file_count_);

  // Create public username for user 2 and authorise user 1
  ASSERT_TRUE(cc_->CreatePublicUsername(public_username2_));
  std::set<std::string> auth_users2_;
  auth_users2_.insert(public_username1_);
  ASSERT_TRUE(cc_->AuthoriseUsers(auth_users2_));

  // logout
  bool logout_ = false;
  #ifdef MAIDSAFE_WIN32
    SHELLEXECUTEINFO shell_info_;
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  logged_in_ = false;
}

TEST_F(FunctionalFuseTest, DISABLED_FUNC_FS_SharesAndMessages) {
  cc_ = maidsafe::ClientController::getInstance();
  ss_ = maidsafe::SessionSingleton::getInstance();
  // try to logout in case previous test failed
  if (logged_in_) {
    try {
//      bool logout_ = false;
      #ifdef MAIDSAFE_WIN32
        SHELLEXECUTEINFO shell_info_;
        memset(&shell_info_, 0, sizeof(shell_info_));
        shell_info_.cbSize = sizeof(shell_info_);
        shell_info_.hwnd = NULL;
        shell_info_.lpVerb = L"open";
        shell_info_.lpFile = L"dokanctl";
        shell_info_.lpParameters = L" /u M";
        shell_info_.nShow = SW_HIDE;
        shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
        logout_ = ShellExecuteEx(&shell_info_);
        if (logout_)
          WaitForSingleObject(shell_info_.hProcess, INFINITE);
        base::sleep(0.5);
      #else
        fsl_.UnMount();
      #endif
      cc_->Logout();
      logged_in_ = false;
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }
  username1_ = "user1";
  username2_ = "user2";
  public_username1_ = "XXXXX";
  public_username2_ = "YYYYY";
  pin_ = "1234";
  password_ = "password1";
  cc_->JoinKademlia();
  cc_->Init();
  // check session reset OK
  ASSERT_EQ("", ss_->Username());
  ASSERT_EQ("", ss_->Pin());
  ASSERT_EQ("", ss_->Password());
  maidsafe::exitcode result_ = cc_->CheckUserExists(
                                        username1_,
                                        pin_,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb_,
                                            _1),
                                        maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  std::list<std::string> list;
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
    fs::path mount_path_("m:", fs::native);
  #elif defined MAIDSAFE_POSIX
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    file_system::FileSystem fsys_;
    std::string mount_point_ = fsys_.MaidsafeFuseDir();
    fs::path mount_path_(mount_point_, fs::native);
    std::string debug_mode_("-d");
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // Authorise user 2
  std::set<std::string> auth_users1_;
  auth_users1_.insert(public_username2_);
  ASSERT_TRUE(cc_->AuthoriseUsers(auth_users1_));

  // TODO(Fraser#5#): Authorise user 2 for previously-created private share

  // TODO(Fraser#5#): Add user 2 to contact list

  // logout
  bool logout_ = false;
  #ifdef MAIDSAFE_WIN32
    SHELLEXECUTEINFO shell_info_;
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 2
  result_ = cc_->CheckUserExists(username2_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  list.clear();
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
  #elif defined MAIDSAFE_POSIX
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // TODO(Fraser#5#): ensure user 2 can add to private share

  // TODO(Fraser#5#): Add user 1 to contact list and send him a message and file.
  //                  Message is hash of file to allow verification

  // logout
  logout_ = false;
  #ifdef MAIDSAFE_WIN32
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 1
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  list.clear();
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
  #elif defined MAIDSAFE_POSIX
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // TODO(Fraser#5#): Ensure user 1 has received correct message (containing the
  //                  file hash) and can access and verify the file

  // TODO(Fraser#5#): Reply to user 2 with a similar file and message

  // logout
  logout_ = false;
  #ifdef MAIDSAFE_WIN32
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 2
  result_ = cc_->CheckUserExists(username2_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON2);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  base::sleep(5);
  list.clear();
  ASSERT_TRUE(cc_->ValidateUser(password_, &list));
  ss_->SetMounted(0);
  #if defined MAIDSAFE_WIN32
    Mount(cc_->DriveLetter());
  #elif defined MAIDSAFE_POSIX
    fsl_.Mount(mount_point_, debug_mode_);
  #elif defined MAIDSAFE_APPLE
    fsm_.Mount(mount_point_, debug_mode_);
  #endif
  base::sleep(5);
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  base::sleep(5);

  // TODO(Fraser#5#): Ensure user 2 has received correct message (containing the
  //               file hash) and can access and verify the file

  // logout
  logout_ = false;
  #ifdef MAIDSAFE_WIN32
    memset(&shell_info_, 0, sizeof(shell_info_));
    shell_info_.cbSize = sizeof(shell_info_);
    shell_info_.hwnd = NULL;
    shell_info_.lpVerb = L"open";
    shell_info_.lpFile = L"dokanctl";
    shell_info_.lpParameters = L" /u M";
    shell_info_.nShow = SW_HIDE;
    shell_info_.fMask = SEE_MASK_NOCLOSEPROCESS;
    logout_ = ShellExecuteEx(&shell_info_);
    if (logout_)
      WaitForSingleObject(shell_info_.hProcess, INFINITE);
    base::sleep(0.5);
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  base::sleep(30);
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  try {
    if (fs::exists("KademilaDb.db"))
      fs::remove(fs::path("KademilaDb.db"));
    if (fs::exists("StoreChunks"))
      fs::remove_all("StoreChunks");
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there\n");
  }
  catch(const std::exception &e_) {
    printf("Error: %s\n", e_.what());
  }
  logged_in_ = false;
}

}  // namespace fs_w_fuse or fs_l_fuse
