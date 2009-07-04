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

#include "tests/maidsafe/localvaults.h"

#if defined MAIDSAFE_WIN32
  #include "fs/w_fuse/fswin.h"
#elif defined MAIDSAFE_POSIX
  #include "fs/l_fuse/fslinux.h"
#elif defined MAIDSAFE_APPLE
  #include "fs/m_fuse/fsmac.h"
#endif


#if defined MAIDSAFE_WIN32
  namespace fs_w_fuse {
#elif defined MAIDSAFE_POSIX
  namespace fs_l_fuse {
#elif defined MAIDSAFE_APPLE
  namespace fs_m_fuse {
#endif

namespace fuse_test {

static std::vector< boost::shared_ptr<maidsafe_vault::PDVault> > pdvaults_;
static const int kNetworkSize_ = 10;
static const int kTestK_ = 4;
static bool logged_in_;
static std::vector<fs::path> test_file_;
static std::vector<std::string> pre_hash_;

class TestCallback {
 public:
  explicit TestCallback(boost::mutex* mutex) : mutex_(mutex),
                                               result_(""),
                                               callback_timed_out_(true),
                                               callback_succeeded_(false),
                                               callback_prepared_(false) {}
  void CallbackFunc(const std::string &result) {
    base::GeneralResponse result_msg;
    boost::mutex::scoped_lock lock(*mutex_);
    if ((!result_msg.ParseFromString(result))||
        (result_msg.result() != kad::kRpcResultSuccess)) {
      callback_succeeded_ = false;
      callback_timed_out_ = false;
    } else {
      callback_succeeded_ = true;
      callback_timed_out_ = false;
    }
    result_ = result;
  }
  void Reset() {
    boost::mutex::scoped_lock lock(*mutex_);
    result_ = "";
    callback_timed_out_ = true;
    callback_succeeded_ = false;
    callback_prepared_ = true;
  }
  void Wait(int seconds) {
    if (!callback_prepared_) {
      printf("Callback result variables were not set.\n");
      return;
    }
    bool got_callback = false;
    //  for (int i = 0; i < seconds*100; ++i) {
    while (!got_callback) {
      {
        boost::mutex::scoped_lock lock_(*mutex_);
        if (!callback_timed_out_) {
          got_callback = true;
          if (callback_succeeded_) {
    //        printf("Callback succeeded after %3.2f seconds\n",
    //               static_cast<float>(i)/100);
            callback_prepared_ = false;
            return;
          } else {
    //        printf("Callback failed after %3.2f seconds\n",
    //               static_cast<float>(i)/100);
            callback_prepared_ = false;
            return;
          }
        }
      }
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
    {
      boost::mutex::scoped_lock lock_(*mutex_);
      callback_prepared_ = false;
    }
    printf("Callback timed out after %i second(s)\n", seconds);
  }

 private:
  TestCallback(const TestCallback&);
  TestCallback &operator=(const TestCallback&);
  boost::mutex* mutex_;
  std::string result_;
  bool callback_timed_out_;
  bool callback_succeeded_;
  bool callback_prepared_;
};

//  class FakeCallback {
//   public:
//    FakeCallback() : result_("") {}
//    void CallbackFunc(const std::string &res_) {
//      result_ = res_;
//    }
//    void Reset() {
//      result_ = "";
//    }
//   private:
//    std::string result_;
//  };
//

bool CreateRandomFile(const std::string &filename,
                      const boost::uint32_t &size,
                      std::string *hash) {
  printf("In CreateRandomFile, filename = %s and size = %u\n",
         filename.c_str(), size);
  std::string file_content = base::RandomString(size);
  file_system::FileSystem fsys;
  boost::filesystem::ofstream ofs;
  try {
    ofs.open(filename);
    ofs << file_content;
    ofs.close();
  }
  catch(const std::exception &e1) {
    printf("%s\n", e1.what());
    return false;
  }
  bool success = false;
  try {
    success = (fs::exists(filename) && (fs::file_size(filename) == size));
    if (success) {
      fs::path file_path(filename);
      maidsafe::SelfEncryption se;
      *hash = se.SHA512(file_path);
    } else {
      *hash = "";
    }
    printf("In CreateRandomFile, filename = %s and hashsize = %u\n",
           filename.c_str(), hash->size());
  }
  catch(const std::exception &e2) {
    printf("%s\n", e2.what());
    return false;
  }
  return success;
};

void UnmountAndLogout(maidsafe::ClientController *cc,
#ifdef MAIDSAFE_WIN32
                     maidsafe::SessionSingleton *ss
#elif defined(MAIDSAFE_POSIX)
                     fs_l_fuse::FSLinux &fsl
#elif defined(MAIDSAFE_APPLE)
                     fs_l_fuse::FSLinux &fsm
#endif
                     ) {
  printf("Logging out.\n");
  if (!logged_in_)
    return;
#ifdef MAIDSAFE_WIN32
  std::locale loc;
  wchar_t drive_letter = std::use_facet< std::ctype<wchar_t> >
                         (loc).widen(ss->WinDrive());
  ASSERT_TRUE(fs_w_fuse::DokanUnmount(drive_letter));
#elif defined(MAIDSAFE_POSIX)
  fsl.UnMount();
#elif defined(MAIDSAFE_APPLE)
  fsm.UnMount();
#endif
  bool success = cc->Logout();
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success);
  logged_in_ = false;
}

void CreateUserLoginMount(maidsafe::ClientController *cc,
                          maidsafe::SessionSingleton *ss,
                          const std::string &user,
                          const std::string &pin,
                          const std::string &pw,
                          const std::string &public_name,
#ifdef MAIDSAFE_POSIX
                          fs_l_fuse::FSLinux &fsl,
#elif defined(MAIDSAFE_APPLE)
                          fs_l_fuse::FSLinux &fsm,
#endif
                          fs::path *mount_path) {
  printf("Logging in.\n");
  // If user already logged in, try to logout.
  if (logged_in_) {
#ifdef MAIDSAFE_WIN32
    UnmountAndLogout(cc, ss);
#elif defined(MAIDSAFE_POSIX)
    UnmountAndLogout(cc, fsl);
#elif defined(MAIDSAFE_APPLE)
    UnmountAndLogout(cc, fsm);
#endif
  }
  // If user not logged in, check session has been started OK and login
  ASSERT_TRUE(cc->JoinKademlia());
  ASSERT_TRUE(cc->Init());
  // check session reset OK
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  boost::mutex mutex;
  TestCallback cb(&mutex);
  maidsafe::exitcode result = cc->CheckUserExists(user, pin, boost::bind(
      &TestCallback::CallbackFunc, &cb, _1), maidsafe::DEFCON3);

  if (ss->Username() == user) {
    ASSERT_EQ(maidsafe::USER_EXISTS, result);
    boost::this_thread::sleep(boost::posix_time::seconds(5));
    ASSERT_TRUE(cc->ValidateUser(pw));
    logged_in_ = true;
    boost::this_thread::sleep(boost::posix_time::seconds(5));
  } else {  // If user not logged in and session not started, create user
    ASSERT_EQ(maidsafe::NON_EXISTING_USER, result);
    ASSERT_TRUE(cc->CreateUser(user, pin, pw));
    ASSERT_TRUE(cc->CreatePublicUsername(public_name));
    logged_in_ = true;
    boost::this_thread::sleep(boost::posix_time::seconds(10));
  }
  // Mount drive
  ASSERT_TRUE(ss->SetMounted(0));
#ifdef MAIDSAFE_WIN32
  char drive = cc->DriveLetter();
  std::string mount_point(1, drive);
  mount_point += ":\\";
  *mount_path = fs::path(mount_point, fs::native);
  Mount(drive);
  ASSERT_TRUE(ss->SetWinDrive(drive));
#elif defined(MAIDSAFE_POSIX)
  file_system::FileSystem fsys;
  std::string mount_point = fsys.MaidsafeFuseDir();
  *mount_path = fs::path(mount_point, fs::native);
  std::string debug_mode("-d");
  ASSERT_TRUE(fsl.Mount(mount_point, debug_mode));
#elif defined(MAIDSAFE_APPLE)
  file_system::FileSystem fsys;
  std::string mount_point = fsys.MaidsafeFuseDir();
  *mount_path = fs::path(mount_point, fs::native);
  std::string debug_mode("-d");
  ASSERT_TRUE(fsm.Mount(mount_point, debug_mode));
#endif
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss->Mounted());
  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

}  // namespace fs_?_fuse::fuse_test

class FuseTest : public testing::Test {
 public:
  FuseTest() : cc_(maidsafe::ClientController::getInstance()),
               ss_(maidsafe::SessionSingleton::getInstance()),
               username1_("user1"),
               username2_("user2"),
               public_username1_("XXXXX"),
               public_username2_("YYYYY"),
               pin_("1234"),
               password_("password1"),
               mount_path_(),
#ifdef MAIDSAFE_POSIX
               fsl_(),
#elif defined(MAIDSAFE_APPLE)
               fsm_(),
#endif
               mutex_(),
               cbk_(&mutex_) {}
 protected:
  maidsafe::ClientController *cc_;
  maidsafe::SessionSingleton *ss_;
  const std::string username1_, username2_;
  const std::string public_username1_, public_username2_;
  const std::string pin_, password_;
  fs::path mount_path_;
#ifdef MAIDSAFE_POSIX
  fs_l_fuse::FSLinux fsl_;
#elif defined(MAIDSAFE_APPLE)
  fs_l_fuse::FSLinux fsm_;
  // fs_m_fuse::FSMac fsm_;
#endif
  boost::mutex mutex_;
  fuse_test::TestCallback cbk_;
 private:
  FuseTest(const FuseTest&);
  FuseTest &operator=(const FuseTest&);
};

TEST_F(FuseTest, FUNC_FS_RepeatedMount) {
  for (int i = 0; i < 7; ++i) {
    std::string trace = "Mount / unmount repetiton " + base::itos(i);
    SCOPED_TRACE(trace);
#ifdef MAIDSAFE_WIN32
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, fsm_, &mount_path_);
#endif
    ASSERT_TRUE(fs::exists(mount_path_));
    printf("Logged in.\n");
    // read root dir
//    mount_path_ = fs::path("M:\\My Files", fs::native);
//    fs::directory_iterator end_itr_;
//    for (fs::directory_iterator itr_(mount_path_); itr_ != end_itr_; ++itr_) {
//      printf("%s\n", itr_->path().string().c_str());
//    }
#ifdef MAIDSAFE_WIN32
    fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
    fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
    fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
    ASSERT_FALSE(fs::exists(mount_path_));
    printf("Logged out (%i)\n--------------------------------------\n\n", i+1);
  }
////  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  cc_->CloseConnection();
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
}

TEST_F(FuseTest, FUNC_FS_StoreFilesAndDirs) {
#ifdef MAIDSAFE_WIN32
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
    fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_, password_,
                                    public_username1_, fsm_, &mount_path_);
#endif
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Logged in.\n");
  printf("Mount path = %s\n", mount_path_.string().c_str());

  // try to write file to root dir
  fs::path test_path_(mount_path_);
  test_path_ /= "test.txt";
  std::string hash_("");
// TODO(Fraser#5#): 2009-07-03 - Uncomment following line
//  ASSERT_FALSE(fuse_test::CreateRandomFile(test_path_.string(), 1, &hash_));

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
    fuse_test::test_file_.push_back(test_root_);
  fuse_test::test_file_[0] /= "test0.txt";
  fuse_test::test_file_[1] /= "test1.txt";
  fuse_test::test_file_[2] /= "test2.txt";
  fuse_test::test_file_.push_back(test_dir_0_);
  fuse_test::test_file_.push_back(test_dir_1_);
  // /My Files/TestDir0/test3.txt
  fuse_test::test_file_[3] /= "test3.txt";
  // /My Files/TestDir0/TestDir1/test4.txt
  fuse_test::test_file_[4] /= "test4.txt";
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_.push_back("");
  bool success_ = false;
  int success_count = 0;
  try {
    ASSERT_TRUE(fs::exists(test_root_)) << test_root_ << " doesn't exist.";
    fs::create_directory(test_dir_0_);
    fs::create_directory(test_dir_1_);
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", fuse_test::test_file_[0].string().c_str());
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[0].string(), 2,
                                         &fuse_test::pre_hash_[0]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[1].string(), 10,
                                         &fuse_test::pre_hash_[1]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[2].string(), 100,
                                         &fuse_test::pre_hash_[2]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[3].string(), 100,
                                         &fuse_test::pre_hash_[3]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[4].string(), 100,
                                         &fuse_test::pre_hash_[4]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  if (success_count == 5) {
    maidsafe::SelfEncryption se;
    for (int i = 0; i < 5; ++i) {
      ASSERT_EQ(fuse_test::pre_hash_[i], se.SHA512(fuse_test::test_file_[i]));
      boost::this_thread::sleep(boost::posix_time::seconds(5));
    }
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
//    fuse_test::test_file_.push_back(test_root_);
//  fuse_test::test_file_[5] /= "test0.txt";
//  fuse_test::test_file_[6] /= "test1.txt";
//  fuse_test::test_file_[7] /= "test2.txt";
//  fuse_test::test_file_.push_back(test_dir_0_);
//  fuse_test::test_file_.push_back(test_dir_1_);
//  // Shares/Public/TestDir0/test3.txt
//  fuse_test::test_file_[8] /= "test3.txt";
//  // Shares/Public/TestDir0/TestDir1/test4.txt
//  fuse_test::test_file_[9] /= "test4.txt";
//  for (int i = 0; i < 5; ++i)
//    fuse_test::pre_hash_.push_back("");
//  success_ = false;
//  try {
//    fs::create_directory(test_dir_0_);
//    fs::create_directory(test_dir_1_);
//    boost::this_thread::sleep(boost::posix_time::seconds(30));
//    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_TRUE(success_);
//  printf("Trying to create %s\n", fuse_test::test_file_[5].string().c_str());
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[5].string(),
//                                         2, &fuse_test::pre_hash_[5]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[6].string(),
//                                         10, &fuse_test::pre_hash_[6]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[7].string(),
//                                         100, &fuse_test::pre_hash_[7]);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[8].string(),
//                                         100, &fuse_test::pre_hash_[8]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[9].string(),
//                                         100, &fuse_test::pre_hash_[9]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  for (int i = 5; i < 10; ++i) {
//    ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(fuse_test::test_file_[i]));
//    boost::this_thread::sleep(boost::posix_time::seconds(5));
//  }

  test_root_ = root_;
  // write files and dirs to "/Shares/Anonymous" dir
  test_root_ /= kSharesSubdir[1][0];  // /Shares/Anonymous/
  test_dir_0_ = test_root_;
  test_dir_0_ /= "TestDir0";
  test_dir_1_ = test_dir_0_;
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    fuse_test::test_file_.push_back(test_root_);
  fuse_test::test_file_[5] /= "test0.txt";
  fuse_test::test_file_[6] /= "test1.txt";
  fuse_test::test_file_[7] /= "test2.txt";
  fuse_test::test_file_.push_back(test_dir_0_);
  fuse_test::test_file_.push_back(test_dir_1_);
  // /Shares/Anonymous/TestDir0/test3.txt
  fuse_test::test_file_[8] /= "test3.txt";
  // /Shares/Anon.../TestDir0/TestDir1/test4.txt
  fuse_test::test_file_[9] /= "test4.txt";
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_.push_back("");
  success_ = false;
  try {
    ASSERT_TRUE(fs::exists(test_root_)) << test_root_ << " doesn't exist.";
    fs::create_directory(test_dir_0_);
    fs::create_directory(test_dir_1_);
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_TRUE(success_);
  success_ = false;
  success_count = 0;
  printf("Trying to create %s\n", fuse_test::test_file_[5].string().c_str());
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[5].string(),
                                         2, &fuse_test::pre_hash_[5]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[6].string(),
                                         10, &fuse_test::pre_hash_[6]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[7].string(),
                                         100, &fuse_test::pre_hash_[7]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[8].string(),
                                         100, &fuse_test::pre_hash_[8]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[9].string(),
                                         100, &fuse_test::pre_hash_[9]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  if (success_) {
    ++success_count;
    success_ = false;
  }
  if (success_count == 5) {
    maidsafe::SelfEncryption se;
    for (int i = 5; i < 10; ++i) {
      ASSERT_EQ(fuse_test::pre_hash_[i], se.SHA512(fuse_test::test_file_[i]));
      boost::this_thread::sleep(boost::posix_time::seconds(5));
    }
  }

//  test_root_ = root_;
//  // try to write files and dirs to "/Shares/Private" dir without first
//  // creating a private share via clientcontroller
//  test_root_ /= kSharesSubdir[0][0];  // /Shares/Private/
//  fs::path test_dir_(test_root_);
//  test_dir_ /= "TestDir";
//  fs::path test_txt_(test_root_);
//  test_txt_ /= "test.txt";
//  success_ = false;
//  try {
//    printf("Trying to create %s\n", test_dir_.string().c_str());
//    ASSERT_TRUE(fs::exists(test_root_)) << test_root_ << " doesn't exist.";
//    fs::create_directory(test_dir_);
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  try {
//    printf("Checking dir's existence.\n");
//    success_ = (fs::exists(test_dir_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_FALSE(success_);
//  printf("Trying to create %s\n", test_txt_.string().c_str());
//  std::string file_hash_("");
//  success_ = fuse_test::CreateRandomFile(test_txt_.string(), 2, &file_hash_);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//// TODO(Fraser#5#): 2009-07-03 - Uncomment following line
////  ASSERT_FALSE(success_);

//  // Add user 2 as an authorised user and as a contact and create a share
//  // giving him admin rights
//  std::string share_name = "TestDir0";
//  std::set<std::string> admins1, readonlys1;
//  admins1.insert(public_username2_);
//  ASSERT_TRUE(cc_->AuthoriseUsers(admins1));
//  ASSERT_EQ(0, cc_->AddContact(public_username2_));
//  ASSERT_EQ(0, cc_->CreateNewShare(share_name, admins1, readonlys1));
//
//  test_root_ = root_;
//  // try to write files and dirs to "/Shares/Private" dir
//  test_root_ /= kSharesSubdir[0][0];  // /Shares/Private/
//  test_dir_0_ = test_root_;
//  test_dir_0_ /= share_name;
//  test_dir_1_ = test_dir_0_;
//  test_dir_1_ /= "TestDir1";
//  for (int i = 0; i < 3; ++i)
//    fuse_test::test_file_.push_back(test_root_);
//  fuse_test::test_file_[10] /= "test0.txt";
//  fuse_test::test_file_[11] /= "test1.txt";
//  fuse_test::test_file_[12] /= "test2.txt";
//  fuse_test::test_file_.push_back(test_dir_0_);
//  fuse_test::test_file_.push_back(test_dir_1_);
//  // /Shares/Private/TestDir0/test3.txt
//  fuse_test::test_file_[13] /= "test3.txt";
//  // /Shares/Private/TestDir0/TestDir1/test4.txt
//  fuse_test::test_file_[14] /= "test4.txt";
//  for (int i = 0; i < 5; ++i)
//    fuse_test::pre_hash_.push_back("");
//  success_ = false;
//  try {
//    ASSERT_TRUE(fs::exists(test_root_)) << test_root_ << " doesn't exist.";
//    fs::create_directory(test_dir_1_);
//    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_TRUE(success_);
//  success_ = false;
//  success_count = 0;
//  printf("Trying to create %s\n", fuse_test::test_file_[10].string().c_str());
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[10].string(),
//                                         2, &fuse_test::pre_hash_[10]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  if (success_) {
//    ++success_count;
//    success_ = false;
//  }
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[11].string(),
//                                         10, &fuse_test::pre_hash_[11]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  if (success_) {
//    ++success_count;
//    success_ = false;
//  }
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[12].string(),
//                                         100, &fuse_test::pre_hash_[12]);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  ASSERT_TRUE(success_);
//  if (success_) {
//    ++success_count;
//    success_ = false;
//  }
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[13].string(),
//                                         100, &fuse_test::pre_hash_[13]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  if (success_) {
//    ++success_count;
//    success_ = false;
//  }
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[14].string(),
//                                         100, &fuse_test::pre_hash_[14]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  if (success_) {
//    ++success_count;
//    success_ = false;
//  }
//  if (success_count == 5) {
//    maidsafe::SelfEncryption se;
//    for (int i = 5; i < 10; ++i) {
//      ASSERT_EQ(fuse_test::pre_hash_[i], se.SHA512(fuse_test::test_file_[i]));
//      boost::this_thread::sleep(boost::posix_time::seconds(5));
//    }
//  }

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");
//  fuse_test::test_file_.clear();
//  fuse_test::pre_hash_.clear();
}

TEST_F(FuseTest, DISABLED_FUNC_FS_Rename_Dir) {
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
//        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
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
//                                        maidsafe::DEFCON3);
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
//                                 maidsafe::DEFCON3);
//  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_EQ(0, ss_->Mounted());
//  logged_in_ = true;
//  printf("Logged in.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
//    fs::create_directory(test_dir_0_);
//    success_ = fs::exists(test_dir_0_);
//    fs::rename(test_dir_0_.string(), test_dir_0_renamed.string());
//    renamation = (!fs::exists(test_dir_0_) && fs::exists(test_dir_0_renamed));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_TRUE(success_);
//  ASSERT_TRUE(renamation);
//
//  fs::path fileillo(test_dir_0_renamed / "summat.txt");
//  success_ = fuse_test::CreateRandomFile(fileillo.string(), 100, &fuse_test::pre_hash_[2]);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));

// DO NOT ERASE. HAD TO COMMIT TO GENERATE BUILD.
}








/*
TEST_F(FuseTest, FUNC_FS_RepeatStoreFilesAndDirs) {
#ifdef MAIDSAFE_WIN32
    ASSERT_EQ(0, fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_,
                                                 password_, public_username1_,
                                                 &mount_path_));
#elif defined(MAIDSAFE_POSIX)
    ASSERT_EQ(0, fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_,
                                                 password_, public_username1_,
                                                 fsl_, &mount_path_));
#elif defined(MAIDSAFE_APPLE)
    ASSERT_EQ(0, fuse_test::CreateUserLoginMount(cc_, ss_, username1_, pin_,
                                                 password_, public_username1_,
                                                 fsm_, &mount_path_));
#endif
  printf("Logged in.\n");
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;


  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // try to write file to root dir
  fs::path test_path_(mount_path_);
  test_path_ /= "test.txt";
  std::string hash_("");
  ASSERT_FALSE(fuse_test::CreateRandomFile(test_path_.string(), 1, &hash_));

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
    fuse_test::test_file_.push_back(test_root_);
  fuse_test::test_file_[0] /= "test0.txt";
  fuse_test::test_file_[1] /= "test1.txt";
  fuse_test::test_file_[2] /= "test2.txt";
  fuse_test::test_file_.push_back(test_dir_0_);
  fuse_test::test_file_.push_back(test_dir_1_);
  fuse_test::test_file_[3] /= "test3.txt";  // /My Files/TestDir0/test3.txt
  fuse_test::test_file_[4] /= "test4.txt";  // /My Files/TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_.push_back("");
  bool success_ = false;
  try {
    fs::create_directory(test_dir_0_);
    fs::create_directory(test_dir_1_);
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", fuse_test::test_file_[0].string().c_str());
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[0].string(), 2, &fuse_test::pre_hash_[0]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[1].string(), 10, &fuse_test::pre_hash_[1]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[2].string(), 100, &fuse_test::pre_hash_[2]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[3].string(), 100, &fuse_test::pre_hash_[3]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[4].string(), 100, &fuse_test::pre_hash_[4]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  maidsafe::SelfEncryption se_;
  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(fuse_test::test_file_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
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
//    fuse_test::test_file_.push_back(test_root_);
//  fuse_test::test_file_[5] /= "test0.txt";
//  fuse_test::test_file_[6] /= "test1.txt";
//  fuse_test::test_file_[7] /= "test2.txt";
//  fuse_test::test_file_.push_back(test_dir_0_);
//  fuse_test::test_file_.push_back(test_dir_1_);
//  fuse_test::test_file_[8] /= "test3.txt";  // Shares/Public/TestDir0/test3.txt
//  fuse_test::test_file_[9] /= "test4.txt";  // Shares/Public/TestDir0/TestDir1/test4.txt
//  for (int i = 0; i < 5; ++i)
//    fuse_test::pre_hash_.push_back("");
//  success_ = false;
//  try {
//    fs::create_directory(test_dir_0_);
//    fs::create_directory(test_dir_1_);
//    boost::this_thread::sleep(boost::posix_time::seconds(30));
//    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
//  }
//  catch(const std::exception &e_) {
//    printf("%s\n", e_.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_TRUE(success_);
//  printf("Trying to create %s\n", fuse_test::test_file_[5].string().c_str());
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[5].string(), 2, &fuse_test::pre_hash_[5]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[6].string(), 10, &fuse_test::pre_hash_[6]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[7].string(), 100, &fuse_test::pre_hash_[7]);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[8].string(), 100, &fuse_test::pre_hash_[8]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[9].string(), 100, &fuse_test::pre_hash_[9]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  ASSERT_TRUE(success_);
//  for (int i = 5; i < 10; ++i) {
//    ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(fuse_test::test_file_[i]));
//    boost::this_thread::sleep(boost::posix_time::seconds(5));
//  }
  test_root_ = root_;

  // write files and dirs to "/Shares/Anonymous" dir
  test_root_ /= kSharesSubdir[1][0];  // /Shares/Anonymous/
  test_dir_0_ = test_root_;
  test_dir_0_ /= "TestDir0";
  test_dir_1_ = test_dir_0_;
  test_dir_1_ /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    fuse_test::test_file_.push_back(test_root_);
  fuse_test::test_file_[10] /= "test0.txt";
  fuse_test::test_file_[11] /= "test1.txt";
  fuse_test::test_file_[12] /= "test2.txt";
  fuse_test::test_file_.push_back(test_dir_0_);
  fuse_test::test_file_.push_back(test_dir_1_);
  fuse_test::test_file_[13] /= "test3.txt";  // /Shares/Anonymous/TestDir0/test3.txt
  fuse_test::test_file_[14] /= "test4.txt";  // /Shares/Anon.../TestDir0/TestDir1/test4.txt
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_.push_back("");
  success_ = false;
  try {
    fs::create_directory(test_dir_0_);
    fs::create_directory(test_dir_1_);
    success_ = (fs::exists(test_dir_0_) && fs::exists(test_dir_1_));
  }
  catch(const std::exception &e_) {
    printf("%s\n", e_.what());
  }
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_TRUE(success_);
  printf("Trying to create %s\n", fuse_test::test_file_[10].string().c_str());
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[10].string(), 2, &fuse_test::pre_hash_[10]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[11].string(), 10, &fuse_test::pre_hash_[11]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[12].string(), 100, &fuse_test::pre_hash_[12]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[13].string(), 100, &fuse_test::pre_hash_[13]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  success_ = fuse_test::CreateRandomFile(fuse_test::test_file_[14].string(), 100, &fuse_test::pre_hash_[14]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  ASSERT_TRUE(success_);
  for (int i = 10; i < 15; ++i) {
    ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(fuse_test::test_file_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
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
    fs::create_directory(test_dir_);
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
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_FALSE(success_);
  printf("Trying to create %s\n", test_txt_.string().c_str());
  std::string file_hash_("");
  success_ = fuse_test::CreateRandomFile(test_txt_.string(), 2, &file_hash_);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");

  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");

  // login
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // ensure all previous files are still there
  for (int i = 0; i < 15; ++i) {
    printf("Checking file %i\n", i);
    printf("pre_hash[%i] = %s\n", i, fuse_test::pre_hash_[i].c_str());
    printf("se_.SHA512(fuse_test::test_file_[%i]) = %s\n",
           i,
           se_.SHA512(fuse_test::test_file_[i]).c_str());
    ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(fuse_test::test_file_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  logged_in_ = false;
}

*/








/*
TEST_F(FuseTest, DISABLED_FUNC_FS_CheckNewUserDirs) {
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
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
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
                                        maidsafe::DEFCON3);
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
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

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
//          if (itr_->path().filename() == fuse_test::test_file_[i].filename()) {
//            ++file_count_;
//            ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(itr_->path()));
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
//  ASSERT_EQ(0, file_count_);  // TODO(Fraser#5#): Uncommnt line above & rm ths
//
  // check previously-added files exist in "/Shares/Anonymous" dir
  test_root_ = root_;
  test_root_ /= kSharesSubdir[1][0];
  file_count_ = 0;
  for (fs::directory_iterator itr_(test_root_); itr_ != end_itr_; ++itr_) {
    try {
      if (fs::is_regular_file(itr_->status())) {
        for (int i = 10; i < 15; ++i) {
          if (itr_->path().filename() == fuse_test::test_file_[i].filename()) {
            ++file_count_;
            ASSERT_EQ(fuse_test::pre_hash_[i], se_.SHA512(itr_->path()));
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");
  cc_->CloseConnection();
  logged_in_ = false;
}
*/




/*
TEST_F(FuseTest, DISABLED_FUNC_FS_SharesAndMessages) {
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
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
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
                                        maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 2
  result_ = cc_->CheckUserExists(username2_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // TODO(Fraser#5#): ensure user 2 can add to private share

  // TODO(Fraser#5#): Add user 1 to contact list and send him a message and file
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 1
  result_ = cc_->CheckUserExists(username1_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Logged out\n--------------------------------------------------\n\n");

  // login as user 2
  result_ = cc_->CheckUserExists(username2_,
                                 pin_,
                                 boost::bind(&FakeCallback::CallbackFunc,
                                             &cb_,
                                             _1),
                                 maidsafe::DEFCON3);
  ASSERT_EQ(maidsafe::USER_EXISTS, result_);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
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
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_EQ(0, ss_->Mounted());
  logged_in_ = true;
  printf("Logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

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
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    logout_ = true;
  #else
    fsl_.UnMount();
    logout_ = true;
  #endif
  ASSERT_TRUE(logout_);
  ASSERT_TRUE(cc_->Logout());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
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
*/





}  // namespace fs_w_fuse or fs_l_fuse or fs_m_fuse

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
#ifdef MAIDSAFE_WIN32
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(fs_w_fuse::fuse_test::kNetworkSize_,
                           fs_w_fuse::fuse_test::kTestK_,
                           &fs_w_fuse::fuse_test::pdvaults_));
#elif defined(MAIDSAFE_POSIX)
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(fs_l_fuse::fuse_test::kNetworkSize_,
                           fs_l_fuse::fuse_test::kTestK_,
                           &fs_l_fuse::fuse_test::pdvaults_));
#elif defined(MAIDSAFE_APPLE)
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(fs_m_fuse::fuse_test::kNetworkSize_,
                           fs_m_fuse::fuse_test::kTestK_,
                           &fs_m_fuse::fuse_test::pdvaults_));
#endif
  return RUN_ALL_TESTS();
}
