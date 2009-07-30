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
#include "fs/l_fuse/fslinux.h"
#endif


#if defined MAIDSAFE_WIN32
namespace fs_w_fuse {
#elif defined MAIDSAFE_POSIX
namespace fs_l_fuse {
#elif defined MAIDSAFE_APPLE
namespace fs_l_fuse {
#endif

namespace fuse_test {

static std::vector< boost::shared_ptr<maidsafe_vault::PDVault> > pdvaults_;
static const int kNetworkSize_ = 16;
static const int kTestK_ = 4;
static bool logged_in_;
static std::vector<fs::path> test_myfile_, test_share_;
static std::vector<std::string> pre_hash_myfile_, pre_hash_share_;

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
  // Unmount drive
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
  // Logout
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
  boost::this_thread::sleep(boost::posix_time::seconds(20));
}

}  // namespace fs_?_fuse::fuse_test

class FuseTest : public testing::Test {
 public:
  FuseTest() : cc_(maidsafe::ClientController::getInstance()),
               ss_(maidsafe::SessionSingleton::getInstance()),
               username1_("user1"),
               username2_("user2"),
               username3_("user3"),
               public_username1_("XXXXX"),
               public_username2_("YYYYY"),
               public_username3_("ZZZZZ"),
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

  ~FuseTest() {
#ifdef MAIDSAFE_WIN32
    for (char driveletter = 'm'; driveletter <= 'z'; ++driveletter) {
      std::locale loc;
      wchar_t wdriveletter = std::use_facet< std::ctype<wchar_t> >
                             (loc).widen(driveletter);
      DokanUnmount(wdriveletter);
    }
#endif
  }
 protected:
  maidsafe::ClientController *cc_;
  maidsafe::SessionSingleton *ss_;
  const std::string username1_, username2_, username3_;
  const std::string public_username1_, public_username2_, public_username3_;
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

TEST_F(FuseTest, FUNC_FUSE_RepeatedMount) {
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
//    fs::directory_iterator end_itr;
//    for (fs::directory_iterator itr(mount_path_); itr != end_itr; ++itr) {
//      printf("%s\n", itr->path().string().c_str());
//    }
#ifdef MAIDSAFE_WIN32
    fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
    fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
    fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
    ASSERT_FALSE(fs::exists(mount_path_));
    printf("Logged out (%i)\n-------------------------------------\n\n", i+1);
  }
//  //  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  cc_->CloseConnection();
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
}

TEST_F(FuseTest, FUNC_FUSE_MyFiles) {
  // Test comprises following steps:-
  // 01. Create user 1 and check all default directories exist.
  // 02. Save 5 files to 2 subdirs in /My Files.
  // 03. Logout, then login again.
  // 04. Check /My Files has correct 5 files.
  // 05. Check a subdir can be renamed.
  // 06. Logout, then create user 2.
  // 07. Check /My Files is empty.
  // ---------------------------------------------------------------------------
  // fuse_test::test_myfile_'s as follows (where mount_path_ = "M:/")
  // 0 = M:/My Files/test0.txt
  // 1 = M:/My Files/test1.txt
  // 2 = M:/My Files/test2.txt
  // 3 = M:/My Files/TestDir0/test3.txt
  // 4 = M:/My Files/TestDir0/TestDir1/test4.txt

  // 01. Create user 1 and check all default directories exist.
  // ----------------------------------------------------------
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
  printf("User 1 logged in.\n");
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      " didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());
  fs::path test_path(mount_path_);
  test_path /= kRootSubdir[0][0];
  ASSERT_TRUE(fs::exists(test_path)) << test_path << " doesn't exist.";
  test_path = mount_path_;
  test_path /= kSharesSubdir[0][0];
  ASSERT_TRUE(fs::exists(test_path)) << test_path << " doesn't exist.";
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  test_path = mount_path_;
//  test_path /= kSharesSubdir[1][0];
//  ASSERT_TRUE(fs::exists(test_path)) << test_path << " doesn't exist.";


  // 02. Save 5 files to 2 subdirs in /My Files.
  // -------------------------------------------
  // Ensure we can't write to root dir
  bool success = false;
  test_path = mount_path_;
  test_path /= "test.txt";
  std::string hash("");
// TODO(Fraser#5#): 2009-07-05 - Uncomment one of the two checks below:-
//  fuse_test::CreateRandomFile(test_path.string(), 1, &hash);
//  ASSERT_FALSE(fs::exists(test_path));

//  ASSERT_FALSE(fuse_test::CreateRandomFile(test_path.string(), 1, &hash));

// TODO(Fraser#5#): 2009-07-05 - Uncomment check below:-
//  test_path = mount_path_;
//  test_path /= "testdir";
//  try {
//    fs::create_directory(test_path);
//    success = true;
//  }
//  catch(std::exception &) {}
//  ASSERT_FALSE(success);

  #if defined MAIDSAFE_WIN32
    std::string win_root(mount_path_.string());
    win_root = base::TidyPath(win_root);
    const fs::path kRoot(win_root);
  #else
    const fs::path kRoot(mount_path_);
  #endif
  fs::path test_root(kRoot);
  test_root /= kRootSubdir[0][0];
  fs::path test_dir_0(test_root);
  test_dir_0 /= "TestDir0";
  fs::path test_dir_1(test_dir_0);
  test_dir_1 /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    fuse_test::test_myfile_.push_back(test_root);
  fuse_test::test_myfile_[0] /= "test0.txt";
  fuse_test::test_myfile_[1] /= "test1.txt";
  fuse_test::test_myfile_[2] /= "test2.txt";
  fuse_test::test_myfile_.push_back(test_dir_0);
  fuse_test::test_myfile_.push_back(test_dir_1);
  fuse_test::test_myfile_[3] /= "test3.txt";
  fuse_test::test_myfile_[4] /= "test4.txt";
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_myfile_.push_back("");
  try {
    ASSERT_TRUE(fs::create_directory(test_dir_0)) << "Couldn't create " <<
        test_dir_0;
    ASSERT_TRUE(fs::create_directory(test_dir_1)) << "Couldn't create " <<
        test_dir_1;
    boost::this_thread::sleep(boost::posix_time::seconds(30));
    success = (fs::exists(test_dir_0) && fs::exists(test_dir_1));
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_TRUE(success);
  printf("Trying to create %s\n", fuse_test::test_myfile_[0].string().c_str());
  success = fuse_test::CreateRandomFile(fuse_test::test_myfile_[0].string(), 2,
                                        &fuse_test::pre_hash_myfile_[0]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_TRUE(success);
  success = fuse_test::CreateRandomFile(fuse_test::test_myfile_[1].string(), 10,
                                        &fuse_test::pre_hash_myfile_[1]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  success = fuse_test::CreateRandomFile(fuse_test::test_myfile_[2].string(),
                                        100, &fuse_test::pre_hash_myfile_[2]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  success = fuse_test::CreateRandomFile(fuse_test::test_myfile_[3].string(),
                                        100, &fuse_test::pre_hash_myfile_[3]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  success = fuse_test::CreateRandomFile(fuse_test::test_myfile_[4].string(),
                                        100, &fuse_test::pre_hash_myfile_[4]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  maidsafe::SelfEncryption se;
  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(fuse_test::pre_hash_myfile_[i],
              se.SHA512(fuse_test::test_myfile_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
  }

  // 03. Logout, then login again.
  // -----------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

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
  printf("User 1 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());

  // 04. Check /My Files has correct 5 files.
  // ----------------------------------------
  ASSERT_TRUE(fs::exists(test_root));
  for (int i = 0; i < 5; ++i) {
    ASSERT_TRUE(fs::exists(fuse_test::test_myfile_[i]));
    ASSERT_EQ(fuse_test::pre_hash_myfile_[i],
              se.SHA512(fuse_test::test_myfile_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
  }

  // 05. Check a subdir can be renamed.
  // ----------------------------------
  fs::path new_test_dir_1(test_dir_0);
  new_test_dir_1 /= "RenamedTestDir1";
  fs::rename(test_dir_1, new_test_dir_1);
  fs::path new_file_4(new_test_dir_1);
  new_file_4 /= "test4.txt";
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  ASSERT_FALSE(fs::exists(test_dir_1));
  ASSERT_TRUE(fs::exists(new_test_dir_1));
  ASSERT_TRUE(fs::exists(new_file_4));
  ASSERT_EQ(fuse_test::pre_hash_myfile_[4], se.SHA512(new_file_4));

  // 06. Logout, then create user 2.
  // -------------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsm_, &mount_path_);
#endif
  printf("User 2 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());

  // 07. Check /My Files is empty.
  // -----------------------------
  test_root = kRoot;
  test_root /= kRootSubdir[0][0];
  for (int i = 0; i < 5; ++i) {
    printf("Checking file %i\n", i);
    ASSERT_FALSE(fs::exists(fuse_test::test_myfile_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
  }
// TODO(Fraser#5#): 2009-07-05 - Find out why directory_itr causes segfault
//  fs::directory_iterator end_itr;
//  int file_count(0);
//  for (fs::directory_iterator itr(test_root); itr != end_itr; ++itr) {
//    ++file_count;
//    boost::this_thread::sleep(boost::posix_time::seconds(10));
//  }
//  printf("In My Files, file count = %i\n", file_count);
//  ASSERT_EQ(0, file_count);
}

TEST_F(FuseTest, FUNC_FUSE_SharesAndMessages) {
  // Test comprises following steps:-
  // 01. Create / login 3 users and add each to others' contact lists.
  // 02. Save 5 files to 2 subdirs in /Shares/Anonymous.
  // 03. Logout, then login as user 2.
  // 04. Check /Shares/Private is empty & /Shares/Anon has 5 files.
  // 05. Create a private share with user 1 (admin rights) & user 3 (r-o rights)
  // 06. Save 5 files to 2 subdirs in new share.
  // 07. Logout, then login as user 3.
  // 08. Check /Shares/Private has files and that they are read-only.
  // 09. Logout then login as user 1.
  // 10. Check /Shares/Private has files and that they can be modified.
  // 11. Send user 2 a message and file (with message = hash of file).
  // 12. Logout then login as user 2.
  // 13. Check shared files reflect user 1's modifications.
  // 14. Check file and message have been received correctly.
  // ---------------------------------------------------------------------------
  // fuse_test::test_share_'s as follows (where mount_path_ = "M:/")
  // 0 = M:/Shares/Anonymous/test0.txt
  // 1 = M:/Shares/Anonymous/test1.txt
  // 2 = M:/Shares/Anonymous/test2.txt
  // 3 = M:/Shares/Anonymous/TestDir0/test3.txt
  // 4 = M:/Shares/Anonymous/TestDir0/TestDir1/test4.txt
  // 5 = M:/Shares/Private/TestShare/test0.txt
  // 6 = M:/Shares/Private/TestShare/test1.txt
  // 7 = M:/Shares/Private/TestShare/test2.txt
  // 8 = M:/Shares/Private/TestShare/TestDir0/test3.txt
  // 9 = M:/Shares/Private/TestShare/TestDir0/TestDir1/test4.txt


  // 01. Create / login 3 users and add each to others' contact lists.
  // -----------------------------------------------------------------
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
  printf("User 1 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("Mount path = %s\n", mount_path_.string().c_str());

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsm_, &mount_path_);
#endif
  printf("User 2 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("Mount path = %s\n", mount_path_.string().c_str());

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, fsm_, &mount_path_);
#endif
  printf("User 3 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("Mount path = %s\n", mount_path_.string().c_str());
  ASSERT_EQ(0, cc_->AddContact(public_username1_));
  ASSERT_EQ(0, cc_->AddContact(public_username2_));

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsm_, &mount_path_);
#endif
  printf("User 2 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("Mount path = %s\n", mount_path_.string().c_str());
  ASSERT_EQ(0, cc_->AddContact(public_username1_));
  ASSERT_EQ(0, cc_->AddContact(public_username3_));

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

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
  printf("User 1 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("Mount path = %s\n", mount_path_.string().c_str());
  ASSERT_EQ(0, cc_->AddContact(public_username2_));
  ASSERT_EQ(0, cc_->AddContact(public_username3_));


  // 02. Save 5 files to 2 subdirs in /Shares/Anonymous.
  // ---------------------------------------------------
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
  bool success(false);
  std::string hash("");

  #if defined MAIDSAFE_WIN32
    std::string win_root(mount_path_.string());
    win_root = base::TidyPath(win_root);
    const fs::path kRoot(win_root);
  #else
    const fs::path kRoot(mount_path_);
  #endif
  fs::path test_root(kRoot);

// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  test_root /= kSharesSubdir[1][0];  // /Shares/Anonymous/
  fs::path test_dir_0(test_root);
  test_dir_0 /= "TestDir0";
  fs::path test_dir_1(test_dir_0);
  test_dir_1 /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    fuse_test::test_share_.push_back(test_root);
  fuse_test::test_share_[0] /= "test0.txt";
  fuse_test::test_share_[1] /= "test1.txt";
  fuse_test::test_share_[2] /= "test2.txt";
  fuse_test::test_share_.push_back(test_dir_0);
  fuse_test::test_share_.push_back(test_dir_1);
  fuse_test::test_share_[3] /= "test3.txt";
  fuse_test::test_share_[4] /= "test4.txt";
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_share_.push_back("");
// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  try {
//    ASSERT_TRUE(fs::create_directory(test_dir_0)) << "Couldn't create " <<
//        test_dir_0;
//    ASSERT_TRUE(fs::create_directory(test_dir_1)) << "Couldn't create " <<
//        test_dir_1;
//    boost::this_thread::sleep(boost::posix_time::seconds(30));
//    success = (fs::exists(test_dir_0) && fs::exists(test_dir_1));
//  }
//  catch(const std::exception &e) {
//    printf("%s\n", e.what());
//  }
//  ASSERT_TRUE(success);
//  printf("Trying to create %s\n", fuse_test::test_share_[0].string().c_str());
//  success = fuse_test::CreateRandomFile(fuse_test::test_share_[0].string(),
//                                        2, &fuse_test::pre_hash_share_[0]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  success = fuse_test::CreateRandomFile(fuse_test::test_share_[1].string(),
//                                        10, &fuse_test::pre_hash_share_[1]);
//  boost::this_thread::sleep(boost::posix_time::seconds(5));
//  success = fuse_test::CreateRandomFile(fuse_test::test_share_[2].string(),
//                                        100, &fuse_test::pre_hash_share_[2]);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  success = fuse_test::CreateRandomFile(fuse_test::test_share_[3].string(),
//                                        100, &fuse_test::pre_hash_share_[3]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  success = fuse_test::CreateRandomFile(fuse_test::test_share_[4].string(),
//                                        100, &fuse_test::pre_hash_share_[4]);
//  boost::this_thread::sleep(boost::posix_time::seconds(60));
//  for (int i = 0; i < 5; ++i) {
//    ASSERT_EQ(fuse_test::pre_hash_share_[i],
//              se.SHA512(fuse_test::test_share_[i]));
//    boost::this_thread::sleep(boost::posix_time::seconds(5));
//  }


  // 03. Logout, then login as user 2.
  // ---------------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsm_, &mount_path_);
#endif
  printf("User 2 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());


  // 04. Check /Shares/Private is empty & /Shares/Anon has 5 files.
  // --------------------------------------------------------------
// TODO(Fraser#5#): 2009-07-05 - Find out why directory_itr causes segfault
//  fs::directory_iterator end_itr;
//  printf("Here 3\n");
//  int file_count(0);
//  printf("Here 4\n");
//  for (fs::directory_iterator itr(test_root); itr != end_itr; ++itr) {
//    printf("Here 5\n");
//    ++file_count;
//    boost::this_thread::sleep(boost::posix_time::seconds(10));
//  }
//  printf("In My Files, file count = %i\n", file_count);
//  ASSERT_EQ(0, file_count);
//  test_root = kRoot;
//  test_root /= kSharesSubdir[0][0];
//  for (fs::directory_iterator itr(test_root); itr != end_itr; ++itr) {
//    ++file_count;
//  }
//  printf("In Shares/Private, file count = %i\n", file_count);
//  ASSERT_EQ(0, file_count);

// *********************************************
// Anonymous Shares are disabled at the moment *
// *********************************************
//  for (int i = 0; i < 5; ++i) {
//    printf("Checking file %i\n", i);
//    ASSERT_TRUE(fs::exists(fuse_test::test_share_[i]));
//    boost::this_thread::sleep(boost::posix_time::seconds(10));
//    printf("pre_hash[%i] = %s\n", i, fuse_test::pre_hash_share_[i].c_str());
//    std::string hash = se.SHA512(fuse_test::test_share_[i]);
//    printf("se.SHA512(fuse_test::test_share_[%i]) = %s\n",
//           i,
//           hash.c_str());
//    ASSERT_EQ(fuse_test::pre_hash_share_[i], hash);
//  }


  // 05. Create a private share with user 1 (admin rights) & user 3 (r-o rights)
  // ---------------------------------------------------------------------------
// // TODO(Fraser#5#): 2009-07-03 - Uncomment following code
//  test_root = kRoot;
//  // try to write files and dirs to "/Shares/Private" dir without first
//  // creating a private share via clientcontroller
//  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
//  fs::path test_dir_(test_root);
//  test_dir_ /= "TestDir";
//  fs::path test_txt_(test_root);
//  test_txt_ /= "test.txt";
//  success = false;
//  try {
//    printf("Trying to create %s\n", test_dir_.string().c_str());
//    ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
//    fs::create_directory(test_dir_);
//    boost::this_thread::sleep(boost::posix_time::seconds(30));
//  }
//  catch(const std::exception &e) {
//    printf("%s\n", e.what());
//  }
//  try {
//    printf("Checking dir's existence.\n");
//    success = (fs::exists(test_dir_));
//  }
//  catch(const std::exception &e) {
//    printf("%s\n", e.what());
//  }
//  boost::this_thread::sleep(boost::posix_time::seconds(30));
//  ASSERT_FALSE(success);
//  printf("Trying to create %s\n", test_txt_.string().c_str());
//  std::string file_hash_("");
//  success = fuse_test::CreateRandomFile(test_txt_.string(), 2, &file_hash_);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
// // TODO(Fraser#5#): 2009-07-03 - Uncomment following line
// //  ASSERT_FALSE(success);

  boost::this_thread::sleep(boost::posix_time::seconds(20));
  std::string share_name = "TestShare";
  std::set<std::string> admins, readonlys;
  admins.insert(public_username1_);
  readonlys.insert(public_username3_);
  ASSERT_TRUE(cc_->AuthoriseUsers(admins));
  ASSERT_TRUE(cc_->AuthoriseUsers(readonlys));
  test_root = kRoot;
  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_EQ(0, cc_->CreateNewShare(share_name, admins, readonlys));
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  test_root /= share_name;  // /Shares/Private/TestShare/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));


  // 06. Save 5 files to 2 subdirs in new share.
  // -------------------------------------------
  test_dir_0 = test_root;
  test_dir_0 /= "TestDir0";
  test_dir_1 = test_dir_0;
  test_dir_1 /= "TestDir1";
  for (int i = 0; i < 3; ++i)
    fuse_test::test_share_.push_back(test_root);
  fuse_test::test_share_[5] /= "test0.txt";
  fuse_test::test_share_[6] /= "test1.txt";
  fuse_test::test_share_[7] /= "test2.txt";
  fuse_test::test_share_.push_back(test_dir_0);
  fuse_test::test_share_.push_back(test_dir_1);
  fuse_test::test_share_[8] /= "test3.txt";
  fuse_test::test_share_[9] /= "test4.txt";
  for (int i = 0; i < 5; ++i)
    fuse_test::pre_hash_share_.push_back("");
  success = false;
  try {
    ASSERT_TRUE(fs::create_directory(test_dir_0)) << "Couldn't create " <<
        test_dir_0;
    boost::this_thread::sleep(boost::posix_time::seconds(30));
    success = (fs::exists(test_dir_0));
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_TRUE(success);
  success = false;
  try {
    ASSERT_TRUE(fs::create_directory(test_dir_1)) << "Couldn't create " <<
        test_dir_1;
    boost::this_thread::sleep(boost::posix_time::seconds(30));
    success = (fs::exists(test_dir_1));
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  ASSERT_TRUE(success);
  success = false;
  printf("Trying to create %s\n", fuse_test::test_share_[5].string().c_str());
  success = fuse_test::CreateRandomFile(fuse_test::test_share_[5].string(),
                                         2, &fuse_test::pre_hash_share_[5]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  success = fuse_test::CreateRandomFile(fuse_test::test_share_[6].string(),
                                         10, &fuse_test::pre_hash_share_[6]);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  success = fuse_test::CreateRandomFile(fuse_test::test_share_[7].string(),
                                         100, &fuse_test::pre_hash_share_[7]);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  success = fuse_test::CreateRandomFile(fuse_test::test_share_[8].string(),
                                         100, &fuse_test::pre_hash_share_[8]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  success = fuse_test::CreateRandomFile(fuse_test::test_share_[9].string(),
                                         100, &fuse_test::pre_hash_share_[9]);
  boost::this_thread::sleep(boost::posix_time::seconds(60));

  maidsafe::SelfEncryption se;
  for (int i = 5; i < 10; ++i) {
    ASSERT_EQ(fuse_test::pre_hash_share_[i],
              se.SHA512(fuse_test::test_share_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(5));
  }


  // 07. Logout, then login as user 3.
  // ---------------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username3_, pin_, password_,
                                  public_username3_, fsm_, &mount_path_);
#endif
  printf("User 3 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());
  // Get messages to add share
  ASSERT_TRUE(cc_->GetMessages());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  std::list<packethandler::InstantMessage> messages;
  packethandler::InstantMessage im;
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(static_cast<unsigned int>(3), messages.size());
  // message 1 from user 2 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username2_, im.sender());
  // message 2 from user 1 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username1_, im.sender());
  // message 3 from user 2 notifying of share
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username2_, im.sender());
  ASSERT_TRUE(im.has_privateshare_notification());
  test_root = kRoot;
  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_EQ(0, cc_->HandleReceivedShare(im.privateshare_notification(), ""));
  boost::this_thread::sleep(boost::posix_time::seconds(30));


  // 08. Check /Shares/Private has files and that they are read-only.
  // ----------------------------------------------------------------
  for (int i = 5; i < 10; ++i) {
    printf("Checking file %i\n", i);
    ASSERT_TRUE(fs::exists(fuse_test::test_share_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    printf("pre_hash[%i] = %s\n", i, fuse_test::pre_hash_share_[i].c_str());
    std::string hash = se.SHA512(fuse_test::test_share_[i]);
    printf("se.SHA512(fuse_test::test_share_[%i]) = %s\n",
           i,
           hash.c_str());
    ASSERT_EQ(fuse_test::pre_hash_share_[i], hash);
    // TODO(Fraser#5#): 2009-07-16 - Uncomment two checks below:-
//    ASSERT_FALSE(fs::remove(fuse_test::test_share_[i]));
//    success = false;
//    try {
//      fs::rename(fuse_test::test_share_[i], fs::path("renamed.txt"));
//      success = true;
//    }
//    catch(const std::exception&) {}
//    ASSERT_FALSE(success);
  }


  // 09. Logout then login as user 1.
  // --------------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

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
  printf("User 1 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());
  // Get messages to add share
  ASSERT_TRUE(cc_->GetMessages());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(static_cast<unsigned int>(3), messages.size());
  // message 1 from user 3 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username3_, im.sender());
  // message 2 from user 2 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username2_, im.sender());
  // message 3 from user 2 notifying of share
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username2_, im.sender());
  ASSERT_TRUE(im.has_privateshare_notification());
  test_root = kRoot;
  test_root /= kRootSubdir[0][0];  // /My Files/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  test_root = kRoot;
  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_EQ(0, cc_->HandleReceivedShare(im.privateshare_notification(), ""));
  boost::this_thread::sleep(boost::posix_time::seconds(30));


  // 10. Check /Shares/Private has files and that they can be modified.
  // ------------------------------------------------------------------
  for (int i = 5; i < 10; ++i) {
    printf("Checking file %i\n", i);
    ASSERT_TRUE(fs::exists(fuse_test::test_share_[i]));
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    printf("pre_hash[%i] = %s\n", i, fuse_test::pre_hash_share_[i].c_str());
    std::string hash = se.SHA512(fuse_test::test_share_[i]);
    printf("se.SHA512(fuse_test::test_share_[%i]) = %s\n",
           i,
           hash.c_str());
    ASSERT_EQ(fuse_test::pre_hash_share_[i], hash);
  }
  test_root = kRoot;
  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
  test_root /= share_name;  // /Shares/Private/TestShare/
  test_dir_0 = test_root;
  test_dir_0 /= "TestDir0";
  test_dir_1 = test_dir_0;
  fs::path new_test_dir_1(test_dir_0);
  test_dir_1 /= "TestDir1";
  new_test_dir_1 /= "RenamedTestDir1";
  fs::path new_test_file_5(test_root);
  new_test_file_5 /= "renamed_test0.txt";
  fs::path new_test_file_9(new_test_dir_1);
  new_test_file_9 /= "test4.txt";
  success = false;
  try {
    fs::rename(test_dir_1, new_test_dir_1);
    success = true;
  }
  catch(const std::exception&) {}
  ASSERT_TRUE(success);
  success = false;
  try {
    fs::rename(fuse_test::test_share_[5], new_test_file_5);
    boost::this_thread::sleep(boost::posix_time::seconds(30));
    success = true;
  }
  catch(const std::exception&) {}
  ASSERT_TRUE(success);
  success = false;
  try {
    printf("Trying to delete %s\n", fuse_test::test_share_[6].string().c_str());
    ASSERT_TRUE(fs::exists(fuse_test::test_share_[6]));
    printf("%s exists OK.\n", fuse_test::test_share_[6].string().c_str());
    // TODO(Fraser#5#): 2009-07-23 - Uncomment lines below
//    fs::remove(fuse_test::test_share_[6]);
//    boost::this_thread::sleep(boost::posix_time::seconds(30));
    success = true;
  }
  catch(const std::exception&) {}
  ASSERT_TRUE(success);
  // TODO(Fraser#5#): 2009-07-23 - Uncomment line below
//  ASSERT_FALSE(fs::exists(fuse_test::test_share_[6]));


  // 11. Send user 2 a message and file (with message = hash of file).
  // -----------------------------------------------------------------
  const std::string kTestMessage("Test message");
  fs::path test_path(base::TidyPath(kSharesSubdir[0][0]));
  test_path /= share_name;
  test_path /= "/test2.txt";
  std::string test_file(test_path.string());
  ASSERT_EQ(0, cc_->SendInstantFile(&test_file,
                                    kTestMessage, public_username2_));
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  ASSERT_EQ(0, cc_->SendInstantMessage(fuse_test::pre_hash_share_[7],
                                       public_username2_));
  boost::this_thread::sleep(boost::posix_time::seconds(30));


  // 12. Logout then login as user 2.
  // --------------------------------
#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");

#ifdef MAIDSAFE_WIN32
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, &mount_path_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsl_, &mount_path_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::CreateUserLoginMount(cc_, ss_, username2_, pin_, password_,
                                  public_username2_, fsm_, &mount_path_);
#endif
  printf("User 2 logged in.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(mount_path_)) << "Drive " << mount_path_ <<
      "didn't mount." << std::endl;
  printf("Mount path = %s\n", mount_path_.string().c_str());


  // 13. Check shared files reflect user 1's modifications.
  // ------------------------------------------------------
  // Check modifications to file 5
  test_root = kRoot;
  test_root /= kSharesSubdir[0][0];  // /Shares/Private/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  test_root /= share_name;  // /Shares/Private/TestShare/
  ASSERT_TRUE(fs::exists(test_root)) << test_root << " doesn't exist.";
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Checking modified file 5 (%s)\n", new_test_file_5.string().c_str());
  ASSERT_FALSE(fs::exists(fuse_test::test_share_[5]));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(new_test_file_5));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("pre_hash[5] = %s\n", fuse_test::pre_hash_share_[5].c_str());
  hash = se.SHA512(new_test_file_5);
  printf("se.SHA512(new_test_file_5) = %s\n", hash.c_str());
  ASSERT_EQ(fuse_test::pre_hash_share_[5], hash);

  // Check deletion of file 6
  printf("Checking modified file 6\n");
  // TODO(Fraser#5#): 2009-07-23 - Uncomment lines below
//  ASSERT_FALSE(fs::exists(fuse_test::test_share_[6]));
//  boost::this_thread::sleep(boost::posix_time::seconds(10));

  // Check file 7 is unmodified
  printf("Checking file 7\n");
  ASSERT_TRUE(fs::exists(fuse_test::test_share_[7]));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("pre_hash[7] = %s\n", fuse_test::pre_hash_share_[7].c_str());
  hash = se.SHA512(fuse_test::test_share_[7]);
  printf("se.SHA512(fuse_test::test_share_[7]) = %s\n", hash.c_str());
  ASSERT_EQ(fuse_test::pre_hash_share_[7], hash);

  // Check file 8 is unmodified
  printf("Checking file 8\n");
  ASSERT_TRUE(fs::exists(fuse_test::test_share_[8]));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("pre_hash[8] = %s\n", fuse_test::pre_hash_share_[8].c_str());
  hash = se.SHA512(fuse_test::test_share_[8]);
  printf("se.SHA512(fuse_test::test_share_[8]) = %s\n", hash.c_str());
  ASSERT_EQ(fuse_test::pre_hash_share_[8], hash);

  // Check modifications to "TestDir1" affecting file 9
  printf("Checking modified file 9\n");
  ASSERT_FALSE(fs::exists(fuse_test::test_share_[9]));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  ASSERT_TRUE(fs::exists(new_test_file_9));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  printf("pre_hash[9] = %s\n", fuse_test::pre_hash_share_[9].c_str());
  hash = se.SHA512(new_test_file_9);
  printf("se.SHA512(new_test_file_9) = %s\n", hash.c_str());
  ASSERT_EQ(fuse_test::pre_hash_share_[9], hash);


  // 14. Check file and message have been received correctly.
  // --------------------------------------------------------
  printf("Gettimg messages.\n");
  // Get messages to add share
  ASSERT_TRUE(cc_->GetMessages());
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(static_cast<unsigned int>(4), messages.size());
  // message 1 from user 3 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username3_, im.sender());
  // message 2 from user 1 requesting add contact
  im = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username1_, im.sender());
  // message 3 from user 1 notifying of file transfer
  packethandler::InstantMessage im1, im2;
  im1 = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username1_, im1.sender());
  std::string recvd_message = kTestMessage + " - Filename: test2.txt";
  ASSERT_EQ(recvd_message, im1.message());
  ASSERT_TRUE(im1.has_instantfile_notification());
  ASSERT_EQ(0, cc_->AddInstantFile(im1.instantfile_notification(), ""));
  // File sent should be "/My Files/test2.txt"
  fs::path test_sent_file(kRoot);
  test_sent_file /= kRootSubdir[0][0];
  test_sent_file /= "test2.txt";
  ASSERT_TRUE(fs::exists(test_sent_file));
  hash = se.SHA512(test_sent_file);
  printf("se.SHA512(test_sent_file) = %s\n", hash.c_str());
  // message 4 from user 1 - instant message
  im2 = messages.front();
  messages.pop_front();
  ASSERT_EQ(public_username1_, im2.sender());
  ASSERT_EQ(hash, im2.message());

#ifdef MAIDSAFE_WIN32
  fuse_test::UnmountAndLogout(cc_, ss_);
#elif defined(MAIDSAFE_POSIX)
  fuse_test::UnmountAndLogout(cc_, fsl_);
#elif defined(MAIDSAFE_APPLE)
  fuse_test::UnmountAndLogout(cc_, fsm_);
#endif
  ASSERT_FALSE(fs::exists(mount_path_));
  printf("Logged out\n--------------------------------------------------\n\n");
//  fuse_test::test_share_.clear();
//  fuse_test::pre_hash_share_.clear();
}

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
      new localvaults::Env(fs_l_fuse::fuse_test::kNetworkSize_,
                           fs_l_fuse::fuse_test::kTestK_,
                           &fs_l_fuse::fuse_test::pdvaults_));
#endif
  return RUN_ALL_TESTS();
}
