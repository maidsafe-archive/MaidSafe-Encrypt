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

#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <gtest/gtest.h>
#include <maidsafe/base/utils.h>
#include <maidsafe/encrypt/selfencryption.h>

#include <list>
#include <string>
#include <vector>

#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/client/clientutils.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/sharedtest/networktest.h"


namespace fs = boost::filesystem;

namespace test_cc {

#ifdef MS_NETWORK_TEST
void Sleep(const int &millisecs) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(millisecs));
#else
void Sleep(const int&) {
#endif
}

}  // namespace test_cc

namespace maidsafe {

namespace test {

class ClientControllerTest : public testing::Test {
 public:
  ClientControllerTest()
      : network_test_("CC"),
        cc_(ClientController::getInstance()),
        ss_(SessionSingleton::getInstance()),
        sm_(network_test_.store_manager()),
        vcp_() {}
 protected:
  void SetUp() {
    ss_->ResetSession();
    ASSERT_TRUE(network_test_.Init());
#ifdef MS_NETWORK_TEST
    cc_->client_chunkstore_ = network_test_.chunkstore();
    cc_->sm_ = sm_;
    cc_->auth_.Init(sm_);
    cc_->ss_ = ss_;
    cc_->initialised_ = true;
#else
    cc_->Init(network_test_.K());
#endif
    vcp_.space = 1000000;
    vcp_.directory = (network_test_.test_dir() / "VaultChunkstore").string();
  }
  void TearDown() {
#ifndef MS_NETWORK_TEST
    cc_->CloseConnection(true);
    cc_->Destroy();
#endif
  }

  NetworkTest network_test_;
  ClientController *cc_;
  SessionSingleton *ss_;
  boost::shared_ptr<TestStoreManager> sm_;
  VaultConfigParameters vcp_;
 private:
  ClientControllerTest(const ClientControllerTest&);
  ClientControllerTest &operator=(const ClientControllerTest&);
};

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_LoginSequence) {
  std::string username("User1");
  std::string pin("1234");
  std::string password("The beagle has landed.");
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Preconditions fulfilled.\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));

  {
    boost::progress_timer t;
    ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
    ASSERT_EQ(username, ss_->Username());
    ASSERT_EQ(pin, ss_->Pin());
    ASSERT_EQ(password, ss_->Password());
    printf("User created, time: ");
  }

//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.");

  printf("\n\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));

  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.");

  printf("\n\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.");

  printf("\n\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_NE(kUserExists, cc_->CheckUserExists("juan.smer", pin, kDefCon3));
  printf("Can't log in with fake details.\n");
}

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_ChangeDetails) {
  std::string username("User2");
  std::string pin("2345");
  std::string password("The axolotl has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Changed username.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.\n");
  ASSERT_TRUE(cc_->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Changed pin.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207", kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("Logged in.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ("elpasguor", ss_->Password());
  printf("Changed password.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207", kDefCon3));
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc_->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss_->Username());
  ASSERT_EQ("2207", ss_->Pin());
  ASSERT_EQ("elpasguor", ss_->Password());
  printf("Logged in. New u/p/w.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
//  boost::this_thread::sleep(boost::posix_time::seconds(15));

  ASSERT_EQ(kUserExists, cc_->CheckUserExists("juan.smer", "2207", kDefCon3));
  ASSERT_FALSE(cc_->ValidateUser(password))
               << "old details still work, damn it, damn the devil to hell";
  ss_->ResetSession();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Can't log in with old u/p/w.\n");
}

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_CreatePubUsername) {
  std::string username("User3");
  std::string pin("3456");
  std::string password("The fanjeeta has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_FALSE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username already created.\n");

  ASSERT_TRUE(cc_->GetMessages());
  std::list<InstantMessage> messages;
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
}

/*
TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_LeaveNetwork) {
  std::string username ("User4");
  std::string pin("4567");
  std::string password("The chubster has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Preconditions fulfilled.\n");

  ASSERT_NE(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  test_cc::Sleep(30000);
  printf("User created.\n=============\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  test_cc::Sleep(60));
  printf("Logged out.\n===========\n\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  test_cc::Sleep(30000);
  printf("Logged in.\n==========\n\n");

  ASSERT_TRUE(cc_->LeaveMaidsafeNetwork());
  test_cc::Sleep(60));
  printf("Left maidsafe ='(.\n==================\n\n");

  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("User no longer exists.\n======================\n\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  test_cc::Sleep(30000);
  printf("User created again.\n===================\n\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n===========\n\n");
}

*/

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_BackupFile) {
  std::string username("User5");
  std::string pin("5678");
  std::string password("The limping dog has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
                         kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "testencryption.txt";
  std::string rel_str_ = TidyPath(rel_path.string());

  fs::path full_path(file_system::MaidsafeHomeDir(ss_->SessionName()));
  full_path /= rel_path;
  fs::ofstream testfile(full_path.string().c_str());
  testfile << base::RandomAlphaNumericString(1024 * 1024);
  testfile.close();
  std::string hash_original_file = SHA512File(full_path);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->write(rel_str_));
    printf("File backed up in ");
  }

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out user.\n\n");

  if (fs::exists(full_path))
    fs::remove(full_path);

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User logged in.\n");
  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
                         kRootSubdir[0][0]);

  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->read(rel_str_));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = SHA512File(full_path);
  ASSERT_EQ(hash_original_file, hash_dec_file);

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out user.\n");
}

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_SaveSession) {
  // Create a user
  std::string username("User5andAhalf");
  std::string pin("55678");
  std::string password("That pair should have its own television show.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");
  std::string pmid_name;
  ASSERT_EQ(kSuccess, ss_->ProxyMID(&pmid_name, NULL, NULL, NULL));
  // Create a file
  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
                         kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  rel_path /= "testencryption.txt";
  std::string rel_str = TidyPath(rel_path.string());

  fs::path full_path(file_system::MaidsafeHomeDir(ss_->SessionName()));
  full_path /= rel_path;
  fs::ofstream testfile(full_path.string().c_str());
  testfile << base::RandomAlphaNumericString(1024 * 1024);
  testfile.close();
  std::string hash_original_file = SHA512File(full_path);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->write(rel_str));
    printf("File backed up in ");
  }

  // Save the session
  ASSERT_EQ(0, cc_->SaveSession());
  printf("\n\n\nSaved the session\n\n\n");
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  // Reset the client controller
  /*
  printf("Client controller address before: %d\n", cc_);
  cc_ = NULL;
  cc_ = ClientController::getInstance();
  printf("Client controller address after: %d\n", cc_);
  */
  network_test_.chunkstore()->Clear();
  printf("\n\n\nCleared the chunkstore\n\n\n");
  ss_->ResetSession();
  printf("\n\n\nReset the session\n\n\n");

  // Remove the local file
  if (fs::exists(full_path))
      fs::remove(full_path);

  // Login
  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("\n\n\nChecked for user\n\n\n");
  ASSERT_TRUE(cc_->ValidateUser(password));
  printf("\n\n\nLogged in\n\n\n");
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  std::string recovered_pmid_name;
  ASSERT_EQ(kSuccess, ss_->ProxyMID(&recovered_pmid_name, NULL, NULL, NULL));
  ASSERT_EQ(pmid_name, recovered_pmid_name);
//  ASSERT_EQ(pmid, ss_->PublicKey(passport::PMID));
//  ASSERT_EQ(pmid, ss_->PrivateKey(passport::PMID));
//  ASSERT_EQ(pmid, ss_->Signed(passport::PMID));


  // Check for file
  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
                         kRootSubdir[0][0]);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc_->read(rel_str));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = SHA512File(full_path);
  ASSERT_EQ(hash_original_file, hash_dec_file);
  printf("Hashes match\n");

  // Log out
  ASSERT_TRUE(cc_->Logout());
  printf("Logged out\n");

  // Clean up
  // Delete file
  if (fs::exists(full_path))
      fs::remove(full_path);
}

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_ContactAddition) {
  std::string username("User6");
  std::string pin("6789");
  std::string password("The deleted folder has landed.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  std::string public_username("el.mambo.nalga");
  ASSERT_TRUE(cc_->CreatePublicUsername(public_username));
  ASSERT_EQ(public_username, ss_->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  std::string username1("User61");
  std::string pin1("67891");
  std::string password1("The deleted folder has landed.1");
  std::string public_username1("el.mambo.nalga1");

  ASSERT_TRUE(cc_->CreateUser(username1, pin1, password1, vcp_));
  ASSERT_EQ(username1, ss_->Username());
  ASSERT_EQ(pin1, ss_->Pin());
  ASSERT_EQ(password1, ss_->Password());
  printf("User1 created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername(public_username1));
  ASSERT_EQ(public_username1, ss_->PublicUsername());
  printf("Public Username 1 created.\n");

  ASSERT_EQ(0, cc_->AddContact(public_username));
  printf("Public Username 1 added Public Username.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out 1.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ(public_username, ss_->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc_->GetMessages());
  std::list<InstantMessage> messages;
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  InstantMessage im = messages.front();
  ASSERT_TRUE(im.has_contact_notification());
  ASSERT_EQ(public_username1, im.sender());
  ASSERT_EQ("\"" + public_username1 +
            "\" has requested to add you as a contact.", im.message());
  ContactNotification cn = im.contact_notification();
  ASSERT_EQ(0, cn.action());
  ContactInfo ci;
  if (cn.has_contact())
    ci = cn.contact();
  printf("Putisisisisisiisisisisisiisma chingadisisisisisisisisisisima "
         "madreeeeeeeeeeeeee.\n");
  ASSERT_EQ(0, cc_->HandleAddContactRequest(ci, im.sender()));
  ASSERT_FALSE(ss_->GetContactPublicKey(public_username1).empty());
  printf("Public Username confirmed Public Username 1.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username1, pin1, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password1));
  ASSERT_EQ(username1, ss_->Username());
  ASSERT_EQ(pin1, ss_->Pin());
  ASSERT_EQ(password1, ss_->Password());
  ASSERT_EQ(public_username1, ss_->PublicUsername());
  printf("Logged in 1.\n");

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  InstantMessage im1 = messages.front();
  ASSERT_TRUE(im1.has_contact_notification());
  ASSERT_EQ(public_username, im1.sender());
  ASSERT_EQ("\"" + public_username + "\" has confirmed you as a contact.",
            im1.message());
  ContactNotification cn1 = im1.contact_notification();
  ASSERT_EQ(1, cn1.action());
  ContactInfo ci1;
  if (cn1.has_contact())
    ci1 = cn1.contact();
  ASSERT_EQ(0, cc_->HandleAddContactResponse(ci1, im1.sender()));
  printf("Public Username 1 received Public Username confirmation.\n");

  std::string text_msg("The arctic trails have their secret tales");
  std::vector<std::string> contact_names;
  contact_names.push_back(public_username);
  ASSERT_EQ(0, cc_->SendInstantMessage(text_msg, contact_names, ""));
  printf("Public Username 1 sent txt message  to Public Username.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out 1.\n");

  ASSERT_EQ(kUserExists, cc_->CheckUserExists(username, pin, kDefCon3));
  ASSERT_TRUE(cc_->ValidateUser(password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  ASSERT_EQ(public_username, ss_->PublicUsername());

  ASSERT_TRUE(cc_->GetMessages());
  messages.clear();
  ASSERT_EQ(0, cc_->GetInstantMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  InstantMessage im2 = messages.front();
  ASSERT_FALSE(im2.has_contact_notification());
  ASSERT_FALSE(im2.has_instantfile_notification());
  ASSERT_FALSE(im2.has_privateshare_notification());
  ASSERT_EQ(public_username1, im2.sender());
  ASSERT_EQ(text_msg, im2.message());

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");
}

/*
TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_Shares) {
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss_->PublicUsername());
  printf("Public Username created.\n");

  std::set<std::string> auth_users;
  std::string users[3] = {"el.dan.liiiiiisto", "es tu", "padre"};
  for (int n=0; n<3 ; n++)
    auth_users.insert(users[n]);

  ASSERT_TRUE(cc_->AuthoriseUsers(auth_users));
  std::set<std::string> local_set = ss_->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p==users[0] || *p==users[1] || *p==users[2])
      << "User missing";
  printf("Authorised 3 users.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_->CreateUser("smer","7777","palofeo", vcp_));
  ASSERT_TRUE(ss_->Username() == "smer");
  ASSERT_TRUE(ss_->Pin() == "7777");
  ASSERT_TRUE(ss_->Password() == "palofeo");
  printf("User created.\n");

  ASSERT_TRUE(cc_->CreatePublicUsername("el.dan.liiiiiisto"));
  ASSERT_TRUE(ss_->PublicUsername() == "el.dan.liiiiiisto");
  printf("Public Username created.\n");

  std::string path = file_system::getInstance()->HomeDir() +
                     "/testencryption.txt";
  fs::path path_(path);
  fs::ofstream testfile(path.c_str());
  testfile << base::RandomAlphaNumericString(1024 * 1024);
  testfile.close();
  std::string hash_original_file = self_encryption.SHA512(path_);
  ASSERT_TRUE(cc_->BackupElement(path));
  while(ss_->SelfEncrypting())
    test_cc::Sleep(100));
  OutputProcessedJobs(cc);
  printf("File backed up.\n");

  std::vector<std::string> paths, share_users;
  std::string ms_path = path;
  ms_path.erase(0,
                file_system::getInstance()->HomeDir().size());
  paths.push_back(ms_path);
  share_users.push_back("el.mambo.tonnnnnto");
  ASSERT_TRUE(cc_->CreateShare(paths,share_users,"fotos puercas"));
  printf("Created share.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  ASSERT_TRUE(cc_->Start(username, pin, password));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User logged in.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out.\n");

  if (fs::exists(path))
    fs::remove(fs::path(path));
}
*/

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_FuseFunctions) {
  std::string username("User7");
  std::string pin("7890");
  std::string password("The pint of lager has landed on the floor.");
  ss_ = SessionSingleton::getInstance();
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  ASSERT_EQ(kUserDoesntExist, cc_->CheckUserExists(username, pin, kDefCon3));
  printf("Preconditions fulfilled.\n");

  ASSERT_TRUE(cc_->CreateUser(username, pin, password, vcp_));
  ASSERT_EQ(username, ss_->Username());
  ASSERT_EQ(pin, ss_->Pin());
  ASSERT_EQ(password, ss_->Password());
  printf("User created.\n");

  fs::create_directories(file_system::MaidsafeHomeDir(ss_->SessionName()) /
      kRootSubdir[0][0]);
  fs::path rel_path(kRootSubdir[0][0]);
  fs::path testfile[15];
  fs::path homedir(file_system::HomeDir());
  fs::path mshomedir(file_system::MaidsafeHomeDir(ss_->SessionName()));
  // fs::path newdir = homedir / "NewDir";
  // fs::path msnewdir = mshomedir / "NewDir";
  fs::path my_files(TidyPath(kRootSubdir[0][0]));
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
      ASSERT_EQ(0, cc_->mkdir(temp_path));
    } else {
      std::string full_ = mshomedir.string()+"/"+temp_path;
      fs::ofstream testfile(full_.c_str());
      testfile.close();
      ASSERT_EQ(0, cc_->mknod(temp_path));
    }
    // printf("Creating element [%i]: %s\n", i, temp_path);
  }

  fs::path newdirtest2_ = insidenewdir / "testdir1/dansdir";
  temp_path = newdirtest2_.string();
  ASSERT_NE(0, cc_->mkdir(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible directory.\n");
  fs::path newfiletest3_ = insidenewdir / "testdir/lapuercota.jpg";
  temp_path = newfiletest3_.string();
  ASSERT_NE(0, cc_->mknod(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible file.\n");

  temp_path = testfile[1].string();
  fs::path temp_b_path = insidenewdir / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc_->rename(temp_path, temp_path1)) << "file rename failed";
  printf("Renamed file.\n");


  temp_path = testfile[10].string();
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc_->rename(temp_path, temp_path1)) << "directory rename failed";
  printf("Renamed directory.\n");
  testfile[10] = temp_b_path.string();

  temp_path = testfile[2].string();
  temp_b_path = insidenewdir / "nonexistent" / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc_->rename(temp_path, temp_path1))
            << "impossible file rename failed";
  printf("Didn't rename existent file to impossible one.\n");

  temp_path = testfile[13].string();
  temp_b_path = deepinsidenewdir / "nonexistent" /
                    "renamed_reallydeepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc_->rename(temp_path, temp_path1))
            << "impossible directory rename failed";
  printf("Didn't rename existent directory to impossible one.\n");

  temp_path = testfile[13].string();
  ASSERT_NE(0, cc_->rmdir(temp_path)) << "remove non-empty directory failed";
  printf("Doesn't remove non-empty directory.\n");

  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" /
                "reallydeepinsidenewdir" / "file9";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  printf("Removed file.\n");

  temp_b_path = temp_b_path.parent_path();
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->rmdir(temp_path)) << "remove directory failed";
  printf("Removed directory.\n");

  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file8";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file7";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->unlink(temp_path)) << "remove stupid dir failed";
  printf("Recursively removed directory and its content.\n");

  std::string o_path = testfile[8].string();
  fs::path ppp = startdir / "file6";
  std::string n_path = ppp.string();
  ASSERT_EQ(0, cc_->link(o_path, n_path));
  printf("\nCopied file %s to %s\n", o_path.c_str(), n_path.c_str());
  o_path = testfile[9].string();
  fs::path ppp1 = startdir / "dirA";
  n_path = ppp1.string();
  ASSERT_EQ(0, cc_->cpdir(o_path, n_path));
  printf("Copied directory.\n");

  temp_b_path = startdir;
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc_->utime(temp_path));
  printf("Changed the last modification time to directory.\n");

  ASSERT_TRUE(cc_->Logout());
  ASSERT_TRUE(ss_->Username().empty());
  ASSERT_TRUE(ss_->Pin().empty());
  ASSERT_TRUE(ss_->Password().empty());
  printf("Logged out user.\n");
}

TEST_MS_NET(ClientControllerTest, BEH, MAID, CC_HandleMessages) {
  int total_msgs(5);
  boost::uint32_t now(base::GetEpochTime());
  std::list<ValidatedBufferPacketMessage> valid_messages;
  ValidatedBufferPacketMessage vbpm;
  InstantMessage im;
  for (int n = 0; n < total_msgs; ++n) {
    vbpm.Clear();
    im.Clear();
    vbpm.set_sender("nalga");
    vbpm.set_index("aaaaaaaaaaaaaaaaaaa");
    vbpm.set_type(INSTANT_MSG);
    vbpm.set_timestamp(now);
    im.set_sender("nalga");
    im.set_message("que nalgotas!!");
    im.set_date(now);
    vbpm.set_message(im.SerializeAsString());
    valid_messages.push_back(vbpm);
  }

  ASSERT_EQ(0, cc_->HandleMessages(&valid_messages));
  ASSERT_EQ(size_t(1), cc_->instant_messages_.size());
}

TEST_MS_NET(ClientControllerTest, FUNC, MAID, CC_ClearStaleMessages) {
  size_t total_msgs(5);
  boost::thread thr(&ClientController::ClearStaleMessages, cc_);
  boost::uint32_t now(base::GetEpochTime());
  std::list<ValidatedBufferPacketMessage> valid_messages;
  ValidatedBufferPacketMessage vbpm;
  InstantMessage im;
  for (size_t n = 0; n < total_msgs; ++n) {
    vbpm.Clear();
    im.Clear();
    vbpm.set_sender("nalga");
    vbpm.set_index(base::IntToString(n));
    vbpm.set_type(INSTANT_MSG);
    vbpm.set_timestamp(now);
    im.set_sender("nalga");
    im.set_message("que nalgotas!!");
    im.set_date(now);
    vbpm.set_message(im.SerializeAsString());
    valid_messages.push_back(vbpm);
  }

  ASSERT_EQ(0, cc_->HandleMessages(&valid_messages));
  ASSERT_EQ(total_msgs, cc_->instant_messages_.size());
  ASSERT_EQ(total_msgs, cc_->received_messages_.size());
  printf("Before sleep to wait for message clear.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(21));
  printf("After sleep to wait for message clear.\n");
  ASSERT_EQ(size_t(0), cc_->received_messages_.size());
  cc_->logging_out_ = true;
  thr.join();
}

}  // namespace test

}  // namespace maidsafe
