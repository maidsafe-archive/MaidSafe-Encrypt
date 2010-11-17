/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Unit tests for Authentication
* Version:      1.0
* Created:      2009-01-29-03.19.59
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

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/maidsafe_messages.pb.h"
#include "maidsafe/common/maidsafe_service_messages.pb.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/filesystem/dataatlashandler.h"
#include "maidsafe/encrypt/datamap.pb.h"
#include "maidsafe/sharedtest/testcallback.h"
#include "maidsafe/sharedtest/networktest.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace test {

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest() : network_test_(),
                         ss_(SessionSingleton::getInstance()),
                         sm_(network_test_.store_manager()),
                         authentication_(),
                         username_("user"),
                         pin_("1234"),
                         password_("password1"),
                         test_keys_() {}
 protected:
  void SetUp() {
    ss_->ResetSession();
    ASSERT_TRUE(network_test_.Init());
    authentication_.Init(sm_);
    ss_ = SessionSingleton::getInstance();
    ss_->ResetSession();
  }

  NetworkTest network_test_;
  SessionSingleton *ss_;
  boost::shared_ptr<TestStoreManager> sm_;
  Authentication authentication_;
  std::string username_;
  std::string pin_;
  std::string password_;
  std::vector<crypto::RsaKeyPair> test_keys_;
 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_MS_NET(AuthenticationTest, FUNC, MAID, CreateUserSysPackets) {
  username_ += "01";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, GoodLogin) {
  username_ += "02";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  std::string ser_dm_login;
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Unable to get registered user's data";
  ASSERT_EQ(ser_dm, ser_dm_login) <<
            "Serialised DA recovered from login empty string";
  dm.Clear();
  ASSERT_TRUE(dm.ParseFromString(ser_dm_login)) <<
              "Data Atlas hasn't the correct format";
  ASSERT_EQ(ser_dm, ser_dm_login) <<
            "DA recoverd from login different from DA stored in registration";
  ASSERT_EQ(username_, ss_->Username()) << "Saved username_ doesn't correspond";
  ASSERT_EQ(pin_, ss_->Pin()) << "Saved pin_ doesn't correspond";
  ASSERT_EQ(password_, ss_->Password()) << "Saved password_ doesn't correspond";

  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result);
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  ser_dm_login.clear();
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Unable to get registered user's data";
  ASSERT_EQ(ser_dm, ser_dm_login) <<
            "Serialised DA recovered from login empty string";
  dm.Clear();
  ASSERT_TRUE(dm.ParseFromString(ser_dm_login)) <<
              "Data Atlas hasn't the correct format";
  ASSERT_EQ(ser_dm, ser_dm_login) <<
            "DA recoverd from login different from DA stored in registration";
  ASSERT_EQ(username_, ss_->Username()) << "Saved username_ doesn't correspond";
  ASSERT_EQ(pin_, ss_->Pin()) << "Saved pin_ doesn't correspond";
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, LoginNoUser) {
  username_ += "03";
  std::string ser_dm, ser_dm_login;
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  result = authentication_.GetUserData("password_tonto", &ser_dm_login);
  ASSERT_EQ(kPasswordFailure, result);
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, RegisterUserOnce) {
  username_ += "04";
  DataAtlas data_atlas;
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_EQ(username_, ss_->Username()) << "Saved username_ doesn't correspond";
  ASSERT_EQ(pin_, ss_->Pin()) << "Saved pin_ doesn't correspond";
  boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(password_, ss_->Password()) << "Saved password_ doesn't correspond";
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, RegisterUserTwice) {
  username_ += "05";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  //  User registered twice.
  ss_->ResetSession();
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserExists, result) << "The same user was registered twice";
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, RepeatedSaveSessionBlocking) {
  username_ += "06";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string original_tmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  dm.Clear();
  dm.set_file_hash("filehash1");
  dm.add_chunk_name("chunk11");
  dm.add_chunk_name("chunk21");
  dm.add_chunk_name("chunk31");
  dm.add_encrypted_chunk_name("enc_chunk11");
  dm.add_encrypted_chunk_name("enc_chunk21");
  dm.add_encrypted_chunk_name("enc_chunk31");
  dm.add_chunk_size(2001);
  dm.add_chunk_size(2101);
  dm.add_chunk_size(2051);
  dm.set_compression_on(false);
  ser_dm = dm.SerializeAsString();
  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result) << "Can't save session 1";

  dm.Clear();
  dm.set_file_hash("filehash2");
  dm.add_chunk_name("chunk12");
  dm.add_chunk_name("chunk22");
  dm.add_chunk_name("chunk32");
  dm.add_encrypted_chunk_name("enc_chunk12");
  dm.add_encrypted_chunk_name("enc_chunk22");
  dm.add_encrypted_chunk_name("enc_chunk32");
  dm.add_chunk_size(2002);
  dm.add_chunk_size(2102);
  dm.add_chunk_size(2052);
  dm.set_compression_on(false);
  ser_dm = dm.SerializeAsString();
  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result) << "Can't save session 2";
  std::string tmidname, stmidname;
  ss_->GetKey(passport::TMID, &tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &stmidname, NULL, NULL, NULL);

  EXPECT_TRUE(sm_->KeyUnique(original_tmidname, false));
  EXPECT_FALSE(sm_->KeyUnique(stmidname, false));
  EXPECT_FALSE(sm_->KeyUnique(tmidname, false));
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, RepeatedSaveSessionCallbacks) {
  username_ += "07";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string original_tmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  dm.Clear();
  dm.set_file_hash("filehash1");
  dm.add_chunk_name("chunk11");
  dm.add_chunk_name("chunk21");
  dm.add_chunk_name("chunk31");
  dm.add_encrypted_chunk_name("enc_chunk11");
  dm.add_encrypted_chunk_name("enc_chunk21");
  dm.add_encrypted_chunk_name("enc_chunk31");
  dm.add_chunk_size(2001);
  dm.add_chunk_size(2101);
  dm.add_chunk_size(2051);
  dm.set_compression_on(false);
  ser_dm = dm.SerializeAsString();
  CallbackObject cb;
  authentication_.SaveSession(ser_dm, boost::bind(
      &CallbackObject::ReturnCodeCallback, &cb, _1));
  ASSERT_EQ(kSuccess, cb.WaitForReturnCodeResult()) << "Can't save session 1";

  dm.Clear();
  dm.set_file_hash("filehash2");
  dm.add_chunk_name("chunk12");
  dm.add_chunk_name("chunk22");
  dm.add_chunk_name("chunk32");
  dm.add_encrypted_chunk_name("enc_chunk12");
  dm.add_encrypted_chunk_name("enc_chunk22");
  dm.add_encrypted_chunk_name("enc_chunk32");
  dm.add_chunk_size(2002);
  dm.add_chunk_size(2102);
  dm.add_chunk_size(2052);
  dm.set_compression_on(false);
  ser_dm = dm.SerializeAsString();
  cb.Reset();
  authentication_.SaveSession(ser_dm, boost::bind(
      &CallbackObject::ReturnCodeCallback, &cb, _1));
  ASSERT_EQ(kSuccess, cb.WaitForReturnCodeResult()) << "Can't save session 2";
  EXPECT_TRUE(sm_->KeyUnique(original_tmidname, false));
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, ChangeUsername) {
  username_ += "08";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  // Save the session to create different TMIDs for MID and SMID
  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result) << "Can't save the session";
  std::string original_tmidname, original_stmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangeUsername(ser_dm, "el iuserneim"))
            << "Unable to change iuserneim";
  ASSERT_EQ("el iuserneim", ss_->Username()) <<
            "iuserneim is still the old one";

  result = authentication_.GetUserInfo("el iuserneim", pin_);

  ASSERT_EQ(kUserExists, result) << "User does not exist";
  std::string ser_dm_login;
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new iuserneim";

  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserDoesntExist, result);

  // Check the TMIDs are gone
  ASSERT_TRUE(sm_->KeyUnique(original_tmidname, false));
  ASSERT_TRUE(sm_->KeyUnique(original_stmidname, false));
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, ChangePin) {
  username_ += "09";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  // Save the session to create different TMIDs for MID and SMID
  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result) << "Can't save the session";
  std::string original_tmidname, original_stmidname;
  ss_->GetKey(passport::TMID, &original_tmidname, NULL, NULL, NULL);
  ss_->GetKey(passport::STMID, &original_stmidname, NULL, NULL, NULL);
  EXPECT_FALSE(original_tmidname.empty());
  EXPECT_FALSE(original_stmidname.empty());

  ASSERT_EQ(kSuccess, authentication_.ChangePin(ser_dm, "7894"));
  ASSERT_EQ("7894", ss_->Pin()) << "pin_ is still the old one";

  result = authentication_.GetUserInfo(username_, "7894");
  std::string ser_dm_login;
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new pin_";
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserDoesntExist, result);
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, CreatePublicName) {
  username_ += "10";
  ASSERT_EQ(kSuccess, authentication_.CreatePublicName("el public iuserneim"))
            << "Can't create public username_";
  ASSERT_EQ(kPublicUsernameAlreadySet,
            authentication_.CreatePublicName("el public iuserneim"))
            << "Created public username_ twice";
  // Reset PublicUsername to allow attempt to save same public name to network.
  ASSERT_TRUE(ss_->SetPublicUsername(""));
  ASSERT_EQ(kPublicUsernameExists,
            authentication_.CreatePublicName("el public iuserneim"))
            << "Created public username_ twice";
  authentication_.tmid_op_status_ = Authentication::kFailed;
  authentication_.stmid_op_status_ = Authentication::kFailed;
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, CreateMSIDPacket) {
  username_ += "11";
  std::string msid_name, pub_key, priv_key;
  ASSERT_EQ(kSuccess,
            authentication_.CreateMsidPacket(&msid_name, &pub_key, &priv_key));
  ASSERT_FALSE(msid_name.empty());
  ASSERT_FALSE(priv_key.empty());
  ASSERT_FALSE(pub_key.empty());

  // Check the packet exits
  std::vector<std::string> packet_content;
  ASSERT_EQ(kSuccess, sm_->LoadPacket(msid_name, &packet_content));
  ASSERT_EQ(size_t(1), packet_content.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(packet_content[0]));

  // Check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), pub_key));
  ASSERT_EQ(SHA512String(pub_key + gp.signature()), msid_name);
  authentication_.tmid_op_status_ = Authentication::kFailed;
  authentication_.stmid_op_status_ = Authentication::kFailed;
}

TEST_MS_NET(AuthenticationTest, FUNC, MAID, RegisterLeaveRegister) {
  username_ += "12";
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  encrypt::DataMap dm;
  dm.set_file_hash("filehash");
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.add_chunk_size(200);
  dm.add_chunk_size(210);
  dm.add_chunk_size(205);
  dm.set_compression_on(false);
  std::string ser_dm = dm.SerializeAsString();
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  //  Remove user.
  result = authentication_.RemoveMe();
  ASSERT_EQ(kSuccess, result);
  try {
    fs::remove_all(file_system::MaidsafeDir(ss_->SessionName()));
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    FAIL();
  }

  //  Check user no longer registered.
  ss_->ResetSession();
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_NE(kUserExists, result);

  ss_->ResetSession();
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user again.";
  result = authentication_.CreateTmidPacket(username_, pin_, password_, ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user again.";
}

}  // namespace test

}  // namespace maidsafe
