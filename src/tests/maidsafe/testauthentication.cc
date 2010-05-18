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

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "tests/maidsafe/cached_keys.h"

namespace fs = boost::filesystem;

namespace test_auth {

class FakeCallback {
 public:
  FakeCallback() : result() {}
  void CallbackFunc(const std::string &res) {
    result = res;
  }
  void Reset() {
    result.clear();
  }
  std::string result;
};

void WaitForResult(const FakeCallback &cb, boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (!cb.result.empty())
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(20));
  }
};

void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
};

std::vector<crypto::RsaKeyPair> keys;

}  // namespace test_auth

namespace maidsafe {

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest() : test_root_dir_(file_system::TempDir() /
                                        ("maidsafe_TestAuth_" +
                                         base::RandomString(6))),
                         ss_(),
                         sm_(),
                         client_chunkstore_(),
                         authentication_(),
                         username_("user1"),
                         pin_("1234"),
                         password_("password1"),
                         cb_() {}
 protected:
  void SetUp() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
    client_chunkstore_.reset(new ChunkStore(test_root_dir_.string(), 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    sm_.reset(new LocalStoreManager(client_chunkstore_));
    sm_->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb_, _1),
              test_root_dir_);
    boost::mutex mutex;
    test_auth::WaitForResult(cb_, &mutex);
    GenericResponse res;
    if ((!res.ParseFromString(cb_.result)) ||
        (res.result() == kNack)) {
      FAIL();
      return;
    }
    authentication_.Init(kNoOfSystemPackets, sm_);
    ss_ = SessionSingleton::getInstance();
    ss_->ResetSession();
    cb_.Reset();
  }
  void TearDown() {
    cb_.Reset();
    try {
      cb_.Reset();
      sm_->Close(boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb_, _1),
          true);
      boost::mutex mutex;
      test_auth::WaitForResult(cb_, &mutex);
      GenericResponse res;
      if ((!res.ParseFromString(cb_.result)) ||
          (res.result() == kNack)) {
        printf("Failed to close LocalStoreManager.\n");
      }
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }

  fs::path test_root_dir_;
  SessionSingleton *ss_;
  boost::shared_ptr<LocalStoreManager> sm_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  Authentication authentication_;
  std::string username_;
  std::string pin_;
  std::string password_;
  test_auth::FakeCallback cb_;
 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, FUNC_MAID_CreateUserSysPackets) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
}

TEST_F(AuthenticationTest, FUNC_MAID_GoodLogin) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

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
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

TEST_F(AuthenticationTest, FUNC_MAID_LoginNoUser) {
  std::string ser_dm, ser_dm_login;
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  DataMap dm;
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
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserOnce) {
  DataAtlas data_atlas;
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss_->SerialisedKeyRing(&ser_da);
  DataMap dm;
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
  ASSERT_NE("", ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";
  ASSERT_EQ(6, data_atlas.keys_size());
  ASSERT_EQ(username_, ss_->Username()) << "Saved username_ doesn't correspond";
  ASSERT_EQ(pin_, ss_->Pin()) << "Saved pin_ doesn't correspond";
  ASSERT_EQ(password_, ss_->Password()) << "Saved password_ doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserTwice) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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
  // need to wait before exiting because in the background it is getting
  // the TMID of the user
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

TEST_F(AuthenticationTest, FUNC_MAID_RepeatedSaveSession) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string tmidsmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->SmidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);
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
  ASSERT_TRUE(sm_->KeyUnique(tmidsmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_RepeatedSaveSessionCallbacks) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string tmidsmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->SmidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);
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
  result = kPendingResult;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  VoidFuncOneInt func = boost::bind(&test_auth::PacketOpCallback, _1, &mutex,
                                    &cond_var, &result);
  authentication_.SaveSession(ser_dm, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
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
  result = kPendingResult;
  authentication_.SaveSession(ser_dm, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
  ASSERT_EQ(kSuccess, result) << "Can't save session 2";
  ASSERT_TRUE(sm_->KeyUnique(tmidsmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangeUsername) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string tmidmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->MidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);

  std::string tmidsmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->SmidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);

  ASSERT_EQ(kSuccess, authentication_.ChangeUsername(ser_dm, "el iuserneim"))
            << "Unable to change iuserneim";
  ASSERT_EQ("el iuserneim", ss_->Username()) <<
            "iuserneim is still the old one";
  ASSERT_NE(ss_->MidRid(), ss_->SmidRid());

  result = authentication_.GetUserInfo("el iuserneim", pin_);

  ASSERT_EQ(kUserExists, result) << "User does not exist";
  std::string ser_dm_login;
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new iuserneim";
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserDoesntExist, result);
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));

  // Check the TMIDs are gone
  ASSERT_TRUE(sm_->KeyUnique(tmidmidname, false));
  ASSERT_TRUE(sm_->KeyUnique(tmidsmidname, false));
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePin) {
  int result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  result = authentication_.CreateUserSysPackets(username_, pin_);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  DataMap dm;
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
  std::string tmidcontent = ss_->TmidContent();
  result = authentication_.SaveSession(ser_dm);
  ASSERT_EQ(kSuccess, result) << "Can't save the session";

  // store current mid, smid and tmid details to check later whether they remain
  // on the network
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string tmidmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->MidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);

  std::string tmidsmidname = co.Hash(
         co.Hash(ss_->Username(), "", crypto::STRING_STRING, false) +
         co.Hash(ss_->Pin(), "", crypto::STRING_STRING, false) +
         co.Hash(boost::lexical_cast<std::string>(ss_->SmidRid()), "",
                 crypto::STRING_STRING, false),
         "", crypto::STRING_STRING, false);
  std::string mid_tmid = ss_->TmidContent();
  std::string smid_tmid = ss_->SmidTmidContent();

  ASSERT_EQ(kSuccess, authentication_.ChangePin(ser_dm, "7894"));
  ASSERT_EQ("7894", ss_->Pin()) << "pin_ is still the old one";
  ASSERT_NE(ss_->MidRid(), ss_->SmidRid());

  result = authentication_.GetUserInfo(username_, "7894");
  std::string ser_dm_login;
  result = authentication_.GetUserData(password_, &ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new pin_";
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  result = authentication_.GetUserInfo(username_, pin_);
  ASSERT_EQ(kUserDoesntExist, result);
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

TEST_F(AuthenticationTest, BEH_MAID_CreatePublicName) {
  crypto::Crypto crypto_obj;
  crypto_obj.set_symm_algorithm(crypto::AES_256);
  crypto_obj.set_hash_algorithm(crypto::SHA_512);
  ASSERT_EQ(kSuccess, authentication_.CreatePublicName("el public iuserneim"))
            << "Can't create public username_";
  ASSERT_EQ(kPublicUsernameExists,
            authentication_.CreatePublicName("el public iuserneim"))
            << "Created public username_ twice";
}

TEST_F(AuthenticationTest, BEH_MAID_InvalidUsernamePassword) {
  cached_keys::MakeKeys(2, &test_auth::keys);
  crypto::RsaKeyPair keypair1 = test_auth::keys.at(0);
  crypto::RsaKeyPair keypair2 = test_auth::keys.at(1);
  boost::shared_ptr<Packet> midPacket(PacketFactory::Factory(MID));
  PacketParams params;
  params["username"] = username_;
  params["pin"] = pin_;
  std::string mid_name = midPacket->PacketName(params);
  int result(kGeneralError);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  VoidFuncOneInt func = boost::bind(&test_auth::PacketOpCallback, _1, &mutex,
                                    &cond_var, &result);
  ss_->AddKey(ANMID, "ID", keypair2.private_key(), keypair2.public_key(), "");
  sm_->StorePacket(mid_name, "rubbish data with same mid name", MID,
      PRIVATE, "", kDoNothingReturnFailure, func);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError)
      cond_var.wait(lock);
  }
  ASSERT_EQ(kSuccess, result);
  result = authentication_.GetUserInfo(username_, pin_);
  EXPECT_EQ(kUserDoesntExist, result);
  while (authentication_.get_smidtimid_result() == kPendingResult)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}

TEST_F(AuthenticationTest, BEH_MAID_CreateMSIDPacket) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string msid_name, pub_key, priv_key;
  cb_.Reset();
  authentication_.CreateMSIDPacket(boost::bind(
      &test_auth::FakeCallback::CallbackFunc, &cb_, _1));
  boost::mutex mutex;
  test_auth::WaitForResult(cb_, &mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  CreateMSIDResult msid_result;
  ASSERT_TRUE(msid_result.ParseFromString(cb_.result));
  ASSERT_EQ(kAck, static_cast<int>(msid_result.result()));
  msid_name = msid_result.name();
  priv_key = msid_result.private_key();
  pub_key = msid_result.public_key();
  std::string empty_str;
  cb_.Reset();
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_NE(empty_str, msid_name);
  ASSERT_NE(empty_str, priv_key);
  ASSERT_NE(empty_str, pub_key);

  // Check the packet exits
  std::vector<std::string> packet_content;
  ASSERT_EQ(kSuccess, sm_->LoadPacket(msid_name, &packet_content));
  ASSERT_EQ(size_t(1), packet_content.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(packet_content[0]));

  // Check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(), pub_key,
    crypto::STRING_STRING));
  ASSERT_EQ(co.Hash(pub_key + gp.signature(), "",
            crypto::STRING_STRING, false), msid_name);
}

TEST(AuthenticationTest1, BEH_MAID_TestDestructor) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore("tmp", 0, 0));
  boost::shared_ptr<LocalStoreManager> sm(new LocalStoreManager(chunkstore));
  Authentication *auth = new Authentication;
  auth->Init(kNoOfSystemPackets, sm);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  delete auth;
  SUCCEED();
}

}  // namespace maidsafe
