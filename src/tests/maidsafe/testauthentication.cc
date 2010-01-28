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
#include "protobuf/datamaps.pb.h"
#include "maidsafe/client/localstoremanager.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "maidsafe/client/packetfactory.h"

namespace fs = boost::filesystem;

namespace test_auth {

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

void wait_for_result_ta(const FakeCallback &cb, boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (cb.result != "")
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

}  // namespace test_auth

namespace maidsafe {

class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                        "/maidsafe_TestAuth"),
                         ss(),
                         storemanager(),
                         client_chunkstore_(),
                         username("user1"),
                         pin("1234"),
                         password("password1"),
                         cb() {}
  ~AuthenticationTest() {}
 protected:
  void SetUp() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
    username = "user1";
    pin = "1234";
    password = "password1";
    client_chunkstore_ =
        boost::shared_ptr<ChunkStore>(new ChunkStore(test_root_dir_, 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    boost::shared_ptr<LocalStoreManager>
        storemanager(new LocalStoreManager(client_chunkstore_));
    storemanager->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc,
                                      &cb, _1));
    boost::mutex mutex;
    wait_for_result_ta(cb, &mutex);
    GenericResponse res;
    if ((!res.ParseFromString(cb.result)) ||
        (res.result() == kNack)) {
      FAIL();
      return;
    }
    ss = SessionSingleton::getInstance();
    ss->ResetSession();
    cb.Reset();
  }
  void TearDown() {
    cb.Reset();
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }

  std::string test_root_dir_;
  SessionSingleton *ss;
  boost::shared_ptr<LocalStoreManager> storemanager;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  std::string username;
  std::string pin;
  std::string password;
  test_auth::FakeCallback cb;
 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, FUNC_MAID_GoodLogin) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  DataAtlas data_atlas;
  std::string ser_dm_login;
  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
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

  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";

  cb.Reset();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  result = authentication->GetUserData(password, ser_dm_login);
  ASSERT_EQ(kSuccess, result)<< "Unable to get registered user's data";
  ASSERT_NE("", ser_dm_login)
      << "Serialised DA recovered from login empty string";
  dm.Clear();
  ASSERT_TRUE(dm.ParseFromString(ser_dm_login))
      << "Data Atlas hasn't the correct format";
  ASSERT_EQ(ser_dm, ser_dm_login)
      << "DA recoverd from login different from DA stored in registration";
  ASSERT_EQ(username, ss->Username()) << "Saved username doesn't correspond";
  ASSERT_EQ(pin, ss->Pin()) << "Saved pin doesn't correspond";
  ASSERT_EQ(password, ss->Password()) << "Saved password doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_LoginNoUser) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  std::string ser_dm, ser_dm_login;
  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  result = authentication->GetUserData("password_tonto", ser_dm_login);
  ASSERT_EQ(kPasswordFailure, result);
}

TEST_F(AuthenticationTest, BEH_MAID_RegisterUserOnce) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  DataAtlas data_atlas;

  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss->SerialisedKeyRing(&ser_da);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_NE("", ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";
  ASSERT_EQ(5, data_atlas.keys_size());
  ASSERT_EQ(username, ss->Username()) << "Saved username doesn't correspond";
  ASSERT_EQ(pin, ss->Pin()) << "Saved pin doesn't correspond";
  ASSERT_EQ(password, ss->Password()) << "Saved password doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserTwice) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  DataAtlas data_atlas;

  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss->SerialisedKeyRing(&ser_da);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";
  //  User registered twice.
  ss->ResetSession();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserExists, result) << "The same user was registered twice";
  // need to wait before exiting because in the background it is getting
  // the TMID of the user
  boost::this_thread::sleep(boost::posix_time::seconds(1));
}

/*
  TEST_F(AuthenticationTest, 50_RemoveMe) {
    DataAtlas data_atlas;
    DataAtlasHandler dah;
    std::string ser_da;
    int result = authentication->CreateUserSysPackets(username,
                                                           pin,
                                                           password,
                                                           ser_da);
    ASSERT_EQ(kSuccess, result) << "Result not kSuccess";

    ASSERT_TRUE(dah.Init("DAH.db"));
    ASSERT_TRUE(dah.ParseFromStringDataAtlas(ser_da)) << "No DA --> Db";

    std::list<Key_Type> lasquis;
    dah.GetKeyRing(lasquis);
    EXPECT_EQ((unsigned int)4,lasquis.size()) << "Not all keys perhaps...";
    ASSERT_EQ(kSuccess, authentication->RemoveMe(lasquis))
      << "Not completely removed from maidsafe network";
    dah.Close();
  }
*/

TEST_F(AuthenticationTest, DISABLED_FUNC_MAID_ChangeUsername) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  DataAtlas data_atlas;
  PacketParams lasquis, pubkeys;

  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss->SerialisedKeyRing(&ser_da);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }

  ASSERT_EQ(kSuccess, authentication->ChangeUsername(ser_dm, lasquis, pubkeys,
            "el iuserneim")) << "Unable to change iuserneim";
  ASSERT_EQ("el iuserneim", ss->Username()) << "iuserneim is still the old one";
  std::string ser_dm_login;
  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());

  result = authentication->GetUserInfo("el iuserneim", pin);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new iuserneim";

  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserDoesntExist, result);
}

TEST_F(AuthenticationTest, DISABLED_FUNC_MAID_ChangePin) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss->SerialisedKeyRing(&ser_da);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }
  ASSERT_EQ(kSuccess, authentication->ChangePin(ser_dm, lasquis, pubkeys,
      "7894")) << "Unable to change pin";
  ASSERT_EQ("7894", ss->Pin()) << "pin is still the old one";
  std::string ser_dm_login;
  result = authentication->GetUserInfo(username, "7894");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new pin";
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserDoesntExist, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePassword) {
  cb.Reset();
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  int result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kUserDoesntExist, result) << "User already exists";
  cb.Reset();
  uint32_t rid;
  result = authentication->CreateUserSysPackets(username, pin, &rid);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  std::string ser_da;
  ss->SerialisedKeyRing(&ser_da);
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
  result = authentication->CreateTmidPacket(username, pin, password, rid,
    ser_dm);
  ASSERT_EQ(kSuccess, result) << "Unable to register user";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }
  ASSERT_EQ(kSuccess, authentication->ChangePassword(ser_dm, lasquis, pubkeys,
            "elpasguord")) << "Unable to change password";

  ASSERT_EQ("elpasguord", ss->Password()) << "Password is still the old one";
  std::string ser_dm_login;
  cb.Reset();
  test_auth::FakeCallback fcb;
  result = authentication->GetUserInfo(username, pin);
  cb.Reset();
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  result = authentication->GetUserData("elpasguord", ser_dm_login);
  ASSERT_EQ(kSuccess, result) << "Can't login with new password";
  cb.Reset();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(kUserExists, result) << "User does not exist";
  result = authentication->GetUserData(password, ser_dm_login);
  ASSERT_EQ(kPasswordFailure, result);
}

TEST_F(AuthenticationTest, BEH_MAID_CreatePublicName) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  PacketParams result;
  crypto::Crypto crypto_obj;
  crypto_obj.set_symm_algorithm(crypto::AES_256);
  crypto_obj.set_hash_algorithm(crypto::SHA_512);
  ASSERT_EQ(kSuccess, authentication->CreatePublicName("el public iuserneim",
            &result)) << "Can't create public username";
  ASSERT_EQ(kPublicUsernameExists,
            authentication->CreatePublicName("el public iuserneim", &result))
            << "Created public username twice";
}

TEST_F(AuthenticationTest, BEH_MAID_InvalidUsernamePassword) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  MidPacket *midPacket = static_cast<MidPacket*>
      (PacketFactory::Factory(MID));
  PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  std::string mid_name = midPacket->PacketName(&params);
  int result(kGeneralError);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  VoidFuncOneInt func = boost::bind(&test_auth::PacketOpCallback, _1, &mutex,
                                    &cond_var, &result);
  sm->StorePacket(mid_name, "rubish data with same mid name", MID,
      PRIVATE, "", kDoNothingReturnFailure, func);
  while (result == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex);
    cond_var.wait(lock);
  }
  ASSERT_EQ(kSuccess, result);
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(kInvalidUsernameOrPin, result);
}

TEST_F(AuthenticationTest, BEH_MAID_CreateMSIDPacket) {
  boost::shared_ptr<LocalStoreManager>
      sm(new LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(new Authentication());
  authentication->Init(sm);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string msid_name, pub_key, priv_key;
  cb.Reset();
  authentication->CreateMSIDPacket(boost::bind(
      &test_auth::FakeCallback::CallbackFunc, &cb, _1));
  boost::mutex mutex;
  wait_for_result_ta(cb, &mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  CreateMSIDResult msid_result;
  ASSERT_TRUE(msid_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(msid_result.result()));
  msid_name = msid_result.name();
  priv_key = msid_result.private_key();
  pub_key = msid_result.public_key();
  std::string empty_str("");
  cb.Reset();
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_NE(empty_str, msid_name);
  ASSERT_NE(empty_str, priv_key);
  ASSERT_NE(empty_str, pub_key);

  // Check the packet exits
  std::string packet_content;
  ASSERT_EQ(kSuccess, sm->LoadPacket(msid_name, &packet_content));
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(packet_content));

  // Check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(), pub_key,
    crypto::STRING_STRING));
  ASSERT_EQ(co.Hash(pub_key + gp.signature(), "",
            crypto::STRING_STRING, true), msid_name);
}

}  // namespace maidsafe
