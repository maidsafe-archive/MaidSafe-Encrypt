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

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/client/dataatlashandler.h"
#include "protobuf/datamaps.pb.h"
#include "maidsafe/client/localstoremanager.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "maidsafe/client/packetfactory.h"


namespace maidsafe {

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

void wait_for_result_ta(const FakeCallback &cb, boost::recursive_mutex *mutex) {
  while (true) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(20));
  }
};


class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest() : ss(),
                         storemanager(),
                         client_chunkstore_(),
                         username("user1"),
                         pin("1234"),
                         password("password1"),
                         mutex(),
                         cb() {
    try {
      boost::filesystem::remove_all("./TestAuth");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  ~AuthenticationTest() {
    try {
      boost::filesystem::remove_all("./TestAuth");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
 protected:
  void SetUp() {
    if (boost::filesystem::exists("KademilaDb.db"))
      boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
    if (boost::filesystem::exists("DAH.db"))
      boost::filesystem::remove(boost::filesystem::path("DAH.db"));
    if (boost::filesystem::exists("StoreChunks"))
      boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
    username = "user1";
    pin = "1234";
    password = "password1";
    mutex = new boost::recursive_mutex();
    client_chunkstore_ =
        boost::shared_ptr<ChunkStore>(new ChunkStore("./TestAuth", 0, 0));
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    boost::shared_ptr<LocalStoreManager>
        storemanager(new LocalStoreManager(mutex, client_chunkstore_));
    storemanager->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_ta(cb, mutex);
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
    if (boost::filesystem::exists("KademilaDb.db"))
      boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
    if (boost::filesystem::exists("DAH.db"))
      boost::filesystem::remove(boost::filesystem::path("DAH.db"));
    if (boost::filesystem::exists("StoreChunks"))
      boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
  }

  SessionSingleton *ss;
  boost::shared_ptr<LocalStoreManager> storemanager;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  std::string username;
  std::string pin;
  std::string password;
  boost::recursive_mutex *mutex;
  FakeCallback cb;
 private:
  explicit AuthenticationTest(const AuthenticationTest&);
  AuthenticationTest &operator=(const AuthenticationTest&);
};

TEST_F(AuthenticationTest, BEH_MAID_Login) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da_login, ser_da_register;
  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result) << "Unable to register user";
  ss->SerialisedKeyRing(&ser_da_register);
  cb.Reset();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(OK, result)<< "Unable to get registered user's data";
  ASSERT_NE("", ser_da_login)
      << "Serialised DA recovered from login empty string";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da_login))
      << "Data Atlas hasn't the correct format";
  ASSERT_EQ(ser_da_login, ser_da_register)
      << "DA recoverd from login different from DA stored in registration";
  ASSERT_EQ(username, ss->Username()) << "Saved username doesn't correspond";
  ASSERT_EQ(pin, ss->Pin()) << "Saved pin doesn't correspond";
  ASSERT_EQ(password, ss->Password()) << "Saved password doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_LoginNoUser) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  std::string ser_da, ser_da_login;
  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  cb.Reset();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  result = authentication->GetUserData("password_tonto", ser_da_login);
  ASSERT_EQ(PASSWORD_FAIL, result);
}

TEST_F(AuthenticationTest, BEH_MAID_RegisterUser) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;

  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ss->SerialisedKeyRing(&ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ASSERT_NE("", ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";
  ASSERT_EQ(5, data_atlas.keys_size());
  ASSERT_EQ(username, ss->Username()) << "Saved username doesn't correspond";
  ASSERT_EQ(pin, ss->Pin()) << "Saved pin doesn't correspond";
  ASSERT_EQ(password, ss->Password()) << "Saved password doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserTwice) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;

  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ss->SerialisedKeyRing(&ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";
  //  User registered twice.
  ss->ResetSession();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(USER_EXISTS, result) << "The same user was registered twice";
  // need to wait before exiting because in the background it is getting
  // the TMID of the user
  boost::this_thread::sleep(boost::posix_time::seconds(1));
}

/*
  TEST_F(AuthenticationTest, 50_RemoveMe) {
    DataAtlas data_atlas;
    DataAtlasHandler dah;
    std::string ser_da;
    Exitcode result = authentication->CreateUserSysPackets(username,
                                                           pin,
                                                           password,
                                                           ser_da);
    ASSERT_EQ(OK, result) << "Result not OK";

    ASSERT_TRUE(dah.Init("DAH.db"));
    ASSERT_TRUE(dah.ParseFromStringDataAtlas(ser_da)) << "No DA --> Db";

    std::list<Key_Type> lasquis;
    dah.GetKeyRing(lasquis);
    EXPECT_EQ((unsigned int)4,lasquis.size()) << "Not all keys perhaps...";
    ASSERT_EQ(OK, authentication->RemoveMe(lasquis))
      << "Not completely removed from maidsafe network";
    dah.Close();
  }
*/

TEST_F(AuthenticationTest, FUNC_MAID_ChangeUsername) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;
  packethandler::PacketParams lasquis, pubkeys;

  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ss->SerialisedKeyRing(&ser_da);
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

  ASSERT_EQ(OK, authentication->ChangeUsername(ser_da, lasquis, pubkeys,
            "el iuserneim")) << "Unable to change iuserneim";
  ASSERT_EQ("el iuserneim", ss->Username()) << "iuserneim is still the old one";
  std::string ser_da_login;
  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());

  result = authentication->GetUserInfo("el iuserneim", pin);
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new iuserneim";

  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(NON_EXISTING_USER, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePin) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  std::string ser_da;
  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ss->SerialisedKeyRing(&ser_da);
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
  ASSERT_EQ(OK, authentication->ChangePin(ser_da, lasquis, pubkeys, "7894"))
            << "Unable to change pin";
  ASSERT_EQ("7894", ss->Pin()) << "pin is still the old one";
  std::string ser_da_login;
  result = authentication->GetUserInfo(username, "7894");
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new pin";
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(NON_EXISTING_USER, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePassword) {
  cb.Reset();
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  std::string ser_da;
  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  cb.Reset();
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password);
  ASSERT_EQ(OK, result) << "Unable to register user";
  EXPECT_TRUE(data_atlas.ParseFromString(ser_da));
  ss->SerialisedKeyRing(&ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da)) <<
              "Data Atlas hasn't the correct format";

  printf("AAAAAAAAAAAAAAAAAAAA\n");

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
  ASSERT_EQ(OK, authentication->ChangePassword(ser_da, lasquis, pubkeys,
            "elpasguord")) << "Unable to change password";
  printf("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
  ASSERT_EQ("elpasguord", ss->Password()) << "Password is still the old one";
  std::string ser_da_login;
  cb.Reset();
  FakeCallback fcb;
  result = authentication->GetUserInfo(username, pin);
  cb.Reset();
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  result = authentication->GetUserData("elpasguord", ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new password";
  cb.Reset();
  result = authentication->GetUserInfo(username, pin);
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(PASSWORD_FAIL, result);
}

TEST_F(AuthenticationTest, BEH_MAID_CreatePublicName) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams result;
  crypto::Crypto crypto_obj;
  crypto_obj.set_symm_algorithm(crypto::AES_256);
  crypto_obj.set_hash_algorithm(crypto::SHA_512);
  ASSERT_EQ(OK, authentication->CreatePublicName("el public iuserneim",
            &result)) << "Can't create public username";
  ASSERT_EQ(PUBLIC_USERNAME_EXISTS,
            authentication->CreatePublicName("el public iuserneim", &result))
            << "Created public username twice";
}

TEST_F(AuthenticationTest, BEH_MAID_InvalidUsernamePassword) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::MidPacket *midPacket = static_cast<packethandler::MidPacket*>
      (packethandler::PacketFactory::Factory(packethandler::MID));
  packethandler::PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  std::string mid_name = midPacket->PacketName(params);
  ASSERT_EQ(0, sm->StorePacket(mid_name, "rubish data with same mid name",
      packethandler::MID, maidsafe::PRIVATE, ""));

  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  Exitcode result = authentication->GetUserInfo(username, pin);
  EXPECT_EQ(INVALID_USERNAME_PIN, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_CreateMSIDPacket) {
  boost::scoped_ptr<LocalStoreManager>
      sm(new LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(new Authentication(
    sm.get(), mutex));
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string msid_name, pub_key, priv_key;
  cb.Reset();
  authentication->CreateMSIDPacket(boost::bind(&FakeCallback::CallbackFunc,
                                   &cb, _1));
  wait_for_result_ta(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  packethandler::CreateMSIDResult msid_result;
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
  sm->LoadPacket(msid_name, &packet_content);
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  packethandler::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(load_res.content()));

  // Check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(), pub_key,
    crypto::STRING_STRING));
  ASSERT_EQ(co.Hash(pub_key + gp.signature(), "",
            crypto::STRING_STRING, true), msid_name);
}

}  // namespace maidsafe
