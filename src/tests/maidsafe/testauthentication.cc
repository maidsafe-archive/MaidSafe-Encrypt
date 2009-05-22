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

#include "gtest/gtest.h"

#include "maidsafe/client/authentication.h"
#include "maidsafe/client/dataatlashandler.h"
#include "protobuf/datamaps.pb.h"
#include "maidsafe/client/localstoremanager.h"
#include "protobuf/general_messages.pb.h"
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(5));
  }
};


class AuthenticationTest : public testing::Test {
 public:
  AuthenticationTest() : ss(),
                         storemanager(),
                         username("user1"),
                         pin("1234"),
                         password("password1"),
                         mutex(),
                         cb() {}
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
    boost::shared_ptr<LocalStoreManager>
        storemanager(new LocalStoreManager(mutex));
    storemanager->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_ta(cb, mutex);
    base::GeneralResponse res;
    if ((!res.ParseFromString(cb.result)) ||
        (res.result() == kCallbackFailure)) {
      FAIL();
      return;
    }
    ss = SessionSingleton::getInstance();
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
  std::string username;
  std::string pin;
  std::string password;
  boost::recursive_mutex *mutex;
  FakeCallback cb;
 private:
  AuthenticationTest(const maidsafe::AuthenticationTest&);
  AuthenticationTest &operator=(const maidsafe::AuthenticationTest&);
};

TEST_F(AuthenticationTest, BEH_MAID_Login) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::shared_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da_login, ser_da_register;
  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da_register);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  cb.Reset();
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  wait_for_result_ta(cb, mutex);
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
      sm(new LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  std::string ser_da, ser_da_login;
  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  wait_for_result_ta(cb, mutex);
  result = authentication->GetUserData("password_tonto", ser_da_login);
  ASSERT_EQ(PASSWORD_FAIL, result);
}

TEST_F(AuthenticationTest, BEH_MAID_RegisterUser) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;

  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ASSERT_NE("", ser_da);
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da))
      << "Data Atlas hasn't the correct format";
  ASSERT_EQ(5, data_atlas.keys_size());
  ASSERT_EQ(username, ss->Username()) << "Saved username doesn't correspond";
  ASSERT_EQ(pin, ss->Pin()) << "Saved pin doesn't correspond";
  ASSERT_EQ(password, ss->Password()) << "Saved password doesn't correspond";
}

TEST_F(AuthenticationTest, FUNC_MAID_RegisterUserTwice) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;

  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  ASSERT_TRUE(data_atlas.ParseFromString(ser_da))
      << "Data Atlas hasn't the correct format";
  //  User registered twice.
  ss->ResetSession();
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(USER_EXISTS, result) << "The same user was registered twice";
  // need to wait before exiting because in the background it is getting
  // the TMID of the user
  boost::this_thread::sleep(boost::posix_time::seconds(1));
}

//  TEST_F(AuthenticationTest, 46_IllegalUsername) {
//   //  Illegal username
//    std::string ser_da;
//    std::string illegal_username = "";
//    exitcode result = authentication->CreateUserSysPackets(illegal_username,
//                                                           pin,
//                                                           password,
//                                                           ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, empty username";
//    result = authentication->Login(illegal_username, pin, password, &ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, empty username";
//    illegal_username = "use";
//    result = authentication->RegisterUser(illegal_username,
//                                          pin,
//                                          password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, username  too short";
//    result = authentication->Login(illegal_username,
//                                   pin,
//                                   password,
//                                   &ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, username  too short";
//    illegal_username = "user1user1user1user1user1user1";
//    result = authentication->RegisterUser(illegal_username,
//                                          pin,
//                                          password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, username  too long";
//    result = authentication->Login(illegal_username,
//                                   pin,
//                                   password,
//                                   &ser_da);
//    EXPECT_EQ(INVALID_USERNAME, result)
//      << "Result not INVALID_USERNAME, username  too long";
//  }
//
//  TEST_F(AuthenticationTest, 47_IllegalPassword) {
//   //  Illegal password
//    std::string ser_da;
//    std::string illegal_password = "";
//    exitcode result = authentication->CreateUserSysPackets(username,
//                                                           pin,
//                                                           illegal_password,
//                                                           ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, empty password";
//    result = authentication->Login(username, pin, illegal_password, &ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, empty password";
//    illegal_password = "passw";
//    result = authentication->RegisterUser(username,
//                                          pin,
//                                          illegal_password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, password too short";
//    result = authentication->Login(username,
//                                   pin,
//                                   illegal_password,
//                                   &ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, password too short";
//    illegal_password = "password1password1password1";
//    result = authentication->RegisterUser(username,
//                                          pin,
//                                          illegal_password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, password too long";
//    result = authentication->Login(username, pin, illegal_password, &ser_da);
//    EXPECT_EQ(INVALID_PASSWORD, result)
//      << "Result not INVALID_PASSWORD, password too long";
//  }
//
//  TEST_F(AuthenticationTest, 48_IllegalPin) {
//    //  Illegal pin
//    std::string ser_da;
//    std::string illegal_pin="123";
//    exitcode result = authentication->CreateUserSysPackets(username,
//                                                           illegal_pin,
//                                                           password,
//                                                           ser_da);
//    EXPECT_EQ(INVALID_PIN, result)
//      << "Result not INVALID_PIN, pin too short";
//    result = authentication->Login(username,
//                                   illegal_pin,
//                                   password,
//                                   &ser_da);
//    EXPECT_EQ(INVALID_PIN, result)
//      << "Result not INVALID_PIN, pin too short";
//    illegal_pin = "12345";
//    result = authentication->RegisterUser(username,
//                                          illegal_pin,
//                                          password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_PIN, result) << "Result not INVALID_PIN, pin too long";
//    result = authentication->Login(username, illegal_pin, password, &ser_da);
//    EXPECT_EQ(INVALID_PIN, result) << "Result not INVALID_PIN, pin too long";
//    illegal_pin = "0000";
//    result = authentication->RegisterUser(username,
//                                          illegal_pin,
//                                          password,
//                                          &ser_da);
//    EXPECT_EQ(INVALID_PIN, result) << "Result not INVALID_PIN, pin is zero";
//    result = authentication->Login(username, illegal_pin, password, &ser_da);
//    EXPECT_EQ(INVALID_PIN, result) << "Result not INVALID_PIN, pin is zero";
//  }
//
//  TEST_F(AuthenticationTest, 49_SaveSession) {
//    dht::entry lasquis, pubkeys;
//    DataAtlas data_atlas;
//    std::string ser_da;
//    exitcode result = authentication->CreateUserSysPackets(username,
//                                                           pin,
//                                                           password,
//                                                           ser_da);
//    ASSERT_EQ(OK, result) << "Result not OK";
//    EXPECT_TRUE(data_atlas.ParseFromString(ser_da));
//
//    for (int i=0; i<data_atlas.keys_size(); i++){
//      Key key = data_atlas.keys(i);
//      switch (key.type()){
//        case maidsafe::ANMID:
//          lasquis["ANMID"] = key.private_key();
//          pubkeys["ANMID"] = key.public_key();
//          break;
//        case maidsafe::ANTMID:
//          lasquis["ANTMID"] = key.private_key();
//          pubkeys["ANTMID"] = key.public_key();
//          break;
//        case maidsafe::ANSMID:
//          lasquis["ANSMID"] = key.private_key();
//          pubkeys["ANSMID"] = key.public_key();
//          break;
//        default:;
//      }
//    }
//
//    long int midrid = ss->MidRid();
//    long int smidrid =ss->SmidRid();
//
//    ASSERT_EQ(OK, authentication->SaveSession(ser_da, lasquis, pubkeys))
//      << "Save failed";
//    ASSERT_EQ(smidrid,ss->SmidRid()) << "Smid rid not the same";
//    ASSERT_NE(midrid, ss->MidRid()) << "Mid still the same";
//
//    long int midrid2 = ss->MidRid();
//
//    ASSERT_EQ(OK, authentication->SaveSession(ser_da, lasquis, pubkeys))
//      << "Save failed";
//    ASSERT_EQ(midrid2,ss->SmidRid()) << "Smid rid not equal to last Mid rid";
//    ASSERT_NE(midrid2, ss->MidRid()) << "Mid still the same";
//  }
//
//  TEST_F(AuthenticationTest, 50_RemoveMe) {
//    DataAtlas data_atlas;
//    DataAtlasHandler dah;
//    std::string ser_da;
//    exitcode result = authentication->CreateUserSysPackets(username,
//                                                           pin,
//                                                           password,
//                                                           ser_da);
//    ASSERT_EQ(OK, result) << "Result not OK";
//
//    ASSERT_TRUE(dah.Init("DAH.db"));
//    ASSERT_TRUE(dah.ParseFromStringDataAtlas(ser_da)) << "No DA --> Db";
//
//    std::list<Key_Type> lasquis;
//    dah.GetKeyRing(lasquis);
//    EXPECT_EQ((unsigned int)4,lasquis.size()) << "Not all keys perhaps...";
//    ASSERT_EQ(OK, authentication->RemoveMe(lasquis))
//      << "Not completely removed from maidsafe network";
//    dah.Close();
//  }

TEST_F(AuthenticationTest, FUNC_MAID_ChangeUsername) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  DataAtlas data_atlas;
  std::string ser_da;
  packethandler::PacketParams lasquis, pubkeys;

  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  EXPECT_TRUE(data_atlas.ParseFromString(ser_da));

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case maidsafe::ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case maidsafe::ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case maidsafe::ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }

  ASSERT_EQ(OK, authentication->ChangeUsername(ser_da,
                                               lasquis,
                                               pubkeys,
                                               "el iuserneim"))
    << "Unable to change iuserneim";
  ASSERT_EQ("el iuserneim", ss->Username()) << "iuserneim is still the old one";
  std::string ser_da_login;
  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());

  result = authentication->GetUserInfo("el iuserneim", pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  wait_for_result_ta(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new iuserneim";

  printf("%s\t%s\t%s\n", username.c_str(), pin.c_str(), password.c_str());
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(NON_EXISTING_USER, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePin) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  std::string ser_da;
  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  EXPECT_TRUE(data_atlas.ParseFromString(ser_da));

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case maidsafe::ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case maidsafe::ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case maidsafe::ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }
  ASSERT_EQ(OK,
            authentication->ChangePin(ser_da, lasquis, pubkeys, "7894"))
    << "Unable to change pin";
  ASSERT_EQ("7894", ss->Pin()) << "pin is still the old one";
  std::string ser_da_login;
  result = authentication->GetUserInfo(username, "7894", boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_ta(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new pin";
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(NON_EXISTING_USER, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_ChangePassword) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams lasquis, pubkeys;
  DataAtlas data_atlas;
  std::string ser_da;
  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(NON_EXISTING_USER, result) << "User already exists";
  result = authentication->CreateUserSysPackets(username,
                                                pin,
                                                password,
                                                ser_da);
  ASSERT_EQ(OK, result)<< "Unable to register user";
  EXPECT_TRUE(data_atlas.ParseFromString(ser_da));

  for (int i = 0; i < data_atlas.keys_size(); ++i) {
    Key key = data_atlas.keys(i);
    switch (key.type()) {
      case maidsafe::ANMID:
        lasquis["ANMID"] = key.private_key();
        pubkeys["ANMID"] = key.public_key();
        break;
      case maidsafe::ANTMID:
        lasquis["ANTMID"] = key.private_key();
        pubkeys["ANTMID"] = key.public_key();
        break;
      case maidsafe::ANSMID:
        lasquis["ANSMID"] = key.private_key();
        pubkeys["ANSMID"] = key.public_key();
        break;
      default: {}
    }
  }
  ASSERT_EQ(OK,
            authentication->ChangePassword(ser_da,
                                           lasquis,
                                           pubkeys,
                                           "elpasguord"))
    << "Unable to change password";
  ASSERT_EQ("elpasguord", ss->Password()) << "Password is still the old one";
  std::string ser_da_login;

  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  cb.Reset();
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  wait_for_result_ta(cb, mutex);
  result = authentication->GetUserData("elpasguord", ser_da_login);
  ASSERT_EQ(OK, result) << "Can't login with new password";
  cb.Reset();
  result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  ASSERT_EQ(USER_EXISTS, result) << "User does not exist";
  wait_for_result_ta(cb, mutex);
  result = authentication->GetUserData(password, ser_da_login);
  ASSERT_EQ(PASSWORD_FAIL, result);
}

TEST_F(AuthenticationTest, BEH_MAID_CreatePublicName) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  packethandler::PacketParams result;
  maidsafe_crypto::Crypto crypto_obj;
  crypto_obj.set_symm_algorithm("AES_256");
  crypto_obj.set_hash_algorithm("SHA512");
  ASSERT_EQ(OK,
            authentication->CreatePublicName("el public iuserneim", &result))
    << "Can't create public username";
  ASSERT_EQ(PUBLIC_USERNAME_EXISTS,
            authentication->CreatePublicName("el public iuserneim", &result))
    << "Created public username twice";
}

TEST_F(AuthenticationTest, BEH_MAID_InvalidUsernamePassword) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::MidPacket *midPacket = static_cast<packethandler::MidPacket*>\
    (packethandler::PacketFactory::Factory(packethandler::MID));
  packethandler::PacketParams params;
  params["username"] = username;
  params["PIN"] = pin;
  std::string mid_name = midPacket->PacketName(params);
  sm->StorePacket(mid_name,
                            "rubish data with same mid name",
                            "",
                            "",
                            "",
                            DATA,
                            false,
                            boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_ta(cb, mutex);
  StoreResponse res;
  ASSERT_TRUE(res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, res.result());

  cb.Reset();
  boost::scoped_ptr<Authentication> authentication(
      new Authentication(sm.get(), mutex));
  exitcode result = authentication->GetUserInfo(username, pin, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  EXPECT_EQ(INVALID_USERNAME_PIN, result);
}

TEST_F(AuthenticationTest, FUNC_MAID_CreateMSIDPacket) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  boost::scoped_ptr<Authentication> authentication(new Authentication(
    sm.get(), mutex));
  maidsafe_crypto::Crypto co;
  co.set_symm_algorithm("AES_256");
  co.set_hash_algorithm("SHA512");
  std::string msid_name, pub_key, priv_key;
  cb.Reset();
  authentication->CreateMSIDPacket(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_ta(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  packethandler::CreateMSIDResult msid_result;
  ASSERT_TRUE(msid_result.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, msid_result.result());
  msid_name = msid_result.name();
  priv_key = msid_result.private_key();
  pub_key = msid_result.public_key();
  std::string empty_str("");
  cb.Reset();
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_NE(empty_str, msid_name);
  ASSERT_NE(empty_str, priv_key);
  ASSERT_NE(empty_str, pub_key);
  //Check the packet exits
  sm->LoadPacket(msid_name, boost::bind(&FakeCallback::CallbackFunc,\
    &cb, _1));
  wait_for_result_ta(cb, mutex);
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  packethandler::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(load_res.content()));

  //check packet is correct and signed
  ASSERT_EQ(pub_key, gp.data());
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(), pub_key,\
    maidsafe_crypto::STRING_STRING));
  ASSERT_EQ(co.Hash(pub_key+gp.signature(), "", maidsafe_crypto::STRING_STRING, true), msid_name);
}

}  // namespace maidsafe
