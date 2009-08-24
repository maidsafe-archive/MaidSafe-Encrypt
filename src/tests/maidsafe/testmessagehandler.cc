/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
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
#include <maidsafe/utils.h>
#include <cstdlib>
#include <string>
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/clientbufferpackethandler.h"
#include "maidsafe/client/messagehandler.h"
#include "maidsafe/client/packetfactory.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/packet.pb.h"

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

void wait_for_result_tmsgh(const FakeCallback &cb,
                           boost::recursive_mutex *mutex) {
  while (true) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
};

class MsgHandlerTest : public testing::Test {
 public:
  MsgHandlerTest() : crypto_obj(),
                     rsa_obj(),
                     private_key(rsa_obj.private_key()),
                     public_key(rsa_obj.public_key()),
                     public_username("el tonto smer"),
                     client_chunkstore_(),
                     sm(),
                     ss(),
                     mutex(),
                     cb() {
    try {
      boost::filesystem::remove_all("./TestMsgHandler");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  ~MsgHandlerTest() {
    try {
      boost::filesystem::remove_all("./TestMsgHandler");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
 protected:
  void SetUp() {
    mutex = new boost::recursive_mutex();
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
         (new maidsafe::ChunkStore("./TestMsgHandler", 0, 0));
    boost::shared_ptr<maidsafe::LocalStoreManager>
        sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_tmsgh(cb, mutex);
    maidsafe::GenericResponse result;
    if ((!result.ParseFromString(cb.result)) ||
        (result.result() == kNack)) {
      FAIL();
      return;
    }
    crypto_obj.set_hash_algorithm(crypto::SHA_512);
    crypto_obj.set_symm_algorithm(crypto::AES_256);
    rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
    private_key = rsa_obj.private_key();
    public_key = rsa_obj.public_key();
    public_username = "el tonto smer";
    ss = maidsafe::SessionSingleton::getInstance();
    ss->AddKey(maidsafe::MPID, public_username, private_key, public_key);
    cb.Reset();
  }
  virtual void TearDown() {
    cb.Reset();
    try {
      if (boost::filesystem::exists("KademilaDb.db"))
        boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
      if (boost::filesystem::exists("StoreChunks"))
        boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
    }
    catch(const std::exception &ex_) {
      printf("%s\n", ex_.what());
    }
    delete mutex;
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    ss->Destroy();
  }

  crypto::Crypto crypto_obj;
  crypto::RsaKeyPair rsa_obj;
  std::string private_key;
  std::string public_key;
  std::string public_username;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  boost::shared_ptr<maidsafe::LocalStoreManager> sm;
  maidsafe::SessionSingleton *ss;
  boost::recursive_mutex *mutex;
  FakeCallback cb;
 private:
  explicit MsgHandlerTest(const MsgHandlerTest&);
  MsgHandlerTest &operator=(const MsgHandlerTest&);
};

TEST_F(MsgHandlerTest, BEH_MAID_SendAddContact_Req) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::MessageHandler msghandler(sm.get(), mutex);
  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  maidsafe::StoreResponse store_result;
  ASSERT_TRUE(store_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_result.result()));
  cb.Reset();
  store_result.Clear();

  // Creating keys of the sender
  std::string sender("sender");
  rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
  std::string sender_pubkey = rsa_obj.public_key();
  std::string sender_privkey = rsa_obj.private_key();

  // Creating bufferpacket of the sender
  clientbufferpackethandler.CreateBufferPacket(sender, sender_pubkey,
    sender_privkey, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(store_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_result.result()));
  cb.Reset();
  store_result.Clear();


  // Creating MPID of the sender
  rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
  packethandler::GenericPacket gp;
  gp.set_data(sender_pubkey);
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "", rsa_obj.private_key(),
                   crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  std::string signed_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                              rsa_obj.private_key(),
                              crypto::STRING_STRING);
  sm->StorePacket(crypto_obj.Hash(sender, "", crypto::STRING_STRING,
                  true), ser_gp, crypto_obj.AsymSign(crypto_obj.Hash(
                  rsa_obj.public_key() + signed_pubkey + crypto_obj.Hash(
                  sender, "", crypto::STRING_STRING, false), "",
                  crypto::STRING_STRING, false), "",
                  rsa_obj.private_key(), crypto::STRING_STRING),
                  rsa_obj.public_key(), signed_pubkey, maidsafe::SYSTEM_PACKET,
                  false, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(store_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_result.result()));
  cb.Reset();
  store_result.Clear();


  ss->ResetSession();
  ss->AddKey(maidsafe::MPID, sender, private_key, public_key);

  // Creating the sender's contact info
  packethandler::ContactInfo ci;
  std::string ser_ci;
  ci.set_name("la puerca");
  ci.set_birthday("12/12/1980");
  ci.set_office_number("+44 4256214");
  ci.set_gender("F");
  ci.set_country(6);
  ci.set_language(1);
  ci.SerializeToString(&ser_ci);

  // Adding receiver "el tonto smer"
  maidsafe::Receivers rec;
  rec.id = public_username;
  rec.public_key = public_key;

  std::vector<maidsafe::Receivers> recs;
  recs.push_back(rec);

  //  Sending the message
  msghandler.SendMessage(ser_ci, recs, MPID_BP, packethandler::ADD_CONTACT_RQST,
                         boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  packethandler::StoreMessagesResult store_msg_result;
  ASSERT_TRUE(store_msg_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_msg_result.result()));
  ASSERT_EQ(1, store_msg_result.stored_msgs());
  ASSERT_EQ(0, store_msg_result.failed_size());
  cb.Reset();
  store_msg_result.Clear();

  std::set<std::string> users;
  users.insert(public_username);
  clientbufferpackethandler.AddUsers(users,
      boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tmsgh(cb, mutex);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(add_users_res.result()));
  cb.Reset();
  add_users_res.Clear();

  // Changing the session data to "el tonto smer"
  ss->ResetSession();
  ss->AddKey(maidsafe::MPID, public_username, private_key, public_key);

  // Getting buffer packet
  clientbufferpackethandler.GetBufferPacket(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  maidsafe::GetMessagesResponse get_msgs_res;
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  // Must have one message and no authorised users
  ASSERT_EQ(1, get_msgs_res.messages_size());
  ASSERT_EQ(size_t(0), ss->AuthorisedUsers().size());

  // Get message and validate its ADD_CONTACT_RQST and contents
  std::string ser_msg = get_msgs_res.messages(0);
  get_msgs_res.Clear();
  packethandler::ValidatedBufferPacketMessage vbpm;
  vbpm.ParseFromString(ser_msg);
  ASSERT_EQ(sender, vbpm.sender());
  ASSERT_EQ(packethandler::ADD_CONTACT_RQST, vbpm.type());
  packethandler::ContactInfo ci_ret;
  ASSERT_TRUE(ci_ret.ParseFromString(vbpm.message()));
  ASSERT_EQ(ci_ret.name(), "la puerca");
  ASSERT_EQ(ci_ret.birthday(), "12/12/1980");
  ASSERT_EQ(ci_ret.office_number(), "+44 4256214");
  ASSERT_EQ(ci_ret.gender(), "F");
  ASSERT_EQ(ci_ret.country(), 6);
  ASSERT_EQ(ci_ret.language(), 1);
  cb.Reset();

  // Use the method to get messages only to verify same message
  clientbufferpackethandler.GetMessages(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  ASSERT_EQ(1, get_msgs_res.messages_size());
  std::string ser_msg1 = get_msgs_res.messages(0);
  packethandler::ValidatedBufferPacketMessage vbpm1;
  vbpm1.ParseFromString(ser_msg1);
  ASSERT_EQ(sender, vbpm1.sender());
  ASSERT_EQ(packethandler::ADD_CONTACT_RQST, vbpm1.type());
  packethandler::ContactInfo ci_ret1;
  ASSERT_TRUE(ci_ret1.ParseFromString(vbpm1.message()));
  ASSERT_EQ(ci_ret1.name(), "la puerca");
  ASSERT_EQ(ci_ret1.birthday(), "12/12/1980");
  ASSERT_EQ(ci_ret1.office_number(), "+44 4256214");
  ASSERT_EQ(ci_ret1.gender(), "F");
  ASSERT_EQ(ci_ret1.country(), 6);
  ASSERT_EQ(ci_ret1.language(), 1);
  cb.Reset();

  // Adding user to buffer packet's authorised users
  users.clear();
  users.insert(sender);
  clientbufferpackethandler.AddUsers(users,
      boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(add_users_res.result()));
  cb.Reset();
  add_users_res.Clear();

  // Clearing the messages
  clientbufferpackethandler.ClearMessages(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  maidsafe::DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(del_res.result()));
  cb.Reset();
  del_res.Clear();

  // No more messages & one authorised user
  clientbufferpackethandler.GetBufferPacket(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  ASSERT_EQ(0, get_msgs_res.messages_size());
  ASSERT_EQ(size_t(1), ss->AuthorisedUsers().size());
  cb.Reset();
  get_msgs_res.Clear();
  // TODO(Dan#5#): 2009-07-10 - Maybe check the user is really the one added

  // // // // // // // // // // // // // //
  // Create the response for the request //
  // // // // // // // // // // // // // //

  // Creating the contact info
  ci.set_name("Danbert");
  ci.set_birthday("19/01/1960");
  ci.set_office_number("+44 8888 8888");
  ci.set_gender("M");
  ci.set_country(12);
  ci.set_language(2);
  ci.SerializeToString(&ser_ci);

  // Adding receiver "sender"
  rec.id = sender;
  rec.public_key = sender_pubkey;
  recs.clear();
  recs.push_back(rec);

  //  Sending the message
  msghandler.SendMessage(ser_ci, recs, MPID_BP, packethandler::INSTANT_MSG,
                         boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(store_msg_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_msg_result.result()));
  ASSERT_EQ(1, store_msg_result.stored_msgs());
  ASSERT_EQ(0, store_msg_result.failed_size());
  cb.Reset();
  store_msg_result.Clear();

  // Change session to "sender"
  ss->ResetSession();
  ss->AddKey(maidsafe::MPID, sender, private_key, public_key);

  // Getting buffer packet
  clientbufferpackethandler.GetBufferPacket(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  // Must have one message and no authorised users
  ASSERT_EQ(1, get_msgs_res.messages_size());
  ASSERT_EQ(size_t(1), ss->AuthorisedUsers().size());
  cb.Reset();
  get_msgs_res.Clear();

  // Use the method to get messages only to verify same message
  clientbufferpackethandler.GetMessages(MPID_BP, boost::bind(
      &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  printf("Messages: %i\n", get_msgs_res.messages_size());
  ASSERT_EQ(1, get_msgs_res.messages_size());
  ser_msg1 = get_msgs_res.messages(0);
  vbpm1.ParseFromString(ser_msg1);
  ASSERT_EQ(public_username, vbpm1.sender());
  ASSERT_EQ(packethandler::INSTANT_MSG, vbpm1.type());
  ASSERT_TRUE(ci_ret1.ParseFromString(vbpm1.message()));
  ASSERT_EQ(ci_ret1.name(), "Danbert");
  ASSERT_EQ(ci_ret1.birthday(), "19/01/1960");
  ASSERT_EQ(ci_ret1.office_number(), "+44 8888 8888");
  ASSERT_EQ(ci_ret1.gender(), "M");
  ASSERT_EQ(ci_ret1.country(), 12);
  ASSERT_EQ(ci_ret1.language(), 2);
  cb.Reset();
}
