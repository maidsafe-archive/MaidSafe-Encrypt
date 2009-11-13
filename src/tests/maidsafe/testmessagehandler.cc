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
#include "fs/filesystem.h"
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
                           boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
};

class MsgHandlerTest : public testing::Test {
 public:
  MsgHandlerTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                    "/maidsafe_TestMsgHandler"),
                     crypto_obj(),
                     rsa_obj(),
                     private_key(rsa_obj.private_key()),
                     public_key(rsa_obj.public_key()),
                     public_username("el tonto smer"),
                     client_chunkstore_(),
                     sm(),
                     ss(),
                     mutex(),
                     cb() {}
  ~MsgHandlerTest() {}
 protected:
  void SetUp() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    mutex = new boost::mutex();
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
                         (new maidsafe::ChunkStore(test_root_dir_, 0, 0));
    boost::shared_ptr<maidsafe::LocalStoreManager>
        sm(new maidsafe::LocalStoreManager(client_chunkstore_));
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
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
    private_key = rsa_obj.private_key();
    public_key = rsa_obj.public_key();
    public_username = "el tonto smer";
    ss = maidsafe::SessionSingleton::getInstance();
    ss->AddKey(maidsafe::MPID, public_username, private_key, public_key, "");
    cb.Reset();
  }
  virtual void TearDown() {
    cb.Reset();
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    delete mutex;
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    ss->Destroy();
  }

  std::string test_root_dir_;
  crypto::Crypto crypto_obj;
  crypto::RsaKeyPair rsa_obj;
  std::string private_key;
  std::string public_key;
  std::string public_username;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  boost::shared_ptr<maidsafe::LocalStoreManager> sm;
  maidsafe::SessionSingleton *ss;
  boost::mutex *mutex;
  FakeCallback cb;
 private:
  explicit MsgHandlerTest(const MsgHandlerTest&);
  MsgHandlerTest &operator=(const MsgHandlerTest&);
};

TEST_F(MsgHandlerTest, BEH_MAID_SendAddContactRequest) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get());
  maidsafe::MessageHandler msghandler(sm.get());
  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
            public_key, private_key));

  // Creating keys of the sender
  std::string sender("sender");
  rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
  std::string sender_pubkey = rsa_obj.public_key();
  std::string sender_privkey = rsa_obj.private_key();

  // Creating bufferpacket of the sender
  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(sender,
            sender_pubkey, sender_privkey));

  // Creating MPID of the sender
  rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
  maidsafe::GenericPacket gp;
  gp.set_data(sender_pubkey);
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "", rsa_obj.private_key(),
                   crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  std::string signed_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                              rsa_obj.private_key(),
                              crypto::STRING_STRING);
  ASSERT_EQ(0, sm->StorePacket(crypto_obj.Hash(sender, "",
            crypto::STRING_STRING, true), ser_gp, maidsafe::MPID,
            maidsafe::PRIVATE, ""));

  ss->ResetSession();
  ss->AddKey(maidsafe::MPID, sender, sender_privkey, sender_pubkey, "");

  // Creating the sender's contact info
  maidsafe::ContactInfo ci;
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
  msghandler.SendMessage(ser_ci, recs, maidsafe::MPID,
                         maidsafe::ADD_CONTACT_RQST,
                         boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tmsgh(cb, mutex);
  maidsafe::StoreMessagesResult store_msg_result;
  ASSERT_TRUE(store_msg_result.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(store_msg_result.result()));
  ASSERT_EQ(1, store_msg_result.stored_msgs());
  ASSERT_EQ(0, store_msg_result.failed_size());
  cb.Reset();
  store_msg_result.Clear();

  std::set<std::string> users;
  users.insert(public_username);
  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  // Changing the session data to "el tonto smer"
  ss->ResetSession();
  ss->AddKey(maidsafe::MPID, public_username, private_key, public_key, "");

  // Getting buffer packet messages
  std::list<maidsafe::ValidatedBufferPacketMessage> valid_messages;
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
            &valid_messages));
  // Must have one message and no authorised users
  ASSERT_EQ(size_t(1), valid_messages.size());
  ASSERT_EQ(size_t(0), ss->AuthorisedUsers().size());

  // Get message and validate its ADD_CONTACT_RQST and contents
  maidsafe::ValidatedBufferPacketMessage vbpm = valid_messages.front();
  ASSERT_EQ(sender, vbpm.sender());
  ASSERT_EQ(maidsafe::ADD_CONTACT_RQST, vbpm.type());
  maidsafe::ContactInfo ci_ret;
  ASSERT_TRUE(ci_ret.ParseFromString(vbpm.message()));
  ASSERT_EQ(ci_ret.name(), "la puerca");
  ASSERT_EQ(ci_ret.birthday(), "12/12/1980");
  ASSERT_EQ(ci_ret.office_number(), "+44 4256214");
  ASSERT_EQ(ci_ret.gender(), "F");
  ASSERT_EQ(ci_ret.country(), 6);
  ASSERT_EQ(ci_ret.language(), 1);

  // Use the method to get messages only to verify message was deleted
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
                                                     &valid_messages));
  ASSERT_EQ(size_t(0), valid_messages.size());

  // Adding user to buffer packet's authorised users
  users.clear();
  users.insert(sender);
  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  // No more messages & one authorised user
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
            &valid_messages));
  ASSERT_EQ(size_t(0), valid_messages.size());
  ASSERT_EQ(size_t(1), ss->AuthorisedUsers().size());
  // TODO(Team#5#): 2009-07-10 - Maybe check the user is really the one added

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
  msghandler.SendMessage(ser_ci, recs, maidsafe::MPID, maidsafe::INSTANT_MSG,
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
  ss->AddKey(maidsafe::MPID, sender, sender_privkey, sender_pubkey, "");

  // Getting buffer packet messages
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
            &valid_messages));
  // Must have one message and no authorised users
  ASSERT_EQ(size_t(1), valid_messages.size());
  ASSERT_EQ(size_t(0), ss->AuthorisedUsers().size());
  cb.Reset();

  // Use the method to get messages only to verify message was deleted
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
                                                     &valid_messages));
  ASSERT_EQ(size_t(0), valid_messages.size());
}
