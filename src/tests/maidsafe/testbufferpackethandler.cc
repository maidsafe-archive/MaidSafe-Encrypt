/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for client and vault buffer packet handling
* Version:      1.0
* Created:      2009-03-23-21.26.32
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
#include <stdio.h>

#include <string>
#include <cstdlib>

#include "base/utils.h"
#include "maidsafe/client/clientbufferpackethandler.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"


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

void wait_for_result_tbph(const FakeCallback &cb,
    boost::recursive_mutex *mutex) {
  while (true) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    base::sleep(0.005);
  }
};

class BufferPacketHandlerTest : public testing::Test {
 public:
  BufferPacketHandlerTest() : crypto_obj(),
                              rsa_obj(),
                              private_key(rsa_obj.private_key()),
                              public_key(rsa_obj.public_key()),
                              public_username("el tonto smer"),
                              sm(),
                              ss(),
                              mutex(),
                              cb() {}
 protected:
  virtual void SetUp() {
    try {
      if (boost::filesystem::exists("KademilaDb.db"))
        boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
      if (boost::filesystem::exists("StoreChunks"))
        boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
    }
    catch(const std::exception &ex_) {
      printf("%s\n", ex_.what());
    }
    mutex = new boost::recursive_mutex();
    boost::shared_ptr<maidsafe::LocalStoreManager>
        sm(new maidsafe::LocalStoreManager(mutex));
    sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_tbph(cb, mutex);
    base::sleep(0.5);
    base::GeneralResponse res;
    ASSERT_TRUE(res.ParseFromString(cb.result));
    if (res.result() == kCallbackFailure) {
      FAIL();
      return;
    }
    crypto_obj.set_hash_algorithm("SHA512");
    crypto_obj.set_symm_algorithm("AES_256");
    rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
    private_key =rsa_obj.private_key();
    public_key =rsa_obj.public_key();
    public_username = "el tonto smer";
    ss = maidsafe::SessionSingleton::getInstance();
    ss->SetPublicUsername(public_username);
    ss->SetPublicKey(public_key, MPID_BP);
    ss->SetPrivateKey(private_key, MPID_BP);
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
    base::sleep(1);
    ss->Destroy();
  }
  crypto::Crypto crypto_obj;
  crypto::RsaKeyPair rsa_obj;
  std::string private_key;
  std::string public_key;
  std::string public_username;
  boost::shared_ptr<maidsafe::LocalStoreManager> sm;
  maidsafe::SessionSingleton *ss;
  boost::recursive_mutex *mutex;
  FakeCallback cb;
 private:
  BufferPacketHandlerTest(const BufferPacketHandlerTest&);
  BufferPacketHandlerTest &operator=(const BufferPacketHandlerTest&);
};

 TEST_F(BufferPacketHandlerTest, BEH_MAID_CheckConnectionStatus) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
    sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  // Create the buffer packet
  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  ss->SetConnectionStatus(1);
  cb.Reset();
  store_res.Clear();

  ss->SetPublicUsername(public_username);
  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  // Add authorised users for BP querying
  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  // Get BP
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  packethandler::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
  bpm.set_sender_id(usuarios[0]);
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("STATUS CHECK");
  bpm.set_rsaenc_key("AES_KEY");
  bpm.set_type(packethandler::STATUS_CHECK);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);
  packethandler::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg, "", rsa_obj.private_key(),
    crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  cb.Reset();
  std::string ser_up_bp;
  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                                      "",
                                                      rsa_obj.private_key(),
                                                      crypto::STRING_STRING);

  int status = -1;
  ASSERT_TRUE(vaultbufferpackethandler.CheckStatus(ser_bp, ser_msg,
      sig_sender_pubkey, &status));
  ASSERT_EQ(1, status);

 }

TEST_F(BufferPacketHandlerTest, BEH_MAID_CreateBufferPacket) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::GenericPacket ser_owner_info;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;
  cb.Reset();

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  sm->IsKeyUnique(crypto_obj.Hash(public_username+"BUFFER",
                                  "",
                                  crypto::STRING_STRING,
                                  true),
                  boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  is_unique_res.Clear();
  cb.Reset();
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(1, buffer_packet.owner_info_size()) << "User Info empty";
  ASSERT_TRUE(crypto_obj.AsymCheckSig(buffer_packet.owner_info(0).data(),
                                      buffer_packet.owner_info(0).signature(),
                    public_key, crypto::STRING_STRING)) << "Invalid Signature";

  ASSERT_TRUE(buffer_packet_info.ParseFromString(
      buffer_packet.owner_info(0).data())) << "Incorrect serialization";
  ASSERT_EQ(public_username, buffer_packet_info.owner()) << "Incorrect owner";
  ASSERT_EQ(public_key, buffer_packet_info.ownerpublickey())
      << "Incorrect public key";
  ASSERT_EQ(1, buffer_packet_info.online())
      << "Incorrect connection status";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_AddUsers) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  ss->SetPublicUsername(public_username);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();

  sm->LoadPacket(crypto_obj.Hash(public_username+"BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  cb.Reset();
  load_res.Clear();

  packethandler::BufferPacketInfo bpi;
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";

  bpi.ParseFromString(buffer_packet.owner_info(0).data());
  ASSERT_EQ(3, bpi.users_size()) << "Not all users added";

  for (int i = 0; i < bpi.users_size(); ++i)
    ASSERT_TRUE(bpi.users(i) == usuarios[0] ||
                bpi.users(i) == usuarios[1] ||
                bpi.users(i) == usuarios[2]) << "User missing";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_AddMessage) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
    sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  ss->SetPublicUsername(public_username);
  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  packethandler::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
  bpm.set_sender_id(usuarios[0]);
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("mensaje tonto");
  bpm.set_rsaenc_key("AES_key");
  bpm.set_type(packethandler::SHARE);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);

  packethandler::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                          "",
                                          rsa_obj.private_key(),
                                          crypto::STRING_STRING));

  gp_msg.SerializeToString(&ser_msg);


  cb.Reset();
  std::string ser_up_bp;
  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                                      "",
                                                      rsa_obj.private_key(),
                                                      crypto::STRING_STRING);
  ASSERT_TRUE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
      sig_sender_pubkey, &ser_up_bp));
  ser_bp = ser_up_bp;

  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(1, buffer_packet.messages_size()) << "Incorrect number of messages";
  cb.Reset();

  bpm.clear_sender_id();
  bpm.set_sender_id(usuarios[1]);
  bpm.clear_aesenc_message();
  bpm.set_aesenc_message("mensaje tonto ver2");
  bpm.set_type(packethandler::SHARE);
  bpm.SerializeToString(&ser_msg);

  packethandler::GenericPacket gp_msg1;
  gp_msg1.set_data(ser_msg);
  gp_msg1.set_signature(crypto_obj.AsymSign(ser_msg,
                                            "",
                                            rsa_obj.private_key(),
                                            crypto::STRING_STRING));
  gp_msg1.SerializeToString(&ser_msg);
  cb.Reset();
  ASSERT_TRUE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
    sig_sender_pubkey, &ser_up_bp));
  ser_bp = ser_up_bp;

  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp))
      << "Incorrect serialization";
  ASSERT_EQ(2, buffer_packet.messages_size())
      << "Incorrect number of messages";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_AddMessageNonauthoUser) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  ss->SetPublicUsername(public_username);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username+"BUFFER",
                                  "",
                                  crypto::STRING_STRING, true),
                                  boost::bind(&FakeCallback::CallbackFunc,
                                  &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  packethandler::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
  bpm.set_sender_id("SMER");
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("mensaje tonto");
  bpm.set_rsaenc_key("AES_key");
  bpm.set_type(packethandler::SHARE);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);

  packethandler::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                          "",
                                          rsa_obj.private_key(),
                                          crypto::STRING_STRING));

  gp_msg.SerializeToString(&ser_msg);

  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                                      "",
                                                      rsa_obj.private_key(),
                                                      crypto::STRING_STRING);
  std::string ser_up_bp;
  ASSERT_FALSE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
      sig_sender_pubkey, &ser_up_bp)) << "Unauthorised user added a msg";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_CheckOwner) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  buffer_packet.ParseFromString(ser_bp);
  buffer_packet_info.ParseFromString(buffer_packet.owner_info(0).data());
  ASSERT_TRUE(vaultbufferpackethandler.IsOwner(public_username,
                                               buffer_packet.owner_info(0)))
      <<"incorrect owner";
  ASSERT_FALSE(vaultbufferpackethandler.IsOwner("el tooooonto esmer",
                                                buffer_packet.owner_info(0)))
      <<"unrecognised a wrong owner";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_DeleteUsers) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  ss->SetPublicUsername(public_username);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);


  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();
  base::sleep(0.1);
  ASSERT_TRUE(users == ss->AuthorisedUsers());

  std::set<std::string> del_users;
  del_users.insert(usuarios[1]);

  clientbufferpackethandler.DeleteUsers(del_users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, del_res.result());
  cb.Reset();
  del_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  users.erase(usuarios[1]);
  ASSERT_EQ(static_cast<unsigned int>(2), ss->AuthorisedUsers().size())
      << "User not deleted";
  ASSERT_TRUE(users == ss->AuthorisedUsers());

  buffer_packet.ParseFromString(ser_bp);
  buffer_packet_info.ParseFromString(buffer_packet.owner_info(0).data());
  ASSERT_EQ(2, buffer_packet_info.users_size());
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_CheckSignature) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp));
  ASSERT_TRUE(vaultbufferpackethandler.ValidateOwnerSignature(public_key,
    ser_bp)) << "Incorrectly signed";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_GetMessages) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  maidsafe::SessionSingleton *ss = maidsafe::SessionSingleton::getInstance();
  ss->SetPublicUsername(public_username);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  std::string enc_msgs[3];
  packethandler::BufferPacketMessage bpm;

  for (int i = 0; i < 3; ++i) {
    rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
    bpm.set_sender_id(usuarios[i]);
    bpm.set_sender_public_key(rsa_obj.public_key());
    bpm.set_rsaenc_key(crypto_obj.AsymEncrypt("AES_key",
                                              "",
                                              public_key,
                                              crypto::STRING_STRING));
    enc_msgs[i] = crypto_obj.SymmEncrypt("mensaje tonto " + base::itos(i + 1),
                                         "",
                                         crypto::STRING_STRING,
                                         "AES_key");
    bpm.set_aesenc_message(enc_msgs[i]);
    bpm.set_type(packethandler::SHARE);
    std::string ser_msg;
    bpm.SerializeToString(&ser_msg);

    packethandler::GenericPacket gp_msg;
    gp_msg.set_data(ser_msg);
    gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                             "",
                                             rsa_obj.private_key(),
                                             crypto::STRING_STRING));

    gp_msg.SerializeToString(&ser_msg);

    std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                                        "",
                                                        rsa_obj.private_key(),
                                                        crypto::STRING_STRING);
    std::string ser_up_bp;
    ASSERT_TRUE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
        sig_sender_pubkey, &ser_up_bp));
    ser_bp = ser_up_bp;
  }

  std::string signed_public_key = crypto_obj.AsymSign(public_key,
                                                      "",
                                                      private_key,
                                                      crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(
      public_key+signed_public_key+crypto_obj.Hash(public_username+"BUFFER",
                                                   "",
                                                   crypto::STRING_STRING,
                                                   true),
      "",
      crypto::STRING_STRING,
      true), "", private_key, crypto::STRING_STRING);
  sm->StorePacket(crypto_obj.Hash(public_username + "BUFFER",
                                  "",
                                  crypto::STRING_STRING,
                                  true),
                  ser_bp,
                  signed_request,
                  public_key,
                  signed_public_key,
                  maidsafe::BUFFER_PACKET,
                  true,
                  boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(3, buffer_packet.messages_size()) << "Incorrect number of messages";

  std::vector<std::string> msgs;
  ASSERT_TRUE(vaultbufferpackethandler.GetMessages(ser_bp, &msgs));
  ASSERT_EQ(static_cast<unsigned int>(3), msgs.size());
  for (unsigned int j = 0; j < 3; ++j) {
    packethandler::ValidatedBufferPacketMessage msg;
    std::string ser_msg = msgs[j];
    msg.ParseFromString(ser_msg);
    EXPECT_EQ(usuarios[j], msg.sender());
    EXPECT_EQ(enc_msgs[j], msg.message());
  }

  std::vector<std::string> dec_msgs;
  clientbufferpackethandler.GetMessages(MPID_BP,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetMessagesResponse get_msg_res;
  ASSERT_TRUE(get_msg_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, get_msg_res.result());
  base::sleep(2);
  ASSERT_EQ(3, get_msg_res.messages_size());

  for (int j = 0; j < get_msg_res.messages_size(); ++j) {
    packethandler::ValidatedBufferPacketMessage msg;
    std::string ser_msg = get_msg_res.messages(j);
    msg.ParseFromString(ser_msg);
    EXPECT_EQ(usuarios[j], msg.sender());
    EXPECT_EQ("mensaje tonto "+ base::itos(j+1), msg.message());
    ++j;
  }
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_ClearMessages) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  maidsafe::SessionSingleton *ss = maidsafe::SessionSingleton::getInstance();
  ss->SetPublicUsername(public_username);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);


  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  std::string enc_msgs[3];
  packethandler::BufferPacketMessage bpm;

  for (int i = 0; i < 3; ++i) {
    rsa_obj.GenerateKeys(packethandler::kRsaKeySize);
    bpm.set_sender_id(usuarios[i]);
    bpm.set_sender_public_key(rsa_obj.public_key());
    bpm.set_rsaenc_key(crypto_obj.AsymEncrypt("AES_key",
                                              "",
                                              public_key,
                                              crypto::STRING_STRING));
    enc_msgs[i] = crypto_obj.SymmEncrypt("mensaje tonto "+ base::itos(i+1),
                                         "",
                                         crypto::STRING_STRING,
                                         "AES_key");
    bpm.set_aesenc_message(enc_msgs[i]);
    bpm.set_type(packethandler::SHARE);
    std::string ser_msg;
    bpm.SerializeToString(&ser_msg);

    packethandler::GenericPacket gp_msg;
    gp_msg.set_data(ser_msg);
    gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                             "",
                                             rsa_obj.private_key(),
                                             crypto::STRING_STRING));

    gp_msg.SerializeToString(&ser_msg);


    std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                                        "",
                                                        rsa_obj.private_key(),
                                                        crypto::STRING_STRING);
    std::string ser_up_bp;
    ASSERT_TRUE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
        sig_sender_pubkey, &ser_up_bp));
    ser_bp = ser_up_bp;
  }


  ASSERT_TRUE(vaultbufferpackethandler.ClearMessages(&ser_bp));
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(0, buffer_packet.messages_size()) << "Messages not deleted";
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_ModifyUserInfo) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  packethandler::VaultBufferPacketHandler vaultbufferpackethandler;
  packethandler::BufferPacketInfo buffer_packet_info;
  packethandler::BufferPacket buffer_packet;

  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  sm->IsKeyUnique(crypto_obj.Hash(public_username + "BUFFER",
                                  "",
                                  crypto::STRING_STRING,
                                  true),
                  boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  base::GeneralResponse is_unique_res;
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  is_unique_res.Clear();
  cb.Reset();

  cb.Reset();
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  buffer_packet.ParseFromString(ser_bp);
  buffer_packet_info.ParseFromString(buffer_packet.owner_info(0).data());
  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);
  buffer_packet_info.add_users(usuarios[0]);
  buffer_packet_info.add_users(usuarios[1]);
  buffer_packet_info.add_users(usuarios[2]);
  buffer_packet_info.set_online(2);
  std::string ser_owner_info;
  buffer_packet_info.SerializeToString(&ser_owner_info);

  packethandler::GenericPacket gp;
  gp.set_data(ser_owner_info);
  gp.set_signature(crypto_obj.AsymSign(gp.data(),
                                      "",
                                      public_key,
                                      crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  ASSERT_TRUE(vaultbufferpackethandler.ChangeOwnerInfo(ser_gp,
                                                      &ser_bp,
                                                      public_key));

  packethandler::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  packethandler::BufferPacketInfo bpi_updated;
  ASSERT_TRUE(bpi_updated.ParseFromString(bp.owner_info(0).data()));
  ASSERT_EQ(3, bpi_updated.users_size());
  ASSERT_EQ(2, bpi_updated.online());
}

TEST_F(BufferPacketHandlerTest, BEH_MAID_GetBufferPacket) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  packethandler::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  clientbufferpackethandler.CreateBufferPacket(public_username, public_key,
    private_key, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  clientbufferpackethandler.GetBufferPacket(MPID_BP, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::GetMessagesResponse get_msgs_res;
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, get_msgs_res.result());
  ASSERT_EQ(0, get_msgs_res.messages_size());
  ASSERT_EQ(static_cast<unsigned int>(0), ss->AuthorisedUsers().size());
  cb.Reset();
  get_msgs_res.Clear();

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Juanbert", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  clientbufferpackethandler.AddUsers(users,
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1), MPID_BP);
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  maidsafe::UpdateResponse add_users_res;
  ASSERT_TRUE(add_users_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, add_users_res.result());
  cb.Reset();
  add_users_res.Clear();

  clientbufferpackethandler.GetBufferPacket(MPID_BP, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  base::sleep(0.5);
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, get_msgs_res.result());
  ASSERT_EQ(0, get_msgs_res.messages_size());
  ASSERT_EQ(static_cast<unsigned int>(3), ss->AuthorisedUsers().size());
  ASSERT_TRUE(users == ss->AuthorisedUsers());
}


