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
#include <maidsafe/utils.h>
#include <stdio.h>

#include <string>
#include <cstdlib>

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/clientbufferpackethandler.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_messages.pb.h"
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
    boost::this_thread::sleep(boost::posix_time::milliseconds(5));
  }
};

class ClientBufferPacketHandlerTest : public testing::Test {
 public:
  ClientBufferPacketHandlerTest() : crypto_obj(),
                                    rsa_obj(),
                                    private_key(),
                                    public_key(),
                                    public_username("el tonto smer"),
                                    public_key_signature(),
                                    client_chunkstore_(),
                                    sm(),
                                    ss(),
                                    mutex(),
                                    cb() {
    try {
      boost::filesystem::remove_all("./TestBuffer");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  ~ClientBufferPacketHandlerTest() {
    try {
      boost::filesystem::remove_all("./TestBuffer");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
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
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
         (new maidsafe::ChunkStore("./TestBuffer", 0, 0));
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    boost::shared_ptr<maidsafe::LocalStoreManager>
        sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
    sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_tbph(cb, mutex);
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    maidsafe::GenericResponse res;
    ASSERT_TRUE(res.ParseFromString(cb.result));
    if (res.result() == kNack) {
      FAIL();
      return;
    }
    crypto_obj.set_hash_algorithm(crypto::SHA_512);
    crypto_obj.set_symm_algorithm(crypto::AES_256);
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
    private_key = rsa_obj.private_key();
    public_key = rsa_obj.public_key();
    ss = maidsafe::SessionSingleton::getInstance();
    ss->AddKey(maidsafe::MPID, public_username, private_key, public_key, "");
    public_key_signature = ss->SignedPublicKey(maidsafe::MPID);
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
  std::string public_key_signature;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  boost::shared_ptr<maidsafe::LocalStoreManager> sm;
  maidsafe::SessionSingleton *ss;
  boost::recursive_mutex *mutex;
  FakeCallback cb;
 private:
  ClientBufferPacketHandlerTest(const ClientBufferPacketHandlerTest&);
  ClientBufferPacketHandlerTest &operator=
      (const ClientBufferPacketHandlerTest&);
};

/*
TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_CheckConnectionStatus) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
    sm(new maidsafe::LocalStoreManager(mutex));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  // Create the buffer packet
  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));
  ss->SetConnectionStatus(1);

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  // Add authorised users for BP querying
  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));
  add_users_res.Clear();

  // Get BP
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  maidsafe::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
  bpm.set_sender_id(usuarios[0]);
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("STATUS CHECK");
  bpm.set_rsaenc_key("AES_KEY");
  bpm.set_type(STATUS_CHECK);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);
  maidsafe::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg, "", rsa_obj.private_key(),
    crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  cb.Reset();
  std::string ser_up_bp;
  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                                  rsa_obj.private_key(),
                                  crypto::STRING_STRING);

  int status = -1;
  ASSERT_TRUE(vaultbufferpackethandler.CheckStatus(ser_bp, ser_msg,
              sig_sender_pubkey, &status));
  ASSERT_EQ(1, status);
}
*/
TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_CreateBufferPacket) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                mutex);
  maidsafe::GenericPacket ser_owner_info;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));
  ASSERT_FALSE(sm->KeyUnique(crypto_obj.Hash(public_username+"BUFFER", "",
      crypto::STRING_STRING, true), false));
  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(1, buffer_packet.owner_info_size()) << "User Info empty";
  ASSERT_TRUE(crypto_obj.AsymCheckSig(buffer_packet.owner_info(0).data(),
              buffer_packet.owner_info(0).signature(), public_key,
              crypto::STRING_STRING)) << "Invalid Signature";

  ASSERT_TRUE(buffer_packet_info.ParseFromString(
      buffer_packet.owner_info(0).data())) << "Incorrect serialization";
  ASSERT_EQ(public_username, buffer_packet_info.owner()) << "Incorrect owner";
  ASSERT_EQ(public_key, buffer_packet_info.ownerpublickey())
      << "Incorrect public key";
  ASSERT_EQ(1, buffer_packet_info.online())
      << "Incorrect connection status";
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_AddUsers) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username+"BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  cb.Reset();
  load_res.Clear();

  maidsafe::BufferPacketInfo bpi;
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";

  bpi.ParseFromString(buffer_packet.owner_info(0).data());
  ASSERT_EQ(3, bpi.users_size()) << "Not all users added";

  for (int i = 0; i < bpi.users_size(); ++i)
    ASSERT_TRUE(bpi.users(i) == usuarios[0] ||
                bpi.users(i) == usuarios[1] ||
                bpi.users(i) == usuarios[2]) << "User missing";
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_AddMessage) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  maidsafe::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
  bpm.set_sender_id(usuarios[0]);
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("mensaje tonto");
  bpm.set_rsaenc_key("AES_key");
  bpm.set_type(maidsafe::INSTANT_MSG);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);

  maidsafe::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg, "", rsa_obj.private_key(),
                       crypto::STRING_STRING));

  gp_msg.SerializeToString(&ser_msg);


  cb.Reset();
  std::string ser_up_bp;
  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(), "",
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
  bpm.set_type(maidsafe::INSTANT_MSG);
  bpm.SerializeToString(&ser_msg);

  maidsafe::GenericPacket gp_msg1;
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

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_AddMessageNonauthoUser) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username+"BUFFER",
                                  "",
                                  crypto::STRING_STRING, true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  maidsafe::BufferPacketMessage bpm;
  rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
  bpm.set_sender_id("SMER");
  bpm.set_sender_public_key(rsa_obj.public_key());
  bpm.set_aesenc_message("mensaje tonto");
  bpm.set_rsaenc_key("AES_key");
  bpm.set_type(maidsafe::INSTANT_MSG);
  std::string ser_msg;
  bpm.SerializeToString(&ser_msg);

  maidsafe::GenericPacket gp_msg;
  gp_msg.set_data(ser_msg);
  gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                          "",
                                          rsa_obj.private_key(),
                                          crypto::STRING_STRING));

  gp_msg.SerializeToString(&ser_msg);

  std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                                  rsa_obj.private_key(),
                                  crypto::STRING_STRING);
  std::string ser_up_bp;
  ASSERT_FALSE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
      sig_sender_pubkey, &ser_up_bp)) << "Unauthorised user added a msg";
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_CheckOwner) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  wait_for_result_tbph(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
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

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_DeleteUsers) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);


  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));
  ASSERT_TRUE(users == ss->AuthorisedUsers());
  ASSERT_EQ(size_t(3), ss->AuthorisedUsers().size());

  std::set<std::string> del_users;
  del_users.insert(usuarios[1]);

  ASSERT_EQ(0, clientbufferpackethandler.DeleteUsers(del_users,
                                                     maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  users.erase(usuarios[1]);
  ASSERT_EQ(size_t(2), ss->AuthorisedUsers().size()) << "User not deleted";
  ASSERT_TRUE(users == ss->AuthorisedUsers());

  buffer_packet.ParseFromString(ser_bp);
  buffer_packet_info.ParseFromString(buffer_packet.owner_info(0).data());
  ASSERT_EQ(2, buffer_packet_info.users_size());
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_CheckSignature) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp));
  ASSERT_TRUE(vaultbufferpackethandler.ValidateOwnerSignature(public_key,
    ser_bp)) << "Incorrectly signed";
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_GetMessages) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  std::string enc_msgs[3];
  maidsafe::BufferPacketMessage bpm;

  for (int i = 0; i < 3; ++i) {
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
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
    bpm.set_type(maidsafe::INSTANT_MSG);
    std::string ser_msg;
    bpm.SerializeToString(&ser_msg);

    maidsafe::GenericPacket gp_msg;
    gp_msg.set_data(ser_msg);
    gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                             "",
                                             rsa_obj.private_key(),
                                             crypto::STRING_STRING));

    gp_msg.SerializeToString(&ser_msg);

    std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                    "", rsa_obj.private_key(),
                                    crypto::STRING_STRING);
    std::string ser_up_bp;
    ASSERT_TRUE(vaultbufferpackethandler.AddMessage(ser_bp, ser_msg,
        sig_sender_pubkey, &ser_up_bp));
    ser_bp = ser_up_bp;
  }

  std::string signed_public_key = crypto_obj.AsymSign(public_key, "",
                                  private_key, crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(public_key +
                               signed_public_key + crypto_obj.Hash(
                               public_username + "BUFFER", "",
                               crypto::STRING_STRING, false), "",
                               crypto::STRING_STRING, false), "",
                               private_key, crypto::STRING_STRING);
  ASSERT_EQ(0, sm->StorePacket(crypto_obj.Hash(public_username + "BUFFER",
                                               "",
                                               crypto::STRING_STRING,
                                               true),
                               ser_bp,
                               maidsafe::BUFFER,
                               maidsafe::PRIVATE,
                               ""));
  ASSERT_TRUE(buffer_packet.ParseFromString(ser_bp)) << "Wrong serialization";
  ASSERT_EQ(3, buffer_packet.messages_size()) << "Incorrect number of messages";

  std::vector<std::string> msgs;
  ASSERT_TRUE(vaultbufferpackethandler.GetMessages(ser_bp, &msgs));
  ASSERT_EQ(size_t(3), msgs.size());
  for (unsigned int j = 0; j < 3; ++j) {
    maidsafe::ValidatedBufferPacketMessage msg;
    std::string ser_msg = msgs[j];
    msg.ParseFromString(ser_msg);
    EXPECT_EQ(usuarios[j], msg.sender());
    EXPECT_EQ(enc_msgs[j], msg.message());
  }

  std::list<maidsafe::ValidatedBufferPacketMessage> valid_messages;
  ASSERT_EQ(0, clientbufferpackethandler.GetMessages(maidsafe::MPID,
                                                     &valid_messages));
  int messages_size(valid_messages.size());
  ASSERT_EQ(3, messages_size);

  for (int k = 0; k < messages_size; ++k) {
    EXPECT_EQ(usuarios[k], valid_messages.front().sender());
    EXPECT_EQ("mensaje tonto " + base::itos(k + 1),
        valid_messages.front().message());
    valid_messages.pop_front();
//    ++k;
  }
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_ClearMessages) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Chupitos", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);


  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  std::string ser_bp = load_res.content();
  load_res.Clear();
  cb.Reset();

  std::string enc_msgs[3];
  maidsafe::BufferPacketMessage bpm;

  for (int i = 0; i < 3; ++i) {
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
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
    bpm.set_type(maidsafe::INSTANT_MSG);
    std::string ser_msg;
    bpm.SerializeToString(&ser_msg);

    maidsafe::GenericPacket gp_msg;
    gp_msg.set_data(ser_msg);
    gp_msg.set_signature(crypto_obj.AsymSign(ser_msg,
                                             "",
                                             rsa_obj.private_key(),
                                             crypto::STRING_STRING));

    gp_msg.SerializeToString(&ser_msg);


    std::string sig_sender_pubkey = crypto_obj.AsymSign(rsa_obj.public_key(),
                                    "", rsa_obj.private_key(),
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

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_ModifyUserInfo) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  maidsafe::VaultBufferPacketHandler vaultbufferpackethandler;
  maidsafe::BufferPacketInfo buffer_packet_info;
  maidsafe::BufferPacket buffer_packet;

  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));
  ASSERT_FALSE(sm->KeyUnique(crypto_obj.Hash(public_username + "BUFFER", "",
      crypto::STRING_STRING, true), false));
  cb.Reset();
  std::string packet_content;
  sm->LoadPacket(crypto_obj.Hash(public_username + "BUFFER",
                                 "",
                                 crypto::STRING_STRING,
                                 true),
                 &packet_content);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
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

  maidsafe::GenericPacket gp;
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

  maidsafe::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  maidsafe::BufferPacketInfo bpi_updated;
  ASSERT_TRUE(bpi_updated.ParseFromString(bp.owner_info(0).data()));
  ASSERT_EQ(3, bpi_updated.users_size());
  ASSERT_EQ(2, bpi_updated.online());
}

TEST_F(ClientBufferPacketHandlerTest, BEH_MAID_GetBufferPacket) {
  boost::scoped_ptr<maidsafe::LocalStoreManager>
      sm(new maidsafe::LocalStoreManager(mutex, client_chunkstore_));
  sm->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  maidsafe::ClientBufferPacketHandler clientbufferpackethandler(sm.get(),
                                                                     mutex);
  ASSERT_EQ(0, clientbufferpackethandler.CreateBufferPacket(public_username,
      public_key, private_key));

  clientbufferpackethandler.GetBufferPacket(maidsafe::MPID, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  maidsafe::GetMessagesResponse get_msgs_res;
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  ASSERT_EQ(0, get_msgs_res.messages_size());
  ASSERT_EQ(size_t(0), ss->AuthorisedUsers().size());
  cb.Reset();
  get_msgs_res.Clear();

  std::set<std::string> users;
  std::string usuarios[3] = {"Mambert", "Juanbert", "soy.tu.padre"};
  users.insert(usuarios[0]);
  users.insert(usuarios[1]);
  users.insert(usuarios[2]);

  ASSERT_EQ(0, clientbufferpackethandler.AddUsers(users, maidsafe::MPID));

  clientbufferpackethandler.GetBufferPacket(maidsafe::MPID, boost::bind(\
    &FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_tbph(cb, mutex);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_TRUE(get_msgs_res.ParseFromString(cb.result));
  ASSERT_EQ(kAck, static_cast<int>(get_msgs_res.result()));
  ASSERT_EQ(0, get_msgs_res.messages_size());
  ASSERT_EQ(size_t(3), ss->AuthorisedUsers().size());
  ASSERT_TRUE(users == ss->AuthorisedUsers());
}
