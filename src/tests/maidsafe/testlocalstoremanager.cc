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
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/utils.h>
#include <boost/filesystem/fstream.hpp>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

class FakeCallback {
 public:
  FakeCallback() : result_("") {}
  void CallbackFunc(const std::string &res) {
    result_ = res;
  }
  void Reset() {
    result_ = "";
  }
  std::string result_;
};

void wait_for_result_lsm(const FakeCallback &cb, boost::mutex *mutex) {
  while (true) {
    {
      boost::mutex::scoped_lock guard(*mutex);
      if (cb.result_ != "") {
        return;
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(5));
  }
};

class LocalStoreManagerTest : public testing::Test {
 public:
  LocalStoreManagerTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                           "/maidsafe_TestStoreManager"),
                            cb(),
                            client_chunkstore_(),
                            storemanager(),
                            crypto_obj(),
                            rsa_obj(),
                            mutex_(),
                            ss_(maidsafe::SessionSingleton::getInstance()) {}
  ~LocalStoreManagerTest() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }

 protected:
  void SetUp() {
    ss_->ResetSession();
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
        fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    mutex_ = new boost::mutex();
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
         (new maidsafe::ChunkStore(test_root_dir_, 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    storemanager = new maidsafe::LocalStoreManager(client_chunkstore_);
    // storemanager = new LocalStoreManager();
    storemanager->Init(0, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_lsm(cb, mutex_);
    maidsafe::GenericResponse res;
    ASSERT_TRUE(res.ParseFromString(cb.result_));
    if (res.result() == kNack) {
      FAIL();
      return;
    }
    ss_ = maidsafe::SessionSingleton::getInstance();
    crypto_obj.set_symm_algorithm(crypto::AES_256);
    crypto_obj.set_hash_algorithm(crypto::SHA_512);
    crypto::RsaKeyPair rsa_obj;
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
    ss_->AddKey(maidsafe::MPID, "Me", rsa_obj.private_key(),
                rsa_obj.public_key(), "");
    cb.Reset();
  }

  void TearDown() {
    ss_->ResetSession();
    cb.Reset();
    storemanager->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1),
                        true);
    wait_for_result_lsm(cb, mutex_);
    maidsafe::GenericResponse res;
    ASSERT_TRUE(res.ParseFromString(cb.result_));
    if (res.result() == kAck) {
      try {
        if (fs::exists(test_root_dir_))
          fs::remove_all(test_root_dir_);
        if (fs::exists(file_system::FileSystem::LocalStoreManagerDir()))
          fs::remove_all(file_system::FileSystem::LocalStoreManagerDir());
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }
  }

  std::string test_root_dir_;
  FakeCallback cb;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  maidsafe::LocalStoreManager *storemanager;
  crypto::Crypto crypto_obj;
  crypto::RsaKeyPair rsa_obj;
  boost::mutex *mutex_;
  maidsafe::SessionSingleton *ss_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreSystemPacket) {
  maidsafe::GenericPacket gp;
  rsa_obj.GenerateKeys(4096);
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "",
                  rsa_obj.private_key(), crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data() + gp.signature(), "",
                        crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(gp_name, false));
  std::string gp_content;
  gp.SerializeToString(&gp_content);
  ASSERT_EQ(0, storemanager->StorePacket(gp_name, gp_content,
      maidsafe::BUFFER, maidsafe::PRIVATE, ""));
  ASSERT_FALSE(storemanager->KeyUnique(gp_name, false));
  std::string result;
  storemanager->LoadPacket(gp_name, &result);
  maidsafe::GenericPacket gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(result));
  ASSERT_EQ(gp.data(), gp_res.data());
  ASSERT_EQ(gp.signature(), gp_res.signature());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_DeleteSystemPacketOwner) {
  maidsafe::GenericPacket gp;
  rsa_obj.GenerateKeys(4096);
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "", rsa_obj.private_key(),
                   crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data() + gp.signature(), "",
                        crypto::STRING_STRING, true);
  std::string gp_content;
  gp.SerializeToString(&gp_content);

  std::string signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                                  rsa_obj.private_key(), crypto::STRING_STRING);
  std::string non_hex_gp_name = base::DecodeFromHex(gp_name);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(
      rsa_obj.public_key() + signed_public_key + non_hex_gp_name, "",
      crypto::STRING_STRING, false),
      "", rsa_obj.private_key(), crypto::STRING_STRING);
  ASSERT_EQ(0, storemanager->StorePacket(gp_name, gp_content,
      maidsafe::BUFFER, maidsafe::PRIVATE, ""));

  ASSERT_FALSE(storemanager->KeyUnique(gp_name, false));
  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),
                             signed_public_key, maidsafe::SYSTEM_PACKET,
                             boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kAck, static_cast<int>(del_res.result()));
  cb.Reset();
  ASSERT_TRUE(storemanager->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_MAID_DeleteSystemPacketNotOwner) {
  maidsafe::GenericPacket gp;
  rsa_obj.GenerateKeys(4096);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "", private_key,
                   crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data() + gp.signature(), "",
                        crypto::STRING_STRING, true);
  std::string gp_content;
  gp.SerializeToString(&gp_content);
  std::string signed_public_key = crypto_obj.AsymSign(public_key, "",
                                  private_key, crypto::STRING_STRING);

  ASSERT_EQ(0, storemanager->StorePacket(gp_name, gp_content,
      maidsafe::BUFFER, maidsafe::PRIVATE, ""));
  ASSERT_FALSE(storemanager->KeyUnique(gp_name, false));

  // Creating new public/private keys
  rsa_obj.GenerateKeys(4096);

  signed_public_key = crypto_obj.AsymSign(public_key, "", rsa_obj.private_key(),
                      crypto::STRING_STRING);
  std::string non_hex_gp_name = base::DecodeFromHex(gp_name);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(
      rsa_obj.public_key() + signed_public_key + non_hex_gp_name, "",
      crypto::STRING_STRING, false), "", rsa_obj.private_key(),
      crypto::STRING_STRING);

  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),
                             signed_public_key, maidsafe::SYSTEM_PACKET,
                             boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kNack, static_cast<int>(del_res.result()));
  cb.Reset();
  del_res.Clear();

  ASSERT_FALSE(storemanager->KeyUnique(gp_name, false));
  signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                      rsa_obj.private_key(), crypto::STRING_STRING);

  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),
                signed_public_key, maidsafe::SYSTEM_PACKET,
                boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kNack, static_cast<int>(del_res.result()));
  cb.Reset();
  del_res.Clear();
  ASSERT_FALSE(storemanager->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreChunk) {
  std::string chunk_content = base::RandomString(256 * 1024);
  std::string non_hex_chunk_name = crypto_obj.Hash(chunk_content, "",
                                   crypto::STRING_STRING, false);
  std::string hex_chunk_name = base::EncodeToHex(non_hex_chunk_name);
  fs::path chunk_path(test_root_dir_);
  chunk_path /= hex_chunk_name;
  fs::ofstream ofs;
  ofs.open(chunk_path.string().c_str());
  ofs << chunk_content;
  ofs.close();
  client_chunkstore_->AddChunkToOutgoing(non_hex_chunk_name, chunk_path);
  ASSERT_TRUE(storemanager->KeyUnique(hex_chunk_name, false));
  storemanager->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");

  ASSERT_FALSE(storemanager->KeyUnique(hex_chunk_name, false));
  std::string result_str;
  ASSERT_EQ(0, storemanager->LoadChunk(hex_chunk_name, &result_str));
  ASSERT_EQ(chunk_content, result_str);
}

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreAndLoadBufferPacket) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, storemanager->CreateBP());
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  storemanager->LoadChunk(bufferpacketname, &packet_content);
  maidsafe::BufferPacket buffer_packet;
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  ASSERT_EQ(1, buffer_packet.owner_info_size());
  ASSERT_EQ(0, buffer_packet.messages_size());
  maidsafe::GenericPacket gp = buffer_packet.owner_info(0);
  ASSERT_TRUE(crypto_obj.AsymCheckSig(gp.data(), gp.signature(),
              ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  maidsafe::BufferPacketInfo bpi;
  ASSERT_TRUE(bpi.ParseFromString(gp.data()));
  ASSERT_EQ(ss_->Id(maidsafe::MPID), bpi.owner());
  ASSERT_EQ(ss_->PublicKey(maidsafe::MPID), bpi.ownerpublickey());
  ASSERT_EQ(1, bpi.online());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_ModifyBufferPacketInfo) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, storemanager->CreateBP());
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  storemanager->LoadChunk(bufferpacketname, &packet_content);
  maidsafe::BufferPacket buffer_packet;
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  ASSERT_EQ(1, buffer_packet.owner_info_size());
  ASSERT_EQ(0, buffer_packet.messages_size());
  maidsafe::GenericPacket gp = buffer_packet.owner_info(0);
  ASSERT_TRUE(crypto_obj.AsymCheckSig(gp.data(), gp.signature(),
              ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  maidsafe::BufferPacketInfo bpi;
  ASSERT_TRUE(bpi.ParseFromString(gp.data()));
  ASSERT_EQ(ss_->Id(maidsafe::MPID), bpi.owner());
  ASSERT_EQ(ss_->PublicKey(maidsafe::MPID), bpi.ownerpublickey());
  ASSERT_EQ(1, bpi.online());

  // Modifying the BP info
  maidsafe::BufferPacketInfo buffer_packet_info;
  std::string ser_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(true);
  buffer_packet_info.add_users("Juanito");
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, storemanager->ModifyBPInfo(ser_info));
  packet_content = "";
  ASSERT_EQ(0, storemanager->LoadChunk(bufferpacketname, &packet_content));
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  gp = buffer_packet.owner_info(0);
  std::string ser_gp;
  ASSERT_TRUE(gp.SerializeToString(&ser_gp));
  ASSERT_TRUE(crypto_obj.AsymCheckSig(gp.data(), gp.signature(),
              ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  ASSERT_EQ(ser_info, gp.data());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_AddAndGetBufferPacketMessages) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, storemanager->CreateBP());
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);
  buffer_packet_info.add_users(crypto_obj.Hash("Juanito", "",
                               crypto::STRING_STRING, false));
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, storemanager->ModifyBPInfo(ser_info));

  std::string me_pubusername = ss_->Id(maidsafe::MPID);
  std::string me_pubkey = ss_->PublicKey(maidsafe::MPID);
  std::string me_privkey = ss_->PrivateKey(maidsafe::MPID);
  std::string me_sigpubkey = crypto_obj.AsymSign(me_pubkey, "",
                             me_privkey, crypto::STRING_STRING);

  // Create the user "Juanito", add to session, then the message and send it
  ss_->ResetSession();
  crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(4096);
  std::string private_key = rsa_kp.private_key();
  std::string public_key = rsa_kp.public_key();
  std::string signed_public_key = crypto_obj.AsymSign(public_key, "",
                                  private_key, crypto::STRING_STRING);
  ss_->AddKey(maidsafe::MPID, "Juanito", private_key, public_key,
              signed_public_key);
  ASSERT_EQ(0, ss_->AddContact(me_pubusername, me_pubkey, "", "", "", 'U', 1, 2,
            "", 'C', 0, 0));

  std::vector<std::string> pulbicusernames;
  std::string test_msg("There are strange things done in the midnight sun");
  pulbicusernames.push_back(me_pubusername);
  ASSERT_EQ(0, storemanager->AddBPMessage(pulbicusernames, test_msg,
            maidsafe::INSTANT_MSG));

  // Retrive message and check that it is the correct one
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, me_pubusername, me_privkey, me_pubkey,
              me_sigpubkey);
  std::list<maidsafe::ValidatedBufferPacketMessage> messages;
  ASSERT_EQ(0, storemanager->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_NE("", messages.front().index());
  ASSERT_EQ(maidsafe::INSTANT_MSG, messages.front().type());

  // Check message is gone
  ASSERT_EQ(0, storemanager->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_AddRequestBufferPacketMessage) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, storemanager->CreateBP());
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string me_pubusername = ss_->Id(maidsafe::MPID);
  std::string me_pubkey = ss_->PublicKey(maidsafe::MPID);
  std::string me_privkey = ss_->PrivateKey(maidsafe::MPID);
  std::string me_sigpubkey = crypto_obj.AsymSign(me_pubkey, "",
                             me_privkey, crypto::STRING_STRING);

  // Create the user "Juanito", add to session, then the message and send it
  ss_->ResetSession();
  crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(4096);
  std::string private_key = rsa_kp.private_key();
  std::string public_key = rsa_kp.public_key();
  std::string signed_public_key = crypto_obj.AsymSign(public_key, "",
                                  private_key, crypto::STRING_STRING);
  ss_->AddKey(maidsafe::MPID, "Juanito", private_key, public_key,
              signed_public_key);
  ASSERT_EQ(0, ss_->AddContact(me_pubusername, me_pubkey, "", "", "", 'U', 1, 2,
            "", 'C', 0, 0));
  std::vector<std::string> pulbicusernames;
  std::string test_msg("There are strange things done in the midnight sun");
  pulbicusernames.push_back(me_pubusername);
  ASSERT_NE(0, storemanager->AddBPMessage(pulbicusernames, test_msg,
            maidsafe::INSTANT_MSG));
  ASSERT_EQ(0, storemanager->AddBPMessage(pulbicusernames, test_msg,
            maidsafe::ADD_CONTACT_RQST));

  // Back to "Me"
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, me_pubusername, me_privkey, me_pubkey,
              me_sigpubkey);
  std::list<maidsafe::ValidatedBufferPacketMessage> messages;
  ASSERT_EQ(0, storemanager->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_NE("", messages.front().index());
  ASSERT_EQ(maidsafe::ADD_CONTACT_RQST, messages.front().type());
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);
  buffer_packet_info.add_users(crypto_obj.Hash("Juanito", "",
                               crypto::STRING_STRING, false));
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, storemanager->ModifyBPInfo(ser_info));

  // Back to "Juanito"
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, "Juanito", private_key, public_key,
              signed_public_key);
  ASSERT_EQ(0, ss_->AddContact(me_pubusername, me_pubkey, "", "", "", 'U', 1, 2,
            "", 'C', 0, 0));
  pulbicusernames.clear();
  pulbicusernames.push_back(me_pubusername);
  ASSERT_EQ(0, storemanager->AddBPMessage(pulbicusernames, test_msg,
            maidsafe::INSTANT_MSG));

  // Back to "Me"
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, me_pubusername, me_privkey, me_pubkey,
              me_sigpubkey);
  messages.clear();
  ASSERT_EQ(0, storemanager->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_NE("", messages.front().index());
  ASSERT_EQ(maidsafe::INSTANT_MSG, messages.front().type());
}
