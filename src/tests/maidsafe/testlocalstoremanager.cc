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

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

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

class StoreManagerTest : public testing::Test {
 public:
  StoreManagerTest() : cb(), client_chunkstore_(), storemanager(),
      crypto_obj(), rsa_obj(), mutex_(),
      ss_(maidsafe::SessionSingleton::getInstance()) {
    try {
      boost::filesystem::remove_all("./TestStoreManager");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  ~StoreManagerTest() {
    try {
      boost::filesystem::remove_all("./TestStoreManager");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
 protected:
  void SetUp() {
    ss_->ResetSession();
    try {
      if (boost::filesystem::exists("KademilaDb.db"))
        boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
      if (boost::filesystem::exists("StoreChunks"))
        boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    mutex_ = new boost::mutex();
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
         (new maidsafe::ChunkStore("./TestStoreManager", 0, 0));
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
    crypto_obj.set_symm_algorithm(crypto::AES_256);
    crypto_obj.set_hash_algorithm(crypto::SHA_512);
    crypto::RsaKeyPair rsa_obj;
    rsa_obj.GenerateKeys(maidsafe::kRsaKeySize);
    maidsafe::SessionSingleton::getInstance()->AddKey(
        maidsafe::MPID, "Me", rsa_obj.private_key(), rsa_obj.public_key(), "");
    cb.Reset();
  }
  void TearDown() {
    cb.Reset();
    storemanager->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1),
                        true);
    wait_for_result_lsm(cb, mutex_);
    maidsafe::GenericResponse res;
    ASSERT_TRUE(res.ParseFromString(cb.result_));
    if (res.result() == kAck) {
      try {
        if (boost::filesystem::exists("KademilaDb.db"))
          boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
        if (boost::filesystem::exists("StoreChunks"))
          boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }
  }
  FakeCallback cb;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  maidsafe::LocalStoreManager *storemanager;
  crypto::Crypto crypto_obj;
  crypto::RsaKeyPair rsa_obj;
  boost::mutex *mutex_;
  maidsafe::SessionSingleton *ss_;
 private:
  StoreManagerTest(const StoreManagerTest&);
  StoreManagerTest &operator=(const StoreManagerTest&);
};

TEST_F(StoreManagerTest, BEH_MAID_StoreSystemPacket) {
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
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(result));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  ASSERT_EQ(gp_content, load_res.content());
}

TEST_F(StoreManagerTest, BEH_MAID_DeleteSystemPacket) {
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
  std::string non_hex_gp_name("");
  base::decode_from_hex(gp_name, &non_hex_gp_name);
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

TEST_F(StoreManagerTest, BEH_MAID_DeleteSystemPacketNotOwner) {
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
  std::string non_hex_gp_name;
  base::decode_from_hex(gp_name, &non_hex_gp_name);
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

TEST_F(StoreManagerTest, BEH_MAID_StoreChunk) {
  std::string chunk_content = base::RandomString(256 * 1024);
  std::string non_hex_chunk_name = crypto_obj.Hash(chunk_content, "",
                                   crypto::STRING_STRING, false);
  std::string hex_chunk_name;
  base::encode_to_hex(non_hex_chunk_name, &hex_chunk_name);
  fs::path chunk_path("./TestStoreManager");
  chunk_path /= hex_chunk_name;
  boost::filesystem::ofstream ofs;
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

TEST_F(StoreManagerTest, BEH_MAID_StoreAndLoadBufferPacket) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "",
                                ss_->PrivateKey(maidsafe::MPID),
                                crypto::STRING_STRING));

  std::string ser_bp;
  buffer_packet.SerializeToString(&ser_bp);

  ASSERT_EQ(0, storemanager->CreateBP(bufferpacketname, ser_bp));
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  storemanager->LoadChunk(bufferpacketname, &packet_content);
  ASSERT_EQ(ser_bp.size(), packet_content.size());
}

TEST_F(StoreManagerTest, BEH_MAID_ModifyBufferPacketInfo) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "",
                                ss_->PrivateKey(maidsafe::MPID),
                                crypto::STRING_STRING));

  std::string ser_bp;
  buffer_packet.SerializeToString(&ser_bp);

  ASSERT_EQ(0, storemanager->CreateBP(bufferpacketname, ser_bp));
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  ASSERT_EQ(0, storemanager->LoadChunk(bufferpacketname, &packet_content));
  ASSERT_EQ(ser_bp.size(), packet_content.size());

  // Modifying the BP info
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(true);
  buffer_packet_info.add_users("Juanito");
  buffer_packet_info.SerializeToString(&ser_info);
  maidsafe::GenericPacket info_gp;
  info_gp.set_data(ser_info);
  info_gp.set_signature(crypto_obj.AsymSign(ser_info, "",
                        ss_->PrivateKey(maidsafe::MPID),
                        crypto::STRING_STRING));
  std::string ser_info_gp;
  info_gp.SerializeToString(&ser_info_gp);
  ASSERT_EQ(0, storemanager->ModifyBPInfo(bufferpacketname, ser_info_gp));
  packet_content = "";
  ASSERT_EQ(0, storemanager->LoadChunk(bufferpacketname, &packet_content));
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  maidsafe::GenericPacket gp = buffer_packet.owner_info(0);
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  ASSERT_EQ(ser_info_gp, ser_gp);
}

TEST_F(StoreManagerTest, BEH_MAID_AddAndGetBufferPacketMessages) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);
  buffer_packet_info.add_users("Juanito");

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "",
                                ss_->PrivateKey(maidsafe::MPID),
                                crypto::STRING_STRING));

  std::string ser_bp;
  buffer_packet.SerializeToString(&ser_bp);

  ASSERT_EQ(0, storemanager->CreateBP(bufferpacketname, ser_bp));
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));

  // Create the user "Juanito", then the message and send it
  crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(4096);
  std::string private_key = rsa_kp.private_key();
  std::string public_key = rsa_kp.public_key();
  std::string signed_public_key = crypto_obj.AsymSign(public_key, "",
                                  private_key, crypto::STRING_STRING);

  std::string key("AESkey");
  maidsafe::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id("Juanito");
  bpmsg.set_rsaenc_key(crypto_obj.AsymEncrypt(key, "", public_key,
                       crypto::STRING_STRING));
  bpmsg.set_aesenc_message(crypto_obj.SymmEncrypt("test msg", "",
                           crypto::STRING_STRING, key));
  bpmsg.set_type(maidsafe::INSTANT_MSG);
  bpmsg.set_sender_public_key(public_key);
  std::string ser_bpmsg;
  ASSERT_TRUE(bpmsg.SerializeToString(&ser_bpmsg));
  maidsafe::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(crypto_obj.AsymSign(ser_bpmsg, "", private_key,
                         crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  ASSERT_TRUE(bpmsg_gp.SerializeToString(&ser_bpmsg_gp));
  ASSERT_EQ(0, storemanager->AddBPMessage(bufferpacketname, ser_bpmsg_gp));

  // Retrive message and check that it is the correct one
  std::list<std::string> messages;
  ASSERT_EQ(0, storemanager->LoadBPMessages(bufferpacketname, &messages));
  ASSERT_EQ(1, messages.size());
  maidsafe::ValidatedBufferPacketMessage vbpm;
  ASSERT_TRUE(vbpm.ParseFromString(messages.front()));
  ASSERT_EQ("Juanito", vbpm.sender());
  ASSERT_EQ(bpmsg.aesenc_message(), vbpm.message());
  ASSERT_EQ(bpmsg.rsaenc_key(), vbpm.index());
  ASSERT_EQ(maidsafe::INSTANT_MSG, vbpm.type());

  // Check message is gone
  ASSERT_EQ(0, storemanager->LoadBPMessages(bufferpacketname, &messages));
  ASSERT_EQ(0, messages.size());
}

/*
TEST_F(StoreManagerTest, BEH_MAID_DeleteBufferPacketNotOwner) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "",
                                ss_->PrivateKey(maidsafe::MPID),
                                crypto::STRING_STRING));

  std::string ser_bp;
  buffer_packet.SerializeToString(&ser_bp);

  ASSERT_EQ(0, storemanager->CreateBP(bufferpacketname, ser_bp));
  std::string s;
  std::cin >> s;

  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));

  crypto::RsaKeyPair rsa_obj;
  rsa_obj.GenerateKeys(4096);
  std::string signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(), "",
                                   rsa_obj.private_key(),
                                   crypto::STRING_STRING);
  std::string non_hex_bufferpacketname;
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(
      rsa_obj.public_key() + signed_public_key1 + non_hex_bufferpacketname, "",
      crypto::STRING_STRING, false), "", rsa_obj.private_key(),
      crypto::STRING_STRING);
  storemanager->DeletePacket(bufferpacketname, signed_request,
      rsa_obj.public_key(), signed_public_key1, maidsafe::BUFFER_PACKET,
      boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kNack, static_cast<int>(del_res.result()));
  cb.Reset();
  del_res.Clear();
}

TEST_F(StoreManagerTest, BEH_MAID_Add_Get_Clear_BufferPacket_Msgs) {
  std::string bufferpacketname = crypto_obj.Hash(ss_->Id(maidsafe::MPID) +
                                 ss_->PublicKey(maidsafe::MPID), "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(maidsafe::MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(maidsafe::MPID));
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "",
                                ss_->PrivateKey(maidsafe::MPID),
                                crypto::STRING_STRING));

  std::string ser_bp;
  buffer_packet.SerializeToString(&ser_bp);

  ASSERT_EQ(0, storemanager->CreateBP(bufferpacketname, ser_bp));
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));




  std::string owner_id("Juan U. Smer");
  crypto::RsaKeyPair rsa_kp;
  rsa_kp1.GenerateKeys(4096);
  rsa_obj.GenerateKeys(4096);
  std::string private_key = rsa_kp.private_key();
  std::string public_key = rsa_kp.public_key();

  std::string signed_public_key = crypto_obj.AsymSign(sig_public_key, "",
                                  sig_private_key, crypto::STRING_STRING);

  crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(4096);
  std::string sender_mpid_privkey = rsa_kp.private_key();
  std::string sender_mpid_pubkey = rsa_kp.public_key();


  // storing MPID package for the sender
  maidsafe::GenericPacket sender_mpid;
  sender_mpid.set_data(sender_mpid_pubkey);
  sender_mpid.set_signature(crypto_obj.AsymSign(sender_mpid_pubkey, "",
                            sig_private_key, crypto::STRING_STRING));
  std::string sender_ser_mpid;
  sender_mpid.SerializeToString(&sender_ser_mpid);
  std::string sender("sender");
  std::string sender_mpid_name = crypto_obj.Hash(sender, "",
                                                 crypto::STRING_STRING, true);

  ASSERT_EQ(0, storemanager->StorePacket(sender_mpid_name, sender_ser_mpid,
      maidsafe::MPID, maidsafe::PRIVATE, ""));

  // rsa_obj.GenerateKeys(4096);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();
  ASSERT_NE(public_key, sender_mpid.data());
  ASSERT_NE(private_key, sender_mpid_privkey);

  std::string bufferpacketname = crypto_obj.Hash(owner_id + "BUFFER", "",
                                 crypto::STRING_STRING, true);
  ASSERT_TRUE(storemanager->KeyUnique(bufferpacketname, false));
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info, "", private_key,
                                crypto::STRING_STRING));
  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  std::string ser_bp = ser_packet;

  signed_public_key = crypto_obj.AsymSign(public_key, "", private_key,
                                          crypto::STRING_STRING);

  ASSERT_EQ(0, storemanager->StorePacket(bufferpacketname, ser_bp,
      maidsafe::BUFFER, maidsafe::PRIVATE, ""));
  ASSERT_FALSE(storemanager->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  storemanager->LoadPacket(bufferpacketname, &packet_content);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  ASSERT_EQ(ser_bp, load_res.content());

  // Creating msgs to insert
  std::string key("AESkey");
  maidsafe::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(sender);
  bpmsg.set_rsaenc_key(crypto_obj.AsymEncrypt(key, "", public_key,
                       crypto::STRING_STRING));
  bpmsg.set_aesenc_message(crypto_obj.SymmEncrypt("test msg", "",
                           crypto::STRING_STRING, key));
  bpmsg.set_type(maidsafe::INSTANT_MSG);
  bpmsg.set_sender_public_key(sender_mpid_pubkey);
  std::string ser_bpmsg;
  bpmsg.SerializeToString(&ser_bpmsg);
  maidsafe::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(crypto_obj.AsymSign(ser_bpmsg, "", sender_mpid_privkey,
                         crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  bpmsg_gp.SerializeToString(&ser_bpmsg_gp);

  signed_public_key = crypto_obj.AsymSign(sender_mpid.data(), "",
                      sender_mpid_privkey, crypto::STRING_STRING);

  ASSERT_NE(0, storemanager->StorePacket("incorrect name", ser_bpmsg_gp,
      maidsafe::BUFFER_MESSAGE, maidsafe::PRIVATE, ""));

  ASSERT_NE(0, storemanager->StorePacket(bufferpacketname, ser_bpmsg_gp,
      maidsafe::BUFFER_MESSAGE, maidsafe::PRIVATE, ""));

  // Checking the bp has not been modified
  packet_content = "";
  storemanager->LoadPacket(bufferpacketname, &packet_content);
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  ASSERT_EQ(ser_bp, load_res.content());
  cb.Reset();

  // Changing the msg type
  bpmsg.set_type(maidsafe::ADD_CONTACT_RQST);
  bpmsg.set_sender_public_key(sender_mpid_pubkey);
  bpmsg.SerializeToString(&ser_bpmsg);
  bpmsg_gp.clear_data();
  bpmsg_gp.clear_signature();
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(crypto_obj.AsymSign(ser_bpmsg, "", sender_mpid_privkey,
                         crypto::STRING_STRING));
  bpmsg_gp.SerializeToString(&ser_bpmsg_gp);
  ASSERT_EQ(0, storemanager->StorePacket(bufferpacketname, ser_bpmsg_gp,
      maidsafe::BUFFER_MESSAGE, maidsafe::PRIVATE, ""));

  // Checking if new buffer packet has the msg
  packet_content = "";
  storemanager->LoadPacket(bufferpacketname, &packet_content);
  ASSERT_TRUE(load_res.ParseFromString(packet_content));
  ASSERT_EQ(kAck, static_cast<int>(load_res.result()));
  ser_bp = load_res.content();
  maidsafe::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  ASSERT_EQ(1, bp.messages_size());
  load_res.Clear();
  cb.Reset();

  // Getting the msgs
  std::string sig_mpid_pubkey = crypto_obj.AsymSign(sender_mpid.data(), "",
                                sender_mpid_privkey, crypto::STRING_STRING);
  std::list<std::string> messages;
  ASSERT_NE(0, storemanager->LoadBPMessages(bufferpacketname, &messages));

  messages.push_back("Jibber");
  messages.push_back("Jabber");
  signed_public_key = crypto_obj.AsymSign(public_key, "", private_key,
                      crypto::STRING_STRING);
  ASSERT_EQ(0, storemanager->LoadBPMessages(bufferpacketname, &messages));
  ASSERT_EQ(size_t(1), messages.size());
}
*/
