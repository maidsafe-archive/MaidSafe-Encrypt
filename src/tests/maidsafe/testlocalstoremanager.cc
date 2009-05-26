#include "maidsafe/utils.h"
#include "maidsafe/client/localstoremanager.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include <gtest/gtest.h>

using namespace maidsafe;
using namespace packethandler;

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

void wait_for_result_lsm(FakeCallback &cb, boost::recursive_mutex *mutex) {
  while (true) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb.result_ != "") {
        return;
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(5));
  }
};

class StoreManagerTest : public testing::Test {
  public:
StoreManagerTest() : cb(), storemanager(),
  crypto_obj(), rsa_obj(), mutex_() {}
  protected:
    void SetUp(){
      mutex_ = new boost::recursive_mutex();
      storemanager = new LocalStoreManager(mutex_);
      // storemanager = new LocalStoreManager();
      storemanager->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
      wait_for_result_lsm(cb, mutex_);
      base::GeneralResponse res;
      ASSERT_TRUE(res.ParseFromString(cb.result_));
      if (res.result() == kCallbackFailure) {
        FAIL();
        return;
      }
      crypto_obj.set_symm_algorithm("AES_256");
      crypto_obj.set_hash_algorithm("SHA512");
      cb.Reset();
    }
    void TearDown(){
      cb.Reset();
      storemanager->Close(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
      wait_for_result_lsm(cb, mutex_);
      base::GeneralResponse res;
      ASSERT_TRUE(res.ParseFromString(cb.result_));
      if (res.result() == kCallbackSuccess) {
        if (boost::filesystem::exists("KademilaDb.db"))
          boost::filesystem::remove(boost::filesystem::path("KademilaDb.db"));
        if (boost::filesystem::exists("StoreChunks"))
          boost::filesystem::remove_all(boost::filesystem::path("StoreChunks"));
      }
    }
    FakeCallback cb;
    LocalStoreManager *storemanager;
    maidsafe_crypto::Crypto crypto_obj;
    maidsafe_crypto::RsaKeyPair rsa_obj;
    boost::recursive_mutex *mutex_;
    private:
    StoreManagerTest(const StoreManagerTest&);
    StoreManagerTest &operator=(const StoreManagerTest&);
};

TEST_F(StoreManagerTest, BEH_MAID_StoreSystemPacket) {
  GenericPacket gp;
  rsa_obj.GenerateKeys(1024);
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "",\
    rsa_obj.private_key(),maidsafe_crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data()+gp.signature(),"",\
    maidsafe_crypto::STRING_STRING, true);
  storemanager->IsKeyUnique(gp_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();
  std::string gp_content;
  gp.SerializeToString(&gp_content);
  std::string signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(),"",\
    rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(\
    rsa_obj.public_key()+signed_public_key+gp_name, "", maidsafe_crypto::STRING_STRING, true),\
    "", rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);
  storemanager->StorePacket(gp_name, gp_content, signed_request,\
    rsa_obj.public_key(),signed_public_key, SYSTEM_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();
  is_unique_res.Clear();
  storemanager->IsKeyUnique(gp_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  std::string result;
  storemanager->LoadPacket(gp_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb,mutex_);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_EQ(gp_content, load_res.content());
}

TEST_F(StoreManagerTest, BEH_MAID_DeleteSystemPacket){
  GenericPacket gp;
  rsa_obj.GenerateKeys(1024);
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "",rsa_obj.private_key(),\
    maidsafe_crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data()+gp.signature(),"",\
    maidsafe_crypto::STRING_STRING, true);
  std::string gp_content;
  gp.SerializeToString(&gp_content);

  std::string signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(), "",\
    rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(\
    rsa_obj.public_key()+signed_public_key+gp_name,"", maidsafe_crypto::STRING_STRING, true),\
    "",rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);
  storemanager->StorePacket(gp_name, gp_content, signed_request,\
    rsa_obj.public_key(),signed_public_key, SYSTEM_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(gp_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),\
    signed_public_key, SYSTEM_PACKET, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, del_res.result());
  cb.Reset();

  storemanager->IsKeyUnique(gp_name, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
}

TEST_F(StoreManagerTest, BEH_MAID_StoreChunk) {
  std::string chunk_content = base::RandomString(256*1024);
  std::string chunk_name = crypto_obj.Hash(chunk_content, "",\
    maidsafe_crypto::STRING_STRING, true);
  storemanager->IsKeyUnique(chunk_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  storemanager->StoreChunk(chunk_name, chunk_content, "","","",
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(chunk_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  storemanager->LoadChunk(chunk_name,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_EQ(chunk_content, load_res.content());
}

TEST_F(StoreManagerTest, BEH_MAID_StoreBufferPacket) {
  std::string owner_id("Juan U. Smer");
  rsa_obj.GenerateKeys(1024);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();

  std::string bufferpacketname = crypto_obj.Hash\
    (owner_id+"BUFFER","", maidsafe_crypto::STRING_STRING, true);
  storemanager->IsKeyUnique(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info,"",private_key,\
    maidsafe_crypto::STRING_STRING));

  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  std::string ser_bp = ser_packet;

  std::string signed_public_key = crypto_obj.AsymSign(public_key,"",private_key,\
    maidsafe_crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(public_key+\
    signed_public_key+bufferpacketname, "", maidsafe_crypto::STRING_STRING, true),"",\
    private_key, maidsafe_crypto::STRING_STRING);

  storemanager->StorePacket(bufferpacketname, ser_bp, signed_request,\
    public_key,signed_public_key, BUFFER_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  storemanager->LoadPacket(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_EQ(ser_bp, load_res.content());
}

TEST_F(StoreManagerTest, BEH_MAID_DeleteSystemPacketNotOwner){
  GenericPacket gp;
  rsa_obj.GenerateKeys(1024);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();
  gp.set_data("Generic System Packet Data");
  gp.set_signature(crypto_obj.AsymSign(gp.data(), "", private_key,maidsafe_crypto::STRING_STRING));
  std::string gp_name = crypto_obj.Hash(gp.data()+gp.signature(),"", maidsafe_crypto::STRING_STRING, true);
  std::string gp_content;
  gp.SerializeToString(&gp_content);
  std::string signed_public_key = crypto_obj.AsymSign(public_key, "", private_key,maidsafe_crypto::STRING_STRING);
  std::string signed_request1 = crypto_obj.AsymSign(crypto_obj.Hash(rsa_obj.public_key()+signed_public_key+gp_name,
    "", maidsafe_crypto::STRING_STRING, true), "", rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);

  storemanager->StorePacket(gp_name, gp_content, signed_request1,\
    public_key,signed_public_key, SYSTEM_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(gp_name, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  // Creating new public/private keys
  rsa_obj.GenerateKeys(1024);

  signed_public_key = crypto_obj.AsymSign(public_key, "", rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(rsa_obj.public_key()+signed_public_key+gp_name,
    "", maidsafe_crypto::STRING_STRING, true), "", rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);

  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),\
    signed_public_key, SYSTEM_PACKET, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, del_res.result());
  cb.Reset();
  del_res.Clear();

  storemanager->IsKeyUnique(gp_name, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  signed_public_key = crypto_obj.AsymSign(rsa_obj.public_key(), "", rsa_obj.private_key(),maidsafe_crypto::STRING_STRING);

  storemanager->DeletePacket(gp_name, signed_request, rsa_obj.public_key(),\
    signed_public_key, SYSTEM_PACKET, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, del_res.result());
  cb.Reset();
  del_res.Clear();

  storemanager->IsKeyUnique(gp_name, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();
}

TEST_F(StoreManagerTest, BEH_MAID_DeleteBufferPacketNotOwner){
  std::string owner_id("Juan U. Smer");
  rsa_obj.GenerateKeys(1024);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();

  std::string bufferpacketname = crypto_obj.Hash(owner_id+"BUFFER","", maidsafe_crypto::STRING_STRING, true);
  storemanager->IsKeyUnique(bufferpacketname, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info,"",private_key,maidsafe_crypto::STRING_STRING));

  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  std::string ser_bp = ser_packet;

  std::string signed_public_key = crypto_obj.AsymSign(public_key,"",private_key, maidsafe_crypto::STRING_STRING);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(public_key+signed_public_key+
    bufferpacketname, "", maidsafe_crypto::STRING_STRING, true),"", private_key, maidsafe_crypto::STRING_STRING);

  storemanager->StorePacket(bufferpacketname, ser_bp, signed_request,\
    public_key,signed_public_key, BUFFER_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(bufferpacketname, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  rsa_obj.ClearKeys();
  rsa_obj.GenerateKeys(1024);
  std::string signed_public_key1 = crypto_obj.AsymSign(rsa_obj.public_key(),"",\
    rsa_obj.private_key(), maidsafe_crypto::STRING_STRING);
  std::string signed_request1 = crypto_obj.AsymSign(crypto_obj.Hash(\
    rsa_obj.public_key()+signed_public_key1+bufferpacketname, "",\
    maidsafe_crypto::STRING_STRING, true),"", rsa_obj.private_key(), maidsafe_crypto::STRING_STRING);
  storemanager->DeletePacket(bufferpacketname, signed_request1, rsa_obj.public_key(),\
    signed_public_key1, BUFFER_PACKET, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  DeleteResponse del_res;
  ASSERT_TRUE(del_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, del_res.result());
  cb.Reset();
  del_res.Clear();
}

TEST_F(StoreManagerTest, BEH_MAID_Add_Get_Clear_BufferPacket_Msgs) {
  std::string owner_id("Juan U. Smer");
  maidsafe_crypto::RsaKeyPair rsa_kp1;
  rsa_kp1.GenerateKeys(1024);
  rsa_obj.GenerateKeys(1024);
  std::string sig_private_key = rsa_kp1.private_key();
  std::string sig_public_key = rsa_kp1.public_key();

  std::string signed_public_key = crypto_obj.AsymSign(sig_public_key,"",sig_private_key,\
    maidsafe_crypto::STRING_STRING);

  maidsafe_crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(1024);
  std::string mpidsender_privkey = rsa_kp.private_key();
  std::string mpidsender_pubkey = rsa_kp.public_key();


  // storing MPID package for the sender
  packethandler::GenericPacket mpid;
  mpid.set_data(rsa_kp.public_key());
  mpid.set_signature(crypto_obj.AsymSign(rsa_kp.public_key(),"",sig_private_key,\
    maidsafe_crypto::STRING_STRING));
  std::string ser_mpid;
  mpid.SerializeToString(&ser_mpid);
  std::string sender("sender");
  std::string mpid_name = crypto_obj.Hash(sender, "", maidsafe_crypto::STRING_STRING, true);
  std::string signed_request = crypto_obj.AsymSign(crypto_obj.Hash(sig_public_key+\
    signed_public_key+mpid_name, "", maidsafe_crypto::STRING_STRING, true),"",\
    sig_private_key, maidsafe_crypto::STRING_STRING);
  storemanager->StorePacket(mpid_name, ser_mpid, signed_request,\
    sig_public_key,signed_public_key, SYSTEM_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  StoreResponse store_res;
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  // rsa_obj.GenerateKeys(1024);
  std::string public_key = rsa_obj.public_key();
  std::string private_key = rsa_obj.private_key();
  ASSERT_NE(public_key, mpid.data());
  ASSERT_NE(private_key, mpidsender_privkey);

  std::string bufferpacketname = crypto_obj.Hash\
    (owner_id+"BUFFER","", maidsafe_crypto::STRING_STRING, true);
  storemanager->IsKeyUnique(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  base::GeneralResponse is_unique_res;
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(false);

  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj.AsymSign(ser_info,"",private_key,\
    maidsafe_crypto::STRING_STRING));
  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  std::string ser_bp = ser_packet;

  signed_public_key = crypto_obj.AsymSign(public_key,"",private_key,\
    maidsafe_crypto::STRING_STRING);
  signed_request = crypto_obj.AsymSign(crypto_obj.Hash(public_key+\
    signed_public_key+bufferpacketname, "", maidsafe_crypto::STRING_STRING, true),"",\
    private_key, maidsafe_crypto::STRING_STRING);

  storemanager->StorePacket(bufferpacketname, ser_bp, signed_request,\
    public_key,signed_public_key, BUFFER_PACKET, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  storemanager->IsKeyUnique(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(is_unique_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, is_unique_res.result());
  cb.Reset();
  is_unique_res.Clear();

  storemanager->LoadPacket(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_EQ(ser_bp, load_res.content());

  // Creating msgs to insert

  std::string key("AESkey");
  packethandler::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(sender);
  bpmsg.set_rsaenc_key(crypto_obj.AsymEncrypt(key, "", public_key,
    maidsafe_crypto::STRING_STRING));
  bpmsg.set_aesenc_message(crypto_obj.SymmEncrypt("test msg", "",
    maidsafe_crypto::STRING_STRING, key));
  bpmsg.set_type(packethandler::INSTANT_MSG);
  bpmsg.set_sender_public_key(mpidsender_pubkey);
  std::string ser_bpmsg;
  bpmsg.SerializeToString(&ser_bpmsg);
  packethandler::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(crypto_obj.AsymSign(ser_bpmsg,"",mpidsender_privkey,\
    maidsafe_crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  bpmsg_gp.SerializeToString(&ser_bpmsg_gp);

  signed_public_key = crypto_obj.AsymSign(mpid.data(),"",mpidsender_privkey,\
    maidsafe_crypto::STRING_STRING);

  signed_request = crypto_obj.AsymSign(crypto_obj.Hash(mpid.data()+\
    signed_public_key+"incorrect name", "", maidsafe_crypto::STRING_STRING, true),"",\
    mpidsender_privkey, maidsafe_crypto::STRING_STRING);

  cb.Reset();
  storemanager->StorePacket("incorrect name", ser_bpmsg_gp, signed_request,\
    mpid.data(),signed_public_key, BUFFER_PACKET_MESSAGE, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, store_res.result());
  cb.Reset();
  store_res.Clear();

  signed_request = crypto_obj.AsymSign(crypto_obj.Hash(mpid.data()+\
    signed_public_key+bufferpacketname, "", maidsafe_crypto::STRING_STRING, true),"",\
    mpidsender_privkey, maidsafe_crypto::STRING_STRING);
  storemanager->StorePacket(bufferpacketname, ser_bpmsg_gp, signed_request,\
    mpid.data(),signed_public_key, BUFFER_PACKET_MESSAGE, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, store_res.result());
  cb.Reset();
  store_res.Clear();

  // Checking the bp has not been modified
  storemanager->LoadPacket(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_EQ(ser_bp, load_res.content());
  cb.Reset();


  // Changing the msg type
  bpmsg.set_type(packethandler::ADD_CONTACT_RQST);
  bpmsg.set_sender_public_key(mpidsender_pubkey);
  bpmsg.SerializeToString(&ser_bpmsg);
  bpmsg_gp.clear_data();
  bpmsg_gp.clear_signature();
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(crypto_obj.AsymSign(ser_bpmsg,"",mpidsender_privkey,\
    maidsafe_crypto::STRING_STRING));
  bpmsg_gp.SerializeToString(&ser_bpmsg_gp);
  storemanager->StorePacket(bufferpacketname, ser_bpmsg_gp, signed_request,\
    mpid.data(),signed_public_key, BUFFER_PACKET_MESSAGE, false,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(store_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, store_res.result());
  cb.Reset();
  store_res.Clear();

  // Checking if new buffer packet has the msg
  storemanager->LoadPacket(bufferpacketname, boost::bind\
    (&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(load_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ser_bp = load_res.content();
  packethandler::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  ASSERT_EQ(1, bp.messages_size());
  load_res.Clear();
  cb.Reset();

  // Getting the msgs
  std::string sig_mpid_pubkey = crypto_obj.AsymSign(mpid.data(), "",\
    mpidsender_privkey, maidsafe_crypto::STRING_STRING);
  storemanager->GetMessages(bufferpacketname, mpid.data(), sig_mpid_pubkey,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  maidsafe::GetMessagesResponse get_msg_res;
  ASSERT_TRUE(get_msg_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackFailure, get_msg_res.result());
  cb.Reset();
  get_msg_res.Clear();

  signed_public_key = crypto_obj.AsymSign(public_key, "", private_key,\
    maidsafe_crypto::STRING_STRING);
  storemanager->GetMessages(bufferpacketname, public_key, signed_public_key,\
    boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_for_result_lsm(cb, mutex_);
  ASSERT_TRUE(get_msg_res.ParseFromString(cb.result_));
  ASSERT_EQ(kCallbackSuccess, get_msg_res.result());
  ASSERT_EQ(1, get_msg_res.messages_size());
  cb.Reset();

}
