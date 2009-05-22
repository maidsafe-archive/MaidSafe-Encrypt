#include <iostream>
#include <string>
#include <cstdlib>
#include <stdio.h>
#include <gtest/gtest.h>
#include <sstream>
#include "maidsafe/client/systempackets.h"
#include "boost/timer.hpp"

using namespace packethandler;

class PacketHandlerTest : public testing::Test {
public:
PacketHandlerTest() : crypto_obj(), input_param() {}
  protected:
  virtual void SetUp() {
      crypto_obj.set_symm_algorithm("AES_256");
      crypto_obj.set_hash_algorithm("SHA512");
  }
    maidsafe_crypto::Crypto crypto_obj; // used for validating
    PacketParams input_param;
};

maidsafe_crypto::RsaKeyPair create_keys(){
  maidsafe_crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  return rsakp;
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateMID){
boost::timer t;
  Packet *packet = PacketFactory::Factory(MID);
  MidPacket *midPacket = dynamic_cast<MidPacket*>(packet);
  uint32_t rid=0;
  GenericPacket mid;
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["privateKey"] = keys.private_key();
  PacketParams result = midPacket->Create(input_param);
  std::string mid_name;
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = crypto_obj.Hash("user1","", maidsafe_crypto::STRING_STRING, true);
  std::string hashpin = crypto_obj.Hash("1234","", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(crypto_obj.Hash(hashusername+hashpin,"", maidsafe_crypto::STRING_STRING, true),
      boost::any_cast<std::string>(result["name"]));
  ASSERT_TRUE(mid.ParseFromString(ser_mid));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(mid.data(), mid.signature(),
      keys.public_key(), maidsafe_crypto::STRING_STRING));
  // Check that data is encrypted
  std::stringstream out;
  out << rid;
  std::string str_rid = out.str();
  ASSERT_NE(str_rid, mid.data());
}

TEST_F(PacketHandlerTest, BEH_MAID_GetRidMID){
  Packet *packet = PacketFactory::Factory(MID);
  MidPacket *midPacket = dynamic_cast<MidPacket*>(packet);
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["privateKey"] = keys.private_key();
  PacketParams result = midPacket->Create(input_param);
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  uint32_t rid = boost::any_cast<uint32_t>(result["rid"]);
  PacketParams recovered_rid = midPacket->GetData(ser_mid, "user1", "1234");
  ASSERT_EQ(rid, boost::any_cast<uint32_t>(recovered_rid["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateSigPacket){
  // Signature packets are signed by themselves
  std::string name;
  maidsafe_crypto::RsaKeyPair keys;
  SignaturePacket *sigPacket = dynamic_cast<SignaturePacket*>(PacketFactory::Factory(MAID));
  PacketParams result = sigPacket->Create(input_param);
  GenericPacket sigpacket;
  const std::string ser_packet= boost::any_cast<std::string>(
      result["ser_packet"]);
  keys.set_public_key(boost::any_cast<std::string>(result["publicKey"]));
  keys.set_private_key(boost::any_cast<std::string>(result["privateKey"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(sigpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(sigpacket.data(), sigpacket.signature(),
      keys.public_key(), maidsafe_crypto::STRING_STRING));
  // Checking that the public key returned is a valid one
  ASSERT_TRUE(crypto_obj.AsymCheckSig(keys.public_key(), sigpacket.signature(),
      keys.public_key(), maidsafe_crypto::STRING_STRING));
  std::string expected_name = crypto_obj.Hash(sigpacket.data()+
      sigpacket.signature(), "", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateMPID){
  std::string name;
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  input_param["publicname"] = std::string("juan esmer");
  input_param["privateKey"] = keys.private_key();
  MpidPacket *mpidPacket = dynamic_cast<MpidPacket*>(PacketFactory::Factory(MPID));
  PacketParams result = mpidPacket->Create(input_param);
  GenericPacket mpidpacket;
  const std::string ser_packet(boost::any_cast<std::string>(result["ser_packet"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(mpidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(mpidpacket.data(), mpidpacket.signature(), keys.public_key(),
    maidsafe_crypto::STRING_STRING));
  std::string expected_name = crypto_obj.Hash(boost::any_cast<std::string>(
      input_param["publicname"]), "", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);

}

TEST_F(PacketHandlerTest, BEH_MAID_GetKeyFromPacket){
  maidsafe_crypto::RsaKeyPair keys;
  std::string ser_packet;
  PacketParams result;

  SignaturePacket *sigPacket = dynamic_cast<SignaturePacket*>(PacketFactory::Factory(MAID));
  result = sigPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);
  PacketParams rec_data = sigPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  keys.GenerateKeys(kRsaKeySize);
  input_param["privateKey"] = keys.private_key();
  PmidPacket *pmidPacket = dynamic_cast<PmidPacket*>(PacketFactory::Factory(PMID));
  result = pmidPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);

  rec_data = pmidPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  keys.GenerateKeys(kRsaKeySize);
  input_param["publicname"] = std::string("juan esmer");
  input_param["privateKey"] = keys.private_key();
  MpidPacket *mpidPacket = dynamic_cast<MpidPacket*>(PacketFactory::Factory(MPID));
  result = mpidPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
    boost::any_cast<std::string>(mpidPacket->GetData(ser_packet)["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreatePMID){
  std::string name;
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  input_param["privateKey"] = keys.private_key();
  PmidPacket *pmidPacket = dynamic_cast<PmidPacket*>(PacketFactory::Factory(PMID));
  PacketParams result = pmidPacket->Create(input_param);
  GenericPacket pmidpacket;
  const std::string ser_packet(boost::any_cast<std::string>(result["ser_packet"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(pmidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(pmidpacket.data(), pmidpacket.signature(), keys.public_key(),
    maidsafe_crypto::STRING_STRING));
  std::string expected_name = crypto_obj.Hash(pmidpacket.data()+pmidpacket.signature(), "", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateTMID){
  TmidPacket *tmid_packet = dynamic_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  // MidPacket *midPacket = (packet);
  input_param["username"] = std::string("user1");
  input_param["password"] = std::string("passworddelmambofeo");
  input_param["data"] = std::string("serialised DataAtlas");
  input_param["PIN"] = std::string("1234");
  input_param["rid"]  = uint32_t(5555);
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANTMID
  input_param["privateKey"] = keys.private_key();
  PacketParams result = tmid_packet->Create(input_param);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);

  GenericPacket tmid;

  ASSERT_TRUE(tmid.ParseFromString(ser_tmid));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(tmid.data(), tmid.signature(),
      keys.public_key(), maidsafe_crypto::STRING_STRING));
  // Check name
  std::string hashusername = crypto_obj.Hash("user1","", maidsafe_crypto::STRING_STRING, true);
  std::string hashpin = crypto_obj.Hash("1234","", maidsafe_crypto::STRING_STRING, true);
  std::string hashrid = crypto_obj.Hash("5555","", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(crypto_obj.Hash(hashusername+hashpin+hashrid,"",
      maidsafe_crypto::STRING_STRING, true), boost::any_cast<std::string>(result["name"]));
  // Check data is encrypted
  ASSERT_NE(boost::any_cast<std::string>(input_param["data"]), tmid.data());
}

TEST_F(PacketHandlerTest, BEH_MAID_GetDataFromTMID){
  TmidPacket *tmid_packet = dynamic_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  input_param["username"] = std::string("user1");
  input_param["password"] = std::string("passworddelmambofeo");
  input_param["data"] = std::string("serialised DataAtlas");
  input_param["PIN"] = std::string("1234");
  input_param["rid"]  = uint32_t(5555);
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANTMID
  input_param["privateKey"] = keys.private_key();
  PacketParams result = tmid_packet->Create(input_param);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);
  // std::string ser_tmid = packet_handler.CreateTMID(username, pin, rid, data, keys.private_key(), name);
  PacketParams rec_data = tmid_packet->GetData(ser_tmid,
      boost::any_cast<std::string>(input_param["password"]), 5555);
  ASSERT_EQ(boost::any_cast<std::string>(input_param["data"]),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateSMID){
  SmidPacket *smidPacket = dynamic_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  GenericPacket smid;
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["rid"] = uint32_t(444455555);
  input_param["privateKey"] = keys.private_key();
  PacketParams result = smidPacket->Create(input_param);
  std::string smid_name;
  std::string ser_smid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = crypto_obj.Hash("user1","", maidsafe_crypto::STRING_STRING, true);
  std::string hashpin = crypto_obj.Hash("1234","", maidsafe_crypto::STRING_STRING, true);
  ASSERT_EQ(crypto_obj.Hash(hashusername+hashpin+"1","", maidsafe_crypto::STRING_STRING, true),
      boost::any_cast<std::string>(result["name"]));
  ASSERT_TRUE(smid.ParseFromString(ser_smid));
  // Check it is correctly signed
  ASSERT_TRUE(crypto_obj.AsymCheckSig(smid.data(), smid.signature(),
    keys.public_key(), maidsafe_crypto::STRING_STRING));
}

TEST_F(PacketHandlerTest, BEH_MAID_GetRidSMID){
  SmidPacket *smidPacket = dynamic_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize); // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["rid"] = uint32_t(444455555);
  input_param["privateKey"] = keys.private_key();
  PacketParams result = smidPacket->Create(input_param);
  std::string ser_smid = boost::any_cast<std::string>(result["ser_packet"]);
  PacketParams recovered_rid = smidPacket->GetData(ser_smid, "user1", "1234");
  ASSERT_EQ(boost::any_cast<uint32_t>(input_param["rid"]),
      boost::any_cast<uint32_t>(recovered_rid["data"]));
}

