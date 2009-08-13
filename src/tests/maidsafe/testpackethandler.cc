/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-12-22.59.40
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

#include <stdio.h>
#include <gtest/gtest.h>
#include <string>
#include <cstdlib>
#include "maidsafe/client/systempackets.h"

crypto::RsaKeyPair create_keys() {
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(packethandler::kRsaKeySize);
  return rsakp;
}

namespace packethandler {

class PacketHandlerTest : public testing::Test {
 public:
  PacketHandlerTest() : co_(), input_param() {}
 protected:
  virtual void SetUp() {
    co_.set_symm_algorithm(crypto::AES_256);
    co_.set_hash_algorithm(crypto::SHA_512);
  }
  crypto::Crypto co_;  // used for validating
  PacketParams input_param;
};

TEST_F(PacketHandlerTest, BEH_MAID_CreateMID) {
  Packet *packet = PacketFactory::Factory(MID);
  MidPacket *midPacket = static_cast<MidPacket*>(packet);
  uint32_t rid = 0;
  GenericPacket mid;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["privateKey"] = keys.private_key();
  PacketParams result = midPacket->Create(input_param);
  std::string mid_name;
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      true);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, true);
  ASSERT_EQ(co_.Hash(hashusername + hashpin, "", crypto::STRING_STRING,
      true), boost::any_cast<std::string>(result["name"]));
  ASSERT_TRUE(mid.ParseFromString(ser_mid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(mid.data(), mid.signature(),
      keys.public_key(), crypto::STRING_STRING));
  // Check that data is encrypted
  std::stringstream out;
  out << rid;
  std::string str_rid = out.str();
  ASSERT_NE(str_rid, mid.data());
}

TEST_F(PacketHandlerTest, BEH_MAID_GetRidMID) {
  Packet *packet = PacketFactory::Factory(MID);
  MidPacket *midPacket = static_cast<MidPacket*>(packet);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["privateKey"] = keys.private_key();
  PacketParams result = midPacket->Create(input_param);
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  uint32_t rid = boost::any_cast<uint32_t>(result["rid"]);
  PacketParams recovered_rid = midPacket->GetData(ser_mid, "user1", "1234");
  ASSERT_EQ(rid, boost::any_cast<uint32_t>(recovered_rid["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateSigPacket) {
  // Signature packets are signed by themselves
  std::string name;
  crypto::RsaKeyPair keys;
  SignaturePacket *sigPacket =
      static_cast<SignaturePacket*>(PacketFactory::Factory(MAID));
  PacketParams result = sigPacket->Create(input_param);
  GenericPacket sigpacket;
  const std::string ser_packet= boost::any_cast<std::string>(
      result["ser_packet"]);
  keys.set_public_key(boost::any_cast<std::string>(result["publicKey"]));
  keys.set_private_key(boost::any_cast<std::string>(result["privateKey"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(sigpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(sigpacket.data(), sigpacket.signature(),
      keys.public_key(), crypto::STRING_STRING));
  // Checking that the public key returned is a valid one
  ASSERT_TRUE(co_.AsymCheckSig(keys.public_key(), sigpacket.signature(),
      keys.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(sigpacket.data() +
      sigpacket.signature(), "", crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateMPID) {
  std::string name;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  input_param["publicname"] = std::string("juan esmer");
  input_param["privateKey"] = keys.private_key();
  MpidPacket *mpidPacket =
      static_cast<MpidPacket*>(PacketFactory::Factory(MPID));
  PacketParams result = mpidPacket->Create(input_param);
  GenericPacket mpidpacket;
  const std::string ser_packet(boost::any_cast<std::string>
      (result["ser_packet"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(mpidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(mpidpacket.data(), mpidpacket.signature(),
      keys.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(boost::any_cast<std::string>(
      input_param["publicname"]), "", crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);
}

TEST_F(PacketHandlerTest, BEH_MAID_GetKeyFromPacket) {
  crypto::RsaKeyPair keys;
  std::string ser_packet;
  PacketParams result;

  SignaturePacket *sigPacket =
      static_cast<SignaturePacket*>(PacketFactory::Factory(MAID));
  result = sigPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);
  PacketParams rec_data = sigPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  keys.GenerateKeys(kRsaKeySize);
  input_param["privateKey"] = keys.private_key();
  PmidPacket *pmidPacket =
      static_cast<PmidPacket*>(PacketFactory::Factory(PMID));
  result = pmidPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);

  rec_data = pmidPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  keys.GenerateKeys(kRsaKeySize);
  input_param["publicname"] = std::string("juan esmer");
  input_param["privateKey"] = keys.private_key();
  MpidPacket *mpidPacket =
      static_cast<MpidPacket*>(PacketFactory::Factory(MPID));
  result = mpidPacket->Create(input_param);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
    boost::any_cast<std::string>(mpidPacket->GetData(ser_packet)["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreatePMID) {
  std::string name;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  input_param["privateKey"] = keys.private_key();
  PmidPacket *pmidPacket =
      static_cast<PmidPacket*>(PacketFactory::Factory(PMID));
  PacketParams result = pmidPacket->Create(input_param);
  GenericPacket pmidpacket;
  const std::string ser_packet(boost::any_cast<std::string>
      (result["ser_packet"]));
  name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(pmidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(pmidpacket.data(), pmidpacket.signature(),
      keys.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(pmidpacket.data() +
      pmidpacket.signature(), "", crypto::STRING_STRING, true);
  ASSERT_EQ(expected_name, name);
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateTMID) {
  TmidPacket *tmid_packet =
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  // MidPacket *midPacket = (packet);
  input_param["username"] = std::string("user1");
  input_param["password"] = std::string("passworddelmambofeo");
  input_param["data"] = std::string("serialised DataAtlas");
  input_param["PIN"] = std::string("1234");
  input_param["rid"]  = uint32_t(5555);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANTMID
  input_param["privateKey"] = keys.private_key();
  PacketParams result = tmid_packet->Create(input_param);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);

  GenericPacket tmid;

  ASSERT_TRUE(tmid.ParseFromString(ser_tmid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(tmid.data(), tmid.signature(),
      keys.public_key(), crypto::STRING_STRING));
  // Check name
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      true);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, true);
  std::string hashrid = co_.Hash("5555", "", crypto::STRING_STRING, true);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + hashrid, "",
      crypto::STRING_STRING, true),
      boost::any_cast<std::string>(result["name"]));
  // Check data is encrypted
  ASSERT_NE(boost::any_cast<std::string>(input_param["data"]), tmid.data());
}

TEST_F(PacketHandlerTest, BEH_MAID_GetDataFromTMID) {
  TmidPacket *tmid_packet =
      static_cast<TmidPacket*>(PacketFactory::Factory(TMID));
  input_param["username"] = std::string("user1");
  input_param["password"] = std::string("passworddelmambofeo");
  input_param["data"] = std::string("serialised DataAtlas");
  input_param["PIN"] = std::string("1234");
  input_param["rid"]  = uint32_t(5555);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANTMID
  input_param["privateKey"] = keys.private_key();
  PacketParams result = tmid_packet->Create(input_param);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);
  // std::string ser_tmid = packet_handler.CreateTMID(username, pin, rid, data,
  // keys.private_key(), name);
  PacketParams rec_data = tmid_packet->GetData(ser_tmid,
      boost::any_cast<std::string>(input_param["password"]), 5555);
  ASSERT_EQ(boost::any_cast<std::string>(input_param["data"]),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(PacketHandlerTest, BEH_MAID_CreateSMID) {
  SmidPacket *smidPacket =
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  GenericPacket smid;
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANMID
  input_param["username"] = std::string("user1");
  input_param["PIN"] = std::string("1234");
  input_param["rid"] = uint32_t(444455555);
  input_param["privateKey"] = keys.private_key();
  PacketParams result = smidPacket->Create(input_param);
  std::string smid_name;
  std::string ser_smid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      true);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, true);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + "1", "",
      crypto::STRING_STRING, true),
      boost::any_cast<std::string>(result["name"]));
  ASSERT_TRUE(smid.ParseFromString(ser_smid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(smid.data(), smid.signature(),
    keys.public_key(), crypto::STRING_STRING));
}

TEST_F(PacketHandlerTest, BEH_MAID_GetRidSMID) {
  SmidPacket *smidPacket =
      static_cast<SmidPacket*>(PacketFactory::Factory(SMID));
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);  // simulating signing keys of ANMID
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

}  // namespace packethandler
