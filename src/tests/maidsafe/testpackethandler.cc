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

namespace test_sph {

int count(0);

std::vector<crypto::RsaKeyPair> keys;

void MakeKeys() {
  if (keys.empty()) {
    crypto::RsaKeyPair keypair1, keypair2, keypair3, keypair4, keypair5;
    boost::thread thr1(&crypto::RsaKeyPair::GenerateKeys, boost::ref(keypair1),
        maidsafe::kRsaKeySize);
    boost::thread thr2(&crypto::RsaKeyPair::GenerateKeys, boost::ref(keypair2),
        maidsafe::kRsaKeySize);
    boost::thread thr3(&crypto::RsaKeyPair::GenerateKeys, boost::ref(keypair3),
        maidsafe::kRsaKeySize);
    boost::thread thr4(&crypto::RsaKeyPair::GenerateKeys, boost::ref(keypair4),
        maidsafe::kRsaKeySize);
    boost::thread thr5(&crypto::RsaKeyPair::GenerateKeys, boost::ref(keypair5),
        maidsafe::kRsaKeySize);
    thr1.join();
    thr2.join();
    thr3.join();
    thr4.join();
    thr5.join();
    keys.push_back(keypair1);
    keys.push_back(keypair2);
    keys.push_back(keypair3);
    keys.push_back(keypair4);
    keys.push_back(keypair5);
  }
}

}  // namespace test_sph

namespace maidsafe {

class SystemPacketHandlerTest : public testing::Test {
 public:
  SystemPacketHandlerTest() : co_(), input_param_() {}
 protected:
  virtual void SetUp() {
    co_.set_symm_algorithm(crypto::AES_256);
    co_.set_hash_algorithm(crypto::SHA_512);
    test_sph::MakeKeys();
  }
  crypto::Crypto co_;  // used for validating
  PacketParams input_param_;
};

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<MidPacket> midPacket(boost::static_pointer_cast<MidPacket>(
      PacketFactory::Factory(MID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["PIN"] = std::string("1234");
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = midPacket->Create(&input_param_);
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin, "", crypto::STRING_STRING,
      false), boost::any_cast<std::string>(result["name"]));
  GenericPacket mid;
  ASSERT_TRUE(mid.ParseFromString(ser_mid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(mid.data(), mid.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  // Check that data is encrypted
  std::stringstream out;
  uint32_t rid = 0;
  out << rid;
  std::string str_rid = out.str();
  ASSERT_NE(str_rid, mid.data());
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetRidMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<MidPacket> midPacket(boost::static_pointer_cast<MidPacket>(
      PacketFactory::Factory(MID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["PIN"] = std::string("1234");
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = midPacket->Create(&input_param_);
  std::string ser_mid = boost::any_cast<std::string>(result["ser_packet"]);
  uint32_t rid = boost::any_cast<uint32_t>(result["rid"]);
  PacketParams recovered_rid = midPacket->GetData(ser_mid, "user1", "1234");
  ASSERT_EQ(rid, boost::any_cast<uint32_t>(recovered_rid["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateSigPacket) {
  // Signature packets are signed by themselves
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  boost::shared_ptr<SignaturePacket> sigPacket(
      boost::static_pointer_cast<SignaturePacket>(PacketFactory::Factory(MAID,
      keypair1)));
  sigPacket->Create(&input_param_);
  GenericPacket sigpacket;
  const std::string ser_packet= boost::any_cast<std::string>(
      input_param_["ser_packet"]);
  crypto::RsaKeyPair keypair2;
  keypair2.set_public_key(boost::any_cast<std::string>(
      input_param_["publicKey"]));
  keypair2.set_private_key(boost::any_cast<std::string>(
      input_param_["privateKey"]));
  std::string name = boost::any_cast<std::string>(input_param_["name"]);
  ASSERT_TRUE(sigpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(sigpacket.data(), sigpacket.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  // Checking that the public key returned is a valid one
  ASSERT_TRUE(co_.AsymCheckSig(keypair2.public_key(), sigpacket.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(sigpacket.data() +
      sigpacket.signature(), "", crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateMPID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<MpidPacket> mpidPacket(
      boost::static_pointer_cast<MpidPacket>(PacketFactory::Factory(MPID,
      keypair1)));
  input_param_["publicname"] = std::string("juan esmer");
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = mpidPacket->Create(&input_param_);
  GenericPacket mpidpacket;
  const std::string ser_packet(boost::any_cast<std::string>
      (result["ser_packet"]));
  std::string name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(mpidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(mpidpacket.data(), mpidpacket.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(boost::any_cast<std::string>(
      input_param_["publicname"]), "", crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetKeyFromPacket) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  crypto::RsaKeyPair &keypair3 = test_sph::keys.at(2);
  crypto::RsaKeyPair &keypair4 = test_sph::keys.at(3);
  crypto::RsaKeyPair &keypair5 = test_sph::keys.at(4);
  boost::shared_ptr<SignaturePacket> sigPacket(
      boost::static_pointer_cast<SignaturePacket>(PacketFactory::Factory(MAID,
      keypair1)));
  sigPacket->Create(&input_param_);
  std::string ser_packet =
      boost::any_cast<std::string>(input_param_["ser_packet"]);
  PacketParams rec_data = sigPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(input_param_["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));
  input_param_["privateKey"] = keypair2.private_key();
  boost::shared_ptr<PmidPacket> pmidPacket(
      boost::static_pointer_cast<PmidPacket>(PacketFactory::Factory(PMID,
      keypair3)));
  PacketParams result = pmidPacket->Create(&input_param_);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);

  rec_data = pmidPacket->GetData(ser_packet);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  input_param_["publicname"] = std::string("juan esmer");
  input_param_["privateKey"] = keypair4.private_key();
  boost::shared_ptr<MpidPacket> mpidPacket(
      boost::static_pointer_cast<MpidPacket>(PacketFactory::Factory(MPID,
      keypair5)));
  result = mpidPacket->Create(&input_param_);
  ser_packet = boost::any_cast<std::string>(result["ser_packet"]);
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
    boost::any_cast<std::string>(mpidPacket->GetData(ser_packet)["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreatePMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<PmidPacket> pmidPacket(
      boost::static_pointer_cast<PmidPacket>(PacketFactory::Factory(PMID,
      keypair1)));
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = pmidPacket->Create(&input_param_);
  GenericPacket pmidpacket;
  const std::string ser_packet(boost::any_cast<std::string>
      (result["ser_packet"]));
  std::string name = boost::any_cast<std::string>(result["name"]);
  ASSERT_TRUE(pmidpacket.ParseFromString(ser_packet));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(pmidpacket.data(), pmidpacket.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  std::string expected_name = co_.Hash(pmidpacket.data() +
      pmidpacket.signature(), "", crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateTMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANTMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<TmidPacket> tmid_packet(
      boost::static_pointer_cast<TmidPacket>(
      PacketFactory::Factory(TMID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["password"] = std::string("passworddelmambofeo");
  input_param_["data"] = std::string("serialised DataAtlas");
  input_param_["PIN"] = std::string("1234");
  input_param_["rid"]  = uint32_t(5555);
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = tmid_packet->Create(&input_param_);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);
  GenericPacket tmid;
  ASSERT_TRUE(tmid.ParseFromString(ser_tmid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(tmid.data(), tmid.signature(),
      keypair2.public_key(), crypto::STRING_STRING));
  // Check name
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  std::string hashrid = co_.Hash("5555", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + hashrid, "",
      crypto::STRING_STRING, false),
      boost::any_cast<std::string>(result["name"]));
  // Check data is encrypted
  ASSERT_NE(boost::any_cast<std::string>(input_param_["data"]), tmid.data());
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetDataFromTMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANTMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<TmidPacket> tmid_packet(
      boost::static_pointer_cast<TmidPacket>(
      PacketFactory::Factory(TMID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["password"] = std::string("passworddelmambofeo");
  input_param_["data"] = std::string("serialised DataAtlas");
  input_param_["PIN"] = std::string("1234");
  input_param_["rid"]  = uint32_t(5555);
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = tmid_packet->Create(&input_param_);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string ser_tmid = boost::any_cast<std::string>(result["ser_packet"]);
  PacketParams rec_data = tmid_packet->GetData(ser_tmid,
      boost::any_cast<std::string>(input_param_["password"]), 5555);
  ASSERT_EQ(boost::any_cast<std::string>(input_param_["data"]),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateSMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANSMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<SmidPacket> smidPacket(
      boost::static_pointer_cast<SmidPacket>(
      PacketFactory::Factory(SMID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["PIN"] = std::string("1234");
  input_param_["rid"] = uint32_t(444455555);
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = smidPacket->Create(&input_param_);
  std::string ser_smid = boost::any_cast<std::string>(result["ser_packet"]);
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + "1", "",
      crypto::STRING_STRING, false),
      boost::any_cast<std::string>(result["name"]));
  GenericPacket smid;
  ASSERT_TRUE(smid.ParseFromString(ser_smid));
  // Check it is correctly signed
  ASSERT_TRUE(co_.AsymCheckSig(smid.data(), smid.signature(),
    keypair2.public_key(), crypto::STRING_STRING));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetRidSMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  // simulating signing keys of ANSMID
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<SmidPacket> smidPacket(
      boost::static_pointer_cast<SmidPacket>(
      PacketFactory::Factory(SMID, keypair1)));
  input_param_["username"] = std::string("user1");
  input_param_["PIN"] = std::string("1234");
  input_param_["rid"] = uint32_t(444455555);
  input_param_["privateKey"] = keypair2.private_key();
  PacketParams result = smidPacket->Create(&input_param_);
  std::string ser_smid = boost::any_cast<std::string>(result["ser_packet"]);
  PacketParams recovered_rid = smidPacket->GetData(ser_smid, "user1", "1234");
  ASSERT_EQ(boost::any_cast<uint32_t>(input_param_["rid"]),
      boost::any_cast<uint32_t>(recovered_rid["data"]));
}

}  // namespace maidsafe
