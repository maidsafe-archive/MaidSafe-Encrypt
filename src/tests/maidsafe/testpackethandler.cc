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
#include <boost/lexical_cast.hpp>
#include "maidsafe/client/systempackets.h"
#include "tests/maidsafe/cached_keys.h"

namespace test_sph {

std::vector<crypto::RsaKeyPair> keys;

}  // namespace test_sph

namespace maidsafe {

class SystemPacketHandlerTest : public testing::Test {
 public:
  SystemPacketHandlerTest()
      : co_(),
        input_param_() {}
 protected:
  virtual void SetUp() {
    co_.set_symm_algorithm(crypto::AES_256);
    co_.set_hash_algorithm(crypto::SHA_512);
    cached_keys::MakeKeys(5, &test_sph::keys);
  }
  crypto::Crypto co_;  // used for validating
  PacketParams input_param_;
};

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateMID) {
  boost::shared_ptr<Packet> midPacket(PacketFactory::Factory(MID));
  input_param_["username"] = std::string("user1");
  input_param_["pin"] = std::string("1234");
  PacketParams result = midPacket->Create(input_param_);

  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin, "", crypto::STRING_STRING,
      false), boost::any_cast<std::string>(result["name"]));

  ASSERT_NE(0, boost::any_cast<boost::uint32_t>(result["rid"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetRidMID) {
  // simulating signing keys of ANMID
  crypto::RsaKeyPair &keypair = test_sph::keys.at(0);
  boost::shared_ptr<Packet> midPacket(PacketFactory::Factory(MID));
  input_param_["username"] = std::string("user1");
  input_param_["pin"] = std::string("1234");
  PacketParams recovered_rid = midPacket->GetData("", input_param_);
  boost::uint32_t rid(0);
  PacketParams result;
  ASSERT_EQ(rid, boost::any_cast<boost::uint32_t>(recovered_rid["data"]));
  result = midPacket->Create(input_param_);
  GenericPacket packet;
  packet.set_data(boost::any_cast<std::string>(result["encRid"]));
  packet.set_signature(co_.AsymSign(packet.data(), "", keypair.private_key(),
      crypto::STRING_STRING));
  std::string ser_packet = packet.SerializeAsString();
  rid = boost::any_cast<boost::uint32_t>(result["rid"]);
  recovered_rid = midPacket->GetData(ser_packet, input_param_);
  ASSERT_EQ(rid, boost::any_cast<boost::uint32_t>(recovered_rid["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateSigPacket) {
  // Signature packets are signed by themselves
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  boost::shared_ptr<Packet> sigPacket(PacketFactory::Factory(MAID));
  PacketParams rec_data = sigPacket->GetData("", PacketParams());
  ASSERT_TRUE(boost::any_cast<std::string>(rec_data["data"]).empty());
  input_param_["publicKey"] = keypair1.public_key();
  input_param_["privateKey"] = keypair1.private_key();
  PacketParams result = sigPacket->Create(input_param_);
  crypto::RsaKeyPair keypair2;

  keypair2.set_public_key(boost::any_cast<std::string>(result["publicKey"]));
  keypair2.set_private_key(boost::any_cast<std::string>(result["privateKey"]));
  std::string name = boost::any_cast<std::string>(result["name"]);

  std::string sig_pubkey(co_.AsymSign(keypair2.public_key(), "",
      keypair2.private_key(), crypto::STRING_STRING));

  std::string expected_name = co_.Hash(keypair2.public_key() + sig_pubkey, "",
      crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);
  ASSERT_EQ(keypair1.public_key(), keypair2.public_key());
  ASSERT_EQ(keypair1.private_key(), keypair2.private_key());
  GenericPacket packet;
  packet.set_data(boost::any_cast<std::string>(result["publicKey"]));;
  packet.set_signature(sig_pubkey);
  std::string ser_packet(packet.SerializeAsString());
  rec_data = sigPacket->GetData(ser_packet, PacketParams());
  ASSERT_EQ(keypair1.public_key(),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateMPID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<Packet> mpidPacket(PacketFactory::Factory(MPID));
  PacketParams rec_data = mpidPacket->GetData("", PacketParams());
  ASSERT_TRUE(boost::any_cast<std::string>(rec_data["data"]).empty());
  input_param_["publicname"] = std::string("juan esmer");
  input_param_["privateKey"] = keypair1.private_key();
  input_param_["publicKey"] = keypair1.public_key();
  PacketParams result = mpidPacket->Create(input_param_);

  std::string name = boost::any_cast<std::string>(result["name"]);

  std::string expected_name = co_.Hash(boost::any_cast<std::string>(
      input_param_["publicname"]), "", crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);

  GenericPacket packet;
  packet.set_data(boost::any_cast<std::string>(result["publicKey"]));
  packet.set_signature(co_.AsymSign(keypair1.public_key(), "",
      keypair2.private_key(), crypto::STRING_STRING));
  std::string ser_packet(packet.SerializeAsString());
  rec_data = mpidPacket->GetData(ser_packet, PacketParams());
  ASSERT_EQ(keypair1.public_key(),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetKeyFromPacket) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  crypto::RsaKeyPair &keypair3 = test_sph::keys.at(2);
  crypto::RsaKeyPair &keypair4 = test_sph::keys.at(3);
  crypto::RsaKeyPair &keypair5 = test_sph::keys.at(4);
  boost::shared_ptr<Packet> sigPacket(PacketFactory::Factory(MAID));
  input_param_["privateKey"] = keypair1.private_key();
  input_param_["publicKey"] = keypair1.public_key();
  PacketParams result = sigPacket->Create(input_param_);
  GenericPacket gp;
  gp.set_data(boost::any_cast<std::string>(result["publicKey"]));
  gp.set_signature(co_.AsymSign(gp.data(), "", keypair1.private_key(),
      crypto::STRING_STRING));
  std::string ser_packet(gp.SerializeAsString());
  PacketParams rec_data = sigPacket->GetData(ser_packet, PacketParams());
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));
  input_param_["signerPrivateKey"] = keypair2.private_key();
  input_param_["privateKey"] = keypair3.private_key();
  input_param_["publicKey"] = keypair3.public_key();
  boost::shared_ptr<Packet> pmidPacket(PacketFactory::Factory(PMID));
  result = pmidPacket->Create(input_param_);
  gp.Clear();
  gp.set_data(boost::any_cast<std::string>(result["publicKey"]));
  gp.set_signature(boost::any_cast<std::string>(result["signature"]));

  ser_packet = gp.SerializeAsString();

  rec_data = pmidPacket->GetData(ser_packet, PacketParams());
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
      boost::any_cast<std::string>(rec_data["data"]));

  input_param_["publicname"] = std::string("juan esmer");
  input_param_["privateKey"] = keypair5.private_key();
  input_param_["publicKey"] = keypair5.public_key();
  boost::shared_ptr<Packet> mpidPacket(PacketFactory::Factory(MPID));
  result = mpidPacket->Create(input_param_);
  gp.Clear();
  gp.set_data(boost::any_cast<std::string>(result["publicKey"]));
  gp.set_signature(co_.AsymSign(gp.data(), "", keypair4.private_key(),
      crypto::STRING_STRING));
  ser_packet = gp.SerializeAsString();
  ASSERT_EQ(boost::any_cast<std::string>(result["publicKey"]),
    boost::any_cast<std::string>(mpidPacket->GetData(ser_packet,
    PacketParams())["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreatePMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  crypto::RsaKeyPair &keypair2 = test_sph::keys.at(1);
  boost::shared_ptr<Packet> pmidPacket(PacketFactory::Factory(PMID));
  input_param_["publicKey"] = keypair1.public_key();
  input_param_["privateKey"] = keypair1.private_key();
  input_param_["signerPrivateKey"] = keypair2.private_key();
  PacketParams result = pmidPacket->Create(input_param_);
  std::string name = boost::any_cast<std::string>(result["name"]);
  std::string expected_name = co_.Hash(keypair1.public_key() +
      co_.AsymSign(keypair1.public_key(), "", keypair2.private_key(),
          crypto::STRING_STRING),
      "", crypto::STRING_STRING, false);
  ASSERT_EQ(expected_name, name);
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateTMID) {
  boost::shared_ptr<Packet> tmid_packet(PacketFactory::Factory(TMID));
  input_param_["username"] = std::string("user1");
  input_param_["password"] = std::string("passworddelmambofeo");
  input_param_["data"] = std::string("serialised DataAtlas");
  input_param_["pin"] = std::string("1234");
  input_param_["rid"]  = boost::uint32_t(5555);
  PacketParams result = tmid_packet->Create(input_param_);
  std::string name = boost::any_cast<std::string>(result["name"]);
  // Check name
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  std::string hashrid = co_.Hash("5555", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + hashrid, "",
      crypto::STRING_STRING, false),
      boost::any_cast<std::string>(result["name"]));
  // Check data is encrypted
  ASSERT_NE(boost::any_cast<std::string>(input_param_["data"]),
      boost::any_cast<std::string>(result["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetDataFromTMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  boost::shared_ptr<Packet> tmid_packet(PacketFactory::Factory(TMID));
  input_param_["username"] = std::string("user1");
  input_param_["password"] = std::string("passworddelmambofeo");
  input_param_["data"] = std::string("serialised DataAtlas");
  input_param_["pin"] = std::string("1234");
  input_param_["rid"]  = boost::uint32_t(5555);
  PacketParams result = tmid_packet->Create(input_param_);
  GenericPacket gp;
  gp.set_data(boost::any_cast<std::string>(result["data"]));
  gp.set_signature(co_.AsymSign(gp.data(), "", keypair1.private_key(),
      crypto::STRING_STRING));

  PacketParams rec_data = tmid_packet->GetData(gp.SerializeAsString(),
      input_param_);
  ASSERT_EQ(boost::any_cast<std::string>(input_param_["data"]),
      boost::any_cast<std::string>(rec_data["data"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_CreateSMID) {
  boost::shared_ptr<Packet> smidPacket(PacketFactory::Factory(SMID));
  input_param_["username"] = std::string("user1");
  input_param_["pin"] = std::string("1234");
  input_param_["rid"] = boost::uint32_t(444455555);
  PacketParams result = smidPacket->Create(input_param_);
  std::string hashusername = co_.Hash("user1", "", crypto::STRING_STRING,
      false);
  std::string hashpin = co_.Hash("1234", "", crypto::STRING_STRING, false);
  ASSERT_EQ(co_.Hash(hashusername + hashpin + "1", "",
      crypto::STRING_STRING, false),
      boost::any_cast<std::string>(result["name"]));
}

TEST_F(SystemPacketHandlerTest, BEH_MAID_GetRidSMID) {
  crypto::RsaKeyPair &keypair1 = test_sph::keys.at(0);
  boost::shared_ptr<Packet> smidPacket(PacketFactory::Factory(SMID));
  input_param_["username"] = std::string("user1");
  input_param_["pin"] = std::string("1234");
  input_param_["rid"] = boost::uint32_t(444455555);
  PacketParams result = smidPacket->Create(input_param_);
  GenericPacket gp;
  gp.set_data(boost::any_cast<std::string>(result["encRid"]));
  gp.set_signature(co_.AsymSign(gp.data(), "", keypair1.private_key(),
      crypto::STRING_STRING));
  PacketParams recovered_rid = smidPacket->GetData(gp.SerializeAsString(),
      input_param_);
  ASSERT_EQ(boost::any_cast<uint32_t>(input_param_["rid"]),
      boost::any_cast<uint32_t>(recovered_rid["data"]));
}

}  // namespace maidsafe
