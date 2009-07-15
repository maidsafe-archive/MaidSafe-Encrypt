/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       Team www.maidsafe.net
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
#include "maidsafe/vault/vaultbufferpackethandler.h"

class VaultBufferPacketHandlerTest : public testing::Test {
 public:
  VaultBufferPacketHandlerTest() : vbph(), public_key(), private_key(),
                                   testuser(""), ser_bp(""), cry_obj() {}
 protected:
  void SetUp() {
    maidsafe_crypto::RsaKeyPair rsakp;
    cry_obj.set_symm_algorithm("AES_256");
    cry_obj.set_hash_algorithm("SHA512");
    testuser = "testuser";
    rsakp.GenerateKeys(4096);
    public_key = rsakp.public_key();
    private_key = rsakp.private_key();
    packethandler::BufferPacketInfo bpi;
    bpi.set_owner("test bufferpacket");
    bpi.set_ownerpublickey(public_key);
    bpi.add_users(testuser);
    packethandler::BufferPacket bp;
    packethandler::GenericPacket *info = bp.add_owner_info();
    std::string ser_bpi;
    bpi.SerializeToString(&ser_bpi);
    info->set_data(ser_bpi);
    info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                        maidsafe_crypto::STRING_STRING));
    bp.SerializeToString(&ser_bp);
  }

  packethandler::VaultBufferPacketHandler vbph;
  std::string public_key;
  std::string private_key;
  std::string testuser;
  std::string ser_bp;
  maidsafe_crypto::Crypto cry_obj;
};

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_ValidateOwnerSig) {
  ASSERT_TRUE(vbph.ValidateOwnerSignature(public_key, ser_bp));
  maidsafe_crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(1024);
  ASSERT_FALSE(vbph.ValidateOwnerSignature(rsakp.public_key(), ser_bp));
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_ChangeOwnerInfo) {
  packethandler::BufferPacketInfo bpi;
  bpi.set_owner("test bufferpacket");
  bpi.set_ownerpublickey(public_key);
  bpi.set_online(1);
  bpi.add_users(testuser);
  bpi.add_users("newuser");
  packethandler::BufferPacket bp;
  packethandler::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                      maidsafe_crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  ASSERT_TRUE(vbph.ChangeOwnerInfo(ser_gp, &ser_bp, public_key));
  packethandler::BufferPacket bp_up;
  ASSERT_TRUE(bp_up.ParseFromString(ser_bp));
  packethandler::GenericPacket new_gp;
  new_gp = bp.owner_info(0);
  packethandler::BufferPacketInfo bpi_up;
  bpi_up.ParseFromString(new_gp.data());
  ASSERT_EQ("test bufferpacket", bpi_up.owner());
  ASSERT_EQ(1, bpi.online());
  ASSERT_EQ(2, bpi.users_size());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_Add_Get_Clear_Msgs) {
  std::string ser_msg("Invalid msg format");
  std::string sender;
  packethandler::MessageType type;
  ASSERT_FALSE(vbph.CheckMsgStructure(ser_msg, sender, type));
  maidsafe_crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(1024);
  packethandler::GenericPacket gp_msg;
  packethandler::BufferPacketMessage bp_msg;
  bp_msg.set_sender_id("non authuser");
  std::string signed_public_key = cry_obj.AsymSign(rsakp.public_key(),
                                  "", rsakp.private_key(),
                                  maidsafe_crypto::STRING_STRING);
  std::string enc_key = cry_obj.AsymEncrypt("key", "", public_key,
    maidsafe_crypto::STRING_STRING);
  bp_msg.set_rsaenc_key(enc_key);
  std::string enc_msg = cry_obj.SymmEncrypt("msj tonto", "",
                        maidsafe_crypto::STRING_STRING, "key");
  bp_msg.set_aesenc_message(enc_msg);
  bp_msg.set_type(packethandler::INSTANT_MSG);
  std::string ser_bp_msg;
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       maidsafe_crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, sender, type));
  ASSERT_EQ("non authuser", sender);
  ASSERT_EQ(packethandler::INSTANT_MSG, type);

  std::string sender_id = cry_obj.Hash(rsakp.public_key() + signed_public_key,
                          "", maidsafe_crypto::STRING_STRING, true);
  bp_msg.set_sender_id(sender_id);
  bp_msg.SerializeToString(&ser_bp_msg);
  bp_msg.set_sender_public_key(rsakp.public_key());
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
    maidsafe_crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, sender, type));
  ASSERT_EQ(sender_id, sender);
  ASSERT_EQ(packethandler::INSTANT_MSG, type);
  std::string ser_bp_updated;
  ASSERT_FALSE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
               &ser_bp_updated));

  // Adding the user
  packethandler::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  packethandler::GenericPacket bp_info = bp.owner_info(0);
  packethandler::BufferPacketInfo bpi;
  bpi.ParseFromString(bp_info.data());
  bpi.add_users(sender_id);
  bp.clear_owner_info();
  packethandler::GenericPacket *bp_info_up = bp.add_owner_info();
  std::string new_ser_bpi;
  bpi.SerializeToString(&new_ser_bpi);
  bp_info_up->set_data(new_ser_bpi);
  bp_info_up->set_signature(cry_obj.AsymSign(new_ser_bpi, "", private_key,
                            maidsafe_crypto::STRING_STRING));
  bp.SerializeToString(&ser_bp);

  bp_msg.set_sender_public_key(rsakp.public_key());
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       maidsafe_crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  ASSERT_TRUE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
              &ser_bp_updated));

  packethandler::BufferPacket bp_updated;
  ASSERT_TRUE(bp_updated.ParseFromString(ser_bp_updated));
  ASSERT_EQ(static_cast<boost::int32_t>(1), bp_updated.messages_size());
  std::vector<std::string> msgs, msgs1;
  ASSERT_TRUE(vbph.IsOwner("test bufferpacket", bp_updated.owner_info(0)));
  ASSERT_TRUE(vbph.GetMessages(ser_bp_updated, &msgs));
  ASSERT_EQ(static_cast<unsigned int>(1), msgs.size());
  ASSERT_TRUE(vbph.ClearMessages(&ser_bp_updated));
  ASSERT_TRUE(vbph.GetMessages(ser_bp_updated, &msgs1));
  ASSERT_EQ(static_cast<unsigned int>(0), msgs1.size());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_Add_Get_ReqMsgs) {
  std::string ser_msg;
  std::string sender;
  packethandler::MessageType type;
  maidsafe_crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(1024);
  packethandler::GenericPacket gp_msg;
  packethandler::BufferPacketMessage bp_msg;
  bp_msg.set_sender_id("non authuser");
  std::string enc_key = cry_obj.AsymEncrypt("key", "", public_key,
    maidsafe_crypto::STRING_STRING);
  bp_msg.set_rsaenc_key(enc_key);
  std::string enc_msg = cry_obj.SymmEncrypt("msj tonto auth req", "",
                        maidsafe_crypto::STRING_STRING, "key");
  bp_msg.set_aesenc_message(enc_msg);
  bp_msg.set_type(packethandler::ADD_CONTACT_RQST);

  std::string str_bp_updated;
  bp_msg.set_sender_public_key("invalid_pubkey");
  std::string ser_bp_msg;
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
    maidsafe_crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, sender, type));
  ASSERT_EQ("non authuser", sender);
  std::string signed_public_key = cry_obj.AsymSign(rsakp.public_key(),
                                  "", rsakp.private_key(),
                                  maidsafe_crypto::STRING_STRING);
  ASSERT_EQ(packethandler::ADD_CONTACT_RQST, type);
  ASSERT_FALSE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
                               &str_bp_updated));
  bp_msg.set_sender_public_key(rsakp.public_key());
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.Clear();
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       maidsafe_crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  packethandler::GenericPacket sig_packet;
  sig_packet.set_data(rsakp.public_key());
  sig_packet.set_signature(signed_public_key);
  std::string ser_sig_packet;
  sig_packet.SerializeToString(&ser_sig_packet);
  packethandler::BufferPacket bp_updated;
  ASSERT_TRUE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
              &str_bp_updated));
  ASSERT_TRUE(bp_updated.ParseFromString(str_bp_updated));
  ASSERT_EQ(1, bp_updated.messages_size());
  std::vector<std::string> msgs;
  ASSERT_TRUE(vbph.IsOwner("test bufferpacket", bp_updated.owner_info(0)));
  ASSERT_TRUE(vbph.GetMessages(str_bp_updated, &msgs));
  ASSERT_EQ(static_cast<unsigned int>(1), msgs.size());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_GetStatus) {
  // Create a BP
  packethandler::BufferPacketInfo bpi;
  bpi.set_owner(testuser);
  bpi.set_ownerpublickey(public_key);
  bpi.set_online(1);
  bpi.add_users("newuser");
  packethandler::BufferPacket bp;
  packethandler::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                      maidsafe_crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  // Create the message
  maidsafe_crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  packethandler::GenericPacket gp_msg;
  packethandler::BufferPacketMessage bp_msg;
  bp_msg.set_sender_id("newuser");
  std::string enc_key = cry_obj.AsymEncrypt("key", "", public_key,
    maidsafe_crypto::STRING_STRING);
  bp_msg.set_rsaenc_key(enc_key);
  std::string enc_msg = cry_obj.SymmEncrypt("STATUS_CHECK", "",
                        maidsafe_crypto::STRING_STRING, "key");
  bp_msg.set_aesenc_message(enc_msg);
  bp_msg.set_type(packethandler::STATUS_CHECK);
  bp_msg.set_sender_public_key(rsakp.public_key());
  std::string ser_bp_msg;
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       maidsafe_crypto::STRING_STRING));
  std::string ser_msg;
  gp_msg.SerializeToString(&ser_msg);

  // Create the signed public key
  std::string sig_public_key = cry_obj.AsymSign(rsakp.public_key(), "",
                               rsakp.private_key(),
                               maidsafe_crypto::STRING_STRING);
  // Testing the results
  int status = -1;
  ASSERT_TRUE(vbph.CheckStatus(ser_bp, ser_msg, sig_public_key, &status));
  ASSERT_EQ(1, bpi.online());
}
