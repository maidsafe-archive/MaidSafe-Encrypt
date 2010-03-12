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
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vaultbufferpackethandler.h"

class VaultBufferPacketHandlerTest : public testing::Test {
 public:
  VaultBufferPacketHandlerTest() : vbph(), public_key(), private_key(),
                                   testuser(""), ser_bp(""), cry_obj() {}
 protected:
  void SetUp() {
    crypto::RsaKeyPair rsakp;
    cry_obj.set_symm_algorithm(crypto::AES_256);
    cry_obj.set_hash_algorithm(crypto::SHA_512);
    testuser = "testuser";
    rsakp.GenerateKeys(maidsafe::kRsaKeySize);
    public_key = rsakp.public_key();
    private_key = rsakp.private_key();
    maidsafe::BufferPacketInfo bpi;
    bpi.set_owner("test bufferpacket");
    bpi.set_owner_publickey(public_key);
    bpi.add_users(cry_obj.Hash(testuser, "", crypto::STRING_STRING, false));
    maidsafe::BufferPacket bp;
    maidsafe::GenericPacket *info = bp.add_owner_info();
    std::string ser_bpi;
    bpi.SerializeToString(&ser_bpi);
    info->set_data(ser_bpi);
    info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                        crypto::STRING_STRING));
    bp.SerializeToString(&ser_bp);
  }

  maidsafe::VaultBufferPacketHandler vbph;
  std::string public_key;
  std::string private_key;
  std::string testuser;
  std::string ser_bp;
  crypto::Crypto cry_obj;
};

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_ValidateOwnerSig) {
  ASSERT_TRUE(vbph.ValidateOwnerSignature(public_key, ser_bp));
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(maidsafe::kRsaKeySize);
  ASSERT_FALSE(vbph.ValidateOwnerSignature(rsakp.public_key(), ser_bp));
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_ChangeOwnerInfo) {
  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("test bufferpacket");
  bpi.set_owner_publickey(public_key);
  bpi.set_online(1);
  bpi.add_users(testuser);
  bpi.add_users("newuser");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                      crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  ASSERT_TRUE(vbph.ChangeOwnerInfo(ser_gp, public_key, &ser_bp));
  maidsafe::BufferPacket bp_up;
  ASSERT_TRUE(bp_up.ParseFromString(ser_bp));
  maidsafe::GenericPacket new_gp;
  new_gp = bp.owner_info(0);
  maidsafe::BufferPacketInfo bpi_up;
  bpi_up.ParseFromString(new_gp.data());
  ASSERT_EQ("test bufferpacket", bpi_up.owner());
  ASSERT_EQ(1, bpi_up.online());
  ASSERT_EQ(2, bpi_up.users_size());
  ASSERT_FALSE(bpi_up.has_ep());
  ASSERT_FALSE(bpi_up.has_pd());

  maidsafe::PersonalDetails *pd = bpi.mutable_pd();
  pd->Clear();
  maidsafe::EndPoint *ep = bpi.mutable_ep();
  ep->set_ip("132.248.59.1");
  ep->set_port(12345);
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                      crypto::STRING_STRING));
  info->SerializeToString(&ser_gp);
  ASSERT_TRUE(vbph.ChangeOwnerInfo(ser_gp, public_key, &ser_bp));
  ASSERT_TRUE(bp_up.ParseFromString(ser_bp));
  new_gp = bp.owner_info(0);
  bpi_up.ParseFromString(new_gp.data());
  ASSERT_EQ("test bufferpacket", bpi_up.owner());
  ASSERT_EQ(1, bpi_up.online());
  ASSERT_EQ(2, bpi_up.users_size());
  ASSERT_TRUE(bpi_up.has_ep());
  ASSERT_TRUE(bpi_up.has_pd());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_Add_Get_Clear_Msgs) {
  std::string ser_msg("Invalid msg format");
  std::string sender;
  maidsafe::MessageType type;
  ASSERT_FALSE(vbph.CheckMsgStructure(ser_msg, &sender, &type));
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(maidsafe::kRsaKeySize);
  maidsafe::GenericPacket gp_msg;
  maidsafe::BufferPacketMessage bp_msg;
  bp_msg.set_sender_id("non authuser");
  std::string signed_public_key = cry_obj.AsymSign(rsakp.public_key(),
                                  "", rsakp.private_key(),
                                  crypto::STRING_STRING);
  std::string enc_key = cry_obj.AsymEncrypt("key", "", public_key,
    crypto::STRING_STRING);
  bp_msg.set_rsaenc_key(enc_key);
  std::string enc_msg = cry_obj.SymmEncrypt("msj tonto", "",
                        crypto::STRING_STRING, "key");
  bp_msg.set_aesenc_message(enc_msg);
  bp_msg.set_type(maidsafe::INSTANT_MSG);
  std::string ser_bp_msg;
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, &sender, &type));
  ASSERT_EQ("non authuser", sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);

  std::string sender_id = cry_obj.Hash(rsakp.public_key() + signed_public_key,
                          "", crypto::STRING_STRING, false);
  std::string hashed_sender_id = cry_obj.Hash(sender_id, "",
                                 crypto::STRING_STRING, false);
  bp_msg.set_sender_id(sender_id);
  bp_msg.SerializeToString(&ser_bp_msg);
  bp_msg.set_sender_public_key(rsakp.public_key());
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
    crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, &sender, &type));
  ASSERT_EQ(sender_id, sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  std::string ser_bp_updated;
  ASSERT_FALSE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
               &ser_bp_updated));

  // Adding the user
  maidsafe::BufferPacket bp;
  bp.ParseFromString(ser_bp);
  maidsafe::GenericPacket bp_info = bp.owner_info(0);
  maidsafe::BufferPacketInfo bpi;
  bpi.ParseFromString(bp_info.data());
  bpi.add_users(hashed_sender_id);
  bp.clear_owner_info();
  maidsafe::GenericPacket *bp_info_up = bp.add_owner_info();
  std::string new_ser_bpi;
  bpi.SerializeToString(&new_ser_bpi);
  bp_info_up->set_data(new_ser_bpi);
  bp_info_up->set_signature(cry_obj.AsymSign(new_ser_bpi, "", private_key,
                            crypto::STRING_STRING));
  bp.SerializeToString(&ser_bp);

  bp_msg.set_sender_public_key(rsakp.public_key());
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  ASSERT_TRUE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
              &ser_bp_updated));

  maidsafe::BufferPacket bp_updated;
  ASSERT_TRUE(bp_updated.ParseFromString(ser_bp_updated));
  ASSERT_EQ(static_cast<boost::int32_t>(1), bp_updated.messages_size());
  std::vector<std::string> msgs, msgs1;
  ASSERT_TRUE(vbph.IsOwner("test bufferpacket", bp_updated.owner_info(0)));
  ASSERT_TRUE(vbph.GetMessages(&ser_bp_updated, &msgs));
  ASSERT_EQ(size_t(1), msgs.size());
  ASSERT_TRUE(vbph.ClearMessages(&ser_bp_updated));
  ASSERT_TRUE(vbph.GetMessages(&ser_bp_updated, &msgs1));
  ASSERT_EQ(size_t(0), msgs1.size());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_Add_Get_ReqMsgs) {
  std::string ser_msg;
  std::string sender;
  maidsafe::MessageType type;
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(maidsafe::kRsaKeySize);
  maidsafe::GenericPacket gp_msg;
  maidsafe::BufferPacketMessage bp_msg;
  bp_msg.set_sender_id("non authuser");
  std::string enc_key = cry_obj.AsymEncrypt("key", "", public_key,
    crypto::STRING_STRING);
  bp_msg.set_rsaenc_key(enc_key);
  std::string enc_msg = cry_obj.SymmEncrypt("msj tonto auth req", "",
                        crypto::STRING_STRING, "key");
  bp_msg.set_aesenc_message(enc_msg);
  bp_msg.set_type(maidsafe::ADD_CONTACT_RQST);

  std::string str_bp_updated;
  bp_msg.set_sender_public_key("invalid_pubkey");
  std::string ser_bp_msg;
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
    crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);
  ASSERT_TRUE(vbph.CheckMsgStructure(ser_msg, &sender, &type));
  ASSERT_EQ("non authuser", sender);
  std::string signed_public_key = cry_obj.AsymSign(rsakp.public_key(),
                                  "", rsakp.private_key(),
                                  crypto::STRING_STRING);
  ASSERT_EQ(maidsafe::ADD_CONTACT_RQST, type);
  ASSERT_FALSE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
                               &str_bp_updated));
  bp_msg.set_sender_public_key(rsakp.public_key());
  bp_msg.SerializeToString(&ser_bp_msg);
  gp_msg.Clear();
  gp_msg.set_data(ser_bp_msg);
  gp_msg.set_signature(cry_obj.AsymSign(ser_bp_msg, "", rsakp.private_key(),
                       crypto::STRING_STRING));
  gp_msg.SerializeToString(&ser_msg);

  maidsafe::GenericPacket sig_packet;
  sig_packet.set_data(rsakp.public_key());
  sig_packet.set_signature(signed_public_key);
  std::string ser_sig_packet;
  sig_packet.SerializeToString(&ser_sig_packet);
  maidsafe::BufferPacket bp_updated;
  ASSERT_TRUE(vbph.AddMessage(ser_bp, ser_msg, signed_public_key,
              &str_bp_updated));
  ASSERT_TRUE(bp_updated.ParseFromString(str_bp_updated));
  ASSERT_EQ(1, bp_updated.messages_size());
  std::vector<std::string> msgs;
  ASSERT_TRUE(vbph.IsOwner("test bufferpacket", bp_updated.owner_info(0)));
  ASSERT_TRUE(vbph.GetMessages(&str_bp_updated, &msgs));
  ASSERT_EQ(size_t(1), msgs.size());
}

TEST_F(VaultBufferPacketHandlerTest, BEH_MAID_GetStatus) {
  // Create a BP
  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner(testuser);
  bpi.set_owner_publickey(public_key);
  bpi.set_online(1);
  bpi.add_users(cry_obj.Hash("newuser", "", crypto::STRING_STRING, false));
  maidsafe::EndPoint *ep = bpi.mutable_ep();
  ep->set_ip("132.248.59.1");
  ep->set_port(12345);
  maidsafe::PersonalDetails *pd = bpi.mutable_pd();
  pd->set_full_name("Juanbert Tupadre");
  pd->set_phone_number("0987654321");
  pd->set_birthday("01/01/1970");
  pd->set_gender("Male");
  pd->set_language("English");
  pd->set_city("Troon");
  pd->set_country("United Kingdom of Her Majesty the Queen");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(cry_obj.AsymSign(ser_bpi, "", private_key,
                      crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  // Get the info
  maidsafe::EndPoint end_point;
  maidsafe::PersonalDetails personal_details;
  boost::uint16_t status;
  ASSERT_FALSE(vbph.ContactInfo("", "newuser", &end_point, &personal_details,
               &status));
  ASSERT_FALSE(vbph.ContactInfo(ser_bp, "non-authorised", &end_point,
               &personal_details, &status));
  ASSERT_TRUE(vbph.ContactInfo(ser_bp, "newuser", &end_point, &personal_details,
              &status));
  ASSERT_EQ(ep->ip(), end_point.ip());
  ASSERT_EQ(ep->port(), end_point.port());
  ASSERT_EQ(bpi.online(), status);
  ASSERT_EQ(pd->full_name(), personal_details.full_name());
  ASSERT_EQ(pd->phone_number(), personal_details.phone_number());
  ASSERT_EQ(pd->birthday(), personal_details.birthday());
  ASSERT_EQ(pd->gender(), personal_details.gender());
  ASSERT_EQ(pd->language(), personal_details.language());
  ASSERT_EQ(pd->city(), personal_details.city());
  ASSERT_EQ(pd->country(), personal_details.country());

  // Get own info
  ASSERT_TRUE(vbph.ContactInfo(ser_bp, testuser, &end_point, &personal_details,
              &status));
  ASSERT_EQ(ep->ip(), end_point.ip());
  ASSERT_EQ(ep->port(), end_point.port());
  ASSERT_EQ(bpi.online(), status);
  ASSERT_EQ(pd->full_name(), personal_details.full_name());
  ASSERT_EQ(pd->phone_number(), personal_details.phone_number());
  ASSERT_EQ(pd->birthday(), personal_details.birthday());
  ASSERT_EQ(pd->gender(), personal_details.gender());
  ASSERT_EQ(pd->language(), personal_details.language());
  ASSERT_EQ(pd->city(), personal_details.city());
  ASSERT_EQ(pd->country(), personal_details.country());
}
