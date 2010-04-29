/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-13-01.18.27
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

#include "gtest/gtest.h"
#include "maidsafe/client/imhandler.h"
#include "maidsafe/client/sessionsingleton.h"
#include "tests/maidsafe/cached_keys.h"

class ImHandlerTest : public testing::Test {
 public:
  ImHandlerTest() : ss_(maidsafe::SessionSingleton::getInstance()),
                    imhandler_(ss_), crypto_(), keys_() {
  }
  void SetUp() {
    ss_->ResetSession();
    keys_.clear();
    // creating MPID keys
    cached_keys::MakeKeys(3, &keys_);
    ss_->AddKey(maidsafe::MPID, "Me", keys_.at(0).private_key(),
                keys_.at(0).public_key(), "");
    ASSERT_EQ(0, ss_->AddContact("contact1", keys_.at(1).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", keys_.at(2).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    maidsafe::EndPoint ep;
    ep.add_ip("127.0.0.1");
    ep.add_port(8888);
    ASSERT_TRUE(ss_->SetEp(ep));
  }

  void TearDown() {
    ss_->ResetSession();
    keys_.clear();
  }
 protected:
  maidsafe::SessionSingleton *ss_;
  maidsafe::IMHandler imhandler_;
  crypto::Crypto crypto_;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateMsg) {
  std::string ser_msg = imhandler_.CreateMessage("testmsg", "contact1");
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(crypto_.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  maidsafe::BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(1).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  ASSERT_EQ("testmsg", crypto_.SymmDecrypt(bpmsg.aesenc_message(),
      "", crypto::STRING_STRING, aes_key));
}

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateEpMsg) {
  std::string ser_msg = imhandler_.CreateMessageEndpoint("contact2");
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(crypto_.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  maidsafe::BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(2).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  maidsafe::InstantMessage im;
  ASSERT_TRUE(im.ParseFromString(crypto_.SymmDecrypt(bpmsg.aesenc_message(),
      "", crypto::STRING_STRING, aes_key)));
  ASSERT_TRUE(im.has_endpoint());
  ASSERT_EQ("Me", im.sender());
  ASSERT_EQ(maidsafe::HELLO_PING, bpmsg.type());
  ASSERT_EQ(ss_->Ep().ip_size(), im.endpoint().ip_size());
  ASSERT_EQ(ss_->Ep().ip(0), im.endpoint().ip(0));
  ASSERT_EQ(ss_->Ep().port_size(), im.endpoint().port_size());
  ASSERT_EQ(ss_->Ep().port(0), im.endpoint().port(0));
}

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateLogOutMsg) {
  std::string ser_msg = imhandler_.CreateLogOutMessage("contact2");
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(crypto_.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));
  maidsafe::BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(2).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  maidsafe::InstantMessage im;
  ASSERT_TRUE(im.ParseFromString(crypto_.SymmDecrypt(bpmsg.aesenc_message(),
      "", crypto::STRING_STRING, aes_key)));
  ASSERT_EQ("Me", im.sender());
  ASSERT_EQ(maidsafe::LOGOUT_PING, bpmsg.type());;
}

TEST_F(ImHandlerTest, BEH_MAID_Create_ValidateMsg) {
  maidsafe::InstantMessage im;
  im.set_sender(ss_->PublicUsername());
  im.set_message("testmsg");
  im.set_date(base::GetEpochTime());
  std::string ser_msg = imhandler_.CreateMessage(im.SerializeAsString(),
    "contact1");

  // reseting session and setting contact1 as owner to validate
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, "contact1", keys_.at(1).private_key(),
                keys_.at(1).public_key(), "");
  ASSERT_EQ(0, ss_->AddContact("Me", keys_.at(0).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", keys_.at(2).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::EndPoint ep;
  ep.add_ip("127.0.0.1");
  ep.add_port(8888);
  ASSERT_TRUE(ss_->SetEp(ep));
  maidsafe::MessageType type;
  std::string rec_msg;
  ASSERT_TRUE(imhandler_.ValidateMessage(ser_msg, &type, &rec_msg));

  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  maidsafe::InstantMessage rec_im;
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ(im.sender(), rec_im.sender());
  ASSERT_EQ(im.message(), rec_im.message());
  ASSERT_EQ(im.date(), rec_im.date());

  ser_msg.clear();
  rec_msg.clear();
  rec_im.Clear();
  ser_msg = imhandler_.CreateMessageEndpoint("contact2");

  // reseting session and setting contact1 as owner to validate
  ss_->ResetSession();
  ss_->AddKey(maidsafe::MPID, "contact2", keys_.at(2).private_key(),
                keys_.at(2).public_key(), "");
  ASSERT_EQ(0, ss_->AddContact("Me", keys_.at(0).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
  ASSERT_EQ(0, ss_->AddContact("contact1", keys_.at(1).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::EndPoint ep1;
  ep1.add_ip("127.0.0.1");
  ep1.add_port(8889);
  ASSERT_TRUE(ss_->SetEp(ep1));

  ASSERT_TRUE(imhandler_.ValidateMessage(ser_msg, &type, &rec_msg));
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ("contact1", rec_im.sender());
  ASSERT_TRUE(rec_im.message().empty());
  ASSERT_TRUE(rec_im.has_endpoint());
  ASSERT_EQ(ep.ip(0), rec_im.endpoint().ip(0));
  ASSERT_EQ(ep.port(0), rec_im.endpoint().port(0));
}

TEST_F(ImHandlerTest, BEH_MAID_ValidateMsgs) {
  maidsafe::MessageType type;
  std::string rec_msg;
  ASSERT_FALSE(imhandler_.ValidateMessage("not GP", &type,
      &rec_msg));

  // Generic packet incorrectly signed
  maidsafe::InstantMessage im;
  im.set_sender("contact1");
  im.set_message("testmsg");
  im.set_date(base::GetEpochTime());

  maidsafe::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id("contact1");
  bpmsg.set_type(maidsafe::INSTANT_MSG);
  boost::uint32_t iter(base::RandomUint32() % 1000 +1);
  std::string aes_key = crypto_.SecurePassword(
      crypto_.Hash("testmsg", "", crypto::STRING_STRING, false), iter);
  bpmsg.set_aesenc_message(crypto_.SymmEncrypt(im.SerializeAsString(), "",
      crypto::STRING_STRING, aes_key));
  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "",
      keys_.at(2).public_key(), crypto::STRING_STRING));

  maidsafe::GenericPacket gp;
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(crypto_.AsymSign(gp.data(), "", keys_.at(2).private_key(),
      crypto::STRING_STRING));

  ASSERT_FALSE(imhandler_.ValidateMessage(gp.SerializeAsString(),
      &type, &rec_msg));

  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "",
      keys_.at(0).public_key(), crypto::STRING_STRING));
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(crypto_.AsymSign(gp.data(), "", keys_.at(1).private_key(),
      crypto::STRING_STRING));
  ASSERT_TRUE(imhandler_.ValidateMessage(gp.SerializeAsString(),
      &type, &rec_msg));

  maidsafe::InstantMessage rec_im;
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ(im.sender(), rec_im.sender());
  ASSERT_EQ(im.message(), rec_im.message());
}
