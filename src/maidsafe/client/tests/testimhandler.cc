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

#include <gtest/gtest.h>
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/maidsafe.h"
#include "maidsafe/client/imhandler.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/sharedtest/cached_keys.h"
#include "maidsafe/sharedtest/cachepassport.h"
#include "maidsafe/sharedtest/mocksessionsingleton.h"


namespace maidsafe {

namespace test {

class ImHandlerTest : public testing::Test {
 public:
  ImHandlerTest() : ss_(SessionSingleton::getInstance()),
                    imhandler_(),
                    crypto_(),
                    keys_(),
                    mpid_public_key_() {}
  virtual void SetUp() {
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss_->passport_ = passport;
    ss_->ResetSession();
    keys_.clear();
    // creating MPID keys
    cached_keys::MakeKeys(2, &keys_);
    ss_->CreateTestPackets("Me");
    ASSERT_EQ(0, ss_->AddContact("contact1", keys_.at(0).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", keys_.at(1).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    EndPoint ep;
    ep.add_ip("127.0.0.1");
    ep.add_port(8888);
    ASSERT_TRUE(ss_->SetEp(ep));
    ASSERT_EQ(kSuccess, ss_->MPublicID(NULL, &mpid_public_key_, NULL, NULL));
  }

  void TearDown() {
    ss_->ResetSession();
    keys_.clear();
  }
 protected:
  SessionSingleton *ss_;
  IMHandler imhandler_;
  crypto::Crypto crypto_;
  std::vector<crypto::RsaKeyPair> keys_;
  std::string mpid_public_key_;
};

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateMsg) {
  std::string ser_msg = imhandler_.CreateMessage("testmsg", "contact1");
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(0).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  ASSERT_EQ("testmsg", crypto_.SymmDecrypt(bpmsg.aesenc_message(), "",
                                           crypto::STRING_STRING, aes_key));
}

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateEpMsg) {
  std::string ser_msg = imhandler_.CreateMessageEndpoint("contact2");
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(1).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  InstantMessage im;
  ASSERT_TRUE(im.ParseFromString(crypto_.SymmDecrypt(bpmsg.aesenc_message(),
      "", crypto::STRING_STRING, aes_key)));
  ASSERT_TRUE(im.has_endpoint());
  ASSERT_EQ("Me", im.sender());
  ASSERT_EQ(HELLO_PING, bpmsg.type());
  ASSERT_EQ(ss_->Ep().ip_size(), im.endpoint().ip_size());
  ASSERT_EQ(ss_->Ep().ip(0), im.endpoint().ip(0));
  ASSERT_EQ(ss_->Ep().port_size(), im.endpoint().port_size());
  ASSERT_EQ(ss_->Ep().port(0), im.endpoint().port(0));
}

TEST_F(ImHandlerTest, BEH_MAID_InstMsgCreateLogOutMsg) {
  std::string ser_msg = imhandler_.CreateLogOutMessage("contact2");
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(ser_msg));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  BufferPacketMessage bpmsg;
  ASSERT_TRUE(bpmsg.ParseFromString(gp.data()));
  ASSERT_EQ("Me", bpmsg.sender_id());
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      keys_.at(1).private_key(), crypto::STRING_STRING));
  ASSERT_FALSE(aes_key.empty());
  InstantMessage im;
  ASSERT_TRUE(im.ParseFromString(crypto_.SymmDecrypt(bpmsg.aesenc_message(),
      "", crypto::STRING_STRING, aes_key)));
  ASSERT_EQ("Me", im.sender());
  ASSERT_EQ(LOGOUT_PING, bpmsg.type());
}

TEST_F(ImHandlerTest, BEH_MAID_ValidateMsgs) {
  MessageType type;
  std::string rec_msg;
  ASSERT_FALSE(imhandler_.ValidateMessage("not GP", &type,
      &rec_msg));

  // Generic packet incorrectly signed
  InstantMessage im;
  im.set_sender("contact1");
  im.set_message("testmsg");
  im.set_date(base::GetEpochTime());

  BufferPacketMessage bpmsg;
  bpmsg.set_sender_id("contact1");
  bpmsg.set_type(INSTANT_MSG);
  boost::uint32_t iter(base::RandomUint32() % 1000 +1);
  std::string aes_key = crypto_.SecurePassword(
      base::RandomString(crypto::AES256_KeySize),
      base::RandomString(crypto::AES256_IVSize), iter);
  bpmsg.set_aesenc_message(crypto_.SymmEncrypt(im.SerializeAsString(), "",
      crypto::STRING_STRING, aes_key));
  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "",
      keys_.at(1).public_key(), crypto::STRING_STRING));

  GenericPacket gp;
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(RSASign(gp.data(), keys_.at(1).private_key()));

  ASSERT_FALSE(imhandler_.ValidateMessage(gp.SerializeAsString(),
      &type, &rec_msg));

  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "", mpid_public_key_,
                       crypto::STRING_STRING));
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(RSASign(gp.data(), keys_.at(0).private_key()));
  ASSERT_TRUE(imhandler_.ValidateMessage(gp.SerializeAsString(),
      &type, &rec_msg));

  InstantMessage rec_im;
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ(im.sender(), rec_im.sender());
  ASSERT_EQ(im.message(), rec_im.message());
}

class MultiImHandlerTest : public ImHandlerTest {
 public:
  MultiImHandlerTest() : ImHandlerTest(),
                         ss1_(),
                         ss2_(),
                         imhandler1_(),
                         imhandler2_() {}
  void SetUp() {
    ImHandlerTest::SetUp();
    imhandler1_.ss_ = &ss1_;
    imhandler2_.ss_ = &ss2_;
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss_->passport_ = passport;
    ss_->ResetSession();
    keys_.clear();
    ss_->CreateTestPackets("Me");
    ss1_.CreateTestPackets("contact1");
    ss2_.CreateTestPackets("contact2");
    std::string mpid_public_key1, mpid_public_key2;
    ASSERT_EQ(kSuccess, ss1_.MPublicID(NULL, &mpid_public_key1, NULL, NULL));
    ASSERT_EQ(kSuccess, ss2_.MPublicID(NULL, &mpid_public_key2, NULL, NULL));
    ASSERT_EQ(0, ss_->AddContact("contact1", mpid_public_key1, "", "", "", 'U',
                                 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", mpid_public_key2, "", "", "", 'U',
                                 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss1_.AddContact("Me", mpid_public_key_, "", "", "", 'U', 1, 2,
                                 "", 'C', 0, 0));
    ASSERT_EQ(0, ss1_.AddContact("contact2", mpid_public_key2, "", "", "", 'U',
                                 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss2_.AddContact("Me", mpid_public_key_, "", "", "", 'U', 1, 2,
                                 "", 'C', 0, 0));
    ASSERT_EQ(0, ss2_.AddContact("contact1", mpid_public_key1, "", "", "", 'U',
                                 1, 2, "", 'C', 0, 0));
    EndPoint ep;
    ep.add_ip("127.0.0.1");
    ep.add_port(8888);
    ASSERT_TRUE(ss_->SetEp(ep));
    ASSERT_TRUE(ss1_.SetEp(ep));
    ASSERT_TRUE(ss2_.SetEp(ep));
  }
 protected:
  MockSessionSingleton ss1_, ss2_;
  IMHandler imhandler1_, imhandler2_;
};

TEST_F(MultiImHandlerTest, FUNC_MAID_Create_ValidateMsg) {
  InstantMessage im;
  im.set_sender(ss_->PublicUsername());
  im.set_message("testmsg");
  im.set_date(base::GetEpochTime());
  std::string ser_msg = imhandler_.CreateMessage(im.SerializeAsString(),
                                                 "contact1");

  // contact1 to validate
  MessageType type;
  std::string rec_msg;
  ASSERT_TRUE(imhandler1_.ValidateMessage(ser_msg, &type, &rec_msg));

  ASSERT_EQ(INSTANT_MSG, type);
  InstantMessage rec_im;
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ(im.sender(), rec_im.sender());
  ASSERT_EQ(im.message(), rec_im.message());
  ASSERT_EQ(im.date(), rec_im.date());

  ser_msg.clear();
  rec_msg.clear();
  rec_im.Clear();
  ser_msg = imhandler1_.CreateMessageEndpoint("contact2");

  // contact2 to validate
  ASSERT_TRUE(imhandler2_.ValidateMessage(ser_msg, &type, &rec_msg));
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_TRUE(rec_im.ParseFromString(rec_msg));
  ASSERT_EQ("contact1", rec_im.sender());
  ASSERT_TRUE(rec_im.message().empty());
  ASSERT_TRUE(rec_im.has_endpoint());
}

}  // namespace test

}  // namespace maidsafe
