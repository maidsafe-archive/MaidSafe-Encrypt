/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for IMMessaging from Maidstoremanager
* Version:      1.0
* Created:      2010-04-14-10.09.29
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
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/filesystem/fstream.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transport-api.h>
#include <maidsafe/transport/transportudt.h>
#include <maidsafe/protobuf/general_messages.pb.h>

#include "maidsafe/client/imconnectionhandler.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/maidsafe_messages.pb.h"
#include "maidsafe/sharedtest/cachepassport.h"
#include "maidsafe/sharedtest/mocksessionsingleton.h"
#include "maidsafe/sharedtest/networktest.h"
#include "maidsafe/sharedtest/testcallback.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace test {

InstantMessage GetImFromBpMessage(const std::string &ser_bpmsg,
    const std::string &priv_key, MessageType *type) {
  InstantMessage im;
  crypto::Crypto co;
  BufferPacketMessage bpmsg;
  if (!bpmsg.ParseFromString(ser_bpmsg))
    return im;
  *type = bpmsg.type();
  std::string aes_key(co.AsymDecrypt(bpmsg.rsaenc_key(), "", priv_key,
      crypto::STRING_STRING));
  im.ParseFromString(co.SymmDecrypt(bpmsg.aesenc_message(), "",
      crypto::STRING_STRING, aes_key));
  return im;
}

std::string GetStrMsgFromBpMsg(const std::string &ser_bpmsg,
    const std::string &priv_key, MessageType *type,
    std::string *sender) {
  crypto::Crypto co;
  BufferPacketMessage bpmsg;
  if (!bpmsg.ParseFromString(ser_bpmsg))
    return "";
  *type = bpmsg.type();
  *sender = bpmsg.sender_id();
  std::string aes_key(co.AsymDecrypt(bpmsg.rsaenc_key(), "", priv_key,
      crypto::STRING_STRING));
  return co.SymmDecrypt(bpmsg.aesenc_message(), "",
      crypto::STRING_STRING, aes_key);
}

class ImMessagingTest : public testing::Test {
 public:
  ImMessagingTest() : network_test_(),
                      ctc1_trans_(),
                      ctc2_trans_(),
                      ss_(SessionSingleton::getInstance()),
                      publicusername_("Teh contact"),
                      ctc1_ep_(),
                      ctc2_ep_(),
                      sm_(network_test_.store_manager()),
                      keys_(),
                      sm_rec_msg_(),
                      alt_ctc_conn_(0),
                      sender_(),
                      latest_ctc_updated_(),
                      latest_status_(100),
                      alt_ctc_rec_msgs_(),
                      mpid_public_key_() {
    keys_.clear();
    cached_keys::MakeKeys(2, &keys_);
  }
 protected:
  void SetUp() {
    SessionSingleton *ss(SessionSingleton::getInstance());
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss->passport_ = passport;
    ss->ResetSession();
    ss_->CreateTestPackets(publicusername_);
    ASSERT_TRUE(network_test_.Init());
    ss_->SetConnectionStatus(0);
    sm_->SetSessionEndPoint();
    sm_->SetInstantMessageNotifier(
        boost::bind(&ImMessagingTest::SmOnMessageNotifier, this, _1),
        boost::bind(&ImMessagingTest::SmStatusUpdate, this, _1, _2));
    ASSERT_EQ(kSuccess, ss_->GetKey(passport::MPID, NULL, &mpid_public_key_,
                                    NULL, NULL));
    // starting alternative transport
    ctc1_trans_.reset(new transport::TransportUDT);
    ASSERT_TRUE(ctc1_trans_->RegisterOnSend(boost::bind(
          &ImMessagingTest::SendNotifier, this, _1, _2)));
    ASSERT_TRUE(ctc1_trans_->RegisterOnServerDown(boost::bind(
          &ImMessagingTest::OnServerDown, this, _1, _2, _3)));
    ASSERT_TRUE(ctc1_trans_->RegisterOnMessage(boost::bind(
          &ImMessagingTest::UDTTransMsgArrived, this, _1, _2, _3, _4)));
    ASSERT_EQ(0, ctc1_trans_->Start(0));
    boost::asio::ip::address addr;
    base::GetLocalAddress(&addr);
    ctc1_ep_.add_ip(addr.to_string());
    ctc1_ep_.add_ip(addr.to_string());
    ctc1_ep_.add_ip("");
    ctc1_ep_.add_port(ctc1_trans_->listening_port());
    ctc1_ep_.add_port(ctc1_trans_->listening_port());
    ctc1_ep_.add_port(0);

    ctc2_trans_.reset(new transport::TransportUDT);
    ASSERT_TRUE(ctc2_trans_->RegisterOnSend(boost::bind(
          &ImMessagingTest::SendNotifier, this, _1, _2)));
    ASSERT_TRUE(ctc2_trans_->RegisterOnServerDown(boost::bind(
          &ImMessagingTest::OnServerDown, this, _1, _2, _3)));
    ASSERT_TRUE(ctc2_trans_->RegisterOnMessage(boost::bind(
          &ImMessagingTest::UDTTransMsgArrived, this, _1, _2, _3, _4)));
    ASSERT_EQ(0, ctc2_trans_->Start(0));
    ctc2_ep_.add_ip(addr.to_string());
    ctc2_ep_.add_ip(addr.to_string());
    ctc2_ep_.add_ip("");
    ctc2_ep_.add_port(ctc2_trans_->listening_port());
    ctc2_ep_.add_port(ctc2_trans_->listening_port());
    ctc2_ep_.add_port(0);

    // Adding contact information to session
    ss_->CreateTestPackets(publicusername_);
    ASSERT_EQ(0, ss_->AddContact("contact1", keys_.at(0).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", keys_.at(1).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));

    // setting contact1 as a live contact
    ASSERT_EQ(0, ss_->AddLiveContact("contact1", ctc1_ep_, 0));
  }
  void TearDown() {
    ctc1_trans_->Stop();
    ctc2_trans_->Stop();
    ss_->ResetSession();
    sm_rec_msg_.clear();
    alt_ctc_conn_ = 0;
    sender_.clear();
    latest_ctc_updated_.clear();
    latest_status_ = 100;
    alt_ctc_rec_msgs_.clear();
  }

  NetworkTest network_test_;
  boost::shared_ptr<transport::Transport> ctc1_trans_, ctc2_trans_;
  SessionSingleton *ss_;
  std::string publicusername_;
  EndPoint ctc1_ep_, ctc2_ep_;
  boost::shared_ptr<TestStoreManager> sm_;
  std::vector<crypto::RsaKeyPair> keys_;
  std::string sm_rec_msg_;
  boost::uint32_t alt_ctc_conn_;
  std::string sender_, latest_ctc_updated_;
  int latest_status_;
  std::vector<std::string> alt_ctc_rec_msgs_;
  std::string mpid_public_key_;

 private:
  void SendNotifier(const boost::uint32_t&, const bool&) {}
  void OnServerDown(const bool&, const std::string&, const boost::uint16_t&) {}
  void UDTTransMsgArrived(const std::string &msg, const boost::uint32_t &id,
      const boost::int16_t&, const float&) {
    alt_ctc_conn_ = id;
    alt_ctc_rec_msgs_.push_back(msg);
  }
  void SmOnMessageNotifier(const std::string &msg) {
    sm_rec_msg_.clear();
    sm_rec_msg_ = msg;
  }
  void SmStatusUpdate(const std::string &contactname, const int &status) {
    latest_ctc_updated_.clear();
    latest_status_ = 100;
    latest_ctc_updated_ = contactname;
    latest_status_ = status;
  }

  ImMessagingTest(const ImMessagingTest&);
  ImMessagingTest &operator=(const ImMessagingTest&);
};

TEST_MS_NET(ImMessagingTest, FUNC, MAID, SendMessages) {
  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.size() < size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  boost::this_thread::sleep(boost::posix_time::seconds(2));
  alt_ctc_rec_msgs_.clear();
  msg = "Second message";
  results.clear();
  gp.Clear();

  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
  ASSERT_EQ(INSTANT_MSG, type);

  boost::this_thread::sleep(boost::posix_time::seconds(
      kConnectionTimeout + 1));
  alt_ctc_rec_msgs_.clear();
  msg = "Third message";
  results.clear();
  gp.Clear();

  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.size() < size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_FALSE(alt_ctc_rec_msgs_.empty());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  im.Clear();
  im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, SendReceiveMessages) {
  MockSessionSingleton client1_ss;
  client1_ss.CreateTestPackets("contact1");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, mpid_public_key_, "", "",
                                     "", 'U', 1, 2, "", 'C', 0, 0));
  IMHandler client1_imh;
  client1_imh.ss_ = &client1_ss;
  client1_ss.SetEp(ctc1_ep_);

  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  std::string val_msg;
  ASSERT_TRUE(client1_imh.ValidateMessage(alt_ctc_rec_msgs_[1], &type,
      &val_msg));

  msg = "Hello from contact1";
  std::string ctc1_msg(client1_imh.CreateMessage(msg, publicusername_));
  ASSERT_EQ(0, ctc1_trans_->Send(ctc1_msg, alt_ctc_conn_, false));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  ASSERT_EQ(msg, sm_rec_msg_);

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  alt_ctc_rec_msgs_.clear();
  results.clear();
  msg = "What up!!!";
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  ASSERT_TRUE(client1_imh.ValidateMessage(alt_ctc_rec_msgs_[0], &type,
      &val_msg));
  ASSERT_EQ(msg, val_msg);

  boost::this_thread::sleep(boost::posix_time::seconds(2));
  sm_rec_msg_.clear();
  msg = "Goodbye";
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ctc1_msg = (client1_imh.CreateMessage(msg, publicusername_));
  ASSERT_EQ(0, ctc1_trans_->Send(ctc1_msg, alt_ctc_conn_, false));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  ASSERT_EQ(msg, sm_rec_msg_);
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, ReceiveEndPointMsg) {
  MockSessionSingleton client2_ss;
  client2_ss.CreateTestPackets("contact2");
  ASSERT_EQ(0, client2_ss.AddContact(publicusername_, mpid_public_key_, "", "",
                                     "", 'U', 1, 2, "", 'C', 0, 0));
  IMHandler client2_imh;
  client2_imh.ss_ = &client2_ss;
  client2_ss.SetEp(ctc2_ep_);
  client2_ss.SetConnectionStatus(0);
  std::string ser_msg(client2_imh.CreateMessageEndpoint(publicusername_));
  boost::uint32_t c_id(0);
  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c_id));
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(std::string("contact2"), latest_ctc_updated_);
  ASSERT_EQ(client2_ss.ConnectionStatus(), latest_status_);

  // checking new contact is in the live contacts map in session
  int ctc2_status(100);
  ASSERT_EQ(0, ss_->LiveContactStatus("contact2", &ctc2_status));
  ASSERT_EQ(client2_ss.ConnectionStatus(), ctc2_status);

  // receiving a message from new contact
  std::string msg("What's up");
  ser_msg = client2_imh.CreateMessage(msg, publicusername_);
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  ASSERT_EQ(msg, sm_rec_msg_);

  boost::this_thread::sleep(boost::posix_time::seconds(1));

  // Sending a message to new contact
  std::vector<std::string> recs;
  recs.push_back("contact2");
  std::map<std::string, ReturnCode> results;
  msg = "Hello dude\n";
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  std::string rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  std::string val_msg;
  ASSERT_TRUE(client2_imh.ValidateMessage(alt_ctc_rec_msgs_[0], &type,
      &val_msg));

  // Letting connection timeout and then send a new msg
  boost::this_thread::sleep(boost::posix_time::seconds(
      kConnectionTimeout + 1));
  alt_ctc_rec_msgs_.clear();
  results.clear();
  msg = "Another message for contact2";
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, SendLogOutMsg) {
  sm_->SendLogOutMessage("contact2");
  sm_->SendLogOutMessage("contact1");
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  im.Clear();
  im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(LOGOUT_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  ctc1_trans_->Stop();
  sm_->SendLogOutMessage("contact1");
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, SendPresenceMsg) {
  ASSERT_FALSE(sm_->SendPresence("contact2"));
  ASSERT_TRUE(sm_->SendPresence("contact1"));
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());
  ASSERT_EQ(ss_->ConnectionStatus(), im.status());

  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, ReturnCode> results;
  std::string msg("Hello World\n");
  alt_ctc_rec_msgs_.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.size() < size_t(1)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(msg, rec_msg);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(INSTANT_MSG, type);


  ctc1_trans_->Stop();
  ASSERT_FALSE(sm_->SendPresence("contact1"));
  int ctc1_status(100);
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactStatus("contact1",
      &ctc1_status));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, ReceiveLogOutMsg) {
  MockSessionSingleton client1_ss;
  client1_ss.CreateTestPackets("contact1");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, mpid_public_key_, "", "",
                                     "", 'U', 1, 2, "", 'C', 0, 0));
  IMHandler client1_imh;
  client1_imh.ss_ = &client1_ss;
  client1_ss.SetEp(ctc1_ep_);
  client1_ss.SetConnectionStatus(0);
  std::string ser_msg(client1_imh.CreateLogOutMessage(publicusername_));
  boost::uint32_t c_id(0);
  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c_id));
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  int ctc1_status(100);
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactStatus("contact1",
      &ctc1_status));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);

  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ser_msg = client1_imh.CreateMessageEndpoint(publicusername_);
  ASSERT_NE(0, ctc2_trans_->Send(ser_msg, c_id, true));

  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c_id));
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(client1_ss.ConnectionStatus(), latest_status_);
  ASSERT_EQ(0, ss_->LiveContactStatus("contact1", &ctc1_status));
  ASSERT_EQ(client1_ss.ConnectionStatus(), ctc1_status);

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ser_msg = client1_imh.CreateLogOutMessage(publicusername_);
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactStatus("contact1",
      &ctc1_status));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, InvalidNewConnection) {
  boost::uint32_t c_id(0);
  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c_id));
  ASSERT_EQ(0, ctc2_trans_->Send("abcdefg", c_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(std::string(""), latest_ctc_updated_);
  ASSERT_EQ(100, latest_status_);
  int ctc2_status(100);
  ASSERT_EQ(kLiveContactNotFound,
      ss_->LiveContactStatus("contact2", &ctc2_status));

  // Checking transport connection was closed
  ASSERT_NE(0, ctc2_trans_->Send("abcdefg", c_id, true));
}

TEST_MS_NET(ImMessagingTest, FUNC, MAID, HandleTwoConverstions) {
  MockSessionSingleton client2_ss;
  client2_ss.CreateTestPackets("contact2");
  ASSERT_EQ(0, client2_ss.AddContact(publicusername_, mpid_public_key_, "", "",
                                     "", 'U', 1, 2, "", 'C', 0, 0));
  IMHandler client2_imh;
  client2_imh.ss_ = &client2_ss;
  client2_ss.SetEp(ctc2_ep_);
  client2_ss.SetConnectionStatus(0);

  MockSessionSingleton client1_ss;
  client1_ss.CreateTestPackets("contact1");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, mpid_public_key_, "", "",
                                     "", 'U', 1, 2, "", 'C', 0, 0));
  IMHandler client1_imh;
  client1_imh.ss_ = &client1_ss;
  client1_ss.SetEp(ctc1_ep_);

  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);

  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string sender;
  MessageType type;

  InstantMessage im = GetImFromBpMessage(gp.data(),
      keys_.at(0).private_key(), &type);
  ASSERT_EQ(HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  std::string rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(0).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  std::string val_msg;
  ASSERT_TRUE(client1_imh.ValidateMessage(alt_ctc_rec_msgs_[1], &type,
      &val_msg));
  boost::uint32_t c1_id = alt_ctc_conn_;
  alt_ctc_rec_msgs_.clear();

  msg = "Hello, what are you doing?";
  std::string ctc1_msg(client1_imh.CreateMessage(msg, publicusername_));
  ASSERT_EQ(0, ctc1_trans_->Send(ctc1_msg, c1_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, sm_rec_msg_);


  std::string ser_msg(client2_imh.CreateMessageEndpoint(publicusername_));
  boost::uint32_t c2_id(0);
  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c2_id));
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c2_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(std::string("contact2"), latest_ctc_updated_);
  ASSERT_EQ(client2_ss.ConnectionStatus(), latest_status_);

  // checking new contact is in the live contacts map in session
  int ctc2_status(100);
  ASSERT_EQ(0, ss_->LiveContactStatus("contact2", &ctc2_status));
  ASSERT_EQ(client2_ss.ConnectionStatus(), ctc2_status);

  // receiving a message from new contact
  msg = "What's up";
  ser_msg = client2_imh.CreateMessage(msg, publicusername_);
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c2_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  ASSERT_EQ(msg, sm_rec_msg_);

  recs.clear();
  recs.push_back("contact2");
  msg = "Hello dude";
  sm_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));

  rec_msg = GetStrMsgFromBpMsg(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  ASSERT_TRUE(client2_imh.ValidateMessage(alt_ctc_rec_msgs_[0], &type,
      &val_msg));

  msg = "Goodbye";
  ctc1_msg = client1_imh.CreateMessage(msg, publicusername_);
  ASSERT_EQ(0, ctc1_trans_->Send(ctc1_msg, c1_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  ASSERT_EQ(msg, sm_rec_msg_);

  ser_msg = client2_imh.CreateLogOutMessage(publicusername_);
  ASSERT_EQ(0, ctc2_trans_->Send(ser_msg, c2_id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ctc2_status = 100;
  ASSERT_EQ(kLiveContactNotFound, ss_->LiveContactStatus("contact2",
      &ctc2_status));
  ASSERT_EQ(std::string("contact2"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

class CCImMessagingTest : public testing::Test {
 public:
  CCImMessagingTest() : network_test_(),
                        ss1_(SessionSingleton::getInstance()),
                        ss2_(new MockSessionSingleton),
                        publicusername1_("contact1"),
                        publicusername2_("contact2"),
                        mpid_public_key1_(),
                        mpid_public_key2_(),
                        sm1_(),
                        sm2_(),
                        sm_rec_msg_(),
                        sender_(),
                        latest_ctc_updated_(),
                        latest_status_(100) {}
  ~CCImMessagingTest() {
    delete ss2_;
  }
 protected:
  void SetUp() {
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss1_->passport_ = passport;
    ss1_->CreateTestPackets(publicusername1_);
    ASSERT_TRUE(network_test_.Init());
    sm1_ = network_test_.store_manager();
    boost::shared_ptr<ChunkStore> cstore2(new ChunkStore(
        network_test_.test_dir().string() + "/ChunkStore2", 0, 0));
    cstore2->Init();
#ifdef MS_NETWORK_TEST
    sm2_.reset(new TestStoreManager(cstore2, network_test_.K()));
    sm2_->im_handler_.ss_ = ss2_;
#else
    sm2_.reset(new TestStoreManager(cstore2, network_test_.K(),
                                    network_test_.test_dir()));
#endif
    sm2_->ss_ = ss2_;
    CallbackObject callback;
    sm2_->Init(
        boost::bind(&CallbackObject::ReturnCodeCallback, &callback, _1), 0);
    int result = callback.WaitForReturnCodeResult();
    if (result != kSuccess) {
      printf("StoreManager2 Init failed - %i\n", result);
      FAIL();
    }

    ss1_->SetConnectionStatus(0);
    ss2_->SetConnectionStatus(0);
    sm1_->SetSessionEndPoint();
    sm2_->SetSessionEndPoint();
    sm1_->SetInstantMessageNotifier(
        boost::bind(&CCImMessagingTest::SmOnMessageNotifier, this, _1),
        boost::bind(&CCImMessagingTest::SmStatusUpdate, this, _1, _2));
    sm2_->SetInstantMessageNotifier(
        boost::bind(&CCImMessagingTest::SmOnMessageNotifier, this, _1),
        boost::bind(&CCImMessagingTest::SmStatusUpdate, this, _1, _2));

    // Adding contact information to session
    ss2_->CreateTestPackets(publicusername2_);
    ASSERT_EQ(kSuccess, ss1_->GetKey(passport::MPID, NULL, &mpid_public_key1_,
                                     NULL, NULL));
    ASSERT_EQ(kSuccess, ss2_->GetKey(passport::MPID, NULL, &mpid_public_key2_,
                                     NULL, NULL));
    ASSERT_EQ(0, ss1_->AddContact(publicusername2_, mpid_public_key2_, "", "",
                                  "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss2_->AddContact(publicusername1_, mpid_public_key1_, "", "",
                                  "", 'U', 1, 2, "", 'C', 0, 0));
  }
  void TearDown() {
    CallbackObject callback;
    sm2_->Close(
        boost::bind(&CallbackObject::ReturnCodeCallback, &callback, _1), true);
    callback.WaitForReturnCodeResult();

    ss1_->ResetSession();
    ss2_->ResetSession();
    sm_rec_msg_.clear();
    sender_.clear();
    latest_ctc_updated_.clear();
    latest_status_ = 100;
    try {
      if (fs::exists("client1"))
        fs::remove_all("client1");
      if (fs::exists("client2"))
        fs::remove_all("client2");
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
  }

  NetworkTest network_test_;
  SessionSingleton *ss1_;
  MockSessionSingleton *ss2_;
  std::string publicusername1_, publicusername2_;
  std::string mpid_public_key1_, mpid_public_key2_;
  boost::shared_ptr<TestStoreManager> sm1_, sm2_;
  std::string sm_rec_msg_;
  std::string sender_, latest_ctc_updated_;
  int latest_status_;
 private:
  void SmOnMessageNotifier(const std::string &msg) {
    sm_rec_msg_.clear();
    sm_rec_msg_ = msg;
  }
  void SmStatusUpdate(const std::string &contactname, const int &status) {
    latest_ctc_updated_.clear();
    latest_status_ = 100;
    latest_ctc_updated_ = contactname;
    latest_status_ = status;
  }
};


TEST_MS_NET(CCImMessagingTest, FUNC, MAID, TestImSendPresenceAndMsgs) {
  // Assuming sm1 gets presence of sm2
  ASSERT_EQ(0, ss1_->AddLiveContact(publicusername2_, ss2_->Ep(), 0));
  ASSERT_TRUE(sm1_->SendPresence(publicusername2_));
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));

  ASSERT_EQ(publicusername1_, latest_ctc_updated_);
  ASSERT_EQ(ss1_->ConnectionStatus(), latest_status_);
  int status(100);
  ASSERT_EQ(0, ss2_->LiveContactStatus(publicusername1_, &status));
  ASSERT_EQ(ss1_->ConnectionStatus(), status);
  latest_status_ = 100;
  latest_ctc_updated_.clear();

  std::string msg("message 1 from contact1");
  std::vector<std::string> recs;
  recs.push_back(publicusername2_);
  std::map<std::string, ReturnCode> results;
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  sm_rec_msg_.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 1 from contact2";
  results.empty();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 2 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 2 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 3 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 3 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 4 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 4 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 5 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 5 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 6 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  sm2_->SendLogOutMessage(publicusername1_);
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  ASSERT_EQ(publicusername2_, latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
  ASSERT_NE(0, ss1_->LiveContactStatus(publicusername2_, &status));
}

TEST_MS_NET(CCImMessagingTest, FUNC, MAID, TestImRecPresenceAndSendMsgs) {
  // Asuming sm1 gets presence  of sm2
  ss1_->AddLiveContact(publicusername2_, ss2_->Ep(), 0);
  ASSERT_TRUE(sm1_->SendPresence(publicusername2_));
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  ASSERT_EQ(publicusername1_, latest_ctc_updated_);
  ASSERT_EQ(ss1_->ConnectionStatus(), latest_status_);
  int status(100);
  ASSERT_EQ(0, ss2_->LiveContactStatus(publicusername1_, &status));
  ASSERT_EQ(ss1_->ConnectionStatus(), status);
  latest_status_ = 100;
  latest_ctc_updated_.clear();

  std::string msg("message 1 from contact2");
  std::vector<std::string> recs;
  recs.push_back(publicusername1_);
  std::map<std::string, ReturnCode> results;
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  sm_rec_msg_.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 1 from contact1";
  results.empty();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 2 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 2 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 3 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 3 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 4 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 4 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 5 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 5 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 6 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  sm2_->SendLogOutMessage(publicusername1_);
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  ASSERT_EQ(publicusername2_, latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
  ASSERT_NE(0, ss1_->LiveContactStatus(publicusername2_, &status));
}

TEST_MS_NET(CCImMessagingTest, FUNC, MAID, TestMultipleImToContact) {
  // Asuming sm1 gets presence  of sm2
  ss1_->AddLiveContact(publicusername2_, ss2_->Ep(), 0);
  ASSERT_TRUE(sm1_->SendPresence(publicusername2_));
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  ASSERT_EQ(publicusername1_, latest_ctc_updated_);
  ASSERT_EQ(ss1_->ConnectionStatus(), latest_status_);
  int status(100);
  ASSERT_EQ(0, ss2_->LiveContactStatus(publicusername1_, &status));
  ASSERT_EQ(ss1_->ConnectionStatus(), status);
  latest_status_ = 100;
  latest_ctc_updated_.clear();

  std::string msg("message 1 from contact1");
  std::vector<std::string> recs;
  recs.push_back(publicusername2_);
  std::map<std::string, ReturnCode> results;
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  std::map<std::string, ReturnCode>::iterator it;
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  sm_rec_msg_.clear();
  boost::this_thread::sleep(boost::posix_time::seconds(2));


  msg = "message 2 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 3 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 4 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 5 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 6 from contact1";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername2_);
  sm1_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername2_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  msg = "message 1 from contact2";
  results.empty();
  recs.clear();
  sm_rec_msg_.clear();
  recs.clear();
  recs.push_back(publicusername1_);
  sm2_->SendMessage(recs, msg, INSTANT_MSG, &results);
  while (sm_rec_msg_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(msg, sm_rec_msg_);
  it = results.find(publicusername1_);
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(kSuccess, it->second);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  sm2_->SendLogOutMessage(publicusername1_);
  while (latest_ctc_updated_.empty())
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  ASSERT_EQ(publicusername2_, latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
  ASSERT_NE(0, ss1_->LiveContactStatus(publicusername2_, &status));
}

}  // namespace test

}  // namespace maidsafe

