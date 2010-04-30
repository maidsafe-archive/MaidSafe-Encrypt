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
#include "fs/filesystem.h"
#include "maidsafe/client/imconnectionhandler.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/mocksessionsingleton.h"

namespace fs = boost::filesystem;

namespace {

maidsafe::InstantMessage get_im_from_bp_message(const std::string &ser_bpmsg,
    const std::string &priv_key, maidsafe::MessageType *type) {
  maidsafe::InstantMessage im;
  crypto::Crypto co;
  maidsafe::BufferPacketMessage bpmsg;
  if (!bpmsg.ParseFromString(ser_bpmsg))
    return im;
  *type = bpmsg.type();
  std::string aes_key(co.AsymDecrypt(bpmsg.rsaenc_key(), "", priv_key,
      crypto::STRING_STRING));
  im.ParseFromString(co.SymmDecrypt(bpmsg.aesenc_message(), "",
      crypto::STRING_STRING, aes_key));
  return im;
}

std::string get_strmsg_from_bp_message(const std::string &ser_bpmsg,
    const std::string &priv_key, maidsafe::MessageType *type,
    std::string *sender) {
  crypto::Crypto co;
  maidsafe::BufferPacketMessage bpmsg;
  if (!bpmsg.ParseFromString(ser_bpmsg))
    return "";
  *type = bpmsg.type();
  *sender = bpmsg.sender_id();
  std::string aes_key(co.AsymDecrypt(bpmsg.rsaenc_key(), "", priv_key,
      crypto::STRING_STRING));
  return co.SymmDecrypt(bpmsg.aesenc_message(), "",
      crypto::STRING_STRING, aes_key);
}

class SMCallback {
 public:
  SMCallback() : result_(kNack), result_arrived_(false) {
  }
  void Callback(const std::string &res) {
    maidsafe::GenericResponse maid_response;
    if (!maid_response.ParseFromString(res)) {
      result_ = kNack;
    } else {
      result_ = static_cast<MaidsafeRpcResult> (maid_response.result());
    }
    result_arrived_ = true;
  }
  void Reset() {
    result_arrived_ = false;
    result_ = kNack;
  }
  MaidsafeRpcResult result_;
  bool result_arrived_;
};

class TestImMessaging : public testing::Test {
 public:
  TestImMessaging() : vault_dir_(file_system::TempDir() /
                          ("maidsafe_TestVaults_" + base::RandomString(6))),
                      kad_config_file_(vault_dir_ / ".kadconfig"),
                      bootstrapping_vault_(),
                      ctc1_trans_(),
                      ctc2_trans_(),
                      ss_(maidsafe::SessionSingleton::getInstance()),
                      publicusername_("Teh contact"),
                      ctc1_ep_(),
                      ctc2_ep_(),
                      sm_(),
                      keys_(),
                      sm_rec_msg_(),
                      alt_ctc_conn_(0),
                      sender_(),
                      latest_ctc_updated_(),
                      latest_status_(100),
                      alt_ctc_rec_msgs_() {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    fs::create_directories(vault_dir_);
    keys_.clear();
    cached_keys::MakeKeys(3, &keys_);
  }
  ~TestImMessaging() {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
  }
 protected:
  void SetUp() {
    crypto::Crypto co;
    crypto::RsaKeyPair keys;
    keys.GenerateKeys(maidsafe::kRsaKeySize);
    std::string signed_key = co.AsymSign(keys.public_key(), "",
                             keys.private_key(), crypto::STRING_STRING);
    std::string public_key = keys.public_key();
    std::string private_key = keys.private_key();
    std::string pmid = co.Hash(signed_key, "", crypto::STRING_STRING, false);
    fs::path local_dir(vault_dir_ / ("Vault_" +
          base::EncodeToHex(pmid).substr(0, 8)));
    if (!fs::exists(fs::path(local_dir))) {
      printf("creating_directories - %s\n", local_dir.string().c_str());
      fs::create_directories(local_dir);
    }
    bootstrapping_vault_.reset(new maidsafe_vault::PDVault(public_key,
        private_key, signed_key, local_dir, 0, false, false, kad_config_file_,
        1073741824, 0));
    bootstrapping_vault_->Start(true);
    ASSERT_EQ(maidsafe_vault::kVaultStarted,
            bootstrapping_vault_->vault_status());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id(
        base::EncodeToHex(bootstrapping_vault_->node_id()));
    kad_contact->set_ip(bootstrapping_vault_->host_ip());
    kad_contact->set_port(bootstrapping_vault_->host_port());
    kad_contact->set_local_ip(bootstrapping_vault_->local_host_ip());
    kad_contact->set_local_port(bootstrapping_vault_->local_host_port());
    // default location in Maidsafestoremanager
    std::fstream output(".kadconfig",
                        std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output));
    output.close();
    printf("Vault 0 started.\n");
    boost::shared_ptr<maidsafe::ChunkStore> cstore(
        new maidsafe::ChunkStore("client", 0, 0));
    cstore->Init();
    sm_.reset(new maidsafe::MaidsafeStoreManager(cstore));
    SMCallback cb;
    fs::path db_path;
    sm_->Init(0, boost::bind(&SMCallback::Callback, &cb, _1), db_path);
    while (!cb.result_arrived_) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(20));
    }
    ASSERT_EQ(kAck, cb.result_);
    printf("maidstoremanager started ...\n");

    ss_->SetConnectionStatus(0);
    sm_->SetSessionEndPoint();
    sm_->SetInstantMessageNotifier(
        boost::bind(&TestImMessaging::SmOnMessageNotifier, this, _1),
        boost::bind(&TestImMessaging::SmStatusUpdate, this, _1, _2));

    // starting alternative transport
    ctc1_trans_.reset(new transport::TransportUDT);
    ASSERT_TRUE(ctc1_trans_->RegisterOnSend(boost::bind(
          &TestImMessaging::SendNotifier, this, _1, _2)));
    ASSERT_TRUE(ctc1_trans_->RegisterOnServerDown(boost::bind(
          &TestImMessaging::OnServerDown, this, _1, _2, _3)));
    ASSERT_TRUE(ctc1_trans_->RegisterOnMessage(boost::bind(
          &TestImMessaging::UDTTransMsgArrived, this, _1, _2, _3, _4)));
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
          &TestImMessaging::SendNotifier, this, _1, _2)));
    ASSERT_TRUE(ctc2_trans_->RegisterOnServerDown(boost::bind(
          &TestImMessaging::OnServerDown, this, _1, _2, _3)));
    ASSERT_TRUE(ctc2_trans_->RegisterOnMessage(boost::bind(
          &TestImMessaging::UDTTransMsgArrived, this, _1, _2, _3, _4)));
    ASSERT_EQ(0, ctc2_trans_->Start(0));
    ctc2_ep_.add_ip(addr.to_string());
    ctc2_ep_.add_ip(addr.to_string());
    ctc2_ep_.add_ip("");
    ctc2_ep_.add_port(ctc2_trans_->listening_port());
    ctc2_ep_.add_port(ctc2_trans_->listening_port());
    ctc2_ep_.add_port(0);

    // Adding contact information to session
    ss_->AddKey(maidsafe::MPID, publicusername_, keys_.at(0).private_key(),
                keys_.at(0).public_key(), "");
    ASSERT_EQ(0, ss_->AddContact("contact1", keys_.at(1).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));
    ASSERT_EQ(0, ss_->AddContact("contact2", keys_.at(2).public_key(), "", "",
        "", 'U', 1, 2, "", 'C', 0, 0));

    // setting contact1 as a live contact
    ASSERT_EQ(0, ss_->AddLiveContact("contact1", ctc1_ep_, 0));
  }
  void TearDown() {
    printf("starting TearDown\n");
    SMCallback cb;
    sm_->Close(boost::bind(&SMCallback::Callback, &cb, _1), true);
    while (!cb.result_arrived_) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(20));
    }
    bootstrapping_vault_->StopRvPing();
    bootstrapping_vault_->Stop();
    ASSERT_EQ(kAck, cb.result_);
    fs::remove(kad_config_file_);
    fs::remove(fs::path(".kadconfig"));
    ctc1_trans_->Stop();
    ctc2_trans_->Stop();
    ss_->ResetSession();
    sm_rec_msg_.clear();
    alt_ctc_conn_ = 0;
    sender_.clear();
    latest_ctc_updated_.clear();
    latest_status_ = 100;
    alt_ctc_rec_msgs_.clear();
    printf("finished TearDown\n");
  }

  fs::path vault_dir_, kad_config_file_;
  boost::shared_ptr<maidsafe_vault::PDVault> bootstrapping_vault_;
  boost::shared_ptr<transport::Transport> ctc1_trans_, ctc2_trans_;
  maidsafe::SessionSingleton *ss_;
  std::string publicusername_;
  maidsafe::EndPoint ctc1_ep_, ctc2_ep_;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm_;
  std::vector<crypto::RsaKeyPair> keys_;
  std::string sm_rec_msg_;
  boost::uint32_t alt_ctc_conn_;
  std::string sender_, latest_ctc_updated_;
  int latest_status_;
  std::vector<std::string> alt_ctc_rec_msgs_;
 private:
  void SendNotifier(const boost::uint32_t&, const bool&) {
  }
  void OnServerDown(const bool&, const std::string&, const boost::uint16_t&) {
  }
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
};

TEST_F(TestImMessaging, FUNC_MAID_SendMessages) {
  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, maidsafe::ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.size() < size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, maidsafe::ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);

  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  boost::this_thread::sleep(boost::posix_time::seconds(2));
  alt_ctc_rec_msgs_.clear();
  msg = "Second message";
  results.clear();
  gp.Clear();

  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);

  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout + 1));
  alt_ctc_rec_msgs_.clear();
  msg = "Third message";
  results.clear();
  gp.Clear();

  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.size() < size_t(2)) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_FALSE(alt_ctc_rec_msgs_.empty());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  im.Clear();
  im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
}

TEST_F(TestImMessaging, FUNC_MAID_SendReceiveMessages) {
  maidsafe::MockSessionSingleton client1_ss;
  client1_ss.AddKey(maidsafe::MPID, "contact1", keys_.at(1).private_key(),
                keys_.at(1).public_key(), "");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, keys_.at(0).public_key(),
        "", "", "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::IMHandler client1_imh(&client1_ss);
  client1_ss.SetEp(ctc1_ep_);

  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, maidsafe::ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, maidsafe::ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);

  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
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
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);
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

TEST_F(TestImMessaging, FUNC_MAID_ReceiveEndPointMsg) {
  maidsafe::MockSessionSingleton client2_ss;
  client2_ss.AddKey(maidsafe::MPID, "contact2", keys_.at(2).private_key(),
                keys_.at(2).public_key(), "");
  ASSERT_EQ(0, client2_ss.AddContact(publicusername_, keys_.at(0).public_key(),
        "", "", "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::IMHandler client2_imh(&client2_ss);
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
  std::map<std::string, maidsafe::ReturnCode> results;
  msg = "Hello dude\n";
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  std::map<std::string, maidsafe::ReturnCode>::iterator it;
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);

  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  std::string rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(2).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);

  std::string val_msg;
  ASSERT_TRUE(client2_imh.ValidateMessage(alt_ctc_rec_msgs_[0], &type,
      &val_msg));

  // Letting connection timeout and then send a new msg
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout + 1));
  alt_ctc_rec_msgs_.clear();
  results.clear();
  msg = "Another message for contact2";
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(2).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(2).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
  ASSERT_EQ(publicusername_, sender);
  ASSERT_EQ(msg, rec_msg);
}

TEST_F(TestImMessaging, FUNC_MAID_SendLogOutMsg) {
  sm_->SendLogOutMessage("contact2");
  sm_->SendLogOutMessage("contact1");
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  im.Clear();
  im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::LOGOUT_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  ctc1_trans_->Stop();
  sm_->SendLogOutMessage("contact1");
}

TEST_F(TestImMessaging, FUNC_MAID_SendPresenceMsg) {
  ASSERT_FALSE(sm_->SendPresence("contact2"));
  ASSERT_TRUE(sm_->SendPresence("contact1"));
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());
  ASSERT_EQ(ss_->ConnectionStatus(), im.status());

  ctc1_trans_->Stop();
  ASSERT_FALSE(sm_->SendPresence("contact1"));
  int ctc1_status(100);
  ASSERT_EQ(maidsafe::kLiveContactNotFound, ss_->LiveContactStatus("contact1",
      &ctc1_status));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

TEST_F(TestImMessaging, FUNC_MAID_ReceiveLogOutMsg) {
  maidsafe::MockSessionSingleton client1_ss;
  client1_ss.AddKey(maidsafe::MPID, "contact1", keys_.at(1).private_key(),
                keys_.at(1).public_key(), "");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, keys_.at(0).public_key(),
        "", "", "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::IMHandler client1_imh(&client1_ss);
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
  ASSERT_EQ(maidsafe::kLiveContactNotFound, ss_->LiveContactStatus("contact1",
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
  ASSERT_EQ(maidsafe::kLiveContactNotFound, ss_->LiveContactStatus("contact1",
      &ctc1_status));
  ASSERT_EQ(std::string("contact1"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

TEST_F(TestImMessaging, FUNC_MAID_InvalidNewConnection) {
  boost::uint32_t c_id(0);
  ASSERT_EQ(0, ctc2_trans_->ConnectToSend(ss_->Ep().ip(0), ss_->Ep().port(0),
      ss_->Ep().ip(1), ss_->Ep().port(1), ss_->Ep().ip(2), ss_->Ep().port(2),
      true, &c_id));
  ASSERT_EQ(0, ctc2_trans_->Send("abcdefg", c_id, true));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(std::string(""), latest_ctc_updated_);
  ASSERT_EQ(100, latest_status_);
  int ctc2_status(100);
  ASSERT_EQ(maidsafe::kLiveContactNotFound,
      ss_->LiveContactStatus("contact2", &ctc2_status));

  // Checking transport connection was closed
  ASSERT_NE(0, ctc2_trans_->Send("abcdefg", c_id, true));
}

TEST_F(TestImMessaging, FUNC_MAID_HandleTwoConverstions) {
  maidsafe::MockSessionSingleton client2_ss;
  client2_ss.AddKey(maidsafe::MPID, "contact2", keys_.at(2).private_key(),
                keys_.at(2).public_key(), "");
  ASSERT_EQ(0, client2_ss.AddContact(publicusername_, keys_.at(0).public_key(),
        "", "", "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::IMHandler client2_imh(&client2_ss);
  client2_ss.SetEp(ctc2_ep_);
  client2_ss.SetConnectionStatus(0);

  maidsafe::MockSessionSingleton client1_ss;
  client1_ss.AddKey(maidsafe::MPID, "contact1", keys_.at(1).private_key(),
                keys_.at(1).public_key(), "");
  ASSERT_EQ(0, client1_ss.AddContact(publicusername_, keys_.at(0).public_key(),
        "", "", "", 'U', 1, 2, "", 'C', 0, 0));
  maidsafe::IMHandler client1_imh(&client1_ss);
  client1_ss.SetEp(ctc1_ep_);

  std::vector<std::string> recs;
  recs.push_back("contact1");
  std::map<std::string, maidsafe::ReturnCode> results;
  std::string msg("Hello World\n");
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(size_t(2), alt_ctc_rec_msgs_.size());
  std::map<std::string, maidsafe::ReturnCode>::iterator it;
  it = results.find("contact1");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);

  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  crypto::Crypto co;
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string sender;
  maidsafe::MessageType type;

  maidsafe::InstantMessage im = get_im_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type);
  ASSERT_EQ(maidsafe::HELLO_PING, type);
  ASSERT_EQ(publicusername_, im.sender());

  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[1]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  std::string rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(1).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
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
  sm_->SendMessage(recs, msg, maidsafe::INSTANT_MSG, &results);
  while (alt_ctc_rec_msgs_.empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(1), alt_ctc_rec_msgs_.size());
  it = results.find("contact2");
  ASSERT_TRUE(it != results.end());
  ASSERT_EQ(maidsafe::kSuccess, it->second);
  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(alt_ctc_rec_msgs_[0]));
  ASSERT_TRUE(co.AsymCheckSig(gp.data(), gp.signature(),
      ss_->PublicKey(maidsafe::MPID), crypto::STRING_STRING));

  rec_msg = get_strmsg_from_bp_message(gp.data(),
      keys_.at(2).private_key(), &type, &sender);
  ASSERT_EQ(maidsafe::INSTANT_MSG, type);
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
  ASSERT_EQ(maidsafe::kLiveContactNotFound, ss_->LiveContactStatus("contact2",
      &ctc2_status));
  ASSERT_EQ(std::string("contact2"), latest_ctc_updated_);
  ASSERT_EQ(1, latest_status_);
}

}  // namespace
