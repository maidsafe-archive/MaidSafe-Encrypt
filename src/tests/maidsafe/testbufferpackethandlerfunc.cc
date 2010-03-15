/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional test for Clientbufferpackethandler
* Version:      1.0
* Created:      2009-11-18-10.09.29
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
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/transportudt.h>

#include "maidsafe/clientbufferpackethandler.h"

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/systempackets.h"
#include "maidsafe/kademlia_service_messages.pb.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/localvaults.h"

static std::vector< boost::shared_ptr<maidsafe_vault::PDVault> > pdvaults_;
static const int kNetworkSize_ = 16;

class KadCB {
 public:
  KadCB() : result("") {}
  void CallbackFunc(const std::string &res) {
    base::GeneralResponse result_msg;
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result = result_msg.result();
  }
  void Reset() {
    result = "";
  }
  std::string result;
};

class BPCallback {
 public:
  BPCallback() : result(maidsafe::kGeneralError) {}
  void BPOperation_CB(const maidsafe::ReturnCode &res) {
    result = res;
  }
  void BPGetMsgs_CB(
      const maidsafe::ReturnCode &res,
      const std::list<maidsafe::ValidatedBufferPacketMessage> &rec_msgs) {
    result = res;
    msgs = rec_msgs;
  }
  void ContactInfo_CB(const maidsafe::ReturnCode &res,
                      const maidsafe::EndPoint &ep,
                      const maidsafe::PersonalDetails &pd,
                      const boost::uint32_t &st) {
    result = res;
    end_point = ep;
    personal_details = pd;
    status = st;
  }
  void Reset() {
    result = maidsafe::kGeneralError;
    msgs.clear();
  }
  maidsafe::ReturnCode result;
  std::list<maidsafe::ValidatedBufferPacketMessage> msgs;
  maidsafe::EndPoint end_point;
  maidsafe::PersonalDetails personal_details;
  boost::uint32_t status;
};

class CBPHandlerTest : public testing::Test {
 public:
  CBPHandlerTest() : trans(NULL),
                     trans_han(),
                     ch_man(NULL),
                     knode(),
                     cbph(NULL),
                     bp_rpcs(),
                     test_dir_(file_system::TempDir() /
                               ("maidsafe_TestCBPH_" + base::RandomString(6))),
                     kad_config_file_(test_dir_ / ".kadconfig"),
                     cryp(),
                     keys_(),
                     cb_() {}
 protected:
  virtual void SetUp() {
    cached_keys::MakeKeys(3, &keys_);
    try {
      boost::filesystem::create_directories(test_dir_);
    }
    catch(const std::exception &e) {
      printf("CBPHandlerTest SetUp - filesystem error: %s\n", e.what());
    }
    trans = new transport::TransportUDT;
    trans_han = new transport::TransportHandler;
    ch_man = new rpcprotocol::ChannelManager(trans_han);
    boost::int16_t trans_id;
    trans_han->Register(trans, &trans_id);
    knode.reset(new kad::KNode(ch_man, trans_han, kad::CLIENT,
        keys_.at(0).private_key(), keys_.at(0).public_key(), false, false));
    knode->SetTransID(trans_id);
    bp_rpcs.reset(new maidsafe::BufferPacketRpcsImpl(trans_han, ch_man));
    cbph = new maidsafe::ClientBufferPacketHandler(bp_rpcs, knode);
    ASSERT_TRUE(ch_man->RegisterNotifiersToTransport());
    ASSERT_TRUE(trans_han->RegisterOnServerDown(
      boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode, _1)));
    EXPECT_EQ(0, trans_han->Start(0, trans_id));
    EXPECT_EQ(0, ch_man->Start());

    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id(pdvaults_[0]->node_id());
    kad_contact->set_ip(pdvaults_[0]->host_ip());
    kad_contact->set_port(pdvaults_[0]->host_port());
    kad_contact->set_local_ip(pdvaults_[0]->local_host_ip());
    kad_contact->set_local_port(pdvaults_[0]->local_host_port());
    std::fstream output1(kad_config_file_.string().c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output1));
    output1.close();

    knode->Join(kad_config_file_.string(),
        boost::bind(&KadCB::CallbackFunc, &cb_, _1));
    while (cb_.result.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result);
    ASSERT_TRUE(knode->is_joined());
  }

  virtual void TearDown() {
    knode->Leave();
    trans_han->StopAll();
    ch_man->Stop();
    delete cbph;
    delete trans;
    delete trans_han;
    delete ch_man;
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      printf("CBPHandlerTest TearDown - filesystem error: %s\n", e.what());
    }
  }

  transport::TransportUDT *trans;
  transport::TransportHandler *trans_han;
  rpcprotocol::ChannelManager *ch_man;
  boost::shared_ptr<kad::KNode> knode;
  maidsafe::ClientBufferPacketHandler *cbph;
  boost::shared_ptr<maidsafe::BufferPacketRpcs> bp_rpcs;
  fs::path test_dir_, kad_config_file_;
  crypto::Crypto cryp;
  std::vector<crypto::RsaKeyPair> keys_;
  KadCB cb_;
};

TEST_F(CBPHandlerTest, FUNC_MAID_TestBPHOperations) {
  std::string owner_pubkey(keys_.at(1).public_key()),
              owner_privkey(keys_.at(1).private_key());
  BPCallback cb;
  std::string signed_pub_key = cryp.AsymSign(owner_pubkey, "",
                               owner_privkey, crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash("publicname", "",
                                      crypto::STRING_STRING, false),
                                      owner_pubkey, owner_privkey};

  std::vector<std::string> users;
  cbph->ModifyOwnerInfo(bpip, 0, users, boost::bind(
                        &BPCallback::BPOperation_CB, &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
  printf("Step 1\n");

  cb.Reset();
  cbph->CreateBufferPacket(bpip, boost::bind(&BPCallback::BPOperation_CB,
                           &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Step 2\n");

  std::string sender_id("user1");
  std::string sender_pmid = cryp.Hash(keys_.at(2).public_key() + cryp.AsymSign(
                            keys_.at(2).public_key(), "",
                            keys_.at(2).private_key(), crypto::STRING_STRING),
                            "", crypto::STRING_STRING, false);
  maidsafe::BPInputParameters bpip1 = {sender_pmid, keys_.at(2).public_key(),
                                       keys_.at(2).private_key()};
  std::string recv_id = cryp.Hash("publicname", "", crypto::STRING_STRING,
                        false);

  cb.Reset();
  cbph->AddMessage(bpip1, sender_id, owner_pubkey, recv_id, "Hello World",
                   maidsafe::INSTANT_MSG, boost::bind(
                   &BPCallback::BPOperation_CB, &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
  printf("Step 3a\n");

  cb.Reset();
  cbph->ContactInfo(bpip1, sender_id, "publicname", owner_pubkey, boost::bind(
                    &BPCallback::ContactInfo_CB, &cb, _1, _2, _3, 4),
                    trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kGetBPInfoError, cb.result);
  printf("Step 3b\n");

  cb.Reset();
  cbph->GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2),
                    trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_TRUE(cb.msgs.empty());
  printf("Step 4\n");

  users.push_back(cryp.Hash(sender_id, "", crypto::STRING_STRING, false));
  cb.Reset();

  cbph->ModifyOwnerInfo(bpip, 5, users, boost::bind(
                        &BPCallback::BPOperation_CB, &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  printf("Step 5\n");

  cb.Reset();

  cbph->AddMessage(bpip1, sender_id, owner_pubkey, recv_id, "Hello World",
                   maidsafe::INSTANT_MSG, boost::bind(
                   &BPCallback::BPOperation_CB, &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  printf("Step 6a\n");

  cb.Reset();
  cbph->ContactInfo(bpip1, sender_id, recv_id, owner_pubkey, boost::bind(
                    &BPCallback::ContactInfo_CB, &cb, _1, _2, _3, _4),
                    trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(boost::uint32_t(5), cb.status);
  ASSERT_EQ(knode->host_ip(), cb.end_point.ip());
  ASSERT_EQ(knode->host_port(), cb.end_point.port());
  printf("Step 6b\n");

  cb.Reset();
  cbph->GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2),
                    trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(size_t(1), cb.msgs.size());
  ASSERT_EQ("Hello World", cb.msgs.front().message());
  ASSERT_EQ(sender_id, cb.msgs.front().sender());
  printf("Step 7\n");

  // Request BPs not belonging to the sender
  bpip1.sign_id = bpip.sign_id;
  bpip1.public_key = bpip.public_key;
  cb.Reset();
  cbph->GetMessages(bpip1, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2),
                    trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
  printf("Step 8\n");

  cb.Reset();
  cbph->ModifyOwnerInfo(bpip1, 0, users, boost::bind(
                        &BPCallback::BPOperation_CB, &cb, _1), trans->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
  printf("Step 9\n");
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(kNetworkSize_, &pdvaults_));
  return RUN_ALL_TESTS();
}
