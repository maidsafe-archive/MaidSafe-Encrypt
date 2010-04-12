/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for Clientbufferpackethandler using Gmock
* Version:      1.0
* Created:      2009-11-18-10.11.25
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
#include <gmock/gmock.h>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/transportudt.h>

#include "fs/filesystem.h"
#include "maidsafe/clientbufferpackethandler.h"
#include "maidsafe/client/packetfactory.h"
#include "tests/maidsafe/cached_keys.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::WithArgs;

void execute_cb(base::callback_func_type cb, const std::string &result) {
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  cb(result);
}

void FindNodesSucceed(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultSuccess);
  kad::Contact ctc("id", "127.0.0.1", 8888, "127.0.0.1", 8888);
  std::string ser_ctc;
  ctc.SerialiseToString(&ser_ctc);
  for (int n = 0; n < kad::K; ++n) {
    res.add_closest_nodes(ser_ctc);
  }
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindNodesFailure(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultFailure);
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindNodesFailNoParse(base::callback_func_type cb) {
  std::string summat("aaaa");
  boost::thread thrd(execute_cb, cb, summat);
}

void FindNodesFailNotEnough(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultSuccess);
  kad::Contact ctc("id", "127.0.0.1", 8888, "127.0.0.1", 8888);
  std::string ser_ctc;
  ctc.SerialiseToString(&ser_ctc);
  for (int n = 0; n < kad::K/4; ++n) {
    res.add_closest_nodes(ser_ctc);
  }
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindNodesFailNotContacts(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultSuccess);
  for (int n = 0; n < kad::K; ++n) {
    res.add_closest_nodes("mis huevos en chile verde");
  }
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void BPCallbackFail(const kad::Contact &peer,
                    maidsafe::CreateBPResponse *response,
                    google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPCallbackSucceed(const kad::Contact &peer,
                       maidsafe::CreateBPResponse *response,
                       google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPInfoCallbackSucceed(
    const kad::Contact &peer,
    maidsafe::ModifyBPInfoResponse *response,
    google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPInfoCallbackFailed(
    const kad::Contact &peer,
    maidsafe::ModifyBPInfoResponse *response,
    google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPAddMsgCallbackSucceed(
    const kad::Contact &peer,
    maidsafe::AddBPMessageResponse *response,
    google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPAddMsgCallbackFailed(
    const kad::Contact &peer,
    maidsafe::AddBPMessageResponse *response,
    google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

class KadCB {
 public:
  KadCB() : result() {}
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
  BPCallback() : result(maidsafe::kGeneralError), msgs() {}
  void BPOperation_CB(const maidsafe::ReturnCode &res) {
    result = res;
  }
  void BPGetMsgs_CB(
      const maidsafe::ReturnCode &res,
      const std::list<maidsafe::ValidatedBufferPacketMessage> &rec_msgs,
      bool b) {
    if (b) {
      result = res;
      msgs.clear();
      std::set<std::string>::iterator it;
      for (it = vbpm_set.begin(); it != vbpm_set.end(); ++it) {
        maidsafe::ValidatedBufferPacketMessage vbpm;
        vbpm.ParseFromString(*it);
        msgs.push_back(vbpm);
      }
    } else {
      msgs.clear();
      msgs = rec_msgs;
      std::list<maidsafe::ValidatedBufferPacketMessage>::iterator it;
      for (it = msgs.begin(); it != msgs.end(); ++it)
        vbpm_set.insert(it->SerializeAsString());
    }
  }
  void Reset() {
    result = maidsafe::kGeneralError;
    msgs.clear();
  }
  std::set<std::string> vbpm_set;
  maidsafe::ReturnCode result;
  std::list<maidsafe::ValidatedBufferPacketMessage> msgs;
};

class GetMsgsHelper {
 public:
  GetMsgsHelper() : msgs(), co() {}
  void BPGetMsgsCallbackSucceed(
      const kad::Contact &peer,
      maidsafe::GetBPMessagesResponse *response,
      google::protobuf::Closure *done) {
    response->set_result(kAck);
    for (unsigned int i = 0; i < msgs.size(); ++i)
      response->add_messages(msgs.at(i).SerializeAsString());
    response->set_pmid_id(peer.node_id());
    done->Run();
  }
  void BPGetMsgsCallbackFailed(
      const kad::Contact &peer,
      maidsafe::GetBPMessagesResponse *response,
      google::protobuf::Closure *done) {
    response->set_result(kNack);
    response->set_pmid_id(peer.node_id());
    done->Run();
  }
  void AddMessage(const std::string &msg,
                  const std::string &rec_pub_key,
                  const std::string &sender) {
    maidsafe::ValidatedBufferPacketMessage bp_msg;
    boost::uint32_t iter = base::random_32bit_uinteger() % 1000 +1;
    std::string aes_key = co.SecurePassword(co.Hash(msg, "",
                          crypto::STRING_STRING, false), iter);
    bp_msg.set_index(co.AsymEncrypt(aes_key, "", rec_pub_key,
                     crypto::STRING_STRING));
    bp_msg.set_sender(sender);
    bp_msg.set_timestamp(base::get_epoch_time());
    bp_msg.set_message(co.SymmEncrypt(msg, "", crypto::STRING_STRING, aes_key));
    bp_msg.set_type(maidsafe::INSTANT_MSG);
    msgs.push_back(bp_msg);
  }
 private:
  std::vector<maidsafe::ValidatedBufferPacketMessage> msgs;
  crypto::Crypto co;
};

class MockBPRpcs : public maidsafe::BufferPacketRpcs {
 public:
  MOCK_METHOD7(CreateBP, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::CreateBPRequest*,
      maidsafe::CreateBPResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure *));
  MOCK_METHOD7(ModifyBPInfo, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::ModifyBPInfoRequest*,
      maidsafe::ModifyBPInfoResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure*));
  MOCK_METHOD7(GetBPMessages, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::GetBPMessagesRequest*,
      maidsafe::GetBPMessagesResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure*));
  MOCK_METHOD7(AddBPMessage, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::AddBPMessageRequest*,
      maidsafe::AddBPMessageResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure*));
  MOCK_METHOD7(GetBPPresence, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::GetBPPresenceRequest*,
      maidsafe::GetBPPresenceResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure*));
  MOCK_METHOD7(AddBPPresence, void(const kad::Contact&, const bool&,
      const boost::int16_t&, const maidsafe::AddBPPresenceRequest*,
      maidsafe::AddBPPresenceResponse*, rpcprotocol::Controller*,
      google::protobuf::Closure*));
};

class MockBPH : public maidsafe::ClientBufferPacketHandler {
 public:
  MockBPH(boost::shared_ptr<maidsafe::BufferPacketRpcs> rpcs,
          boost::shared_ptr<kad::KNode> knode)
    : maidsafe::ClientBufferPacketHandler(rpcs, knode) {}
  MOCK_METHOD2(FindNodes,
      void(base::callback_func_type,
           boost::shared_ptr<maidsafe::ChangeBPData>));
};

class TestClientBP : public testing::Test {
 public:
  TestClientBP() : trans_(NULL),
                   trans_han_(NULL),
                   ch_man_(NULL),
                   knode_(),
                   BPMock(),
                   keys_(),
                   cb_(),
                   test_dir_(file_system::TempDir() /
                            ("maidsafe_TestClientBP_" + base::RandomString(6))),
                   kad_config_file_(test_dir_ / ".kadconfig"),
                   cryp() {}

  ~TestClientBP() {
    transport::TransportUDT::CleanUp();
  }

 protected:
  void SetUp() {
    cached_keys::MakeKeys(3, &keys_);
    trans_ = new transport::TransportUDT();
    trans_han_ = new transport::TransportHandler();
    boost::int16_t trans_id;
    trans_han_->Register(trans_, &trans_id);
    ch_man_ = new rpcprotocol::ChannelManager(trans_han_);
    knode_.reset(new kad::KNode(ch_man_, trans_han_, kad::VAULT,
                                keys_.at(0).private_key(),
                                keys_.at(0).public_key(),
                                false, false));
    knode_->SetTransID(trans_id);
    BPMock.reset(new MockBPRpcs);
    ASSERT_TRUE(ch_man_->RegisterNotifiersToTransport());
    ASSERT_TRUE(trans_han_->RegisterOnServerDown(
                boost::bind(&kad::KNode::HandleDeadRendezvousServer,
                            knode_, _1)));
    EXPECT_EQ(0, trans_han_->Start(0, trans_id));
    EXPECT_EQ(0, ch_man_->Start());

    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::get_local_address(&local_ip));
    knode_->Join(kad_config_file_.string(),
                 local_ip.to_string(),
                 trans_->listening_port(),
                 boost::bind(&KadCB::CallbackFunc, &cb_, _1));
    while (cb_.result.empty())
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result);
    ASSERT_TRUE(knode_->is_joined());

    // Adding Contacts
    for (int i = 0; i < kMinChunkCopies + 1; ++i) {
      kad::Contact con(cryp.Hash(boost::lexical_cast<std::string>(i), "",
                       crypto::STRING_STRING, false), "127.0.0.1", 8000 + i,
                       "127.0.0.1", 8000 + i);
      knode_->AddContact(con, 0, false);
    }
  }
  void TearDown() {
    knode_->Leave();
    trans_han_->StopAll();
    ch_man_->Stop();
//    delete knode_;
    delete trans_;
    delete trans_han_;
    delete ch_man_;
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      printf("filesystem error: %s\n", e.what());
    }
  }

  transport::TransportUDT *trans_;
  transport::TransportHandler *trans_han_;
  rpcprotocol::ChannelManager *ch_man_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<MockBPRpcs> BPMock;
  std::vector<crypto::RsaKeyPair> keys_;
  KadCB cb_;
  fs::path test_dir_, kad_config_file_;
  crypto::Crypto cryp;
};

TEST_F(TestClientBP, BEH_MAID_CreateBpOk) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPCallbackSucceed)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_CreateBpFailFindNodes) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_CreateBpFailRpcs) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPCallbackFail)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOwnerInfoOk) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPInfoCallbackSucceed)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOwnerInfoFailFindNodes) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOwnerInfoFailRpcs) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPInfoCallbackFailed)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                              keys_.at(1).private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMessageOk) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddMsgCallbackSucceed)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                                            keys_.at(1).private_key(),
                                            crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  // creating info of receiver
  signed_pubkey = cryp.AsymSign(keys_.at(2).public_key(), "",
                                keys_.at(2).private_key(),
                                crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys_.at(2).public_key() + signed_pubkey, "",
                                  crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMessageFailFindNodes) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                                            keys_.at(1).private_key(),
                                            crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  // creating info of receiver
  signed_pubkey = cryp.AsymSign(keys_.at(2).public_key(), "",
                                keys_.at(2).private_key(),
                                crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys_.at(2).public_key() + signed_pubkey, "",
                                  crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMessageFailRpcs) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddMsgCallbackFailed)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                                            keys_.at(1).private_key(),
                                            crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  // creating info of receiver
  signed_pubkey = cryp.AsymSign(keys_.at(2).public_key(), "",
                                keys_.at(2).private_key(),
                                crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys_.at(2).public_key() + signed_pubkey, "",
                                  crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_GetMessagesOk) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddMessage("msg1", keys_.at(1).public_key(), "sender1");
  helper.AddMessage("msg2", keys_.at(1).public_key(), "sender2");
  helper.AddMessage("msg3", keys_.at(1).public_key(), "sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, GetBPMessages(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(&helper,
                      &GetMsgsHelper::BPGetMsgsCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys_.at(1).public_key(), "",
                                             keys_.at(1).private_key(),
                                             crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                                signed_pub_key, "",
                                                crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(size_t(3), cb.msgs.size());
  maidsafe::ValidatedBufferPacketMessage msg = cb.msgs.front();
  ASSERT_EQ("msg1", msg.message());
  cb.msgs.pop_front();
  msg.Clear();
  msg = cb.msgs.front();
  ASSERT_EQ("msg2", msg.message());
  cb.msgs.pop_front();
  msg.Clear();
  msg = cb.msgs.front();
  ASSERT_EQ("msg3", msg.message());
}

TEST_F(TestClientBP, BEH_MAID_GetMessagesFailFindNodes) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddMessage("msg1", keys_.at(1).public_key(), "sender1");
  helper.AddMessage("msg2", keys_.at(1).public_key(), "sender2");
  helper.AddMessage("msg3", keys_.at(1).public_key(), "sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = cryp.AsymSign(keys_.at(1).public_key(), "",
                                            keys_.at(1).private_key(),
                                            crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                          signed_pubkey, "",
                                          crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  // creating info of receiver
  signed_pubkey = cryp.AsymSign(keys_.at(2).public_key(), "",
                                keys_.at(2).private_key(),
                                crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys_.at(2).public_key() + signed_pubkey, "",
                                  crypto::STRING_STRING, false);

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_GetMessagesFailRpcs) {
  MockBPH cbph(BPMock, knode_);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddMessage("msg1", keys_.at(1).public_key(), "sender1");
  helper.AddMessage("msg2", keys_.at(1).public_key(), "sender2");
  helper.AddMessage("msg3", keys_.at(1).public_key(), "sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, GetBPMessages(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(&helper,
                      &GetMsgsHelper::BPGetMsgsCallbackFailed)));

  std::string signed_pub_key = cryp.AsymSign(keys_.at(1).public_key(), "",
                                             keys_.at(1).private_key(),
                                             crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys_.at(1).public_key() +
                                                signed_pub_key, "",
                                                crypto::STRING_STRING, false),
                                      keys_.at(1).public_key(),
                                      keys_.at(1).private_key()};

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->GetID());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}
