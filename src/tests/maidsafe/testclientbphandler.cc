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

#include "maidsafe/clientbufferpackethandler.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::WithArgs;

void execute_cb(base::callback_func_type cb, const std::string &result) {
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  cb(result);
}

void FindReferencesCBSucceed(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultSuccess);
  for (int i = 0; i < kMinChunkCopies; ++i)
    res.add_values("id" + boost::lexical_cast<std::string>(i));
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindRemoteCtcCBSucceed(base::callback_func_type cb) {
  kad::FindNodeResult res;
  res.set_result(kad::kRpcResultSuccess);
  kad::Contact ctc("id", "127.0.0.1", 8888, "127.0.0.1", 8888);
  std::string ser_ctc;
  ctc.SerialiseToString(&ser_ctc);
  res.set_contact(ser_ctc);
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindReferencesCBFailed(base::callback_func_type cb) {
  kad::FindResponse res;
  res.set_result(kad::kRpcResultFailure);
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void FindRemoteCtcCBFailed(base::callback_func_type cb) {
  kad::FindNodeResult res;
  res.set_result(kad::kRpcResultFailure);
  boost::thread thrd(execute_cb, cb, res.SerializeAsString());
}

void BPCallbackFail(const kad::Contact &peer,
  maidsafe::CreateBPResponse *response, google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPCallbackSucceed(const kad::Contact &peer,
  maidsafe::CreateBPResponse *response, google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPInfoCallbackSucceed(const kad::Contact &peer,
  maidsafe::ModifyBPInfoResponse *response, google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPInfoCallbackFailed(const kad::Contact &peer,
  maidsafe::ModifyBPInfoResponse *response, google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPAddMsgCallbackSucceed(const kad::Contact &peer,
  maidsafe::AddBPMessageResponse *response, google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void BPAddMsgCallbackFailed(const kad::Contact &peer,
  maidsafe::AddBPMessageResponse *response, google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

void ContactInfoCallbackSucceed(const kad::Contact &peer,
  maidsafe::ContactInfoResponse *response, google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id());
  response->set_status(3);
  maidsafe::EndPoint *ep = response->mutable_ep();
  ep->set_ip("132.248.59.1");
  ep->set_port(48591);
  done->Run();
}

void ContactInfoCallbackFailed(const kad::Contact &peer,
  maidsafe::ContactInfoResponse *response, google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id());
  done->Run();
}

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
  BPCallback()
      : result(maidsafe::kGeneralError), msgs(), end_point(), status(0) {}
  void BPOperation_CB(const maidsafe::ReturnCode &res) {
    result = res;
  }
  void BPGetMsgs_CB(const maidsafe::ReturnCode &res,
      const std::list<maidsafe::ValidatedBufferPacketMessage> &rec_msgs) {
    result = res;
    msgs = rec_msgs;
  }
  void ContactInfo_CB(const maidsafe::ReturnCode &res,
                      const maidsafe::EndPoint &ep,
                      const boost::uint32_t &st) {
    result = res;
    end_point = ep;
    status = st;
  }
  void Reset() {
    result = maidsafe::kGeneralError;
    msgs.clear();
  }
  maidsafe::ReturnCode result;
  std::list<maidsafe::ValidatedBufferPacketMessage> msgs;
  maidsafe::EndPoint end_point;
  boost::uint32_t status;
};

class GetMsgsHelper {
 public:
  GetMsgsHelper() : msgs(), co() {}
  void BPGetMsgsCallbackSucceed(const kad::Contact &peer,
    maidsafe::GetBPMessagesResponse *response,
    google::protobuf::Closure *done) {
    response->set_result(kAck);
    for (unsigned int i = 0; i < msgs.size(); ++i)
      response->add_messages(msgs.at(i).SerializeAsString());
    response->set_pmid_id(peer.node_id());
    done->Run();
  }
  void BPGetMsgsCallbackFailed(const kad::Contact &peer,
    maidsafe::GetBPMessagesResponse *response,
    google::protobuf::Closure *done) {
    response->set_result(kNack);
    response->set_pmid_id(peer.node_id());
    done->Run();
  }
  void AddMessage(const std::string &msg, const std::string &rec_pub_key,
    const std::string &sender) {
    maidsafe::ValidatedBufferPacketMessage bp_msg;
    uint32_t iter = base::random_32bit_uinteger() % 1000 +1;
    std::string aes_key = co.SecurePassword(co.Hash(msg, "",
      crypto::STRING_STRING, true), iter);
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
  MOCK_METHOD6(CreateBP, void(const kad::Contact&, bool,
    const maidsafe::CreateBPRequest*, maidsafe::CreateBPResponse*,
    rpcprotocol::Controller*, google::protobuf::Closure *));
  MOCK_METHOD6(ModifyBPInfo, void(const kad::Contact&, bool,
    const maidsafe::ModifyBPInfoRequest*, maidsafe::ModifyBPInfoResponse*,
    rpcprotocol::Controller*, google::protobuf::Closure*));
  MOCK_METHOD6(GetBPMessages, void(const kad::Contact&, bool,
    const maidsafe::GetBPMessagesRequest*, maidsafe::GetBPMessagesResponse*,
    rpcprotocol::Controller*, google::protobuf::Closure*));
  MOCK_METHOD6(AddBPMessage, void(const kad::Contact&, bool,
    const maidsafe::AddBPMessageRequest*, maidsafe::AddBPMessageResponse*,
    rpcprotocol::Controller*, google::protobuf::Closure*));
  MOCK_METHOD6(ContactInfo, void(const kad::Contact&, bool,
    const maidsafe::ContactInfoRequest*, maidsafe::ContactInfoResponse*,
    rpcprotocol::Controller*, google::protobuf::Closure*));
};

class MockBPH : public maidsafe::ClientBufferPacketHandler {
 public:
  MockBPH(boost::shared_ptr<maidsafe::BufferPacketRpcs> rpcs,
          boost::shared_ptr<kad::KNode> knode)
    : maidsafe::ClientBufferPacketHandler(rpcs, knode) {}
  MOCK_METHOD2(FindReferences,
    void(base::callback_func_type, boost::shared_ptr<maidsafe::ChangeBPData>));
  MOCK_METHOD3(FindRemoteContact,
    void(base::callback_func_type, boost::shared_ptr<maidsafe::ChangeBPData>,
    const int&));
};

class TestClientBP : public testing::Test {
 public:
  TestClientBP() : trans_(NULL), ch_man_(NULL), knode_(), BPMock(),
    keys_(), cb_(), test_dir_(""), kad_config_file_(""), cryp()  {
    keys_.GenerateKeys(4096);
    test_dir_ = std::string("KnodeTest") +
        boost::lexical_cast<std::string>(base::random_32bit_uinteger());
    kad_config_file_ = test_dir_ + std::string("/.kadconfig");
  }

  ~TestClientBP() {
    transport::CleanUp();
  }

 protected:
  void SetUp() {
    trans_ = new transport::Transport();
    ch_man_ = new rpcprotocol::ChannelManager(trans_);
    knode_.reset(new kad::KNode(ch_man_, trans_, kad::VAULT,
                 keys_.private_key(), keys_.public_key(), false, false));
    BPMock.reset(new MockBPRpcs);
    ASSERT_TRUE(ch_man_->RegisterNotifiersToTransport());
    ASSERT_TRUE(trans_->RegisterOnServerDown(
      boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_, _1)));
    EXPECT_EQ(0, trans_->Start(0));
    EXPECT_EQ(0, ch_man_->Start());

    cb_.Reset();
    boost::asio::ip::address local_ip;
    ASSERT_TRUE(base::get_local_address(&local_ip));
    knode_->Join(kad_config_file_, local_ip.to_string(),
        trans_->listening_port(),
        boost::bind(&KadCB::CallbackFunc, &cb_, _1));
    while (cb_.result == "")
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    ASSERT_EQ(kad::kRpcResultSuccess, cb_.result);
    ASSERT_TRUE(knode_->is_joined());

    // Adding Contacts
    for (int i = 0; i < kMinChunkCopies + 1; ++i) {
      kad::Contact con(cryp.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false), "127.0.0.1", 8000+i, "127.0.0.1",
        8000+i);
      knode_->AddContact(con, 0, false);
    }
  }
  void TearDown() {
    knode_->Leave();
    trans_->Stop();
    ch_man_->Stop();
//    delete knode_;
    delete trans_;
    delete ch_man_;
    try {
      if (boost::filesystem::exists(test_dir_))
        boost::filesystem::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      printf("filesystem error: %s\n", e.what());
    }
  }
  transport::Transport *trans_;
  rpcprotocol::ChannelManager *ch_man_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<MockBPRpcs> BPMock;
  crypto::RsaKeyPair keys_;
  KadCB cb_;
  std::string test_dir_, kad_config_file_;
  crypto::Crypto cryp;
};

TEST_F(TestClientBP, BEH_MAID_CreateBP_OK) {
  maidsafe::ClientBufferPacketHandler cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_CreateBPFailOnce) {
  maidsafe::ClientBufferPacketHandler cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _))
    .Times(kMinChunkCopies+1)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPCallbackFail)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_CreateBPFailThenSucceed) {
  maidsafe::ClientBufferPacketHandler cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _))
    .Times(kMinChunkCopies+1)
    .WillOnce(WithArgs<0, 3, 5>(Invoke(BPCallbackFail)))
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOwnerInfo) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPInfoCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, 0, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOINoReferences) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBFailed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(0);

  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, 0, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOIFailAllFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)));

  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, 0, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOIFailOneFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _))
    .Times(kMinChunkCopies-1)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPInfoCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, 0, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ModifyOIFailModifyInfoRpc) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPInfoCallbackFailed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, 0, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMessage) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPAddMsgCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of receiver
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, keys.public_key(), recv_id, "Hello World",
    maidsafe::ADD_CONTACT_RQST,
    boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMsgNoReferences) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBFailed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(0);

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of receiver
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, keys.public_key(), recv_id, "Hello World",
    maidsafe::ADD_CONTACT_RQST,
    boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(TestClientBP, FUNC_MAID_AddMsgFailAllFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)));

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of receiver
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, keys.public_key(), recv_id, "Hello World",
    maidsafe::ADD_CONTACT_RQST,
    boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(TestClientBP, FUNC_MAID_AddMsgFailOneFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(kMinChunkCopies-1)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPAddMsgCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of receiver
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, keys.public_key(), recv_id, "Hello World",
    maidsafe::ADD_CONTACT_RQST,
    boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_AddMsgFailAddMessageRpc) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(BPAddMsgCallbackFailed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of receiver
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.AddMessage(bpip, keys.public_key(), recv_id, "Hello World",
    maidsafe::ADD_CONTACT_RQST,
    boost::bind(&BPCallback::BPOperation_CB, &cb, _1));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_GetMessages) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddMessage("msg1", keys.public_key(), "sender1");
  helper.AddMessage("msg2", keys.public_key(), "sender2");
  helper.AddMessage("msg3", keys.public_key(), "sender3");

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, GetBPMessages(_, _, _, _, _, _))
    .Times(1)
    .WillOnce(WithArgs<0, 3, 5>(Invoke
      (&helper, &GetMsgsHelper::BPGetMsgsCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
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

TEST_F(TestClientBP, BEH_MAID_GetMsgsOneFindContactsFail) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddMessage("msg---1", keys.public_key(), "sender1");
  helper.AddMessage("msg---2", keys.public_key(), "sender2");
  helper.AddMessage("msg---3", keys.public_key(), "sender1");

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(3)
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, GetBPMessages(_, _, _, _, _, _))
    .Times(1)
    .WillOnce(WithArgs<0, 3, 5>(Invoke
      (&helper, &GetMsgsHelper::BPGetMsgsCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(size_t(3), cb.msgs.size());
  maidsafe::ValidatedBufferPacketMessage msg = cb.msgs.front();
  ASSERT_EQ("msg---1", msg.message());
  cb.msgs.pop_front();
  msg.Clear();
  msg = cb.msgs.front();
  ASSERT_EQ("msg---2", msg.message());
  cb.msgs.pop_front();
  msg.Clear();
  msg = cb.msgs.front();
  ASSERT_EQ("msg---3", msg.message());
}

TEST_F(TestClientBP, BEH_MAID_GetMsgsNoReferences) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBFailed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(0);

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_GetMsgsFailAllFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)));

  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_GetMsgsFailGetBPMessagesRpc) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;
  GetMsgsHelper helper;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, GetBPMessages(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke
      (&helper, &GetMsgsHelper::BPGetMsgsCallbackFailed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  cbph.GetMessages(bpip, boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(TestClientBP, BEH_MAID_ContactInfo) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
//    .Times(maidsafe::ClientBufferPacketHandler::kParallelFindCtcs)
// TODO(Team#5#): coordinate with the number of parallel contacts finds
    .Times(1)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ContactInfo(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(ContactInfoCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of querier
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
                   crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
                        crypto::STRING_STRING, false);

  cbph.ContactInfo(bpip, "el nalga derecha",
                   boost::bind(&BPCallback::ContactInfo_CB, &cb, _1, _2, _3));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(boost::uint32_t(3), cb.status);
  ASSERT_EQ("132.248.59.1", cb.end_point.ip());
  ASSERT_EQ(boost::uint32_t(48591), cb.end_point.port());
}

TEST_F(TestClientBP, BEH_MAID_ContactInfoNoReferences) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBFailed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(0);

  EXPECT_CALL(*BPMock, ContactInfo(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of querier
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.ContactInfo(bpip, "el nalga derecha",
                   boost::bind(&BPCallback::ContactInfo_CB, &cb, _1, _2, _3));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kGetBPInfoError, cb.result);
}

TEST_F(TestClientBP, FUNC_MAID_ContactInfoFailAllFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)));

  EXPECT_CALL(*BPMock, ContactInfo(_, _, _, _, _, _))
    .Times(0);

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of querier
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.ContactInfo(bpip, "el nalga derecha",
                   boost::bind(&BPCallback::ContactInfo_CB, &cb, _1, _2, _3));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kGetBPInfoError, cb.result);
}

TEST_F(TestClientBP, FUNC_MAID_ContactInfoOneFindContacts) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBFailed)))
    .WillOnce(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ContactInfo(_, _, _, _, _, _))
    .Times(1)
    .WillOnce(WithArgs<0, 3, 5>(Invoke(ContactInfoCallbackSucceed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of querier
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.ContactInfo(bpip, "el nalga derecha",
                   boost::bind(&BPCallback::ContactInfo_CB, &cb, _1, _2, _3));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(boost::uint32_t(3), cb.status);
  ASSERT_EQ("132.248.59.1", cb.end_point.ip());
  ASSERT_EQ(boost::uint32_t(48591), cb.end_point.port());
}

TEST_F(TestClientBP, BEH_MAID_ContactInfoFailAddMessageRpc) {
  MockBPH cbph(BPMock, knode_);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(4096);

  BPCallback cb;

  EXPECT_CALL(cbph, FindReferences(_, _))
    .Times(1)
    .WillOnce(WithArgs<0>(Invoke(FindReferencesCBSucceed)));

  EXPECT_CALL(cbph, FindRemoteContact(_, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0>(Invoke(FindRemoteCtcCBSucceed)));

  EXPECT_CALL(*BPMock, ContactInfo(_, _, _, _, _, _))
    .Times(kMinChunkCopies)
    .WillRepeatedly(WithArgs<0, 3, 5>(Invoke(ContactInfoCallbackFailed)));

  std::string signed_pub_key = cryp.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);
  maidsafe::BPInputParameters bpip = {cryp.Hash(keys.public_key() +
    signed_pub_key, "", crypto::STRING_STRING, false), keys.public_key(),
    keys.private_key()};

  // creating info of querier
  keys.ClearKeys();
  keys.GenerateKeys(4096);
  signed_pub_key = cryp.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  std::string recv_id = cryp.Hash(keys.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);

  cbph.ContactInfo(bpip, "el nalga derecha",
                   boost::bind(&BPCallback::ContactInfo_CB, &cb, _1, _2, _3));
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kGetBPInfoError, cb.result);
}

