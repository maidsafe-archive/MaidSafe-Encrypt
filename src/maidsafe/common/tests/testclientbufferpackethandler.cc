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

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/bufferpacketrpc.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/clientbufferpackethandler.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/kadops.h"
#include "maidsafe/sharedtest/cached_keys.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::WithArgs;

namespace test_cbph {
static const boost::uint8_t K(4);
static const boost::uint8_t upper_threshold(static_cast<boost::uint8_t>
             (K * maidsafe::kMinSuccessfulPecentageStore));
}  // namespace test_cbph

namespace maidsafe {

void GenerateContacts(std::vector<kad::Contact> *cv) {
  cv->clear();
  std::string id(SHA512String("id"));
  kad::Contact ctc(id, "127.0.0.1", 8888, "127.0.0.1", 8888);
  std::string ser_ctc;
  ctc.SerialiseToString(&ser_ctc);
  for (int n = 0; n < test_cbph::K; ++n) {
    cv->push_back(ctc);
  }
}

void execute_cb(maidsafe::VoidFuncIntContacts cb,
                const maidsafe::ReturnCode &rc,
                const std::vector<kad::Contact> &cv) {
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  cb(rc, cv);
}

void FindNodesSucceed(maidsafe::VoidFuncIntContacts cb) {
  std::vector<kad::Contact> cv;
  GenerateContacts(&cv);
  boost::thread thrd(execute_cb, cb, maidsafe::kSuccess, cv);
}

void FindNodesFailure(maidsafe::VoidFuncIntContacts cb) {
  std::vector<kad::Contact> cv;
  GenerateContacts(&cv);
  boost::thread thrd(execute_cb, cb, maidsafe::kBPError, cv);
}

void FindNodesFailNoParse(maidsafe::VoidFuncIntContacts cb) {
  std::vector<kad::Contact> cv;
  GenerateContacts(&cv);
  boost::thread thrd(execute_cb, cb, maidsafe::kBPError, cv);
}

void FindNodesFailNotEnough(maidsafe::VoidFuncIntContacts cb) {
  std::vector<kad::Contact> cv;
  std::string id(SHA512String("id"));
  kad::Contact ctc(id, "127.0.0.1", 8888, "127.0.0.1", 8888);
  for (int n = 0; n < test_cbph::K/4; ++n) {
    cv.push_back(ctc);
  }
  GenerateContacts(&cv);
  boost::thread thrd(execute_cb, cb, maidsafe::kBPError, cv);
}

void FindNodesFailNotContacts(maidsafe::VoidFuncIntContacts cb) {
  std::vector<kad::Contact> cv;
  GenerateContacts(&cv);
  boost::thread thrd(execute_cb, cb, maidsafe::kBPError, cv);
}

/*
*/
void BPCallbackFail(const kad::Contact &peer,
                    maidsafe::CreateBPResponse *response,
                    google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPCallbackSucceed(const kad::Contact &peer,
                       maidsafe::CreateBPResponse *response,
                       google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPInfoCallbackSucceed(const kad::Contact &peer,
                           maidsafe::ModifyBPInfoResponse *response,
                           google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPInfoCallbackFailed(const kad::Contact &peer,
                          maidsafe::ModifyBPInfoResponse *response,
                          google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPAddMsgCallbackSucceed(const kad::Contact &peer,
                             maidsafe::AddBPMessageResponse *response,
                             google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPAddMsgCallbackFailed(const kad::Contact &peer,
                            maidsafe::AddBPMessageResponse *response,
                            google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPAddPresenceCallbackSucceed(const kad::Contact &peer,
                                  maidsafe::AddBPPresenceResponse *response,
                                  google::protobuf::Closure *done) {
  response->set_result(kAck);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

void BPAddPresenceCallbackFailed(const kad::Contact &peer,
                                 maidsafe::AddBPPresenceResponse *response,
                                 google::protobuf::Closure *done) {
  response->set_result(kNack);
  response->set_pmid_id(peer.node_id().String());
  done->Run();
}

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
  void BPGetPresence_CB(const maidsafe::ReturnCode &res,
                        const std::list<std::string> &pres, bool b) {
    if (b) {
      result = res;
      presences.clear();
      std::set<std::string>::iterator it;
      for (it = presence_set.begin(); it != presence_set.end(); ++it) {
        presences.push_back(*it);
      }
    } else {
      presences.clear();
      presences = pres;
      std::list<std::string>::iterator it;
      for (it = presences.begin(); it != presences.end(); ++it)
        presence_set.insert(*it);
    }
  }
  void Reset() {
    result = maidsafe::kGeneralError;
    msgs.clear();
    presences.clear();
  }
  std::set<std::string> vbpm_set;
  std::set<std::string> presence_set;
  maidsafe::ReturnCode result;
  std::list<maidsafe::ValidatedBufferPacketMessage> msgs;
  std::list<std::string> presences;
};

class GetMsgsHelper {
 public:
  GetMsgsHelper() : msgs() {}
  void BPGetMsgsCallbackSucceed(const kad::Contact &peer,
                                maidsafe::GetBPMessagesResponse *response,
                                google::protobuf::Closure *done) {
    response->set_result(kAck);
    for (size_t i = 0; i < msgs.size(); ++i)
      response->add_messages(msgs.at(i).SerializeAsString());
    response->set_pmid_id(peer.node_id().String());
    done->Run();
  }
  void BPGetMsgsCallbackFailed(const kad::Contact &peer,
                               maidsafe::GetBPMessagesResponse *response,
                               google::protobuf::Closure *done) {
    response->set_result(kNack);
    response->set_pmid_id(peer.node_id().String());
    done->Run();
  }
  void BPGetPresenceCallbackSucceed(const kad::Contact &peer,
                                    maidsafe::GetBPPresenceResponse *response,
                                    google::protobuf::Closure *done) {
    response->set_result(kAck);
    for (size_t i = 0; i < presences.size(); ++i)
      response->add_messages(presences.at(i));
    response->set_pmid_id(peer.node_id().String());
    done->Run();
  }
  void BPGetPresenceCallbackFailed(const kad::Contact &peer,
                                   maidsafe::GetBPPresenceResponse *response,
                                   google::protobuf::Closure *done) {
    response->set_result(kNack);
    response->set_pmid_id(peer.node_id().String());
    done->Run();
  }
  void AddMessage(const std::string &msg,
                  const std::string &rec_pub_key,
                  const std::string &sender) {
    maidsafe::ValidatedBufferPacketMessage bp_msg;
    std::string aes_key =
        base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
    bp_msg.set_index(RSAEncrypt(aes_key, rec_pub_key));
    bp_msg.set_sender(sender);
    bp_msg.set_timestamp(base::GetEpochTime());
    bp_msg.set_message(AESEncrypt(msg, aes_key));
    bp_msg.set_type(maidsafe::INSTANT_MSG);
    msgs.push_back(bp_msg);
  }
  void AddPresence(const std::string &sender) {
    maidsafe::LivePresence bp_presence;
    bp_presence.set_contact_id(sender);
    bp_presence.set_end_point("las nueces del rey mazorca");
    maidsafe::GenericPacket gp;
    gp.set_data(bp_presence.SerializeAsString());
    gp.set_signature("mis enormes testiculos");
    presences.push_back(gp.SerializeAsString());
  }
 private:
  std::vector<maidsafe::ValidatedBufferPacketMessage> msgs;
  std::vector<std::string> presences;
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
          boost::shared_ptr<maidsafe::KadOps> kadops,
          boost::uint8_t upper_threshold)
    : maidsafe::ClientBufferPacketHandler(rpcs, kadops, upper_threshold) {}
  MOCK_METHOD2(FindNodes, void(maidsafe::VoidFuncIntContacts,
                               boost::shared_ptr<maidsafe::ChangeBPData>));
};

class ClientBPTest : public testing::Test {
 public:
  ClientBPTest() : trans_(NULL), trans_han_(NULL), ch_man_(NULL),
                   test_dir_(file_system::TempDir() / ("maidsafe_TestClientBP_"
                             + base::RandomAlphaNumericString(6))),
                   kad_config_file_(test_dir_ / ".kadconfig"),
                   chunkstore_(new maidsafe::ChunkStore(
                       (test_dir_ / "ChunkStore").string(), 99999999, 0)),
                   kad_ops_(), BPMock(), keys_() {}
  ~ClientBPTest() {
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
    kad_ops_.reset(new maidsafe::KadOps(trans_han_, ch_man_, kad::VAULT,
                                        keys_.at(0).private_key(),
                                        keys_.at(0).public_key(), false, false,
                                        test_cbph::K, chunkstore_));
    kad_ops_->set_transport_id(trans_id);
    BPMock.reset(new MockBPRpcs);
    ASSERT_TRUE(ch_man_->RegisterNotifiersToTransport());
    ASSERT_TRUE(trans_han_->RegisterOnServerDown(
                    boost::bind(&maidsafe::KadOps::HandleDeadRendezvousServer,
                                kad_ops_, _1)));
    EXPECT_EQ(0, trans_han_->Start(0, trans_id));
    EXPECT_EQ(0, ch_man_->Start());

    std::string pmid(SHA512String(base::RandomString(200)));
    boost::mutex mutex;
    boost::condition_variable cond_var;
    maidsafe::ReturnCode return_code(maidsafe::kPendingResult);
    kad_ops_->Init(kad_config_file_.string(), true, pmid,
                   trans_->listening_port(), &mutex, &cond_var, &return_code);
    {
      boost::mutex::scoped_lock lock(mutex);
      while (return_code == maidsafe::kPendingResult)
        cond_var.wait(lock);
    }
    if (return_code != maidsafe::kSuccess) {
      FAIL();
      return;
    }

    // Adding Contacts
    for (int i = 0; i < kMinChunkCopies + 1; ++i) {
      kad::Contact con(SHA512String(boost::lexical_cast<std::string>(i)),
                       "127.0.0.1", 8000 + i, "127.0.0.1", 8000 + i);
      kad_ops_->knode_.AddContact(con, 0, false);
    }
  }

  void TearDown() {
    kad_ops_->Leave();
    trans_han_->StopAll();
    ch_man_->Stop();
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
  boost::filesystem::path test_dir_, kad_config_file_;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore_;
  boost::shared_ptr<maidsafe::KadOps> kad_ops_;
  boost::shared_ptr<MockBPRpcs> BPMock;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(ClientBPTest, BEH_MAID_CreateBpOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPCallbackSucceed)));

  std::string signed_pubkey(RSASign(keys_.at(1).public_key(),
                                    keys_.at(1).private_key()));
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  BPCallback cb;
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_CreateBpFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);

  cb.Reset();
  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_CreateBpFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, CreateBP(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPCallbackFail)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.CreateBufferPacket(bpip,
                          boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                          trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kStoreNewBPError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_ModifyOwnerInfoOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPInfoCallbackSucceed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_ModifyOwnerInfoFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);

  cb.Reset();
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_ModifyOwnerInfoFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, ModifyBPInfo(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPInfoCallbackFailed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  std::vector<std::string> users;
  cbph.ModifyOwnerInfo(bpip, users,
                       boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                       trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kModifyBPError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddMessageOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddMsgCallbackSucceed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddMessageFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);

  cb.Reset();
  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddMessageFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPMessage(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddMsgCallbackFailed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddMessage(bpip, "", keys_.at(2).public_key(), recv_id, "Hello World",
                  maidsafe::ADD_CONTACT_RQST,
                  boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                  trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddMessageError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_GetMessagesOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
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

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
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

TEST_F(ClientBPTest, BEH_MAID_GetMessagesFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
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

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());
  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);

  cb.Reset();
  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_GetMessagesFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
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

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.GetMessages(bpip,
                   boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPMessagesRetrievalError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddPresenceOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPPresence(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddPresenceCallbackSucceed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddPresenceFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddPresenceError, cb.result);

  cb.Reset();
  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddPresenceError, cb.result);

  cb.Reset();
  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddPresenceError, cb.result);

  cb.Reset();
  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddPresenceError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_AddBPPresenceFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, AddBPPresence(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(BPAddPresenceCallbackFailed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.AddPresence(bpip, "", keys_.at(2).public_key(), recv_id,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPAddPresenceError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_GetPresenceOk) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddPresence("sender1");
  helper.AddPresence("sender2");
  helper.AddPresence("sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, GetBPPresence(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(&helper,
                      &GetMsgsHelper::BPGetPresenceCallbackSucceed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kSuccess, cb.result);
  ASSERT_EQ(size_t(3), cb.presences.size());
  maidsafe::GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(cb.presences.front()));
  maidsafe::LivePresence pr;
  ASSERT_TRUE(pr.ParseFromString(gp.data()));
  ASSERT_EQ("sender1", pr.contact_id());
  cb.presences.pop_front();
  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(cb.presences.front()));
  pr.Clear();
  ASSERT_TRUE(pr.ParseFromString(gp.data()));
  ASSERT_EQ("sender2", pr.contact_id());
  cb.presences.pop_front();
  gp.Clear();
  ASSERT_TRUE(gp.ParseFromString(cb.presences.front()));
  pr.Clear();
  ASSERT_TRUE(pr.ParseFromString(gp.data()));
  ASSERT_EQ("sender3", pr.contact_id());
}

TEST_F(ClientBPTest, BEH_MAID_GetPresenceFailFindNodes) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddPresence("sender1");
  helper.AddPresence("sender2");
  helper.AddPresence("sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailure)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNoParse)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotEnough)))
      .WillOnce(WithArgs<0>(Invoke(FindNodesFailNotContacts)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                      keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  // creating info of receiver
  signed_pubkey = RSASign(keys_.at(2).public_key(), keys_.at(2).private_key());
  std::string recv_id = SHA512String(keys_.at(2).public_key() + signed_pubkey);

  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPGetPresenceError, cb.result);

  cb.Reset();
  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPGetPresenceError, cb.result);

  cb.Reset();
  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPGetPresenceError, cb.result);

  cb.Reset();
  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPGetPresenceError, cb.result);
}

TEST_F(ClientBPTest, BEH_MAID_GetPresenceFailRpcs) {
  MockBPH cbph(BPMock, kad_ops_, test_cbph::upper_threshold);
  BPCallback cb;
  GetMsgsHelper helper;
  helper.AddPresence("sender1");
  helper.AddPresence("sender2");
  helper.AddPresence("sender3");

  EXPECT_CALL(cbph, FindNodes(_, _))
      .WillOnce(WithArgs<0>(Invoke(FindNodesSucceed)));
  EXPECT_CALL(*BPMock, GetBPPresence(_, _, _, _, _, _, _))
      .WillRepeatedly(WithArgs<0, 4, 6>(Invoke(&helper,
                      &GetMsgsHelper::BPGetPresenceCallbackFailed)));

  std::string signed_pubkey = RSASign(keys_.at(1).public_key(),
                                       keys_.at(1).private_key());
  maidsafe::BPInputParameters bpip(
      SHA512String(keys_.at(1).public_key() + signed_pubkey),
      keys_.at(1).public_key(), keys_.at(1).private_key());

  cbph.GetPresence(bpip,
                   boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                   trans_->transport_id());
  while (cb.result == maidsafe::kGeneralError)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(maidsafe::kBPGetPresenceError, cb.result);
}

}  // namespace maidsafe
