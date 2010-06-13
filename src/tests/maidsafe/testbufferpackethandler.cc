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
#include <maidsafe/base/crypto.h>

#include "maidsafe/clientbufferpackethandler.h"

#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/networktest.h"

namespace maidsafe {

namespace test {

class BPCallback {
 public:
  BPCallback() : result(kGeneralError) {}
  void BPOperation_CB(const ReturnCode &res) {
    result = res;
  }
  void BPGetMsgs_CB(
      const ReturnCode &res,
      const std::list<ValidatedBufferPacketMessage> &rec_msgs,
      bool b) {
    if (b) {
      result = res;
      msgs.clear();
      std::set<std::string>::iterator it;
      for (it = vbpm_set.begin(); it != vbpm_set.end(); ++it) {
        ValidatedBufferPacketMessage vbpm;
        vbpm.ParseFromString(*it);
        msgs.push_back(vbpm);
      }
    } else {
      msgs.clear();
      msgs = rec_msgs;
      std::list<ValidatedBufferPacketMessage>::iterator it;
      for (it = msgs.begin(); it != msgs.end(); ++it)
        vbpm_set.insert(it->SerializeAsString());
    }
  }
  void BPGetPresence_CB(
      const ReturnCode &res,
      const std::list<std::string> &pres,
      bool b) {
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
    result = kGeneralError;
    msgs.clear();
    presences.clear();
    vbpm_set.clear();
    presence_set.clear();
  }
  std::set<std::string> vbpm_set;
  std::set<std::string> presence_set;
  ReturnCode result;
  std::list<ValidatedBufferPacketMessage> msgs;
  std::list<std::string> presences;
};

class CBPHandlerTest : public testing::Test {
 public:
  CBPHandlerTest()
      : network_test_("CBPH"), cbph_(), bp_rpcs_(), crypto_(), keys_() {}
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(network_test_.Init());
    cached_keys::MakeKeys(2, &keys_);
    bp_rpcs_.reset(new BufferPacketRpcsImpl(
        network_test_.transport_handler(), network_test_.channel_manager()));
    cbph_.reset(new ClientBufferPacketHandler(bp_rpcs_,
                network_test_.kad_ops()));
  }

  NetworkTest network_test_;
  boost::shared_ptr<ClientBufferPacketHandler> cbph_;
  boost::shared_ptr<BufferPacketRpcs> bp_rpcs_;
  crypto::Crypto crypto_;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_MS_NET(CBPHandlerTest, FUNC, MAID, TestBPHOperations) {
  std::string owner_pubkey(keys_.at(0).public_key()),
              owner_privkey(keys_.at(0).private_key());
  BPCallback cb;
  std::string signed_pub_key = crypto_.AsymSign(owner_pubkey, "",
                               owner_privkey, crypto::STRING_STRING);
  BPInputParameters bpip = {crypto_.Hash("publicname", "",
                            crypto::STRING_STRING, false), owner_pubkey,
                            owner_privkey};

  std::vector<std::string> users;
  cbph_->ModifyOwnerInfo(bpip, users,
                         boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                         network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kModifyBPError, cb.result);
  printf("Step 1\n");

  cb.Reset();
  cbph_->CreateBufferPacket(bpip, boost::bind(&BPCallback::BPOperation_CB,
                            &cb, _1), network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  boost::this_thread::sleep(boost::posix_time::seconds(30));
  printf("Step 2\n");

  std::string sender_id("user1");
  std::string sender_pmid = crypto_.Hash(keys_.at(1).public_key() +
      crypto_.AsymSign(keys_.at(1).public_key(), "", keys_.at(1).private_key(),
      crypto::STRING_STRING), "", crypto::STRING_STRING, false);
  BPInputParameters bpip1 = {sender_pmid, keys_.at(1).public_key(),
                             keys_.at(1).private_key()};
  std::string recv_id = crypto_.Hash("publicname", "", crypto::STRING_STRING,
                        false);

  cb.Reset();
  cbph_->AddMessage(bpip1, sender_id, owner_pubkey, recv_id, "Hello World",
                   INSTANT_MSG,
                   boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                   network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kBPAddMessageError, cb.result);
  printf("Step 3\n");

  cb.Reset();
  cbph_->AddPresence(bpip1, sender_id, owner_pubkey, recv_id,
                    boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                    network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kBPAddPresenceError, cb.result);
  printf("Step 4\n");

  cb.Reset();
  cbph_->GetMessages(bpip,
                     boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                     network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  ASSERT_TRUE(cb.msgs.empty());
  printf("Step 5\n");

  cb.Reset();
  cbph_->GetPresence(bpip,
                    boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                    network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  ASSERT_TRUE(cb.presences.empty());
  printf("Step 6\n");

  users.push_back(crypto_.Hash(sender_id, "", crypto::STRING_STRING, false));
  cb.Reset();
  cbph_->ModifyOwnerInfo(bpip, users,
                         boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                         network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  printf("Step 7\n");

  cb.Reset();
  cbph_->AddMessage(bpip1, sender_id, owner_pubkey, recv_id, "Hello World",
                    INSTANT_MSG,
                    boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                    network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  printf("Step 8\n");

  cb.Reset();
  cbph_->AddPresence(bpip1, sender_id, owner_pubkey, recv_id,
                     boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                     network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  printf("Step 9\n");

  cb.Reset();
  cbph_->GetMessages(bpip,
                     boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                     network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  ASSERT_EQ(size_t(1), cb.msgs.size());
  ASSERT_EQ("Hello World", cb.msgs.front().message());
  ASSERT_EQ(sender_id, cb.msgs.front().sender());
  printf("Step 10\n");

  cb.Reset();
  cbph_->GetPresence(bpip,
                    boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                    network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kSuccess, cb.result);
  ASSERT_EQ(size_t(1), cb.presences.size());
  GenericPacket gp;
  ASSERT_TRUE(gp.ParseFromString(cb.presences.front()));
  LivePresence pr;
  ASSERT_TRUE(pr.ParseFromString(gp.data()));
  ASSERT_EQ(sender_id, pr.contact_id());
  printf("Step 11\n");

  // Request BPs not belonging to the sender
  bpip1.sign_id = bpip.sign_id;
  bpip1.public_key = bpip.public_key;
  cb.Reset();
  cbph_->GetMessages(bpip1,
                     boost::bind(&BPCallback::BPGetMsgs_CB, &cb, _1, _2, _3),
                     network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kBPMessagesRetrievalError, cb.result);
  printf("Step 12\n");

  cb.Reset();
  cbph_->GetPresence(bpip1,
                    boost::bind(&BPCallback::BPGetPresence_CB, &cb, _1, _2, _3),
                    network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kBPGetPresenceError, cb.result);
  ASSERT_EQ(size_t(0), cb.presences.size());
  printf("Step 13\n");

  cb.Reset();
  cbph_->ModifyOwnerInfo(bpip1, users,
                         boost::bind(&BPCallback::BPOperation_CB, &cb, _1),
                         network_test_.transport_id());
  while (cb.result == -1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(kModifyBPError, cb.result);
  printf("Step 14\n");
}
}  // namepsace test

}  // namespace maidsafe
