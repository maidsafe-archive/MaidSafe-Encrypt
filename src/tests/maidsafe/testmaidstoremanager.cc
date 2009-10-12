/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
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
#include <maidsafe/contact_info.pb.h>
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace test_msm {

class GeneralCallback {
 public:
  GeneralCallback() : called_back_(false),
                      callback_succeeded_(false),
                      callback_mutex_() {}
  void CallbackFunction(const std::string &result) {
    maidsafe::GenericResponse result_msg;
    if ((!result_msg.ParseFromString(result)) ||
        (result_msg.result() != kAck)) {
      boost::mutex::scoped_lock lock(callback_mutex_);
      callback_succeeded_ = false;
      called_back_ = true;
    } else {
      boost::mutex::scoped_lock lock(callback_mutex_);
      callback_succeeded_ = true;
      called_back_ = true;
    }
  }
  bool Success() {
    bool got_callback = false;
    while (!got_callback) {
      {
        boost::mutex::scoped_lock lock(callback_mutex_);
        if (called_back_) {
          got_callback = true;
        }
      }
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
    return callback_succeeded_;
  }
 private:
  bool called_back_;
  bool callback_succeeded_;
  boost::mutex callback_mutex_;
};

void DoneRun(google::protobuf::Closure* callback) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::random_32bit_uinteger() % 5000));
  callback->Run();
}

void ThreadedDoneRun(google::protobuf::Closure* callback) {
  boost::thread(DoneRun, callback);
}

void ConditionNotify(int set_return,
                     int *return_value,
                     maidsafe::GenericConditionData *generic_cond_data) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::random_32bit_uinteger() % 5000));
  {
    boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
    *return_value = set_return;
    generic_cond_data->cond_flag = true;
  }
  generic_cond_data->cond_variable->notify_all();
}

void ThreadedConditionNotifyZero(
    int *return_value,
    maidsafe::GenericConditionData *generic_cond_data) {
  boost::thread(ConditionNotify, 0, return_value, generic_cond_data);
}

void ThreadedConditionNotifyNegOne(
    int *return_value,
    maidsafe::GenericConditionData *generic_cond_data) {
  boost::thread(ConditionNotify, -1, return_value, generic_cond_data);
}

}  // namespace test_msm

namespace maidsafe {

class MaidStoreManagerTest : public testing::Test {
 protected:
  MaidStoreManagerTest() : client_chunkstore_dir_("./TestMSM/Chunkstore"),
                           client_chunkstore_(),
                           client_pmid_keys_(),
                           client_maid_keys_(),
                           client_pmid_public_signature_(),
                           hex_client_pmid_(),
                           client_pmid_(),
                           mutex_(),
                           crypto_() {
    try {
      boost::filesystem::remove_all("./TestMSM");
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest ctor - %s\n", e.what());
    }
    fs::create_directories("./TestMSM");
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    client_maid_keys_.GenerateKeys(kRsaKeySize);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, true);
    SessionSingleton::getInstance()->AddKey(MAID, maid_name, maid_pri, maid_pub,
        maid_pub_key_signature);
    client_pmid_keys_.GenerateKeys(kRsaKeySize);
    std::string pmid_pri = client_pmid_keys_.private_key();
    std::string pmid_pub = client_pmid_keys_.public_key();
    client_pmid_public_signature_ = crypto_.AsymSign(pmid_pub, "",
        maid_pri, crypto::STRING_STRING);
    hex_client_pmid_ = crypto_.Hash(pmid_pub +
        client_pmid_public_signature_, "", crypto::STRING_STRING, true);
    base::decode_from_hex(hex_client_pmid_, &client_pmid_);
    SessionSingleton::getInstance()->AddKey(PMID, hex_client_pmid_, pmid_pri,
        pmid_pub, client_pmid_public_signature_);
    SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  virtual ~MaidStoreManagerTest() {
    try {
      SessionSingleton::getInstance()->ResetSession();
      boost::filesystem::remove_all("./TestMSM");
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest dtor - %s\n", e.what());
    }
  }

  virtual void SetUp() {
    client_chunkstore_ = boost::shared_ptr<ChunkStore>
        (new ChunkStore(client_chunkstore_dir_, 0, 0));
  }
  virtual void TearDown() {}

  std::string client_chunkstore_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_, hex_client_pmid_, client_pmid_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;

 private:
  MaidStoreManagerTest(const MaidStoreManagerTest&);
  MaidStoreManagerTest &operator=(const MaidStoreManagerTest&);
};

class MockMsmKeyUnique : public MaidsafeStoreManager {
 public:
  explicit MockMsmKeyUnique(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD6(FindAndLoadChunk, int(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      bool load_data,
      const std::string &public_key,
      const std::string &signed_public_key,
      std::string *data));
  MOCK_METHOD3(SendChunk, int(
      const StoreTask &store_task,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      int copies));
  MOCK_METHOD2(UpdateChunkCopies, int(
      const StoreTask &store_task,
      const std::vector<std::string> &chunk_holders_ids));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("a", "", crypto::STRING_STRING, false);
  std::string hex_key;
  base::encode_to_hex(non_hex_key, &hex_key);
  EXPECT_CALL(msm, FindValue(non_hex_key, true, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(0));
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(0));
  ASSERT_TRUE(msm.KeyUnique(hex_key, true));
  ASSERT_TRUE(msm.KeyUnique(hex_key, false));
  ASSERT_FALSE(msm.KeyUnique(hex_key, true));
  ASSERT_FALSE(msm.KeyUnique(hex_key, false));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_PreSendAnalysis) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("A", "", crypto::STRING_STRING, false);
  std::string hex_key;
  base::encode_to_hex(non_hex_key, &hex_key);
  // Set up data for calls to FindValue
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id(crypto_.Hash("B", "", crypto::STRING_STRING, false));
  cache_holder.set_ip("192.168.3.3");
  cache_holder.set_port(8888);
  std::vector<std::string> chunk_holders_ids;
  for (int i = 0; i < 10; ++i) {
    chunk_holders_ids.push_back(crypto_.Hash(base::itos(i * i), "",
                                crypto::STRING_STRING, false));
  }
  std::string needs_cache_copy_id = crypto_.Hash("C", "", crypto::STRING_STRING,
                                                 false);
  int return_value(10);
  StoreTask store_task(non_hex_key, PRIVATE, "");

  // Set expectations
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_))
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(0)))  // Call 1
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(0)))  // Call 2
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(0)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(0)))  // Call 4
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(0)))  // Call 5
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(0)))  // Call 6
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(0)))  // Call 7
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-1)))  // Call 8
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(-1)))  // Call 9
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(-1)))  // Call 10
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-1)))  // Call 11
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-1)))  // Call 12
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(-1)))  // Call 13
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-1)))  // Call 14
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-3)))  // Call 15
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(-3)))  // Call 16
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(-3)))  // Call 17
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-3)))  // Call 18
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-3)))  // Call 19
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(-3)))  // Call 20
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(-3)));  // Call 21
  EXPECT_CALL(msm, FindAndLoadChunk(non_hex_key, testing::_, false, "", "",
      testing::_))
          .WillOnce(testing::Return(-1));  // Call 1
  EXPECT_CALL(msm, FindAndLoadChunk(non_hex_key, chunk_holders_ids, false, "",
      "", testing::_))
          .WillOnce(testing::Return(0))  // Call 2
          .WillOnce(testing::Return(1));  // Call 4
  EXPECT_CALL(msm, SendChunk(
      testing::AllOf(testing::Field(&StoreTask::non_hex_key_, non_hex_key),
                     testing::Field(&StoreTask::dir_type_, PRIVATE),
                     testing::Field(&StoreTask::public_key_,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreTask::private_key_,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreTask::public_key_signature_,
                                    client_pmid_public_signature_)),
      testing::_,
      kMinChunkCopies))
          .WillOnce(testing::Return(0))  // Call 1
          .WillOnce(testing::Return(-100))  // Call 4
          .WillOnce(testing::Return(-101))  // Call 15
          .WillOnce(testing::Return(-102))  // Call 16
          .WillOnce(testing::Return(-103))  // Call 17
          .WillOnce(testing::Return(-104))  // Call 18
          .WillOnce(testing::Return(-105))  // Call 19
          .WillOnce(testing::Return(-106))  // Call 20
          .WillOnce(testing::Return(-107));  // Call 21
  EXPECT_CALL(msm, UpdateChunkCopies(
      testing::AllOf(testing::Field(&StoreTask::non_hex_key_, non_hex_key),
                     testing::Field(&StoreTask::dir_type_, PRIVATE),
                     testing::Field(&StoreTask::public_key_,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreTask::private_key_,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreTask::public_key_signature_,
                                    client_pmid_public_signature_)),
      chunk_holders_ids))
          .WillOnce(testing::Return(-99));  // Call 2

  // Run test calls
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 1
  ASSERT_EQ(0, return_value);
  msm.PreSendAnalysis(store_task, kAppend, &return_value);  // Call 2
  ASSERT_EQ(-99, return_value);
  msm.PreSendAnalysis(store_task, kStoreFailure, &return_value);  // Call 3
  ASSERT_EQ(-2, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 4
  ASSERT_EQ(-100, return_value);
  msm.PreSendAnalysis(store_task, kAppend, &return_value);  // Call 5
  ASSERT_EQ(-3, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 6
  ASSERT_EQ(0, return_value);
  msm.PreSendAnalysis(store_task, static_cast<IfExists>(999), &return_value);
  ASSERT_EQ(-4, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 8
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 9
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 10
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 11
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 12
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 13
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 14
  ASSERT_EQ(-1, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 15
  ASSERT_EQ(-101, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 16
  ASSERT_EQ(-102, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 17
  ASSERT_EQ(-103, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 18
  ASSERT_EQ(-104, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 19
  ASSERT_EQ(-105, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 20
  ASSERT_EQ(-106, return_value);
  msm.PreSendAnalysis(store_task, kStoreSuccess, &return_value);  // Call 21
  ASSERT_EQ(-107, return_value);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests) {
  MaidsafeStoreManager msm(client_chunkstore_);
  std::string recipient_id = crypto_.Hash("RecipientID", "",
      crypto::STRING_STRING, false);
  StorePrepRequest store_prep_request;
  StoreRequest store_request;
  IOUDoneRequest iou_done_request;
  // Make chunk/packet names
  std::vector<std::string> names;
  for (int i = 100; i < 117; ++i) {
    std::string j(base::itos(i));
    names.push_back(crypto_.Hash(j, "", crypto::STRING_STRING, false));
  }

  // Check bad data - ensure existing parameters in requests are cleared
  store_prep_request.set_chunkname(names.at(0));
  store_request.set_chunkname(names.at(0));
  iou_done_request.set_chunkname(names.at(0));
  ASSERT_NE("", store_prep_request.chunkname());
  ASSERT_NE("", store_request.chunkname());
  ASSERT_NE("", iou_done_request.chunkname());
  StoreTask st_missing_name("", PRIVATE, "");
  ASSERT_EQ(-1, msm.GetStoreRequests(st_missing_name, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));
  ASSERT_EQ("", store_prep_request.chunkname());
  ASSERT_EQ("", store_request.chunkname());
  ASSERT_EQ("", iou_done_request.chunkname());

  // Check PRIVATE_SHARE chunk
  std::string msid_name = crypto_.Hash("b", "", crypto::STRING_STRING, true);
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  std::vector<std::string> attributes;
  attributes.push_back("PrivateShare");
  attributes.push_back(msid_name);
  attributes.push_back(rsakp.public_key());
  attributes.push_back(rsakp.private_key());
  std::list<ShareParticipants> participants;
  ShareParticipants sp;
  sp.id = "spid";
  sp.public_key = "pub_key";
  sp.role = 'A';
  participants.push_back(sp);
  ASSERT_EQ(0, SessionSingleton::getInstance()->AddPrivateShare(attributes,
      &participants));
  StoreTask st_chunk_private_share(names.at(0), PRIVATE_SHARE, msid_name);
  client_chunkstore_->AddChunkToOutgoing(names.at(0), std::string("100"));
  ASSERT_EQ(0, msm.GetStoreRequests(st_chunk_private_share, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));
  std::string public_key_signature = crypto_.AsymSign(rsakp.public_key(), "",
      rsakp.private_key(), crypto::STRING_STRING);
  std::string request_signature = crypto_.AsymSign(crypto_.Hash(
      public_key_signature + names.at(0) + recipient_id, "",
      crypto::STRING_STRING, false), "", rsakp.private_key(),
      crypto::STRING_STRING);

  ASSERT_EQ(names.at(0), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.pmid());
  ASSERT_EQ(rsakp.public_key(), store_prep_request.public_key());
  ASSERT_EQ(public_key_signature, store_prep_request.signed_public_key());
  ASSERT_EQ(request_signature, store_prep_request.signed_request());

  ASSERT_EQ(names.at(0), store_request.chunkname());
  ASSERT_EQ("100", store_request.data());
  ASSERT_EQ(client_pmid_, store_request.pmid());
  ASSERT_EQ(rsakp.public_key(), store_request.public_key());
  ASSERT_EQ(public_key_signature, store_request.signed_public_key());
  ASSERT_EQ(request_signature, store_request.signed_request());
  ASSERT_EQ(DATA, store_request.data_type());

  ASSERT_EQ(names.at(0), iou_done_request.chunkname());
  ASSERT_EQ(rsakp.public_key(), iou_done_request.public_key());
  ASSERT_EQ(public_key_signature, iou_done_request.signed_public_key());
  ASSERT_EQ(request_signature, iou_done_request.signed_request());

  // Check PUBLIC_SHARE chunk
  StoreTask st_chunk_public_share_bad(names.at(1), PUBLIC_SHARE, "");
  client_chunkstore_->AddChunkToOutgoing(names.at(1), std::string("101"));
  ASSERT_EQ(-3, msm.GetStoreRequests(st_chunk_public_share_bad, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));
  rsakp.GenerateKeys(kRsaKeySize);
  std::string anmpid_pri = rsakp.private_key();
  std::string anmpid_pub = rsakp.public_key();
  std::string anmpid_pub_sig = crypto_.AsymSign(anmpid_pub, "", anmpid_pri,
      crypto::STRING_STRING);
  std::string anmpid_name = crypto_.Hash("Anmpid", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(ANMPID, anmpid_name, anmpid_pri,
      anmpid_pub, anmpid_pub_sig);
  rsakp.GenerateKeys(kRsaKeySize);
  std::string mpid_pri = rsakp.private_key();
  std::string mpid_pub = rsakp.public_key();
  std::string mpid_pub_sig = crypto_.AsymSign(mpid_pub, "",
      anmpid_pri, crypto::STRING_STRING);
  std::string mpid_name = crypto_.Hash("PublicName", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(MPID, mpid_name, mpid_pri, mpid_pub,
      mpid_pub_sig);
  StoreTask st_chunk_public_share_good(names.at(1), PUBLIC_SHARE, "");
  ASSERT_EQ(0, msm.GetStoreRequests(st_chunk_public_share_good, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      mpid_pub_sig + names.at(1) + recipient_id, "", crypto::STRING_STRING,
      false), "", mpid_pri, crypto::STRING_STRING);

  ASSERT_EQ(names.at(1), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.pmid());
  ASSERT_EQ(mpid_pub, store_prep_request.public_key());
  ASSERT_EQ(mpid_pub_sig, store_prep_request.signed_public_key());
  ASSERT_EQ(request_signature, store_prep_request.signed_request());

  ASSERT_EQ(names.at(1), store_request.chunkname());
  ASSERT_EQ("101", store_request.data());
  ASSERT_EQ(client_pmid_, store_request.pmid());
  ASSERT_EQ(mpid_pub, store_request.public_key());
  ASSERT_EQ(mpid_pub_sig, store_request.signed_public_key());
  ASSERT_EQ(request_signature, store_request.signed_request());
  ASSERT_EQ(DATA, store_request.data_type());

  ASSERT_EQ(names.at(1), iou_done_request.chunkname());
  ASSERT_EQ(mpid_pub, iou_done_request.public_key());
  ASSERT_EQ(mpid_pub_sig, iou_done_request.signed_public_key());
  ASSERT_EQ(request_signature, iou_done_request.signed_request());

  // Check ANONYMOUS chunk
  StoreTask st_chunk_anonymous(names.at(2), ANONYMOUS, "");
  client_chunkstore_->AddChunkToOutgoing(names.at(2), std::string("102"));
  ASSERT_EQ(0, msm.GetStoreRequests(st_chunk_anonymous, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));

  ASSERT_EQ(names.at(2), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.pmid());
  ASSERT_EQ(" ", store_prep_request.public_key());
  ASSERT_EQ(" ", store_prep_request.signed_public_key());
  ASSERT_EQ(kAnonymousSignedRequest, store_prep_request.signed_request());

  ASSERT_EQ(names.at(2), store_request.chunkname());
  ASSERT_EQ("102", store_request.data());
  ASSERT_EQ(client_pmid_, store_request.pmid());
  ASSERT_EQ(" ", store_request.public_key());
  ASSERT_EQ(" ", store_request.signed_public_key());
  ASSERT_EQ(kAnonymousSignedRequest, store_request.signed_request());
  ASSERT_EQ(PDDIR_NOTSIGNED, store_request.data_type());

  ASSERT_EQ(names.at(2), iou_done_request.chunkname());
  ASSERT_EQ(" ", iou_done_request.public_key());
  ASSERT_EQ(" ", iou_done_request.signed_public_key());
  ASSERT_EQ(kAnonymousSignedRequest, iou_done_request.signed_request());

  // Check PRIVATE chunk
  StoreTask st_chunk_private(names.at(3), PRIVATE, "");
  client_chunkstore_->AddChunkToOutgoing(names.at(3), std::string("103"));
  ASSERT_EQ(0, msm.GetStoreRequests(st_chunk_private, recipient_id,
      &store_prep_request, &store_request, &iou_done_request));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      client_pmid_public_signature_ + names.at(3) + recipient_id, "",
      crypto::STRING_STRING, false), "", client_pmid_keys_.private_key(),
      crypto::STRING_STRING);

  ASSERT_EQ(names.at(3), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(), store_prep_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_prep_request.signed_public_key());
  ASSERT_EQ(request_signature, store_prep_request.signed_request());

  ASSERT_EQ(names.at(3), store_request.chunkname());
  ASSERT_EQ("103", store_request.data());
  ASSERT_EQ(client_pmid_, store_request.pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(), store_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_request.signed_public_key());
  ASSERT_EQ(request_signature, store_request.signed_request());
  ASSERT_EQ(DATA, store_request.data_type());

  ASSERT_EQ(names.at(3), iou_done_request.chunkname());
  ASSERT_EQ(client_pmid_keys_.public_key(), iou_done_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      iou_done_request.signed_public_key());
  ASSERT_EQ(request_signature, iou_done_request.signed_request());

//  // Check MID packet
//  StoreTask st_packet_mid(names.at(4), "104", MID, PRIVATE, "");
//  // Check ANMID packet
//  StoreTask st_packet_anmid(names.at(5), "105", ANMID, PRIVATE, "");
//  // Check SMID packet
//  StoreTask st_packet_smid(names.at(6), "106", SMID, PRIVATE, "");
//  // Check ANSMID packet
//  StoreTask st_packet_ansmid(names.at(7), "107", ANSMID, PRIVATE, "");
//  // Check TMID packet
//  StoreTask st_packet_tmid(names.at(8), "108", TMID, PRIVATE, "");
//  // Check ANTMID packet
//  StoreTask st_packet_antmid(names.at(9), "109", ANTMID, PRIVATE, "");
//  // Check MPID packet
//  StoreTask st_packet_mpid(names.at(10), "110", MPID, PRIVATE, "");
//  // Check ANMPID packet
//  StoreTask st_packet_anmpid(names.at(11), "111", ANMPID, PRIVATE, "");
//  // Check PMID packet
//  StoreTask st_packet_pmid(names.at(12), "112", PMID, PRIVATE, "");
//  // Check MAID packet
//  StoreTask st_packet_maid(names.at(13), "113", MAID, PRIVATE, "");
//  // Check BUFFER packet
//  StoreTask st_packet_buffer(names.at(14), "114", BUFFER, PRIVATE, "");
//  // Check BUFFER_INFO packet
//  StoreTask st_packet_buffer_info(names.at(15), "115", BUFFER_INFO,
//      PRIVATE, "");
//  // Check BUFFER_MESSAGE packet
//  StoreTask st_packet_buffer_message(names.at(16), "116", BUFFER_MESSAGE,
//      PRIVATE, "");
}

class MockClientRpcs : public ClientRpcs {
 public:
  explicit MockClientRpcs(boost::shared_ptr<rpcprotocol::ChannelManager>
      channel_manager) : ClientRpcs(channel_manager) {}
  MOCK_METHOD6(StoreIOU, void(const kad::Contact &peer,
                              bool local,
                              StoreIOURequest *store_iou_request,
                              StoreIOUResponse *store_iou_response,
                              rpcprotocol::Controller *controller,
                              google::protobuf::Closure *done));
};

class MockMsmStoreIOUs : public MaidsafeStoreManager {
 public:
  explicit MockMsmStoreIOUs(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  ~MockMsmStoreIOUs() {
    // Allow time for all RPCs to return as we can't cancel them
    boost::this_thread::sleep(boost::posix_time::seconds(6));
  }
  MOCK_METHOD2(FindKNodes, int(const std::string &kad_key,
                               std::vector<kad::Contact> *contacts));
};

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_StoreIOUs) {
  MockMsmStoreIOUs msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  std::string recipient_id = crypto_.Hash("RecipientID", "",
      crypto::STRING_STRING, false);
  // Set up k nodes as fake response to FindKNodes
  std::vector<kad::Contact> ref_holders;
  for (int i = 0; i < kad::K; ++i) {
    std::string node_id(crypto_.Hash("Ref Holder " + base::itos(i), "",
        crypto::STRING_STRING, false));
    std::string host_ip("192.168.1." + base::itos(i));
    boost::uint16_t host_port(5555 + i);
    ref_holders.push_back(kad::Contact(node_id, host_ip, host_port));
  }

  // Set up StoreIOUs parameters common to all chunk types
  boost::uint64_t chunk_size(4);
  StorePrepResponse store_prep_response;
  store_prep_response.set_result(kAck);
  store_prep_response.set_pmid_id(recipient_id);
  maidsafe::IOUAuthority iou_authority;
  iou_authority.set_data_size(4);
  iou_authority.set_pmid(recipient_id);
  std::string iou_authority_str;
  iou_authority.SerializeToString(&iou_authority_str);
  store_prep_response.set_iou_authority(iou_authority_str);
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  std::string signed_iou_authority_str = crypto_.AsymSign(
      iou_authority_str, "", rsakp.private_key(), crypto::STRING_STRING);
  store_prep_response.set_signed_iou_authority(signed_iou_authority_str);

  // Set StoreIOUResponses
  std::vector<StoreIOUResponse> store_iou_responses;
  for (int j = 0; j < kad::K; ++j) {
    StoreIOUResponse store_iou_response;
    store_iou_response.set_result(kAck);
    store_iou_response.set_pmid_id(ref_holders.at(j).node_id());
    store_iou_responses.push_back(store_iou_response);
  }
  std::vector<StoreIOUResponse> failed_store_iou_responses;
  StoreIOUResponse sir;
  boost::uint16_t m(0);
  while (true) {
    sir.Clear();
    sir.set_result(kAck);
    failed_store_iou_responses.push_back(sir);
    ++m;
    if (m == kad::K)
      break;
    sir.set_pmid_id(crypto_.Hash("Rubbish", "", crypto::STRING_STRING, false));
    failed_store_iou_responses.push_back(sir);
    ++m;
    if (m == kad::K)
      break;
    sir.Clear();
    sir.set_result(kNack);
    sir.set_pmid_id(ref_holders.at(m).node_id());
    failed_store_iou_responses.push_back(sir);
    ++m;
    if (m == kad::K)
      break;
    sir.Clear();
    sir.set_result(kBusy);
    sir.set_pmid_id(ref_holders.at(m).node_id());
    failed_store_iou_responses.push_back(sir);
    ++m;
    if (m == kad::K)
      break;
  }

  // ********** PRIVATE_SHARE **********
  // Set up StoreIOUs parameters for PRIVATE_SHARE chunk
  std::string msid_name = crypto_.Hash("c", "", crypto::STRING_STRING, true);
  rsakp.GenerateKeys(kRsaKeySize);
  std::vector<std::string> attributes;
  attributes.push_back("PrivateShare");
  attributes.push_back(msid_name);
  attributes.push_back(rsakp.public_key());
  attributes.push_back(rsakp.private_key());
  std::list<ShareParticipants> participants;
  ShareParticipants sp;
  sp.id = "spid";
  sp.public_key = "pub_key";
  sp.role = 'A';
  participants.push_back(sp);
  ASSERT_EQ(0, SessionSingleton::getInstance()->AddPrivateShare(attributes,
      &participants));
  std::string chunkname_private_share =
      crypto_.Hash("ccc0", "", crypto::STRING_STRING, false);
  StoreTask st_chunk_private_share(chunkname_private_share, PRIVATE_SHARE,
      msid_name);
  client_chunkstore_->AddChunkToOutgoing(chunkname_private_share,
      std::string("ccc0"));

  // Create serialised IOU and signed requests to compare with generated ones
  // for PRIVATE_SHARE chunk
  IOU iou;
  iou.set_serialised_iou_authority(iou_authority_str);
  iou.set_signed_iou_authority(signed_iou_authority_str);
  iou.set_signature(crypto_.AsymSign(iou.signed_iou_authority(), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING));
  std::string serialised_iou;
  ASSERT_TRUE(iou.SerializeToString(&serialised_iou));
  std::string public_key_signature = crypto_.AsymSign(rsakp.public_key(), "",
      rsakp.private_key(), crypto::STRING_STRING);
  std::vector<std::string> signed_requests_private_share;
  for (int i = 0; i < kad::K; ++i) {
    signed_requests_private_share.push_back(crypto_.AsymSign(crypto_.Hash(
          public_key_signature + chunkname_private_share +
          ref_holders.at(i).node_id(), "", crypto::STRING_STRING, false),
          "", rsakp.private_key(), crypto::STRING_STRING));
  }

  // Set expectations for PRIVATE_SHARE chunk:
  // FindKnodes fails the first twice and thereafter sets the reference holders
  // to the vector created in the mock class above.
  EXPECT_CALL(msm, FindKNodes(chunkname_private_share, testing::_))
      .Times(5)
      .WillOnce(testing::Return(1))
      .WillOnce(testing::Return(-1))
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(ref_holders),
                            testing::Return(0)));
  // For first kKadStoreThreshold_ - 1 StoreIOU RPCs, set result to kAck each
  // time they are called.
  for (int x = 0; x < msm.kKadStoreThreshold_ - 1; ++x) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(x),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         rsakp.public_key()),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_private_share.at(x))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                      store_iou_responses.at(x)),
                                  testing::WithArgs<5>(testing::Invoke(
                                      test_msm::ThreadedDoneRun))));
  }
  // For "kKadStoreThreshold_"th StoreIOU RPC, set result to kNack once and
  // thereafter kAck.
  EXPECT_CALL(*mock_rpcs, StoreIOU(
      ref_holders.at(msm.kKadStoreThreshold_ - 1),
      false,
      testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                       recipient_id),
                     testing::Property(&StoreIOURequest::iou, serialised_iou),
                     testing::Property(&StoreIOURequest::own_pmid,
                                       client_pmid_),
                     testing::Property(&StoreIOURequest::public_key,
                                       rsakp.public_key()),
                     testing::Property(&StoreIOURequest::signed_request,
                                       signed_requests_private_share.at(
                                          msm.kKadStoreThreshold_ - 1))),
      testing::_,
      testing::_,
      testing::_))
          .Times(3)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                              failed_store_iou_responses.at(
                                  msm.kKadStoreThreshold_ - 1)),
                          testing::WithArgs<5>(testing::Invoke(
                              test_msm::ThreadedDoneRun))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
                                    test_msm::ThreadedDoneRun))));
  // For remaining StoreIOU RPCs, set result to kNack twice and thereafter kAck.
  for (int y = msm.kKadStoreThreshold_; y < kad::K; ++y) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(y),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         rsakp.public_key()),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_private_share.at(y))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))));
  }

  // ********** PUBLIC_SHARE **********
  // Set up StoreIOUs parameters for PUBLIC_SHARE chunk
  rsakp.GenerateKeys(kRsaKeySize);
  std::string anmpid_pri = rsakp.private_key();
  std::string anmpid_pub = rsakp.public_key();
  std::string anmpid_pub_sig = crypto_.AsymSign(anmpid_pub, "", anmpid_pri,
      crypto::STRING_STRING);
  std::string anmpid_name = crypto_.Hash("Anmpid", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(ANMPID, anmpid_name, anmpid_pri,
      anmpid_pub, anmpid_pub_sig);
  rsakp.GenerateKeys(kRsaKeySize);
  std::string mpid_pri = rsakp.private_key();
  std::string mpid_pub = rsakp.public_key();
  std::string mpid_pub_sig = crypto_.AsymSign(mpid_pub, "",
      anmpid_pri, crypto::STRING_STRING);
  std::string mpid_name = crypto_.Hash("PublicName", "", crypto::STRING_STRING,
      false);
  std::string hex_mpid_name;
  base::encode_to_hex(mpid_name, &hex_mpid_name);
  SessionSingleton::getInstance()->AddKey(MPID, hex_mpid_name, mpid_pri,
      mpid_pub, mpid_pub_sig);
  std::string chunkname_public_share =
      crypto_.Hash("ccc1", "", crypto::STRING_STRING, false);
  StoreTask st_chunk_public_share(chunkname_public_share, PUBLIC_SHARE, "");
  client_chunkstore_->AddChunkToOutgoing(chunkname_public_share,
      std::string("ccc1"));

  // Create serialised IOU and signed requests to compare with generated ones
  // for PUBLIC_SHARE chunk
  iou.Clear();
  iou.set_serialised_iou_authority(iou_authority_str);
  iou.set_signed_iou_authority(signed_iou_authority_str);
  iou.set_signature(crypto_.AsymSign(iou.signed_iou_authority(), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING));
  serialised_iou.clear();
  ASSERT_TRUE(iou.SerializeToString(&serialised_iou));
  std::vector<std::string> signed_requests_public_share;
  for (int i = 0; i < kad::K; ++i) {
    signed_requests_public_share.push_back(crypto_.AsymSign(crypto_.Hash(
          mpid_pub_sig + chunkname_public_share + ref_holders.at(i).node_id(),
          "", crypto::STRING_STRING, false), "", mpid_pri,
          crypto::STRING_STRING));
  }

  // Set expectations for PUBLIC_SHARE chunk:
  // FindKnodes sets the reference holders to the vector created in the mock
  // class above.
  EXPECT_CALL(msm, FindKNodes(chunkname_public_share, testing::_))
      .Times(3)
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(ref_holders),
                            testing::Return(0)));
  // For first kKadStoreThreshold_ - 1 StoreIOU RPCs, set result to kAck each
  // time they are called.
  for (int x = 0; x < msm.kKadStoreThreshold_ - 1; ++x) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(x),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         mpid_pub),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_public_share.at(x))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                      store_iou_responses.at(x)),
                                  testing::WithArgs<5>(testing::Invoke(
                                      test_msm::ThreadedDoneRun))));
  }
  // For "kKadStoreThreshold_"th StoreIOU RPC, set result to kNack once and
  // thereafter kAck.
  EXPECT_CALL(*mock_rpcs, StoreIOU(
      ref_holders.at(msm.kKadStoreThreshold_ - 1),
      false,
      testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                       recipient_id),
                     testing::Property(&StoreIOURequest::iou, serialised_iou),
                     testing::Property(&StoreIOURequest::own_pmid,
                                       client_pmid_),
                     testing::Property(&StoreIOURequest::public_key,
                                       mpid_pub),
                     testing::Property(&StoreIOURequest::signed_request,
                                       signed_requests_public_share.at(
                                          msm.kKadStoreThreshold_ - 1))),
      testing::_,
      testing::_,
      testing::_))
          .Times(3)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                              failed_store_iou_responses.at(
                                  msm.kKadStoreThreshold_ - 1)),
                          testing::WithArgs<5>(testing::Invoke(
                              test_msm::ThreadedDoneRun))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
                                    test_msm::ThreadedDoneRun))));
  // For remaining StoreIOU RPCs, set result to kNack twice and thereafter kAck.
  for (int y = msm.kKadStoreThreshold_; y < kad::K; ++y) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(y),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         mpid_pub),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_public_share.at(y))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))));
  }

  // ********** ANONYMOUS **********
  // Set up StoreIOUs parameters for ANONYMOUS chunk
  std::string chunkname_anonymous =
      crypto_.Hash("ccc2", "", crypto::STRING_STRING, false);
  StoreTask st_chunk_anonymous(chunkname_anonymous, ANONYMOUS, "");
  client_chunkstore_->AddChunkToOutgoing(chunkname_anonymous,
      std::string("ccc2"));

  // Create serialised IOU and signed requests to compare with generated ones
  // for ANONYMOUS chunk
  iou.Clear();
  iou.set_serialised_iou_authority(iou_authority_str);
  iou.set_signed_iou_authority(signed_iou_authority_str);
  iou.set_signature(crypto_.AsymSign(iou.signed_iou_authority(), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING));
  serialised_iou.clear();
  ASSERT_TRUE(iou.SerializeToString(&serialised_iou));

  // Set expectations for ANONYMOUS chunk:
  // FindKnodes sets the reference holders to the vector created in the mock
  // class above.
  EXPECT_CALL(msm, FindKNodes(chunkname_anonymous, testing::_))
      .Times(3)
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(ref_holders),
                            testing::Return(0)));

  // For first kKadStoreThreshold_ - 1 StoreIOU RPCs, set result to kAck each
  // time they are called.
  for (int x = 0; x < msm.kKadStoreThreshold_ - 1; ++x) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(x),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key, " "),
                       testing::Property(&StoreIOURequest::signed_request,
                                         kAnonymousSignedRequest)),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                      store_iou_responses.at(x)),
                                  testing::WithArgs<5>(testing::Invoke(
                                      test_msm::ThreadedDoneRun))));
  }
  // For "kKadStoreThreshold_"th StoreIOU RPC, set result to kNack once and
  // thereafter kAck.
  EXPECT_CALL(*mock_rpcs, StoreIOU(
      ref_holders.at(msm.kKadStoreThreshold_ - 1),
      false,
      testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                       recipient_id),
                     testing::Property(&StoreIOURequest::iou, serialised_iou),
                     testing::Property(&StoreIOURequest::own_pmid,
                                       client_pmid_),
                     testing::Property(&StoreIOURequest::public_key, " "),
                     testing::Property(&StoreIOURequest::signed_request,
                                       kAnonymousSignedRequest)),
      testing::_,
      testing::_,
      testing::_))
          .Times(3)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                              failed_store_iou_responses.at(
                                  msm.kKadStoreThreshold_ - 1)),
                          testing::WithArgs<5>(testing::Invoke(
                              test_msm::ThreadedDoneRun))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
                                    test_msm::ThreadedDoneRun))));
  // For remaining StoreIOU RPCs, set result to kNack twice and thereafter kAck.
  for (int y = msm.kKadStoreThreshold_; y < kad::K; ++y) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(y),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key, " "),
                       testing::Property(&StoreIOURequest::signed_request,
                                         kAnonymousSignedRequest)),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))));
  }

  // ********** PRIVATE **********
  // Set up StoreIOUs parameters for PRIVATE chunk
  std::string chunkname_private =
      crypto_.Hash("ccc3", "", crypto::STRING_STRING, false);
  StoreTask st_chunk_private(chunkname_private, PRIVATE, "");
  client_chunkstore_->AddChunkToOutgoing(chunkname_private,
      std::string("ccc3"));

  // Create serialised IOU and signed requests to compare with generated ones
  // for PRIVATE chunk
  iou.Clear();
  iou.set_serialised_iou_authority(iou_authority_str);
  iou.set_signed_iou_authority(signed_iou_authority_str);
  iou.set_signature(crypto_.AsymSign(iou.signed_iou_authority(), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING));
  serialised_iou.clear();
  ASSERT_TRUE(iou.SerializeToString(&serialised_iou));
  std::vector<std::string> signed_requests_private;
  for (int i = 0; i < kad::K; ++i) {
    signed_requests_private.push_back(crypto_.AsymSign(crypto_.Hash(
          client_pmid_public_signature_ + chunkname_private +
          ref_holders.at(i).node_id(), "", crypto::STRING_STRING, false),
          "", client_pmid_keys_.private_key(), crypto::STRING_STRING));
  }

  // Set expectations for PRIVATE chunk:
  // FindKnodes sets the reference holders to the vector created in the mock
  // class above.
  EXPECT_CALL(msm, FindKNodes(chunkname_private, testing::_))
      .Times(5)
      .WillOnce(testing::Return(1))
      .WillOnce(testing::Return(-1))
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(ref_holders),
                            testing::Return(0)));

  // For first kKadStoreThreshold_ - 1 StoreIOU RPCs, set result to kAck each
  // time they are called.
  for (int x = 0; x < msm.kKadStoreThreshold_ - 1; ++x) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(x),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         client_pmid_keys_.public_key()),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_private.at(x))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                      store_iou_responses.at(x)),
                                  testing::WithArgs<5>(testing::Invoke(
                                      test_msm::ThreadedDoneRun))));
  }
  // For "kKadStoreThreshold_"th StoreIOU RPC, set result to kNack once and
  // thereafter kAck.
  EXPECT_CALL(*mock_rpcs, StoreIOU(
      ref_holders.at(msm.kKadStoreThreshold_ - 1),
      false,
      testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                       recipient_id),
                     testing::Property(&StoreIOURequest::iou, serialised_iou),
                     testing::Property(&StoreIOURequest::own_pmid,
                                       client_pmid_),
                     testing::Property(&StoreIOURequest::public_key,
                                       client_pmid_keys_.public_key()),
                     testing::Property(&StoreIOURequest::signed_request,
                                       signed_requests_private.at(
                                          msm.kKadStoreThreshold_ - 1))),
      testing::_,
      testing::_,
      testing::_))
          .Times(3)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                              failed_store_iou_responses.at(
                                  msm.kKadStoreThreshold_ - 1)),
                          testing::WithArgs<5>(testing::Invoke(
                              test_msm::ThreadedDoneRun))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
                                    test_msm::ThreadedDoneRun))));
  // For remaining StoreIOU RPCs, set result to kNack twice and thereafter kAck.
  for (int y = msm.kKadStoreThreshold_; y < kad::K; ++y) {
    EXPECT_CALL(*mock_rpcs, StoreIOU(
        ref_holders.at(y),
        false,
        testing::AllOf(testing::Property(&StoreIOURequest::collector_pmid,
                                         recipient_id),
                       testing::Property(&StoreIOURequest::iou, serialised_iou),
                       testing::Property(&StoreIOURequest::own_pmid,
                                         client_pmid_),
                       testing::Property(&StoreIOURequest::public_key,
                                         client_pmid_keys_.public_key()),
                       testing::Property(&StoreIOURequest::signed_request,
                                         signed_requests_private.at(y))),
        testing::_,
        testing::_,
        testing::_))
            .Times(3)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                                test_msm::ThreadedDoneRun))));
  }

  // Run test calls - sleeps allow all RPCs to return as we can't cancel them

  // Fails due to FindKNodes return value of 1
  ASSERT_EQ(-2, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  // Fails due to FindKNodes return value of -1
  ASSERT_EQ(-2, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(-3, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(-3, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(-3, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to FindKNodes return value of 1
  ASSERT_EQ(-2, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  // Fails due to FindKNodes return value of -1
  ASSERT_EQ(-2, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(-3, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(0, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
}

class MockMsmSendChunk : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendChunk(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD4(GetStorePeer, int(const float &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
  MOCK_METHOD5(SendPrep, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StorePrepRequest *store_prep_request,
      StorePrepResponse *store_prep_response));
  MOCK_METHOD5(SendContent, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      bool is_in_chunkstore,
      StoreRequest *store_request));
  MOCK_METHOD3(StoreIOUs, int(const StoreTask &store_task,
                              const boost::uint64_t &chunk_size,
                              const StorePrepResponse &store_prep_response));
  MOCK_METHOD4(SendIOUDone, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      IOUDoneRequest *iou_done_request));
  MOCK_METHOD3(SendPacket, void(const StoreTask &store_task,
                                int *return_value,
                                GenericConditionData *generic_cond_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendChunk) {
  MockMsmSendChunk msm(client_chunkstore_);
  std::string chunkname = crypto_.Hash("ddd", "", crypto::STRING_STRING, false);
  std::string hex_chunkname;
  base::encode_to_hex(chunkname, &hex_chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("ddd"));
  StoreTask store_task(chunkname, PRIVATE, "");
  boost::shared_ptr<boost::condition_variable> cond_variable;
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
//  ON_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
//      .WillByDefault(DoAll(testing::SetArgumentPointee<3>(true),
//                           testing::Return(0)));
  EXPECT_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
      .Times(10)
      .WillOnce(testing::Return(1))
      .WillOnce(testing::Return(-1))
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<2>(peer),
                            testing::Return(0)));
  EXPECT_CALL(msm, SendPrep(testing::_, testing::_, cond_variable, testing::_,
      testing::_))
      .Times(8).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  EXPECT_CALL(msm, SendContent(testing::_, testing::_, cond_variable,
      testing::_, testing::_))
      .Times(7).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  EXPECT_CALL(msm, StoreIOUs(testing::_, testing::_, testing::_))
      .Times(6).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  EXPECT_CALL(msm, SendIOUDone(testing::_, testing::_, cond_variable,
      testing::_))
      .Times(5).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  ASSERT_EQ(0, msm.SendChunk(store_task, cond_variable, 4));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StorePacket) {
  MockMsmSendChunk msm(client_chunkstore_);
  std::string packetname_hashable = crypto_.Hash("Hashable", "",
                                                 crypto::STRING_STRING, false);
  std::string packetname_non_hashable = crypto_.Hash("Non-Hashable", "",
                                                 crypto::STRING_STRING, false);
  std::string hex_packetname_hashable, hex_packetname_non_hashable;
  base::encode_to_hex(packetname_hashable, &hex_packetname_hashable);
  base::encode_to_hex(packetname_non_hashable, &hex_packetname_non_hashable);
  StoreTask store_task_hashable(packetname_hashable, PRIVATE, "");
  StoreTask store_task_non_hashable(packetname_non_hashable, PRIVATE, "");
  boost::shared_ptr<boost::condition_variable> cond_variable;
  std::string peername = crypto_.Hash("Peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.2", 9998);
  EXPECT_CALL(msm, SendPacket(testing::_, testing::_, testing::_))
      .WillOnce(testing::WithArgs<1, 2>(testing::Invoke(
                          test_msm::ThreadedConditionNotifyNegOne)))
      .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
                          test_msm::ThreadedConditionNotifyZero)));
  ASSERT_EQ(-1, msm.StorePacket(hex_packetname_hashable, "Hashable", PD_DIR,
            PRIVATE, ""));
  ASSERT_EQ(0, msm.StorePacket(hex_packetname_hashable, "Hashable", MID,
            PRIVATE, ""));
  ASSERT_EQ(0, msm.StorePacket(hex_packetname_non_hashable, "eee", BUFFER_INFO,
            PRIVATE, ""));
}

}  // namespace maidsafe
