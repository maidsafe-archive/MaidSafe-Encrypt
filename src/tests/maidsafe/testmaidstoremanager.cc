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

void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int diff = max_delay - min;
  if (diff < 1)
    diff = 1;
  int sleep_time(base::random_32bit_uinteger() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
}

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
}

void ConditionNotify(int set_return,
                     int *return_value,
                     maidsafe::GenericConditionData *generic_cond_data) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::random_32bit_uinteger() % 1000 + 5000));
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

void FailedContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    maidsafe::GenericConditionData *cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder> failed_chunkholder(
      new maidsafe::ChunkHolder(kad::Contact(holder.node_id(), "", 0)));
  failed_chunkholder->status = maidsafe::kFailedHolder;
  {  // NOLINT (Fraser)
    boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
    packet_holders->push_back(failed_chunkholder);
  }
  cond_data->cond_variable->notify_all();
}

void ContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    maidsafe::GenericConditionData *cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder>
      chunkholder(new maidsafe::ChunkHolder(holder));
  chunkholder->status = maidsafe::kContactable;
  {
    boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
    packet_holders->push_back(chunkholder);
  }
  cond_data->cond_variable->notify_all();
}

void ThreadedGetHolderContactCallbacks(
    const std::vector<kad::Contact> &holders,
    const int &failures,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    maidsafe::GenericConditionData *cond_data) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int max(max_delay);
  if (max - min < 1)
    max = min + 1;
  for (size_t i = 0, failed = 0; i < holders.size(); ++i) {
    // Add 500ms to each delay, to allow holders to callback in order
    min += 500;
    max += 500;
    if (static_cast<int>(failed) < failures) {
      boost::thread thr(FailedContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
      ++failed;
    } else {
      boost::thread thr(ContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
    }
  }
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
    client_pmid_ = base::DecodeFromHex(hex_client_pmid_);
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
      const StoreData &store_data,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      int copies));
  MOCK_METHOD2(UpdateChunkCopies, int(
      const StoreData &store_data,
      const std::vector<std::string> &chunk_holders_ids));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("a", "", crypto::STRING_STRING, false);
  std::string hex_key = base::EncodeToHex(non_hex_key);
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

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_PreSendAnalysis) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("A", "", crypto::STRING_STRING, false);
  std::string hex_key = base::EncodeToHex(non_hex_key);
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
  std::string key_id1, public_key1, public_key_signature1, private_key1;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id1, &public_key1,
      &public_key_signature1, &private_key1);
  StoreData store_data(non_hex_key, PRIVATE, "", key_id1, public_key1,
      public_key_signature1, private_key1);

  // Set expectations
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_))
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kSuccess)))  // Call 1
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kSuccess)))  // Call 2
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(kSuccess)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kSuccess)))  // Call 4
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kSuccess)))  // Call 5
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kSuccess)))  // Call 6
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kSuccess)))  // Call 7
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueError)))  // Call 8
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kFindValueError)))  // Call 9
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(kFindValueError)))  // Call 10
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueError)))  // Call 11
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueError)))  // Call 12
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kFindValueError)))  // Call 13
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueError)))  // Call 14
      .WillOnce(DoAll(testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueFailure)))  // Call 15
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kFindValueFailure)))  // Call 16
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::Return(kFindValueFailure)))  // Call 17
      .WillOnce(DoAll(testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueFailure)))  // Call 18
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueFailure)))  // Call 19
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::Return(kFindValueFailure)))  // Call 20
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
          testing::SetArgumentPointee<3>(chunk_holders_ids),
          testing::SetArgumentPointee<4>(needs_cache_copy_id),
          testing::Return(kFindValueFailure)));  // Call 21
  EXPECT_CALL(msm, FindAndLoadChunk(non_hex_key, testing::_, false, "", "",
      testing::_))
          .WillOnce(testing::Return(kLoadChunkFailure));  // Call 1
  EXPECT_CALL(msm, FindAndLoadChunk(non_hex_key, chunk_holders_ids, false, "",
      "", testing::_))
          .WillOnce(testing::Return(kSuccess))  // Call 2
          .WillOnce(testing::Return(kLoadedChunkEmpty));  // Call 4
  EXPECT_CALL(msm, SendChunk(
      testing::AllOf(testing::Field(&StoreData::non_hex_key_, non_hex_key),
                     testing::Field(&StoreData::dir_type_, PRIVATE),
                     testing::Field(&StoreData::public_key_,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreData::private_key_,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreData::public_key_signature_,
                                    client_pmid_public_signature_)),
      testing::_,
      kMinChunkCopies))
          .WillOnce(testing::Return(kSuccess))  // Call 1
          .WillOnce(testing::Return(-100))  // Call 4
          .WillOnce(testing::Return(-101))  // Call 15
          .WillOnce(testing::Return(-102))  // Call 16
          .WillOnce(testing::Return(-103))  // Call 17
          .WillOnce(testing::Return(-104))  // Call 18
          .WillOnce(testing::Return(-105))  // Call 19
          .WillOnce(testing::Return(-106))  // Call 20
          .WillOnce(testing::Return(-107));  // Call 21
  EXPECT_CALL(msm, UpdateChunkCopies(
      testing::AllOf(testing::Field(&StoreData::non_hex_key_, non_hex_key),
                     testing::Field(&StoreData::dir_type_, PRIVATE),
                     testing::Field(&StoreData::public_key_,
                                    client_pmid_keys_.public_key()),
                     testing::Field(&StoreData::private_key_,
                                    client_pmid_keys_.private_key()),
                     testing::Field(&StoreData::public_key_signature_,
                                    client_pmid_public_signature_)),
      chunk_holders_ids))
          .WillOnce(testing::Return(-99));  // Call 2

  // Run test calls
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 1
  ASSERT_EQ(kSuccess, return_value);
  msm.PreSendAnalysis(store_data, kOverwrite, &return_value);  // Call 2
  ASSERT_EQ(-99, return_value);
  msm.PreSendAnalysis(store_data, kStoreFailure, &return_value);  // Call 3
  ASSERT_EQ(kPreSendChunkAlreadyExists, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 4
  ASSERT_EQ(-100, return_value);
  msm.PreSendAnalysis(store_data, kOverwrite, &return_value);  // Call 5
  ASSERT_EQ(kPreSendOverwriteCached, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 6
  ASSERT_EQ(kSuccess, return_value);
  msm.PreSendAnalysis(store_data, static_cast<IfExists>(999), &return_value);
  ASSERT_EQ(kStoreManagerError, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 8
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 9
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 10
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 11
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 12
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 13
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 14
  ASSERT_EQ(kPreSendFindValueFailure, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 15
  ASSERT_EQ(-101, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 16
  ASSERT_EQ(-102, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 17
  ASSERT_EQ(-103, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 18
  ASSERT_EQ(-104, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 19
  ASSERT_EQ(-105, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 20
  ASSERT_EQ(-106, return_value);
  msm.PreSendAnalysis(store_data, kStoreSuccess, &return_value);  // Call 21
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
  std::string key_id2, public_key2, public_key_signature2, private_key2;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id2, &public_key2,
      &public_key_signature2, &private_key2);
  StoreData st_missing_name("", PRIVATE, "", key_id2, public_key2,
      public_key_signature2, private_key2);
  ASSERT_EQ(kChunkNotInChunkstore, msm.GetStoreRequests(st_missing_name,
      recipient_id, &store_prep_request, &store_request, &iou_done_request));
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
  ASSERT_EQ(kSuccess, SessionSingleton::getInstance()->
      AddPrivateShare(attributes, &participants));
  std::string key_id3, public_key3, public_key_signature3, private_key3;
  msm.GetChunkSignatureKeys(PRIVATE_SHARE, msid_name, &key_id3, &public_key3,
      &public_key_signature3, &private_key3);
  StoreData st_chunk_private_share(names.at(0), PRIVATE_SHARE, msid_name,
      key_id3, public_key3, public_key_signature3, private_key3);
  client_chunkstore_->AddChunkToOutgoing(names.at(0), std::string("100"));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_private_share, recipient_id,
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
  std::string key_id4, public_key4, public_key_signature4, private_key4;
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_bad(names.at(1), PUBLIC_SHARE, "", key_id4,
      public_key4, public_key_signature4, private_key4);
  client_chunkstore_->AddChunkToOutgoing(names.at(1), std::string("101"));
  ASSERT_EQ(kGetRequestSigError, msm.GetStoreRequests(st_chunk_public_share_bad,
      recipient_id, &store_prep_request, &store_request, &iou_done_request));
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
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_good(names.at(1), PUBLIC_SHARE, "", key_id4,
      public_key4, public_key_signature4, private_key4);
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_public_share_good,
      recipient_id, &store_prep_request, &store_request, &iou_done_request));
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
  std::string key_id5, public_key5, public_key_signature5, private_key5;
  msm.GetChunkSignatureKeys(ANONYMOUS, "", &key_id5, &public_key5,
      &public_key_signature5, &private_key5);
  StoreData st_chunk_anonymous(names.at(2), ANONYMOUS, "", key_id5, public_key5,
      public_key_signature5, private_key5);
  client_chunkstore_->AddChunkToOutgoing(names.at(2), std::string("102"));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_anonymous, recipient_id,
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
  std::string key_id6, public_key6, public_key_signature6, private_key6;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id6, &public_key6,
      &public_key_signature6, &private_key6);
  StoreData st_chunk_private(names.at(3), PRIVATE, "", key_id6, public_key6,
      public_key_signature6, private_key6);
  client_chunkstore_->AddChunkToOutgoing(names.at(3), std::string("103"));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(st_chunk_private, recipient_id,
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
//  StoreData st_packet_mid(names.at(4), "104", MID, PRIVATE, "");
//  // Check ANMID packet
//  StoreData st_packet_anmid(names.at(5), "105", ANMID, PRIVATE, "");
//  // Check SMID packet
//  StoreData st_packet_smid(names.at(6), "106", SMID, PRIVATE, "");
//  // Check ANSMID packet
//  StoreData st_packet_ansmid(names.at(7), "107", ANSMID, PRIVATE, "");
//  // Check TMID packet
//  StoreData st_packet_tmid(names.at(8), "108", TMID, PRIVATE, "");
//  // Check ANTMID packet
//  StoreData st_packet_antmid(names.at(9), "109", ANTMID, PRIVATE, "");
//  // Check MPID packet
//  StoreData st_packet_mpid(names.at(10), "110", MPID, PRIVATE, "");
//  // Check ANMPID packet
//  StoreData st_packet_anmpid(names.at(11), "111", ANMPID, PRIVATE, "");
//  // Check PMID packet
//  StoreData st_packet_pmid(names.at(12), "112", PMID, PRIVATE, "");
//  // Check MAID packet
//  StoreData st_packet_maid(names.at(13), "113", MAID, PRIVATE, "");
//  // Check BUFFER packet
//  StoreData st_packet_buffer(names.at(14), "114", BUFFER, PRIVATE, "");
//  // Check BUFFER_INFO packet
//  StoreData st_packet_buffer_info(names.at(15), "115", BUFFER_INFO,
//      PRIVATE, "");
//  // Check BUFFER_MESSAGE packet
//  StoreData st_packet_buffer_message(names.at(16), "116", BUFFER_MESSAGE,
//      PRIVATE, "");
}

class MockClientRpcs : public ClientRpcs {
 public:
  MockClientRpcs(transport::Transport *transport,
                 rpcprotocol::ChannelManager *channel_manager)
                     : ClientRpcs(transport, channel_manager) {}
  MOCK_METHOD6(StoreIOU, void(const kad::Contact &peer,
                              bool local,
                              StoreIOURequest *store_iou_request,
                              StoreIOUResponse *store_iou_response,
                              rpcprotocol::Controller *controller,
                              google::protobuf::Closure *done));
  MOCK_METHOD6(GetPacket, void(const kad::Contact &peer,
                               bool local,
                               GetPacketRequest *get_request,
                               GetPacketResponse *get_response,
                               rpcprotocol::Controller *controller,
                               google::protobuf::Closure *done));
  MOCK_METHOD6(StorePacket, void(const kad::Contact &peer,
                                 bool local,
                                 StorePacketRequest *store_packet_request,
                                 StorePacketResponse *store_packet_response,
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
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
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
  ASSERT_EQ(kSuccess, SessionSingleton::getInstance()->
      AddPrivateShare(attributes, &participants));
  std::string chunkname_private_share =
      crypto_.Hash("ccc0", "", crypto::STRING_STRING, false);
  std::string key_id1, public_key1, public_key_signature1, private_key1;
  msm.GetChunkSignatureKeys(PRIVATE_SHARE, msid_name, &key_id1, &public_key1,
      &public_key_signature1, &private_key1);
  StoreData st_chunk_private_share(chunkname_private_share, PRIVATE_SHARE,
      msid_name, key_id1, public_key1, public_key_signature1, private_key1);
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
                  boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
  std::string hex_mpid_name = base::EncodeToHex(mpid_name);
  SessionSingleton::getInstance()->AddKey(MPID, hex_mpid_name, mpid_pri,
      mpid_pub, mpid_pub_sig);
  std::string chunkname_public_share =
      crypto_.Hash("ccc1", "", crypto::STRING_STRING, false);
  std::string key_id2, public_key2, public_key_signature2, private_key2;
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id2, &public_key2,
      &public_key_signature2, &private_key2);
  StoreData st_chunk_public_share(chunkname_public_share, PUBLIC_SHARE, "",
      key_id2, public_key2, public_key_signature2, private_key2);
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // ********** ANONYMOUS **********
  // Set up StoreIOUs parameters for ANONYMOUS chunk
  std::string chunkname_anonymous =
      crypto_.Hash("ccc2", "", crypto::STRING_STRING, false);
  std::string key_id3, public_key3, public_key_signature3, private_key3;
  msm.GetChunkSignatureKeys(ANONYMOUS, "", &key_id3, &public_key3,
      &public_key_signature3, &private_key3);
  StoreData st_chunk_anonymous(chunkname_anonymous, ANONYMOUS, "", key_id3,
      public_key3, public_key_signature3, private_key3);
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // ********** PRIVATE **********
  // Set up StoreIOUs parameters for PRIVATE chunk
  std::string chunkname_private =
      crypto_.Hash("ccc3", "", crypto::STRING_STRING, false);
  std::string key_id4, public_key4, public_key_signature4, private_key4;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_private(chunkname_private, PRIVATE, "", key_id4,
      public_key4, public_key_signature4, private_key4);
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(
                                    store_iou_responses.at(
                                        msm.kKadStoreThreshold_ - 1)),
                                testing::WithArgs<5>(testing::Invoke(
              boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
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
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                failed_store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                store_iou_responses.at(y)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Run test calls - sleeps allow all RPCs to return as we can't cancel them

  // Fails due to FindKNodes return value of 1
  ASSERT_EQ(kStoreIOUsFindNodesFailure, msm.StoreIOUs(st_chunk_private_share,
      chunk_size, store_prep_response));
  // Fails due to FindKNodes return value of -1
  ASSERT_EQ(kStoreIOUsFindNodesFailure, msm.StoreIOUs(st_chunk_private_share,
      chunk_size, store_prep_response));
  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(kStoreIOUsFailure, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_private_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(kStoreIOUsFailure, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_public_share, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(kStoreIOUsFailure, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_anonymous, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  // Fails due to FindKNodes return value of 1
  ASSERT_EQ(kStoreIOUsFindNodesFailure, msm.StoreIOUs(st_chunk_private,
      chunk_size, store_prep_response));
  // Fails due to FindKNodes return value of -1
  ASSERT_EQ(kStoreIOUsFindNodesFailure, msm.StoreIOUs(st_chunk_private,
      chunk_size, store_prep_response));
  // Fails due to insufficient successful StoreIOUs
  ASSERT_EQ(kStoreIOUsFailure, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // Just enough successful StoreIOUs return
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_private, chunk_size,
      store_prep_response));
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  // All StoreIOUs return success
  ASSERT_EQ(kSuccess, msm.StoreIOUs(st_chunk_private, chunk_size,
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
  MOCK_METHOD4(SendContent, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StoreRequest *store_request));
  MOCK_METHOD3(StoreIOUs, int(const StoreData &store_data,
                              const boost::uint64_t &chunk_size,
                              const StorePrepResponse &store_prep_response));
  MOCK_METHOD4(SendIOUDone, int(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      IOUDoneRequest *iou_done_request));
  MOCK_METHOD3(SendPacketToKad, void(const StoreData &store_data,
                                     int *return_value,
                                     GenericConditionData *generic_cond_data));
};

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_SendChunk) {
  MockMsmSendChunk msm(client_chunkstore_);
  std::string chunkname = crypto_.Hash("ddd", "", crypto::STRING_STRING, false);
  std::string hex_chunkname = base::EncodeToHex(chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("ddd"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, PRIVATE, "", key_id, public_key,
      public_key_signature, private_key);
  boost::shared_ptr<boost::condition_variable>
      cond_variable(new boost::condition_variable);
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
      testing::_))
      .Times(7).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  EXPECT_CALL(msm, StoreIOUs(testing::_, testing::_, testing::_))
      .Times(6).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  EXPECT_CALL(msm, SendIOUDone(testing::_, testing::_, cond_variable,
      testing::_))
      .Times(5).WillOnce(testing::Return(1)).WillRepeatedly(testing::Return(0));
  ASSERT_EQ(kSuccess, msm.SendChunk(store_data, cond_variable, 4));
  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StorePacket) {
  MockMsmSendChunk msm(client_chunkstore_);
  std::string packetname_hashable = crypto_.Hash("Hashable", "",
                                                 crypto::STRING_STRING, false);
  std::string packetname_non_hashable = crypto_.Hash("Non-Hashable", "",
                                                 crypto::STRING_STRING, false);
  std::string hex_packetname_hashable = base::EncodeToHex(packetname_hashable);
  std::string hex_packetname_non_hashable =
      base::EncodeToHex(packetname_non_hashable);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_task_hashable(packetname_hashable, PRIVATE, "", key_id,
      public_key, public_key_signature, private_key);
  StoreData store_task_non_hashable(packetname_non_hashable, PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  boost::shared_ptr<boost::condition_variable>
      cond_variable(new boost::condition_variable);
  std::string peername = crypto_.Hash("Peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.2", 9998);
  EXPECT_CALL(msm, SendPacketToKad(testing::_, testing::_, testing::_))
      .WillOnce(testing::WithArgs<1, 2>(testing::Invoke(
                          test_msm::ThreadedConditionNotifyNegOne)))
      .WillRepeatedly(testing::WithArgs<1, 2>(testing::Invoke(
                          test_msm::ThreadedConditionNotifyZero)));
  ASSERT_EQ(-1, msm.StorePacket(hex_packetname_hashable,
            "Hashable", MPID, PRIVATE, ""));
  ASSERT_EQ(kSuccess, msm.StorePacket(hex_packetname_hashable, "Hashable",
            ANMID, PRIVATE, ""));
  ASSERT_EQ(kPacketUnknownType, msm.StorePacket(
            hex_packetname_non_hashable, "eee", BUFFER_INFO, PRIVATE, ""));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AnalyseResults) {
  MaidsafeStoreManager msm(client_chunkstore_);
  crypto_.set_hash_algorithm(crypto::SHA_1);
  std::string good_checksum = crypto_.Hash("DFGHJK", "", crypto::STRING_STRING,
                                           false);
  std::string bad_checksum = crypto_.Hash("POIKKJ", "", crypto::STRING_STRING,
                                           false);
  crypto_.set_hash_algorithm(crypto::SHA_512);
  std::vector<std::string> good_peernames, bad_peernames;
  std::vector<kad::Contact> good_peers, bad_peers;
  std::vector< boost::shared_ptr<ChunkHolder> > good_packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > bad_packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > three_good_packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > two_good_packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > three_knack_packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > all_different_packet_holders;
  for (int i = 0; i < 12; ++i) {
    good_peernames.push_back(crypto_.Hash("good_peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    good_peers.push_back(kad::Contact(good_peernames[i], "192.192.1.1", 999+i));
    StorePacketResponse store_packet_response;
    store_packet_response.set_result(kAck);
    store_packet_response.set_pmid_id(good_peernames[i]);
    store_packet_response.set_checksum(good_checksum);
    boost::shared_ptr<ChunkHolder> ch(new ChunkHolder(good_peers.at(i)));
    ch->store_packet_response = store_packet_response;
    ch->status = kContactable;
    std::string new_string(good_checksum);
    switch (i) {
      case(0):
      case(1):
      case(2):
      case(3):
        good_packet_holders.push_back(ch);
        break;
      case(4):
      case(5):
      case(6):
        three_good_packet_holders.push_back(ch);
        break;
      case(7):
      case(8):
        two_good_packet_holders.push_back(ch);
        break;
      case(9):
        three_knack_packet_holders.push_back(ch);
        break;
      case(10):
        ch->store_packet_response.set_checksum(new_string.replace(0, 10,
            "aaaaaaaaaa"));
        all_different_packet_holders.push_back(ch);
        break;
      default:
        all_different_packet_holders.push_back(ch);
    }
  }
  for (int i = 0; i < 8; ++i) {
    bad_peernames.push_back(crypto_.Hash("baaaaaad_peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    bad_peers.push_back(kad::Contact(bad_peernames[i], "192.192.1.1", 999+i));
    StorePacketResponse store_packet_response;
    store_packet_response.set_result(kAck);
    store_packet_response.set_pmid_id(bad_peernames[i]);
    store_packet_response.set_checksum(bad_checksum);
    boost::shared_ptr<ChunkHolder> ch(new ChunkHolder(bad_peers.at(i)));
    ch->store_packet_response = store_packet_response;
    ch->status = kContactable;
    std::string new_string(bad_checksum);
    switch (i) {
      case(0):
      case(1):
      case(2):
        ch->store_packet_response.set_result(kNack);
        three_knack_packet_holders.push_back(ch);
        break;
      case(3):
      case(4):
        two_good_packet_holders.push_back(ch);
        break;
      case(5):
        three_good_packet_holders.push_back(ch);
        break;
      case(6):
        ch->store_packet_response.set_checksum(new_string.replace(0, 10,
            "zzzzzzzzzz"));
        all_different_packet_holders.push_back(ch);
        break;
      default:
        all_different_packet_holders.push_back(ch);
    }
  }
  std::vector< boost::shared_ptr<ChunkHolder> > failed_packet_holders;
  std::string common_checksum("Junk");

  // All four good peers
  ASSERT_EQ(kSuccess, msm.AssessPacketStoreResults(&good_packet_holders,
                                                   &failed_packet_holders,
                                                   &common_checksum));
  ASSERT_EQ(good_checksum, common_checksum);
  ASSERT_EQ(size_t(0), failed_packet_holders.size());
  common_checksum = "Junk";

  // Three good peers, one bad
  ASSERT_EQ(kCommonChecksumMajority,
            msm.AssessPacketStoreResults(&three_good_packet_holders,
                                         &failed_packet_holders,
                                         &common_checksum));
  ASSERT_EQ(good_checksum, common_checksum);
  ASSERT_EQ(size_t(1), failed_packet_holders.size());
  ASSERT_EQ(size_t(3), three_good_packet_holders.size());
  ASSERT_EQ(kFailedChecksum, failed_packet_holders.at(0)->status);
  for (int i = 0; i < 3; ++i)
    ASSERT_EQ(kDone, three_good_packet_holders.at(i)->status);
  ASSERT_EQ(bad_peernames.at(5),
            failed_packet_holders.at(0)->chunk_holder_contact.node_id());
  common_checksum = "Junk";

  // Two good peers, two bad
  ASSERT_EQ(kCommonChecksumUndecided,
            msm.AssessPacketStoreResults(&two_good_packet_holders,
                                         &failed_packet_holders,
                                         &common_checksum));
  ASSERT_TRUE(common_checksum.empty());
  ASSERT_EQ(size_t(4), failed_packet_holders.size());
  ASSERT_EQ(size_t(0), two_good_packet_holders.size());
  for (int i = 0; i < 4; ++i)
    ASSERT_EQ(kFailedChecksum, failed_packet_holders.at(i)->status);
  common_checksum = "Junk";

  // Three kNack peers, one good
  ASSERT_EQ(kCommonChecksumMajority,
            msm.AssessPacketStoreResults(&three_knack_packet_holders,
                                         &failed_packet_holders,
                                         &common_checksum));
  ASSERT_EQ(good_checksum, common_checksum);
  ASSERT_EQ(size_t(3), failed_packet_holders.size());
  ASSERT_EQ(size_t(1), three_knack_packet_holders.size());
  ASSERT_EQ(kDone, three_knack_packet_holders.at(0)->status);
  for (int i = 0; i < 3; ++i)
    ASSERT_EQ(kFailedHolder, failed_packet_holders.at(i)->status);
  ASSERT_EQ(good_peernames.at(9),
            three_knack_packet_holders.at(0)->chunk_holder_contact.node_id());
  common_checksum = "Junk";

  // All different peers
  ASSERT_EQ(kCommonChecksumUndecided,
            msm.AssessPacketStoreResults(&all_different_packet_holders,
                                         &failed_packet_holders,
                                         &common_checksum));
  ASSERT_TRUE(common_checksum.empty());
  ASSERT_EQ(size_t(4), failed_packet_holders.size());
  ASSERT_EQ(size_t(0), all_different_packet_holders.size());
  for (int i = 0; i < 4; ++i)
    ASSERT_EQ(kFailedChecksum, failed_packet_holders.at(i)->status);
}

class MockMsmStoreLoadPacket : public MaidsafeStoreManager {
 public:
  explicit MockMsmStoreLoadPacket(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD3(FindCloseNodes, void(
      const std::vector<std::string> &packet_holder_ids,
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
      GenericConditionData *find_cond_data));
  MOCK_METHOD4(GetStorePeer, int(const float &,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
  MOCK_METHOD3(AssessPacketStoreResults, int(
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
      std::vector< boost::shared_ptr<ChunkHolder> > *failed_packet_holders,
      std::string *common_checksum));
};

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_StoreNewPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string maid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, maid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);
  std::string original_packet_content("original_packet_content");
  crypto_.set_hash_algorithm(crypto::SHA_1);
  std::string good_checksum = crypto_.Hash("DFGHJK", "", crypto::STRING_STRING,
                                           false);
  std::string bad_checksum = crypto_.Hash("POIKKJ", "", crypto::STRING_STRING,
                                           false);
  crypto_.set_hash_algorithm(crypto::SHA_512);
  std::string packet_content("F");
  std::string packetname = crypto_.Hash("aa", "", crypto::STRING_STRING, false);
  std::string hex_packetname = base::EncodeToHex(packetname);
  std::vector<std::string> peernames;
  std::vector<kad::Contact> peers;
  std::vector< boost::shared_ptr<ChunkHolder> > packet_holders;
  for (int i = 0; i < 4; ++i) {
    peernames.push_back(crypto_.Hash("peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    peers.push_back(kad::Contact(peernames[i], "192.192.1.1", 999+i));
    StorePacketResponse store_packet_response;
    store_packet_response.set_result(kAck);
    store_packet_response.set_pmid_id(peernames[i]);
    store_packet_response.set_checksum(good_checksum);
    boost::shared_ptr<ChunkHolder> ch(new ChunkHolder(peers.at(i)));
    ch->store_packet_response = store_packet_response;
    ch->status = kContactable;
    packet_holders.push_back(ch);
  }
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");

  EXPECT_CALL(msm, FindValue(packetname, false, testing::_, testing::_,
      testing::_))
          .Times(4)
          .WillOnce(testing::Return(-1))  // Call 1
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(0)))  // Call 2
          .WillOnce(testing::Return(kFindValueFailure))  // Call 3
          .WillOnce(testing::Return(kFindValueFailure));  // Call 4

  EXPECT_CALL(msm, FindCloseNodes(testing::_, testing::_, testing::_))
      .Times(2);

  EXPECT_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
      .Times(8)
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[0]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[1]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[2]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[3]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[0]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[1]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[2]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[3]->
          chunk_holder_contact), testing::Return(0)));

  EXPECT_CALL(msm, AssessPacketStoreResults(testing::_, testing::_, testing::_))
      .Times(4)
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 4
      .WillOnce(testing::Return(kCommonChecksumUndecided));  // Call 4

  for (int i = 0; i < 4; ++i) {
    EXPECT_CALL(*mock_rpcs, StorePacket(packet_holders[i]->chunk_holder_contact,
        testing::_, testing::_, testing::_, testing::_, testing::_))
            .Times(2)  // Call 3 then 4
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                      packet_holders[i]->store_packet_response),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                      packet_holders[i]->store_packet_response),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1
  ASSERT_EQ(kSendPacketFindValueFailure, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 2
  ASSERT_EQ(kSendPacketCached, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 3
  ASSERT_EQ(kSuccess, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 4
  ASSERT_EQ(kCommonChecksumUndecided, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));
}

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_StoreExistingPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string maid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, maid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);
  std::string original_packet_content("original_packet_content");
  crypto_.set_hash_algorithm(crypto::SHA_1);
  std::string good_checksum = crypto_.Hash("DFGHJK", "", crypto::STRING_STRING,
                                           false);
  std::string bad_checksum = crypto_.Hash("POIKKJ", "", crypto::STRING_STRING,
                                           false);
  crypto_.set_hash_algorithm(crypto::SHA_512);
  std::string packet_content("F");
  std::string packetname = crypto_.Hash("aa", "", crypto::STRING_STRING, false);
  std::string hex_packetname = base::EncodeToHex(packetname);
  std::vector<std::string> peernames;
  std::vector<kad::Contact> peers;
  std::vector< boost::shared_ptr<ChunkHolder> > packet_holders;
  for (int i = 0; i < 4; ++i) {
    peernames.push_back(crypto_.Hash("peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    peers.push_back(kad::Contact(peernames[i], "192.192.1.1", 999+i));
    StorePacketResponse store_packet_response;
    store_packet_response.set_result(kAck);
    store_packet_response.set_pmid_id(peernames[i]);
    store_packet_response.set_checksum(good_checksum);
    boost::shared_ptr<ChunkHolder> ch(new ChunkHolder(peers.at(i)));
    ch->store_packet_response = store_packet_response;
    ch->status = kContactable;
    packet_holders.push_back(ch);
  }
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");

  EXPECT_CALL(msm, FindValue(packetname, false, testing::_, testing::_,
      testing::_))
          .Times(4)
          .WillOnce(testing::Return(-1))  // Call 1
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(0)))  // Call 2
          .WillOnce(testing::Return(kFindValueFailure))  // Call 3
          .WillOnce(testing::Return(kFindValueFailure));  // Call 4

  EXPECT_CALL(msm, FindCloseNodes(testing::_, testing::_, testing::_))
      .Times(2);

  EXPECT_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
      .Times(8)
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[0]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[1]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[2]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[3]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[0]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[1]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[2]->
          chunk_holder_contact), testing::Return(0)))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(packet_holders[3]->
          chunk_holder_contact), testing::Return(0)));

  EXPECT_CALL(msm, AssessPacketStoreResults(testing::_, testing::_, testing::_))
      .Times(4)
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(good_checksum),
                      testing::Return(0)))  // Call 4
      .WillOnce(testing::Return(kCommonChecksumUndecided));  // Call 4

  for (int i = 0; i < 4; ++i) {
    EXPECT_CALL(*mock_rpcs, StorePacket(packet_holders[i]->chunk_holder_contact,
        testing::_, testing::_, testing::_, testing::_, testing::_))
            .Times(2)  // Call 3 then 4
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                      packet_holders[i]->store_packet_response),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))))
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                      packet_holders[i]->store_packet_response),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1
  ASSERT_EQ(kSendPacketFindValueFailure, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 2
  ASSERT_EQ(kSendPacketCached, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 3
  ASSERT_EQ(kSuccess, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));

  // Call 4
  ASSERT_EQ(kCommonChecksumUndecided, msm.StorePacket(hex_packetname,
      original_packet_content, maidsafe::MID, maidsafe::PRIVATE, ""));
}

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketAllSucceed) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  std::string original_packet_content("original_packet_content");
  GenericPacket gp;
  gp.set_data(original_packet_content);
  gp.set_signature("Sig");
  std::string packet_content("F");
  std::string packetname = crypto_.Hash("aa", "", crypto::STRING_STRING, false);
  std::string hex_packetname = base::EncodeToHex(packetname);
  std::vector<std::string> find_value_results;
  find_value_results.push_back(original_packet_content);
  std::vector<std::string> peernames;
  std::vector<kad::Contact> peers;
  std::vector<GetPacketResponse> get_packet_responses_all_good;
  for (int i = 0; i < 2; ++i) {
    peernames.push_back(crypto_.Hash("peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    peers.push_back(kad::Contact(peernames[i], "192.192.1.1", 999+i));
    GetPacketResponse get_packet_response;
    get_packet_response.set_result(kAck);
    GenericPacket *gp_add = get_packet_response.add_content();
    *gp_add = gp;
    get_packet_response.set_pmid_id(peernames[i]);
    get_packet_responses_all_good.push_back(get_packet_response);
  }


  EXPECT_CALL(msm, FindValue(packetname, false, testing::_, testing::_,
      testing::_))
          .Times(7)
          .WillOnce(testing::Return(-1))  // Call 1
          .WillOnce(testing::Return(-1))  // Call 1
          .WillOnce(testing::Return(-1))  // Call 1
          .WillOnce(testing::Return(kSuccess))  // Call 2
          .WillOnce(testing::Return(kSuccess))  // Call 2
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(find_value_results),
                          testing::Return(0)))  // Call 2
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(peernames),
                                testing::Return(0)));  // Call 3
  EXPECT_CALL(msm, FindCloseNodes(testing::_, testing::_, testing::_))
      .Times(1)
      .WillOnce(testing::WithArgs<1, 2>(testing::Invoke(
                boost::bind(&test_msm::ThreadedGetHolderContactCallbacks,
                peers, 0, 1950, 2000, _1, _2))));  // Call 3
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*mock_rpcs, GetPacket(peers[i], testing::_, testing::_,
        testing::_, testing::_, testing::_))
            .Times(1)  // Call 3
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                                      get_packet_responses_all_good.at(i)),
                                  testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1
  ASSERT_EQ(kFindValueFailure, msm.LoadPacket(hex_packetname, &packet_content));

  // Call 2
  ASSERT_EQ(kSuccess, msm.LoadPacket(hex_packetname, &packet_content));
  ASSERT_EQ(original_packet_content, packet_content);

  // Call 3
  ASSERT_EQ(kSuccess, msm.LoadPacket(hex_packetname, &packet_content));
  ASSERT_EQ(original_packet_content, packet_content);
}

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketAllFail) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  std::string original_packet_content("original_packet_content");
  GenericPacket gp;
  gp.set_data(original_packet_content);
  gp.set_signature("Sig");
  std::string packet_content("F");
  std::string packetname = crypto_.Hash("aa", "", crypto::STRING_STRING, false);
  std::string hex_packetname = base::EncodeToHex(packetname);
  std::vector<std::string> find_value_results;
  find_value_results.push_back(original_packet_content);
  std::vector<std::string> peernames;
  std::vector<kad::Contact> peers;
  std::vector<GetPacketResponse> get_packet_responses_all_bad;
  for (int i = 0; i < 4; ++i) {
    peernames.push_back(crypto_.Hash("peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    peers.push_back(kad::Contact(peernames[i], "192.192.1.1", 999+i));
    GetPacketResponse get_packet_response;
    get_packet_response.set_result(kNack);
    GenericPacket *gp_add = get_packet_response.add_content();
    *gp_add = gp;
    get_packet_response.set_pmid_id(peernames[i]);
    get_packet_responses_all_bad.push_back(get_packet_response);
  }


  EXPECT_CALL(msm, FindValue(packetname, false, testing::_, testing::_,
      testing::_))
          .Times(1)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(peernames),
                          testing::Return(0)));
  EXPECT_CALL(msm, FindCloseNodes(testing::_, testing::_, testing::_))
      .Times(1)
      .WillOnce(testing::WithArgs<1, 2>(testing::Invoke(
                boost::bind(&test_msm::ThreadedGetHolderContactCallbacks,
                peers, 0, 1950, 2000, _1, _2))));
  for (int i = 0; i < 4; ++i) {
    EXPECT_CALL(*mock_rpcs, GetPacket(peers[i], testing::_, testing::_,
        testing::_, testing::_, testing::_))
            .Times(1)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                            get_packet_responses_all_bad.at(i)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }
  ASSERT_EQ(kLoadPacketFailure,
            msm.LoadPacket(hex_packetname, &packet_content));
}

TEST_F(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketOneSucceed) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs>
      mock_rpcs(new MockClientRpcs(&msm.transport_, &msm.channel_manager_));
  msm.SetMockRpcs(mock_rpcs);
  std::string original_packet_content("original_packet_content");
  GenericPacket gp;
  gp.set_data(original_packet_content);
  gp.set_signature("Sig");
  std::string packet_content("F");
  std::string packetname = crypto_.Hash("aa", "", crypto::STRING_STRING, false);
  std::string hex_packetname = base::EncodeToHex(packetname);
  std::vector<std::string> find_value_results;
  find_value_results.push_back(original_packet_content);
  std::vector<std::string> peernames;
  std::vector<kad::Contact> peers;
  std::vector<GetPacketResponse> get_packet_responses_one_good;
  for (int i = 0; i < 4; ++i) {
    peernames.push_back(crypto_.Hash("peer" + base::itos(i), "",
        crypto::STRING_STRING, false));
    peers.push_back(kad::Contact(peernames[i], "192.192.1.1", 999+i));
    GetPacketResponse get_packet_response;
    get_packet_response.set_result(kNack);
    GenericPacket *gp_add = get_packet_response.add_content();
    *gp_add = gp;
    get_packet_response.set_pmid_id(peernames[i]);
    if (i == 3)
      get_packet_response.set_result(kAck);
    get_packet_responses_one_good.push_back(get_packet_response);
  }


  EXPECT_CALL(msm, FindValue(packetname, false, testing::_, testing::_,
      testing::_))
          .Times(1)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(peernames),
                          testing::Return(0)));
  EXPECT_CALL(msm, FindCloseNodes(testing::_, testing::_, testing::_))
      .Times(1)
      .WillOnce(testing::WithArgs<1, 2>(testing::Invoke(
                boost::bind(&test_msm::ThreadedGetHolderContactCallbacks,
                peers, 0, 1950, 2000, _1, _2))));
  for (int i = 0; i < 4; ++i) {
    EXPECT_CALL(*mock_rpcs, GetPacket(peers[i], testing::_, testing::_,
        testing::_, testing::_, testing::_))
            .Times(1)
            .WillOnce(DoAll(testing::SetArgumentPointee<3>(
                            get_packet_responses_one_good.at(i)),
                            testing::WithArgs<5>(testing::Invoke(
                boost::bind(&test_msm::ThreadedDoneRun, 100, 5000, _1)))));
  }
  ASSERT_EQ(kSuccess, msm.LoadPacket(hex_packetname, &packet_content));
  ASSERT_EQ(original_packet_content, packet_content);
}

}  // namespace maidsafe
