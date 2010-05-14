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
#include <maidsafe/protobuf/contact_info.pb.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <queue>
#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/clientrpc.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultservice.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/mockkadops.h"

namespace test_msm {

typedef boost::function<void()> VoidFunc;

/**
 * This is a thread pool, which takes boost functors and executes them in order.
 */
class ThreadedCallContainer {
 public:
  explicit ThreadedCallContainer(const size_t &num_threads)
    : running_(false), mutex_(), condition_(), threads_(), callbacks_() {
    for (size_t i = 0; i < num_threads; ++i) {
      threads_.push_back(new boost::thread(boost::bind(
          &ThreadedCallContainer::Run, this)));
    }
  }
  ~ThreadedCallContainer() {
    {
      boost::mutex::scoped_lock lock(mutex_);
      running_ = false;
      condition_.notify_all();
    }
    for (size_t i = 0; i < threads_.size(); ++i) {
      threads_[i]->join();
      delete threads_[i];
    }
  }
  void Enqueue(VoidFunc callback) {
    boost::mutex::scoped_lock lock(mutex_);
    if (!running_)
      return;
    callbacks_.push(callback);
    condition_.notify_all();
  }
  void Wait() {
    boost::mutex::scoped_lock lock(mutex_);
    while (running_ && !callbacks_.empty())
      condition_.wait(lock);
  }
 private:
  ThreadedCallContainer(const ThreadedCallContainer&);
  ThreadedCallContainer &operator=(const ThreadedCallContainer&);
  void Run() {
    boost::mutex::scoped_lock lock(mutex_);
    running_ = true;
    while (running_) {
      while (running_ && callbacks_.empty()) {
        condition_.wait(lock);
      }
      while (!callbacks_.empty()) {
        // grab the first cb from the queue, but allow other threads to operate
        // while executing it
        VoidFunc f = callbacks_.front();
        mutex_.unlock();
        f();
        mutex_.lock();
        callbacks_.pop();
        condition_.notify_all();
      }
    }
  }
  bool running_;
  boost::mutex mutex_;
  boost::condition_variable condition_;
  std::vector<boost::thread*> threads_;
  std::queue<VoidFunc> callbacks_;
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
  int sleep_time(base::RandomUint32() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
}

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
}

void ConditionNotifyNoFlag(int set_return,
                           int *return_value,
                           maidsafe::GenericConditionData *generic_cond_data) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::RandomUint32() % 1000 + 5000));
  boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
  *return_value = set_return;
  generic_cond_data->cond_variable->notify_all();
}

void WatchListOpStageThree(bool initialise_response,
                           const int &result,
                           const std::string &pmid,
                           maidsafe::ExpectAmendmentResponse *response,
                           google::protobuf::Closure *callback,
                           test_msm::ThreadedCallContainer *tcc) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
  }
  tcc->Enqueue(boost::bind(&google::protobuf::Closure::Run, callback));
}

void AddToWatchListStageFour(bool initialise_response,
                             const int &result,
                             const std::string &pmid,
                             const boost::uint32_t &upload_count,
                             maidsafe::AddToWatchListResponse *response,
                             google::protobuf::Closure* callback,
                             test_msm::ThreadedCallContainer *tcc) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
    response->set_upload_count(upload_count);
  }
  tcc->Enqueue(boost::bind(&google::protobuf::Closure::Run, callback));
}

void RemoveFromWatchListStageFour(
    bool initialise_response,
    const int &result,
    const std::string &pmid,
    maidsafe::RemoveFromWatchListResponse *response,
    google::protobuf::Closure* callback,
    test_msm::ThreadedCallContainer *tcc) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
  }
  tcc->Enqueue(boost::bind(&google::protobuf::Closure::Run, callback));
}

struct AccountStatusValues {
  AccountStatusValues(const boost::uint64_t space_offered_,
                      const boost::uint64_t space_given_,
                      const boost::uint64_t space_taken_)
  : space_offered(space_offered_),
    space_given(space_given_),
    space_taken(space_taken_) {}
  boost::uint64_t space_offered, space_given, space_taken;
};

void AccountStatusCallback(bool initialise_response,
                           const int &result,
                           const std::string &pmid,
                           bool initialise_values,
                           const AccountStatusValues &values,
                           maidsafe::AccountStatusResponse *response,
                           google::protobuf::Closure* callback) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
    if (initialise_values) {
      response->set_space_offered(values.space_offered);
      response->set_space_given(values.space_given);
      response->set_space_taken(values.space_taken);
    }
  }
  callback->Run();
}

void ThreadedAccountStatusCallback(ThreadedCallContainer *tcc,
                                   bool initialise_response,
                                   const int &result,
                                   const std::string &pmid,
                                   bool initialise_values,
                                   const AccountStatusValues &values,
                                   maidsafe::AccountStatusResponse *response,
                                   google::protobuf::Closure *callback) {
  tcc->Enqueue(boost::bind(&AccountStatusCallback, initialise_response, result,
                           pmid, initialise_values, values, response,
                           callback));
}

void AmendAccountCallback(bool initialise_response,
                          const int &result,
                          const std::string &pmid,
                          maidsafe::AmendAccountResponse *response,
                          google::protobuf::Closure* callback) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
  }
  callback->Run();
}

void ThreadedAmendAccountCallback(ThreadedCallContainer *tcc,
                                  bool initialise_response,
                                  const int &result,
                                  const std::string &pmid,
                                  maidsafe::AmendAccountResponse *response,
                                  google::protobuf::Closure *callback) {
  tcc->Enqueue(boost::bind(&AmendAccountCallback, initialise_response, result,
                           pmid, response, callback));
}

int SendChunkCount(int *send_chunk_count,
                   boost::mutex *mutex,
                   boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  ++(*send_chunk_count);
  cond_var->notify_one();
  return 0;
}

void DeleteChunkResult(const maidsafe::ReturnCode &in_result,
                       maidsafe::ReturnCode *out_result,
                       boost::mutex *mutex,
                       boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  *out_result = in_result;
  cond_var->notify_one();
}

void DelayedSetConnectionStatus(const int &status,
                                const int &delay,
                                maidsafe::SessionSingleton *ss) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
  ss->SetConnectionStatus(status);
}

void DelayedCancelTask(const std::string &chunkname,
                       const int &delay,
                       maidsafe::StoreTasksHandler *task_handler) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
  task_handler->CancelTask(chunkname, maidsafe::kStoreChunk);
}

void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

void RunDeletePacketCallbacks(
    std::list< boost::function < void(boost::shared_ptr<
        maidsafe::DeletePacketData>) > > functors,
    boost::shared_ptr<maidsafe::DeletePacketData> delete_data) {
  while (functors.size()) {
    functors.front()(delete_data);
    functors.pop_front();
  }
}

void RunLoadPacketCallback(const kad::VoidFunctorOneString &cb,
                           const std::string &ser_result) {
  cb(ser_result);
}
}  // namespace test_msm

namespace maidsafe {

class MaidStoreManagerTest : public testing::Test {
 protected:
  MaidStoreManagerTest() : test_root_dir_(file_system::TempDir() /
                                 ("maidsafe_TestMSM_" + base::RandomString(6))),
                           client_chunkstore_dir_(test_root_dir_/"Chunkstore"),
                           client_chunkstore_(),
                           client_pmid_keys_(),
                           client_maid_keys_(),
                           client_pmid_public_signature_(),
                           client_pmid_(),
                           mutex_(),
                           crypto_(),
                           cond_var_(),
                           functor_(boost::bind(&test_msm::PacketOpCallback, _1,
                               &mutex_, &cond_var_, &packet_op_result_)),
                           keys_() {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest ctor - %s\n", e.what());
    }
    fs::create_directories(test_root_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    cached_keys::MakeKeys(5, &keys_);
    client_maid_keys_ = keys_.at(0);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, false);
    SessionSingleton::getInstance()->AddKey(MAID, maid_name, maid_pri, maid_pub,
        maid_pub_key_signature);
    client_pmid_keys_ = keys_.at(1);
    std::string pmid_pri = client_pmid_keys_.private_key();
    std::string pmid_pub = client_pmid_keys_.public_key();
    client_pmid_public_signature_ = crypto_.AsymSign(pmid_pub, "",
        maid_pri, crypto::STRING_STRING);
    client_pmid_ = crypto_.Hash(pmid_pub + client_pmid_public_signature_, "",
                                crypto::STRING_STRING, false);
    SessionSingleton::getInstance()->AddKey(PMID, client_pmid_, pmid_pri,
        pmid_pub, client_pmid_public_signature_);
    SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  virtual ~MaidStoreManagerTest() {
    try {
      SessionSingleton::getInstance()->ResetSession();
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest dtor - %s\n", e.what());
    }
  }

  virtual void SetUp() {
    client_chunkstore_ = boost::shared_ptr<ChunkStore>
        (new ChunkStore(client_chunkstore_dir_.string(), 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    boost::uint64_t count(0);
    while (count < 60000 && !client_chunkstore_->is_initialised()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
  }
  virtual void TearDown() {}

  fs::path test_root_dir_, client_chunkstore_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_, client_pmid_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;
  boost::condition_variable cond_var_;
  int packet_op_result_;
  VoidFuncOneInt functor_;
  std::vector<crypto::RsaKeyPair> keys_;

 private:
  MaidStoreManagerTest(const MaidStoreManagerTest&);
  MaidStoreManagerTest &operator=(const MaidStoreManagerTest&);
};

class MockMsmKeyUnique : public MaidsafeStoreManager {
 public:
  explicit MockMsmKeyUnique(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD1(SendChunkPrep, int(const StoreData &store_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;

  // Set up test requirements
  std::vector<kad::KadId> keys;
  const size_t kTestCount(7);
  for (size_t i = 0; i < kTestCount; ++i) {
    keys.push_back(kad::KadId(crypto_.Hash(base::RandomString(100), "",
        crypto::STRING_STRING, false), false));
  }
  std::string ser_result_empty, ser_result_unparsable("Bleh"), ser_result_fail;
  std::string ser_result_no_values, ser_result_cached_copy, ser_result_good;
  kad::FindResponse find_response;
  find_response.set_result(kad::kRpcResultSuccess);
  find_response.SerializeToString(&ser_result_no_values);
  find_response.set_result(kad::kRpcResultFailure);
  kad::SignedValue *sig_val = find_response.add_signed_values();
  sig_val->set_value("Value");
  sig_val->set_value_signature("Sig");
  find_response.SerializeToString(&ser_result_fail);
  find_response.set_result(kad::kRpcResultSuccess);
  find_response.SerializeToString(&ser_result_good);
  kad::ContactInfo *cache_holder =
      find_response.mutable_alternative_value_holder();
  cache_holder->set_node_id("a");
  cache_holder->set_ip("b");
  cache_holder->set_port(1);
  find_response.SerializeToString(&ser_result_cached_copy);

  // Set up expectations
  EXPECT_CALL(*mko, FindValue(keys.at(1), false, testing::_))  // Call 2
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_empty))));

  EXPECT_CALL(*mko, FindValue(keys.at(2), false, testing::_))  // Call 3
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_unparsable))));

  EXPECT_CALL(*mko, FindValue(keys.at(3), false, testing::_))  // Call 4
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_fail))));

  EXPECT_CALL(*mko, FindValue(keys.at(4), false, testing::_))  // Call 5
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_no_values))));

  EXPECT_CALL(*mko, FindValue(keys.at(5), false, testing::_))  // Call 6
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_cached_copy))));

  EXPECT_CALL(*mko, FindValue(keys.at(6), false, testing::_))  // Call 7
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_good))));

  // Call 1 - Check with NULL pointer
  size_t test_number(0);
//  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 2 - FindValue returns an empty string
  ++test_number;
  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 3 - FindValue returns an unparsable string
  ++test_number;
  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 4 - FindValue fails
  ++test_number;
  ASSERT_TRUE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 5 - FindValue claims success but doesn't populate value vector
  ++test_number;
  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 6 - FindValue yields a cached copy
  ++test_number;
  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));

  // Call 7 - Success
  ++test_number;
  ASSERT_FALSE(msm.KeyUnique(keys.at(test_number).ToStringDecoded(), false));
}

class MockClientRpcs : public ClientRpcs {
 public:
  MockClientRpcs(transport::TransportHandler *transport_handler,
                 rpcprotocol::ChannelManager *channel_manager)
                     : ClientRpcs(transport_handler, channel_manager) {}
  MOCK_METHOD7(StorePrep, void(const kad::Contact &peer,
                               bool local,
                               const boost::int16_t &transport_id,
                               StorePrepRequest *store_prep_request,
                               StorePrepResponse *store_prep_response,
                               rpcprotocol::Controller *controller,
                               google::protobuf::Closure *done));
  MOCK_METHOD7(StoreChunk, void(const kad::Contact &peer,
                                bool local,
                                const boost::int16_t &transport_id,
                                StoreChunkRequest *store_chunk_request,
                                StoreChunkResponse *store_chunk_response,
                                rpcprotocol::Controller *controller,
                                google::protobuf::Closure *done));
  MOCK_METHOD7(AddToWatchList, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AddToWatchListRequest *add_to_watch_list_request,
      AddToWatchListResponse *add_to_watch_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(RemoveFromWatchList, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      RemoveFromWatchListRequest *remove_from_watch_list_request,
      RemoveFromWatchListResponse *remove_from_watch_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(ExpectAmendment, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      ExpectAmendmentRequest *expect_amendment_request,
      ExpectAmendmentResponse *expect_amendment_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(AccountStatus, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AccountStatusRequest *account_status_request,
      AccountStatusResponse *account_status_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
};

MATCHER_P(EqualsContact, kad_contact, "") {
  return (arg.Equals(kad_contact));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;
  ASSERT_TRUE(client_chunkstore_->is_initialised());

  // Set up chunks
  const int kTestCount(12);
  std::vector<std::string> chunk_names;
  for (int i = 0; i < kTestCount; ++i) {
    boost::uint64_t chunk_size = 396 + i;
    std::string chunk_value = base::RandomString(chunk_size);
    std::string chunk_name = crypto_.Hash(chunk_value, "",
                                          crypto::STRING_STRING, false);
    ASSERT_EQ(kSuccess,
              client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_value));
    chunk_names.push_back(chunk_name);
  }

  // Set up data for calls to FindKNodes
  std::vector<std::string> good_pmids, few_pmids;
  std::string bad_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kResultFail, &good_pmids);
  std::string good_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kGood, &good_pmids);
  std::string few_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kTooFewContacts, &few_pmids);
  std::vector<kad::Contact> contacts;
  {
    kad::FindResponse find_response;
    kad::Contact contact;
    ASSERT_TRUE(find_response.ParseFromString(good_result));
    for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
      ASSERT_TRUE(contact.ParseFromString(find_response.closest_nodes(i)));
      contacts.push_back(contact);
    }
  }

  int send_chunk_count(0);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  test_msm::ThreadedCallContainer tcc(1);

  // Set expectations
  EXPECT_CALL(*mko, AddressIsLocal(testing::An<const kad::Contact&>()))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(0), false),
                                      testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, bad_result, _1))));   // Call 1

  EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(1), false),
                                      testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result, _1))));   // Call 2

  for (int i = 2; i < kTestCount; ++i) {
    EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(i), false),
                                        testing::_))
        .WillOnce(testing::WithArgs<1>(testing::Invoke(
            boost::bind(&mock_kadops::RunCallback, good_result, _1))));  // 3-12
  }

  for (size_t i = 0; i < contacts.size(); ++i) {
    EXPECT_CALL(*mock_rpcs, ExpectAmendment(
        EqualsContact(contacts.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    i + 1 < kKadLowerThreshold,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 4
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    true,
                    i + 1 < kKadLowerThreshold ? kAck : kNack,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 5
            .WillRepeatedly(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))));                           // Calls 6 to 12
  }

  for (size_t i = 0; i < contacts.size(); ++i) {
    EXPECT_CALL(*mock_rpcs, AddToWatchList(
        EqualsContact(contacts.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    i + 1 < kKadLowerThreshold,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    kMinChunkCopies,
                    _1, _2, &tcc))))                                   // Call 6
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    i + 1 < kKadLowerThreshold ? kAck : kNack,
                    contacts.at(i).node_id().ToStringDecoded(),
                    kMinChunkCopies,
                    _1, _2, &tcc))))                                   // Call 7
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    kAck,
                    contacts.at((i + 1) %
                        contacts.size()).node_id().ToStringDecoded(),
                    kMinChunkCopies,
                    _1, _2, &tcc))))                                   // Call 8
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    kMinChunkCopies +
                        (i + 1 < kKadLowerThreshold ? 0 : 1),
                    _1, _2, &tcc))))                                   // Call 9
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    0,
                    _1, _2, &tcc))))                                  // Call 10
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    kMinChunkCopies,
                    _1, _2, &tcc))))                                  // Call 11
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListStageFour,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    i == 0 ? 0 : kMinChunkCopies - 1,
                    _1, _2, &tcc))));                                 // Call 12
  }

  EXPECT_CALL(msm, SendChunkPrep(
      testing::AllOf(testing::Field(&StoreData::data_name, chunk_names.at(10)),
                     testing::Field(&StoreData::dir_type, PRIVATE))))
          .Times(4)  // Call 11
          .WillRepeatedly(testing::InvokeWithoutArgs(boost::bind(
              &test_msm::SendChunkCount, &send_chunk_count, &mutex,
              &cond_var)));

  EXPECT_CALL(msm, SendChunkPrep(
      testing::AllOf(testing::Field(&StoreData::data_name, chunk_names.at(11)),
                     testing::Field(&StoreData::dir_type, PRIVATE))))
          .Times(3)  // Call 12
          .WillRepeatedly(testing::InvokeWithoutArgs(boost::bind(
              &test_msm::SendChunkCount, &send_chunk_count, &mutex,
              &cond_var)));

  // Run test calls
  std::string long_key('a', kKeySize + 1);
  std::string short_key('z', kKeySize - 1);
  ASSERT_EQ(kIncorrectKeySize, msm.StoreChunk(long_key, PRIVATE, ""));
  ASSERT_EQ(kIncorrectKeySize, msm.StoreChunk(short_key, PRIVATE, ""));
  ASSERT_EQ(kDirUnknownType, msm.StoreChunk(chunk_names.at(0),
      static_cast<DirType>(ANONYMOUS - 1), ""));
  ASSERT_EQ(kDirUnknownType, msm.StoreChunk(chunk_names.at(0),
      static_cast<DirType>(PUBLIC_SHARE + 1), ""));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  int test_run(0);
  // Call 1 - FindKNodes returns failure
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  int time_taken(0);
  const int kTimeout(5000);
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 2 - FindKNodes returns success but not enough contacts
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 3 - FindKNodes returns CIHs, but no AHs available
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  msm.account_holders_manager_.account_holder_group_ = contacts;

  // Call 4 - ExpectAmendment responses partially uninitialised
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 5 - ExpectAmendment responses partially unacknowledged
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 6 - Twelve ATW responses return uninitialised
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 7 - Twelve ATW responses return kNack
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 8 - Twelve ATW responses return with wrong PMIDs
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 9 - Twelve ATW responses return excessive upload_count
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 10 - All ATW responses return upload_count of 0
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  tcc.Wait();
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  boost::mutex::scoped_lock lock(mutex);

  // Call 11 - All ATW responses return upload_count of 4
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  while (send_chunk_count < kMinChunkCopies)
    cond_var.wait(lock);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  StoreTask retrieved_task;
  ASSERT_TRUE(msm.tasks_handler_.Task(chunk_names.at(test_run), kStoreChunk,
      &retrieved_task));
  ASSERT_EQ(kMinChunkCopies, retrieved_task.successes_required_);

  // Call 12 - All ATW responses return upload_count of 3 except one which
  //           returns an upload_count of 0
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  send_chunk_count = 0;
  ASSERT_EQ(kSuccess, msm.StoreChunk(chunk_names.at(test_run), PRIVATE, ""));
  while (send_chunk_count < kMinChunkCopies - 1)
    cond_var.wait(lock);
  ASSERT_EQ(size_t(2), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunk_names.at(test_run), kStoreChunk,
      &retrieved_task));
  ASSERT_EQ(kMinChunkCopies - 1, retrieved_task.successes_required_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AssessUploadCounts) {
  MaidsafeStoreManager msm(client_chunkstore_);

  // Set up test data
  const boost::uint64_t chunk_size(932);
  std::string chunk_value = base::RandomString(chunk_size);
  std::string chunk_name = crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
                                        false);

  StoreData store_data(chunk_name, chunk_size, (kHashable | kNormal), PRIVATE,
      "", client_pmid_, client_pmid_keys_.public_key(),
      client_pmid_public_signature_, client_pmid_keys_.private_key());
  boost::shared_ptr<WatchListOpData>
      add_to_watchlist_data(new WatchListOpData(store_data));
  for (size_t i = 0; i < kad::K; ++i) {
    WatchListOpData::AddToWatchDataHolder
        hldr(crypto_.Hash(base::IntToString(i * i), "", crypto::STRING_STRING,
                          false));
    add_to_watchlist_data->add_to_watchlist_data_holders.push_back(hldr);
  }

  // Run tests
  int test_run(0);

  // All return upload_copies == 2
  ++test_run;  // 1
  for (int i = 0; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    if (i < kKadUpperThreshold - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  // All return upload_copies == 0
  ++test_run;  // 2
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    add_to_watchlist_data->required_upload_copies.insert(0);
    ++add_to_watchlist_data->returned_count;
    if (i < kKadUpperThreshold - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  int minority_threshold(2 * kKadUpperThreshold > kad::K ?
                         kad::K - kKadUpperThreshold :
                         kKadUpperThreshold - 1);

//  printf("K = %d, UpThresh = %d, Min = %d\n",
//         kad::K, kKadUpperThreshold, minority_threshold);

  // First 4 return 0, last 12 return 2.  Consensus should be 2.
  ++test_run;  // 3
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    if (i < minority_threshold)
      add_to_watchlist_data->required_upload_copies.insert(0);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    if (i < kad::K - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  int result_group(1), max_group_val(1);

  // Groups of min. size return different values.  Consensus should be highest.
  ++test_run;  // 4
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    add_to_watchlist_data->required_upload_copies.insert(result_group);
    ++add_to_watchlist_data->returned_count;
    if (i == minority_threshold * result_group - 1) {
      max_group_val = result_group;
      ++result_group;
    }
    if (i < kad::K - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(max_group_val, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  // First returns 0, next 1, next 2, next 3, others 4.  Consensus should be 4.
  ++test_run;  // 5
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    if (i < minority_threshold)
      add_to_watchlist_data->required_upload_copies.insert(i);
    else
      add_to_watchlist_data->required_upload_copies.insert(minority_threshold);
    ++add_to_watchlist_data->returned_count;
    if (i < kad::K - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(minority_threshold,
                add_to_watchlist_data->consensus_upload_copies);
    }
  }

  // Only 4 return, all return 2.  Consensus should be 2.
  ++test_run;  // 6
  add_to_watchlist_data->returned_count = kad::K - kKadLowerThreshold;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kKadLowerThreshold; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    if (i < kKadLowerThreshold - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  // Only 4 return, one returns 2, rest return 1.  Consensus should be 0.
  ++test_run;  // 7
  add_to_watchlist_data->returned_count = kad::K - kKadLowerThreshold;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kKadLowerThreshold; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    if (i == 0)
      add_to_watchlist_data->required_upload_copies.insert(2);
    else
      add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    if (i < kKadLowerThreshold - 1) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else if (kKadLowerThreshold == 1) {
      ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kRequestFailedConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
    }
  }

  // Only 3 return, all return 2.  Consensus should be 0.
  ++test_run;  // 8
  add_to_watchlist_data->returned_count = kad::K - kKadLowerThreshold + 1;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kKadLowerThreshold - 1; ++i) {
    SCOPED_TRACE("Test " + base::IntToString(test_run) + " -- Resp " +
                 base::IntToString(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    if (i < kKadLowerThreshold - 2) {
      ASSERT_EQ(kRequestPendingConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
    } else {
      ASSERT_EQ(kRequestFailedConsensus,
                msm.AssessUploadCounts(add_to_watchlist_data));
      ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
    }
  }
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests) {
  MaidsafeStoreManager msm(client_chunkstore_);
  std::string recipient_id = crypto_.Hash("RecipientID", "",
      crypto::STRING_STRING, false);
  // Make chunk/packet names
  std::vector<std::string> names;
  for (int i = 100; i < 104; ++i) {
    std::string j(base::IntToString(i));
    names.push_back(crypto_.Hash(j, "", crypto::STRING_STRING, false));
  }
  boost::shared_ptr<SendChunkData> send_chunk_data(
      new SendChunkData(StoreData(), kad::Contact(recipient_id, "", 0), true));
  StoreData &store_data = send_chunk_data->store_data;
  StorePrepRequest &store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest &store_chunk_request = send_chunk_data->store_chunk_request;

  // Check bad data - ensure existing parameters in requests are cleared
  store_prep_request.set_chunkname(names.at(0));
  store_chunk_request.set_chunkname(names.at(0));
  ASSERT_NE("", store_prep_request.chunkname());
  ASSERT_NE("", store_chunk_request.chunkname());
  std::string key_id2, public_key2, public_key_signature2, private_key2;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id2, &public_key2,
      &public_key_signature2, &private_key2);
  StoreData st_missing_name("", 10, (kHashable | kNormal), PRIVATE, "", key_id2,
      public_key2, public_key_signature2, private_key2);
  store_data = st_missing_name;
  ASSERT_EQ(kChunkNotInChunkstore, msm.GetStoreRequests(send_chunk_data));
  ASSERT_EQ("", store_prep_request.chunkname());
  ASSERT_EQ("", store_chunk_request.chunkname());

  // Check PRIVATE_SHARE chunk
  std::string msid_name = crypto_.Hash("b", "", crypto::STRING_STRING, false);
  crypto::RsaKeyPair rsakp = keys_.at(2);
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
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(kSuccess, SessionSingleton::getInstance()->
      AddPrivateShare(attributes, share_stats, &participants));
  std::string key_id3, public_key3, public_key_signature3, private_key3;
  msm.GetChunkSignatureKeys(PRIVATE_SHARE, msid_name, &key_id3, &public_key3,
      &public_key_signature3, &private_key3);
  StoreData st_chunk_private_share(names.at(0), 3, (kHashable | kOutgoing),
      PRIVATE_SHARE, msid_name, key_id3, public_key3, public_key_signature3,
      private_key3);
  ASSERT_EQ(kSuccess,
      client_chunkstore_->AddChunkToOutgoing(names.at(0), std::string("100")));
  store_data = st_chunk_private_share;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  std::string public_key_signature = crypto_.AsymSign(rsakp.public_key(), "",
      rsakp.private_key(), crypto::STRING_STRING);
  std::string request_signature = crypto_.AsymSign(crypto_.Hash(
      public_key_signature + names.at(0) + recipient_id, "",
      crypto::STRING_STRING, false), "", rsakp.private_key(),
      crypto::STRING_STRING);
  std::string size_signature(
      crypto_.AsymSign(boost::lexical_cast<std::string>(3), "",
                       rsakp.private_key(), crypto::STRING_STRING));

  ASSERT_EQ(names.at(0), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(msid_name, store_prep_request.signed_size().pmid());
  ASSERT_EQ(rsakp.public_key(), store_prep_request.signed_size().public_key());
  ASSERT_EQ(public_key_signature,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(0), store_chunk_request.chunkname());
  ASSERT_EQ("100", store_chunk_request.data());
  ASSERT_EQ(msid_name, store_chunk_request.pmid());
  ASSERT_EQ(rsakp.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(public_key_signature, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check PUBLIC_SHARE chunk
  std::string key_id4, public_key4, public_key_signature4, private_key4;
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_bad(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  client_chunkstore_->AddChunkToOutgoing(names.at(1), std::string("101"));
  store_data = st_chunk_public_share_bad;
  ASSERT_EQ(kGetRequestSigError, msm.GetStoreRequests(send_chunk_data));
  rsakp = keys_.at(3);
  std::string anmpid_pri = rsakp.private_key();
  std::string anmpid_pub = rsakp.public_key();
  std::string anmpid_pub_sig = crypto_.AsymSign(anmpid_pub, "", anmpid_pri,
      crypto::STRING_STRING);
  std::string anmpid_name = crypto_.Hash("Anmpid", "", crypto::STRING_STRING,
      false);
  SessionSingleton::getInstance()->AddKey(ANMPID, anmpid_name, anmpid_pri,
      anmpid_pub, anmpid_pub_sig);
  rsakp = keys_.at(4);
  std::string mpid_pri = rsakp.private_key();
  std::string mpid_pub = rsakp.public_key();
  std::string mpid_pub_sig = crypto_.AsymSign(mpid_pub, "",
      anmpid_pri, crypto::STRING_STRING);
  std::string mpid_name = crypto_.Hash("PublicName", "", crypto::STRING_STRING,
      false);
  SessionSingleton::getInstance()->AddKey(MPID, mpid_name, mpid_pri, mpid_pub,
      mpid_pub_sig);
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_good(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  store_data = st_chunk_public_share_good;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      mpid_pub_sig + names.at(1) + recipient_id, "", crypto::STRING_STRING,
      false), "", mpid_pri, crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(boost::lexical_cast<std::string>(3), "",
                                    mpid_pri, crypto::STRING_STRING);

  ASSERT_EQ(names.at(1), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(mpid_name, store_prep_request.signed_size().pmid());
  ASSERT_EQ(mpid_pub, store_prep_request.signed_size().public_key());
  ASSERT_EQ(mpid_pub_sig,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(1), store_chunk_request.chunkname());
  ASSERT_EQ("101", store_chunk_request.data());
  ASSERT_EQ(mpid_name, store_chunk_request.pmid());
  ASSERT_EQ(mpid_pub, store_chunk_request.public_key());
  ASSERT_EQ(mpid_pub_sig, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check ANONYMOUS chunk
  std::string key_id5, public_key5, public_key_signature5, private_key5;
  msm.GetChunkSignatureKeys(ANONYMOUS, "", &key_id5, &public_key5,
      &public_key_signature5, &private_key5);
  StoreData st_chunk_anonymous(names.at(2), 3, (kHashable | kOutgoing),
      ANONYMOUS, "", key_id5, public_key5, public_key_signature5, private_key5);
  client_chunkstore_->AddChunkToOutgoing(names.at(2), std::string("102"));
  store_data = st_chunk_anonymous;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));

  ASSERT_EQ(names.at(2), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(" ", store_prep_request.signed_size().pmid());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
    store_prep_request.signed_size().signature());
  ASSERT_EQ(kAnonymousRequestSignature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(2), store_chunk_request.chunkname());
  ASSERT_EQ("102", store_chunk_request.data());
  ASSERT_EQ(" ", store_chunk_request.pmid());
  ASSERT_EQ(" ", store_chunk_request.public_key());
  ASSERT_EQ(" ", store_chunk_request.public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
            store_chunk_request.request_signature());
  ASSERT_EQ(PDDIR_NOTSIGNED, store_chunk_request.data_type());

  // Check PRIVATE chunk
  std::string key_id6, public_key6, public_key_signature6, private_key6;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id6, &public_key6,
      &public_key_signature6, &private_key6);
  StoreData st_chunk_private(names.at(3), 3, (kHashable | kOutgoing), PRIVATE,
      "", key_id6, public_key6, public_key_signature6, private_key6);
  client_chunkstore_->AddChunkToOutgoing(names.at(3), std::string("103"));
  store_data = st_chunk_private;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      client_pmid_public_signature_ + names.at(3) + recipient_id, "",
      crypto::STRING_STRING, false), "", client_pmid_keys_.private_key(),
      crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(boost::lexical_cast<std::string>(3), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING);

  ASSERT_EQ(names.at(3), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(),
      store_prep_request.signed_size().public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(3), store_chunk_request.chunkname());
  ASSERT_EQ("103", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_ValidatePrepResp) {
  MaidsafeStoreManager msm(client_chunkstore_);
  // Make peer keys
  crypto::RsaKeyPair peer_pmid_keys = keys_.at(2);
  std::string peer_pmid_pri = peer_pmid_keys.private_key();
  std::string peer_pmid_pub = peer_pmid_keys.public_key();
  std::string peer_pmid_pub_signature = crypto_.AsymSign(peer_pmid_pub, "",
      peer_pmid_pri, crypto::STRING_STRING);
  std::string peer_pmid = crypto_.Hash(peer_pmid_pub + peer_pmid_pub_signature,
      "", crypto::STRING_STRING, false);
  // Make request
  std::string chunk_value(base::RandomString(163));
  std::string chunk_name(crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
      false));
  StoreData store_data(chunk_name, chunk_value.size(), (kHashable | kOutgoing),
      PRIVATE, "", client_pmid_, client_pmid_keys_.public_key(),
      client_pmid_public_signature_, client_pmid_keys_.private_key());
  client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_value);
  boost::shared_ptr<SendChunkData> send_chunk_data(
      new SendChunkData(store_data, kad::Contact(peer_pmid, "", 0), true));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  StorePrepRequest store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest store_chunk_request = send_chunk_data->store_chunk_request;
  // Make proper response
  maidsafe_vault::VaultChunkStore vault_chunkstore((test_root_dir_ /
      "VaultChunkstore").string(), 999999, 0);
  maidsafe_vault::VaultService vault_service(peer_pmid, peer_pmid_pub,
      peer_pmid_pri, peer_pmid_pub_signature, &vault_chunkstore, NULL, NULL, 0);
  StorePrepResponse good_store_prep_response;
  google::protobuf::Closure *done =
      google::protobuf::NewCallback(&google::protobuf::DoNothing);
  vault_service.StorePrep(NULL, &store_prep_request,
                          &good_store_prep_response, done);

  // Uninitialised StorePrepResponse
  StorePrepResponse store_prep_response;
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised StoreContract
  store_prep_response = good_store_prep_response;
  store_prep_response.clear_store_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised InnerContract
  store_prep_response = good_store_prep_response;
  StoreContract *mutable_store_contract =
      store_prep_response.mutable_store_contract();
  mutable_store_contract->clear_inner_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Wrong PMID
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_pmid(client_pmid_);
  ASSERT_EQ(kSendPrepPeerError, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Altered SignedSize
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  StoreContract::InnerContract *mutable_inner_contract =
      mutable_store_contract->mutable_inner_contract();
  SignedSize *mutable_signed_size =
      mutable_inner_contract->mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_value.size() - 1);
  ASSERT_EQ(kSendPrepSignedSizeAltered, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Returned kNack
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_inner_contract = mutable_store_contract->mutable_inner_contract();
  mutable_inner_contract->set_result(kNack);
  ASSERT_EQ(kSendPrepFailure, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID doesn't validate
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  std::string wrong_pmid = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  mutable_store_contract->set_pmid(wrong_pmid);
  ASSERT_EQ(kSendPrepInvalidId, msm.ValidatePrepResponse(wrong_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign StoreContract correctly
  store_prep_response = good_store_prep_response;
  store_prep_response.set_response_signature(crypto_.AsymSign(
      base::RandomString(100), "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidResponseSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign InnerContract correctly
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_signature(crypto_.AsymSign(base::RandomString(99),
      "", peer_pmid_pri, crypto::STRING_STRING));
  std::string ser_bad_contract;
  mutable_store_contract->SerializeToString(&ser_bad_contract);
  store_prep_response.set_response_signature(crypto_.AsymSign(ser_bad_contract,
      "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidContractSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // All OK
  ASSERT_EQ(kSuccess, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &good_store_prep_response));
}

class MockMsmSendChunkPrep : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendChunkPrep(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD3(AssessTaskStatus, TaskStatus(const std::string &data_name,
                                            StoreTaskType task_type,
                                            StoreTask *task));
  MOCK_METHOD2(WaitForOnline, bool(const std::string &data_name,
                                   const StoreTaskType &task_type));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkPrep) {
  MockMsmSendChunkPrep msm(client_chunkstore_);
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;

  // Set up test data
  std::string chunkname = crypto_.Hash("ddd", "", crypto::STRING_STRING, false);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("ddd"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.data_name,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());

  // Set up expectations
  EXPECT_CALL(msm, AssessTaskStatus(testing::_, kStoreChunk, testing::_))
      .Times(6)
      .WillOnce(testing::Return(kCompleted))  // Call 1
      .WillOnce(testing::Return(kCancelled))  // Call 2
      .WillOnce(testing::Return(kPending))  // Call 3
      .WillRepeatedly(testing::Return(kStarted));

  EXPECT_CALL(*mko, GetStorePeer(testing::_, testing::_, testing::_,
                                 testing::_))
      .WillOnce(testing::Return(kGetStorePeerError))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),  // Call 4
                      testing::InvokeWithoutArgs(boost::bind(
                          &StoreTasksHandler::DeleteTask, &msm.tasks_handler_,
                          store_data.data_name, kStoreChunk,
                          kStoreCancelledOrDone))))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),
                      testing::Return(kSuccess)))  // Call 5
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),
                      testing::Return(kSuccess)));  // Call 6

  EXPECT_CALL(msm, WaitForOnline(chunkname, kStoreChunk))
      .WillOnce(testing::Return(false))  // Call 5
      .WillOnce(testing::Return(true));  // Call 6

  // Run tests
  // Call 1
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkPrep(store_data));

  // Call 2 - should cause the task to be removed
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkPrep(store_data));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 3
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.data_name,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kGetStorePeerError, msm.SendChunkPrep(store_data));

  // Call 4 - GetStorePeer call sneakily deletes the task before it's started
  ASSERT_EQ(kSendChunkFailure, msm.SendChunkPrep(store_data));

  // Call 5
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.data_name,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kTaskCancelledOffline, msm.SendChunkPrep(store_data));

  // Call 6
  ASSERT_EQ(kSuccess, msm.SendChunkPrep(store_data));
}

class MockMsmSendPrepCallback : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendPrepCallback(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD3(ValidatePrepResponse, int(
      const std::string &peer_node_id,
      const SignedSize &request_signed_size,
      const StorePrepResponse *store_prep_response));
  MOCK_METHOD1(SendChunkContent, int(
      boost::shared_ptr<SendChunkData> send_chunk_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendPrepCallback) {
  // Set up test data
  MockMsmSendPrepCallback msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  std::string chunkname = crypto_.Hash("eee", "", crypto::STRING_STRING, false);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("eee"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(0));
  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data, peer, true));

  // Set up expectations
  EXPECT_CALL(msm, ValidatePrepResponse(peername, testing::_, testing::_))
      .Times(5)
      .WillOnce(testing::Return(kSuccess))  // Call 1
      .WillRepeatedly(testing::Return(-1));

  EXPECT_CALL(msm, SendChunkContent(testing::_));  // Call 1

  EXPECT_CALL(*mock_rpcs, StorePrep(EqualsContact(peer), testing::_, testing::_,
      testing::_, testing::_, testing::_, testing::_))
          .Times(1);  // Call 2

  // Run tests
  // Call 1 - All OK
  msm.SendPrepCallback(send_chunk_data);
  StoreTask retrieved_task;
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);
  ASSERT_EQ(1, send_chunk_data->attempt);

  // Call 2 - Validation of store_contract fails and we're now offline.  Once
  // online, task is still valid.
  send_chunk_data->attempt = 0;
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(1));
  boost::thread thr1(&test_msm::DelayedSetConnectionStatus, 0, 3000, msm.ss_);
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 3 - Validation of store_contract fails and we're now offline.  Once
  // online, task has been cancelled.
  send_chunk_data->attempt = 0;
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(1));
  boost::thread thr2(&test_msm::DelayedSetConnectionStatus, 0, 3000, msm.ss_);
  boost::thread thr3(&test_msm::DelayedCancelTask, chunkname, 1500,
      &msm.tasks_handler_);
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 4 - Validation of store_contract fails and task has been cancelled.
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(store_data.data_name,
      kStoreChunk));
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 5 - Validation of store_contract fails on final attempt.
  send_chunk_data->attempt = kMaxChunkStoreTries - 1;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(kMaxChunkStoreTries, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkContent) {
  MaidsafeStoreManager msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  std::string chunkname = crypto_.Hash("fff", "", crypto::STRING_STRING, false);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("fff"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(0));
  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data, peer, true));

  // Set up expectations
  EXPECT_CALL(*mock_rpcs, StoreChunk(EqualsContact(peer), testing::_,
      testing::_, testing::_, testing::_, testing::_, testing::_))
          .Times(3);  // Calls 2, 3, & 5

  // Run tests
  // Call 1 - Task cancelled before sending RPC
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(chunkname, kStoreChunk));
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkContent(send_chunk_data));
  StoreTask retrieved_task;
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 2 - SendChunkContent success
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.SendChunkContent(send_chunk_data));
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 3 - Callback with unitialised response - task still active
  send_chunk_data->attempt = 0;
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 4 - Callback with unitialised response - task cancelled
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(chunkname, kStoreChunk));
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 5 - Callback with wrong PMID - task still active
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  StoreChunkResponse &response = send_chunk_data->store_chunk_response;
  response.set_result(kAck);
  response.set_pmid(chunkname);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 6 - Callback with kNack - last attempt
  send_chunk_data->attempt = kMaxChunkStoreTries - 1;
  response.set_result(kNack);
  response.set_pmid(peername);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 7 - Callback OK - only one chunk copy required
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, 1, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  response.set_result(kAck);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ChunkType chunk_type = msm.client_chunkstore_->chunk_type(chunkname);
  ASSERT_EQ((kHashable | kNormal), chunk_type);

  // Call 8 - Callback OK - kMinChunkCopies required
  send_chunk_data->attempt = 0;
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  ASSERT_EQ(kSuccess, client_chunkstore_->ChangeChunkType(chunkname, new_type));
  ASSERT_EQ((kHashable | kOutgoing),
            msm.client_chunkstore_->chunk_type(chunkname));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  response.set_result(kAck);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(0), retrieved_task.active_subtask_count_);
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.success_count_);
  ASSERT_EQ((kHashable | kNormal),
            msm.client_chunkstore_->chunk_type(chunkname));
}

TEST_F(MaidStoreManagerTest, DISABLED_BEH_MAID_MSM_LoadChunk) {
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_RemoveFromWatchList) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;
  ASSERT_TRUE(client_chunkstore_->is_initialised());

  // Set up chunks
  const int kTestCount(10);
  std::vector<std::string> chunk_names;
  std::vector<boost::uint64_t> chunk_sizes;
  std::vector<StoreData> store_datas_i_know_the_plural_should_be_data_but_still;
  std::vector<ReturnCode> delete_chunk_results;
  for (int i = 0; i < kTestCount; ++i) {
    boost::uint64_t chunk_size = 661 + i;
    std::string chunk_value = base::RandomString(chunk_size);
    std::string chunk_name = crypto_.Hash(chunk_value, "",
                                          crypto::STRING_STRING, false);
    if (i > 0) {
      ASSERT_EQ(kSuccess, client_chunkstore_->AddChunkToOutgoing(chunk_name,
          chunk_value));
      ASSERT_EQ(kSuccess, client_chunkstore_->ChangeChunkType(chunk_name,
          (kNormal | kHashable)));
    }
    StoreData data(chunk_name, chunk_size, (kHashable | kNormal), PRIVATE, "",
        client_pmid_, client_pmid_keys_.public_key(),
        client_pmid_public_signature_, client_pmid_keys_.private_key());
    ReturnCode ret_code(kEmptyConversationId);
    chunk_names.push_back(chunk_name);
    chunk_sizes.push_back(chunk_size);
    store_datas_i_know_the_plural_should_be_data_but_still.push_back(data);
    delete_chunk_results.push_back(ret_code);
  }

  // Set up data for calls to FindKNodes
  std::vector<std::string> good_pmids, few_pmids;
  std::string bad_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kResultFail, &good_pmids);
  std::string good_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kGood, &good_pmids);
  std::string few_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kTooFewContacts, &few_pmids);
  std::vector<kad::Contact> contacts;
  {
    kad::FindResponse find_response;
    kad::Contact contact;
    ASSERT_TRUE(find_response.ParseFromString(good_result));
    for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
      ASSERT_TRUE(contact.ParseFromString(find_response.closest_nodes(i)));
      contacts.push_back(contact);
    }
  }
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(0));

  test_msm::ThreadedCallContainer tcc(1);

  // Set expectations
  EXPECT_CALL(*mko, AddressIsLocal(testing::An<const kad::Contact&>()))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(1), false),
                                      testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, bad_result, _1))));   // Call 2

  EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(2), false),
                                      testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result, _1))));   // Call 3

  for (int i = 3; i < kTestCount; ++i) {
    EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(chunk_names.at(i), false),
                                        testing::_))
        .WillOnce(testing::WithArgs<1>(testing::Invoke(
            boost::bind(&mock_kadops::RunCallback, good_result, _1))));   // 4-7
  }

  for (size_t i = 0; i < contacts.size(); ++i) {
    EXPECT_CALL(*mock_rpcs, ExpectAmendment(
        EqualsContact(contacts.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    i + 1 < kKadLowerThreshold,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    true,
                    i + 1 < kKadLowerThreshold ? kAck : kNack,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 6
            .WillRepeatedly(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::WatchListOpStageThree,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))));                           // Calls 7 to 10
  }
  
  for (size_t i = 0; i < contacts.size(); ++i) {
    EXPECT_CALL(*mock_rpcs, RemoveFromWatchList(
        EqualsContact(contacts.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::RemoveFromWatchListStageFour,
                    i + 1 < kKadLowerThreshold,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 7
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::RemoveFromWatchListStageFour,
                    true,
                    i + 1 < kKadLowerThreshold ? kAck : kNack,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 8
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::RemoveFromWatchListStageFour,
                    true,
                    kAck,
                    contacts.at((i + 1) %
                        contacts.size()).node_id().ToStringDecoded(),
                    _1, _2, &tcc))))                                   // Call 9
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::RemoveFromWatchListStageFour,
                    true,
                    kAck,
                    contacts.at(i).node_id().ToStringDecoded(),
                    _1, _2, &tcc))));                                 // Call 10
  }

  // Run test calls
  std::string long_key('a', kKeySize + 1);
  std::string short_key('z', kKeySize - 1);
  ASSERT_EQ(kIncorrectKeySize, msm.DeleteChunk(long_key, 10, PRIVATE, ""));
  ASSERT_EQ(kIncorrectKeySize, msm.DeleteChunk(short_key, 10, PRIVATE, ""));
  ASSERT_EQ(kDirUnknownType, msm.DeleteChunk(chunk_names.at(0),
      chunk_sizes.at(0), static_cast<DirType>(ANONYMOUS - 1), ""));
  ASSERT_EQ(kDirUnknownType, msm.DeleteChunk(chunk_names.at(0),
      chunk_sizes.at(0), static_cast<DirType>(PUBLIC_SHARE + 1), ""));

  int test_run(0);
  StoreTask task;
  // Call 1 - Didn't provide size and chunk not in local chunkstore
  ASSERT_EQ(kDeleteSizeError,
            msm.DeleteChunk(chunk_names.at(test_run), 0, PRIVATE, ""));

  // Call 2 - FindKNodes returns failure
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  int time_taken(0);
  const int kTimeout(5000);
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  // Call 3 - FindKNodes returns success but not enough contacts
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  // Call 4 - FindKNodes returns CIHs, but no AHs available
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  msm.account_holders_manager_.account_holder_group_ = contacts;

  // Call 5 - ExpectAmendment responses partially uninitialised
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  // Call 6 - ExpectAmendment responses partially unacknowledged
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  // Call 7 - Twelve RFW responses return uninitialised
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.DeleteChunk(chunk_names.at(test_run),
            chunk_sizes.at(test_run), PRIVATE, ""));
  time_taken = 0;
  while (msm.tasks_handler_.TasksCount() != 0 && time_taken < kTimeout) {
    time_taken += 100;
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ASSERT_EQ((kTempCache | kHashable),
            client_chunkstore_->chunk_type(chunk_names.at(test_run)));

  // Call 8 - Twelve RFW responses return kNack
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ReturnCode delete_chunk_result1(kLoadKeysFailure);
  ReturnCode delete_chunk_result2(kLoadKeysFailure);
  ReturnCode delete_chunk_result3(kLoadKeysFailure);
  boost::mutex mutex1, mutex2, mutex3;
  boost::condition_variable cond_var1, cond_var2, cond_var3;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunk_names.at(test_run),
      kDeleteChunk, chunk_sizes.at(test_run), 1, 1));
  {
    boost::mutex::scoped_lock lock(msm.tasks_handler_.mutex_);
    std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
    it = msm.tasks_handler_.tasks_.equal_range(boost::make_tuple(
        chunk_names.at(test_run), kDeleteChunk));
    if (it.first != it.second) {
      task = (*it.first);
      task.callback_ = boost::bind(&test_msm::DeleteChunkResult, _1,
          &delete_chunk_result1, &mutex1, &cond_var1);
      task.has_callback_ = true;
      msm.tasks_handler_.tasks_.replace(it.first, task);
    }
  }
  msm.RemoveFromWatchList(
      store_datas_i_know_the_plural_should_be_data_but_still.at(test_run));

  // Call 9 - Twelve RFW responses return with wrong PMIDs
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunk_names.at(test_run),
      kDeleteChunk, chunk_sizes.at(test_run), 1, 1));
  {
    boost::mutex::scoped_lock lock(msm.tasks_handler_.mutex_);
    std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
    it = msm.tasks_handler_.tasks_.equal_range(boost::make_tuple(
        chunk_names.at(test_run), kDeleteChunk));
    if (it.first != it.second) {
      task = (*it.first);
      task.callback_ = boost::bind(&test_msm::DeleteChunkResult, _1,
          &delete_chunk_result2, &mutex2, &cond_var2);
      task.has_callback_ = true;
      msm.tasks_handler_.tasks_.replace(it.first, task);
    }
  }
  msm.RemoveFromWatchList(
      store_datas_i_know_the_plural_should_be_data_but_still.at(test_run));

  // Call 10 - All OK
  ++test_run;
  printf("--- call %d ---\n", test_run + 1);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunk_names.at(test_run),
      kDeleteChunk, chunk_sizes.at(test_run), 1, 1));
  {
    boost::mutex::scoped_lock lock(msm.tasks_handler_.mutex_);
    std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
    it = msm.tasks_handler_.tasks_.equal_range(boost::make_tuple(
        chunk_names.at(test_run), kDeleteChunk));
    if (it.first != it.second) {
      task = (*it.first);
      task.callback_ = boost::bind(&test_msm::DeleteChunkResult, _1,
          &delete_chunk_result3, &mutex3, &cond_var3);
      task.has_callback_ = true;
      msm.tasks_handler_.tasks_.replace(it.first, task);
    }
  }
  msm.RemoveFromWatchList(
      store_datas_i_know_the_plural_should_be_data_but_still.at(test_run));

  boost::mutex::scoped_lock lock1(mutex1);
  while (delete_chunk_result1 == kLoadKeysFailure) {
    cond_var1.wait(lock1);
  }
  boost::mutex::scoped_lock lock2(mutex2);
  while (delete_chunk_result2 == kLoadKeysFailure) {
    cond_var2.wait(lock2);
  }
  boost::mutex::scoped_lock lock3(mutex3);
  while (delete_chunk_result3 == kLoadKeysFailure) {
    cond_var3.wait(lock3);
  }
  ASSERT_EQ(kDeleteChunkFailure, delete_chunk_result1);
  ASSERT_EQ(kDeleteChunkFailure, delete_chunk_result2);
  ASSERT_EQ(kSuccess, delete_chunk_result3);
}

class MockMsmStoreLoadPacket : public MaidsafeStoreManager {
 public:
  explicit MockMsmStoreLoadPacket(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD1(SendPacket, void(boost::shared_ptr<StoreData> store_data));
  MOCK_METHOD1(DeletePacketFromNet,
               void(boost::shared_ptr<DeletePacketData> delete_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreNewPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys = keys_.at(2);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, false);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up test requirements
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");
  std::string ser_kad_store_response_cant_parse("Rubbish");
  std::string ser_kad_store_response_empty;
  std::string ser_kad_store_response_good, ser_kad_store_response_fail;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);
  store_response.set_result("Fail");
  store_response.SerializeToString(&ser_kad_store_response_fail);

  // Set up expectations
  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_name, false), true, testing::_,
      testing::_, testing::_))
          .Times(6)
          .WillOnce(testing::Return(-1))  // Call 4
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(kSuccess)))  // Call 5
          .WillRepeatedly(testing::Return(kFindValueFailure));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_empty, _1))))  // Call 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_cant_parse, _1))))  // Call 7
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_fail, _1))))  // Call 8
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Call 9

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  std::string short_key('z', kKeySize - 1);
  msm.StorePacket(short_key, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Check with bad packet type
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value,
      static_cast<PacketType>(PacketType_MIN - 1), PRIVATE, "",
      kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - Check with bad dir type
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID,
      static_cast<DirType>(PUBLIC_SHARE + 1), "",  kDoNothingReturnSuccess,
      functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDirUnknownType, packet_op_result_);

  // Call 4 - FindValue fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFindValueFailure, packet_op_result_);

  // Call 5 - FindValue yields a cached copy
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketCached, packet_op_result_);

  // Call 6 - SendPacket returns no result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketError, packet_op_result_);

  // Call 7 - SendPacket returns unparseable result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketParseError, packet_op_result_);

  // Call 8 - SendPacket returns failure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFailure, packet_op_result_);

  // Call 9 - SendPacket returns success
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreExistingPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys = keys_.at(2);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, false);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up store response
  std::string ser_kad_store_response_good;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  const size_t kExistingValueCount(5);
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kExistingValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  // Set up vector of existing values
  std::vector<std::string> existing_values;
  for (size_t i = 0; i < kExistingValueCount; ++i)
    existing_values.push_back("ExistingValue" + base::IntToString(i));

  // Set up expectations
  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_name, false), true, testing::_,
      testing::_, testing::_))
          .Times(8)
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(existing_values),
                                testing::Return(kSuccess)));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .Times(2)
      .WillRepeatedly(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Calls 3 & 8

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))  // Calls 5 to 8 inclusive
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));

  // Call 1 - If exists kDoNothingReturnFailure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnFailure, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketAlreadyExists, packet_op_result_);

  // Call 2 - If exists kDoNothingReturnSuccess
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 3 - If exists kAppend
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "", kAppend,
                  functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 4 - Invalid IfExists
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "",
                  static_cast<IfPacketExists>(-1), functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketUnknownExistsType, packet_op_result_);

  // Call 5 - If exists kOverwrite - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 6 - If exists kOverwrite - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 7 - If exists kOverwrite - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 8 - If exists kOverwrite - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.StorePacket(packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_LoadPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;

  // Set up test requirements
  std::vector<std::string> packet_names;
  const size_t kTestCount(8);
  packet_names.push_back("InvalidName");
  for (size_t i = 1; i < kTestCount; ++i) {
    packet_names.push_back(crypto_.Hash(base::RandomString(100), "",
                                        crypto::STRING_STRING, false));
  }
  const size_t kValueCount(5);
  std::string ser_result_empty, ser_result_unparsable("Bleh"), ser_result_fail;
  std::string ser_result_no_values, ser_result_cached_copy, ser_result_good;
  kad::FindResponse find_response;
  find_response.set_result(kad::kRpcResultSuccess);
  find_response.SerializeToString(&ser_result_no_values);
  find_response.set_result(kad::kRpcResultFailure);
  for (size_t i = 0; i < kValueCount; ++i) {
    kad::SignedValue *sig_val = find_response.add_signed_values();
    sig_val->set_value("Value" + base::IntToString(i));
    sig_val->set_value_signature("Sig");
  }
  find_response.SerializeToString(&ser_result_fail);
  find_response.set_result(kad::kRpcResultSuccess);
  find_response.SerializeToString(&ser_result_good);
  kad::ContactInfo *cache_holder =
      find_response.mutable_alternative_value_holder();
  cache_holder->set_node_id("a");
  cache_holder->set_ip("b");
  cache_holder->set_port(1);
  find_response.SerializeToString(&ser_result_cached_copy);
  std::vector<std::string> returned_values;

  // Set up expectations
  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(2), false), false,
      testing::_))  // Call 3
      .Times(kMaxChunkLoadRetries)
      .WillRepeatedly(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_empty))));

  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(3), false), false,
      testing::_))  // Call 4
      .Times(kMaxChunkLoadRetries)
      .WillRepeatedly(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_unparsable))));

  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(4), false), false,
      testing::_))  // Call 5
      .Times(kMaxChunkLoadRetries)
      .WillRepeatedly(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_fail))));

  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(5), false), false,
      testing::_))  // Call 6
      .Times(kMaxChunkLoadRetries)
      .WillRepeatedly(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_no_values))));

  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(6), false), false,
      testing::_))  // Call 7
      .Times(kMaxChunkLoadRetries)
      .WillRepeatedly(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_cached_copy))));

  EXPECT_CALL(*mko, FindValue(kad::KadId(packet_names.at(7), false), false,
      testing::_))  // Call 8
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_cached_copy))))
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_fail))))
      .WillOnce(testing::WithArgs<2>(testing::Invoke(boost::bind(
          &test_msm::RunLoadPacketCallback, _1, ser_result_good))));

  // Call 1 - Check with bad packet name length
  size_t test_number(0);
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kIncorrectKeySize,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 2 - Check with NULL pointer
  ++test_number;
  ASSERT_EQ(kLoadPacketFailure,
            msm.LoadPacket(packet_names.at(test_number), NULL));

  // Call 3 - FindValue returns an empty string
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueError,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 4 - FindValue returns an unparsable string
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueParseError,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 5 - FindValue fails
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 6 - FindValue claims success but doesn't populate value vector
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 7 - FindValue yields a cached copy
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kLoadPacketCached,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 8 - Success
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kSuccess,
            msm.LoadPacket(packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(kValueCount), returned_values.size());
  for (size_t i = 0; i < kValueCount; ++i)
    ASSERT_EQ(find_response.signed_values(i).SerializeAsString()/*value()*/,
              returned_values.at(i));
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_DeletePacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys = keys_.at(2);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, false);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for deletion
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  const size_t kValueCount(5);
  std::vector<std::string> packet_values, single_value;
  for (size_t i = 0; i < kValueCount; ++i)
    packet_values.push_back("Value" + base::IntToString(i));
  single_value.push_back("Value");

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))  // 4
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))  // 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));  // 7

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  msm.DeletePacket("InvalidName", packet_values, MID, PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Invalid PacketType
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values,
      static_cast<PacketType>(PacketType_MAX + 1), PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - Invalid DirType
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values, MID,
                   static_cast<DirType>(ANONYMOUS - 1), "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDirUnknownType, packet_op_result_);

  // Call 4 - Multiple value request - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values, MID, PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 5 - Multiple value request - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values, MID, PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 6 - Multiple value request - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values, MID, PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 7 - Multiple value request - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(packet_name, packet_values, MID, PRIVATE, "", functor_);
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (packet_op_result_ == kGeneralError)
      cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetAccountDetails) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  boost::shared_ptr<MockKadOps> mko(new MockKadOps(msm.knode_));
  msm.kad_ops_ = mko;
  ASSERT_TRUE(client_chunkstore_->is_initialised());

  std::string account_name = crypto_.Hash(client_pmid_ + kAccount, "",
      crypto::STRING_STRING, false);

  // Set up data for calls to FindKNodes
  std::vector<std::string> good_pmids, few_pmids;
  std::string bad_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kResultFail, &good_pmids);
  std::string good_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kGood, &good_pmids);
  std::string few_result = mock_kadops::MakeFindNodesResponse(
      mock_kadops::kTooFewContacts, &few_pmids);
  std::vector<kad::Contact> account_holders;
  {
    kad::FindResponse find_response;
    kad::Contact contact;
    ASSERT_TRUE(find_response.ParseFromString(good_result));
    for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
      ASSERT_TRUE(contact.ParseFromString(find_response.closest_nodes(i)));
      account_holders.push_back(contact);
    }
  }

  // only one thread, so the RPCs are called in order
  // (important for the expected averages)
  test_msm::ThreadedCallContainer tcc(1);

  // Set expectations
  EXPECT_CALL(*mko, AddressIsLocal(testing::An<const kad::Contact&>()))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mko, FindKClosestNodes(kad::KadId(account_name, false),
                                      testing::_))
      .Times(7)
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, bad_result, _1))))  // Call 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result, _1))))  // Call 2
      .WillRepeatedly(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result, _1))));

  // Account holder responses
  for (int i = 0; i < kad::K; ++i) {
    EXPECT_CALL(*mock_rpcs, AccountStatus(
        EqualsContact(account_holders.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAccountStatusCallback, &tcc,
                false, kAck, account_holders.at(i).node_id().ToStringDecoded(),
                false, test_msm::AccountStatusValues(0, 0, 0), _1, _2))))  // 3
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAccountStatusCallback, &tcc,
                i < kKadLowerThreshold, kAck,
                account_holders.at(i).node_id().ToStringDecoded(), true,
                test_msm::AccountStatusValues(i*i, i, i), _1, _2))))  // 4
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAccountStatusCallback, &tcc,
                i < kKadUpperThreshold, kAck,
                account_holders.at(i).node_id().ToStringDecoded(), false,
                test_msm::AccountStatusValues(1, 2, 3), _1, _2))))  // #5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAccountStatusCallback, &tcc,
                i < kKadUpperThreshold, kNack,
                account_holders.at(i).node_id().ToStringDecoded(), true,
                test_msm::AccountStatusValues(1, 2, 3), _1, _2))))   // #6
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAccountStatusCallback, &tcc,
                i < kKadUpperThreshold, kAck,
                account_holders.at(i).node_id().ToStringDecoded(), true,
                test_msm::AccountStatusValues(1, 2, 3), _1, _2))));  // #7
  }

  boost::uint64_t space_offered, space_given, space_taken;

  // Call 0 - not online
  printf(">> Call 0\n");
  ASSERT_TRUE(SessionSingleton::getInstance()->SetConnectionStatus(1));
  ASSERT_EQ(kTaskCancelledOffline,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));
  ASSERT_TRUE(SessionSingleton::getInstance()->SetConnectionStatus(0));

  // Call 1 - FindKNodes fails
  printf(">> Call 1\n");
  ASSERT_EQ(kFindAccountHoldersError,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));

  // Call 2 - FindKNodes returns too few contacts
  printf(">> Call 2\n");
  ASSERT_EQ(kFindAccountHoldersError,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));

  // Call 3 - RPCs return uninitialised responses
  printf(">> Call 3\n");
  ASSERT_EQ(kRequestInsufficientResponses,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));

  // Call 4 - only 4 initialised responses, but no consensus
  printf(">> Call 4\n");
  if (kKadLowerThreshold <= 2)
    ASSERT_EQ(kSuccess, msm.GetAccountDetails(&space_offered, &space_given,
                                              &space_taken));
  else
    ASSERT_EQ(kRequestFailedConsensus,
              msm.GetAccountDetails(&space_offered, &space_given,
                                    &space_taken));

  // Call 5 - uninitialised values in responses, equals consensus (all zero)
  printf(">> Call 5\n");
  ASSERT_EQ(kSuccess,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_offered);
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_given);
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_taken);

  // Call 6 - non-acknowledged responses, same as #5
  printf(">> Call 6\n");
  ASSERT_EQ(kSuccess,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_offered);
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_given);
  ASSERT_EQ(static_cast<boost::uint64_t>(0), space_taken);

  // Call 7 - initialised, constant values in responses
  printf(">> Call 7\n");
  ASSERT_EQ(kSuccess,
            msm.GetAccountDetails(&space_offered, &space_given, &space_taken));
  ASSERT_EQ(static_cast<boost::uint64_t>(1), space_offered);
  ASSERT_EQ(static_cast<boost::uint64_t>(2), space_given);
  ASSERT_EQ(static_cast<boost::uint64_t>(3), space_taken);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetFilteredAverage) {
  /**
   * note: keep values smaller than 2^(64-log2(n)); 53 bits precision!
   */
  std::vector<boost::uint64_t> values;
  boost::uint64_t average;
  size_t n;

  // no values
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(0), average);
  ASSERT_EQ(static_cast<size_t>(0), n);

  // one value
  values.push_back(5);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(5), average);
  ASSERT_EQ(static_cast<size_t>(1), n);

  // three values
  values.push_back(4);
  values.push_back(6);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(5), average);
  ASSERT_EQ(static_cast<size_t>(3), n);

  // four values, one is an outlier
  values.push_back(10);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(5), average);
  ASSERT_EQ(static_cast<size_t>(3), n);

  // five values and one huge outlier outside precision
  values.push_back(1000000000000000000ll);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(6), average);
  ASSERT_EQ(static_cast<size_t>(4), n);

  // four huge values within precision
  values.clear();
  values.push_back(9000000000000000ll);
  values.push_back(9000000000000010ll);
  values.push_back(9000000000000020ll);
  values.push_back(9000000000000030ll);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(9000000000000015ll), average);
  ASSERT_EQ(static_cast<size_t>(4), n);

  // four huge values and one small outlier
  values.push_back(10);
  MaidsafeStoreManager::GetFilteredAverage(values, &average, &n);
  ASSERT_EQ(static_cast<boost::uint64_t>(9000000000000015ll), average);
  ASSERT_EQ(static_cast<size_t>(4), n);
}

/* TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AmendAccount) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  ASSERT_TRUE(client_chunkstore_->is_initialised());

  std::string account_name = crypto_.Hash(client_pmid_ + kAccount, "",
      crypto::STRING_STRING, false);

  // Set up data for calls to FindKNodes
  std::vector<kad::Contact> account_holders, few_account_holders;
  for (boost::uint16_t i = 0; i < kad::K; ++i) {
    kad::Contact contact(crypto_.Hash(base::IntToString(i * i), "",
        crypto::STRING_STRING, false), "192.168.10." + base::IntToString(i), 8000 + i,
        "192.168.10." + base::IntToString(i), 8000 + i);
    account_holders.push_back(contact);
    if (i >= kKadStoreThreshold)
      few_account_holders.push_back(contact);
  }

  // call RPCs from 4 threads
  test_msm::ThreadedCallContainer tcc(4);

  // Set expectations
  EXPECT_CALL(msm, FindKNodes(account_name, testing::_))
      .Times(6)
      .WillOnce(DoAll(testing::SetArgumentPointee<1>(account_holders),
          testing::Return(-1)))  // Call 1
      .WillOnce(DoAll(testing::SetArgumentPointee<1>(few_account_holders),
          testing::Return(kSuccess)))  // Call 2
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(account_holders),
          testing::Return(kSuccess)));

  // Account holder responses
  for (int i = 0; i < kad::K; ++i) {
    EXPECT_CALL(*mock_rpcs, AmendAccount(
        EqualsContact(account_holders.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAmendAccountCallback, &tcc,
                false, kAck, account_holders.at(i).node_id().ToStringDecoded(),
                _1, _2))))   // #3
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAmendAccountCallback, &tcc,
                true, (i < kKadStoreThreshold - 1 ? kAck : kNack),
                account_holders.at(i).node_id().ToStringDecoded(), _1, _2))))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAmendAccountCallback, &tcc,
                true, kAck, (i < kKadStoreThreshold - 1 ?
                    account_holders.at(i).node_id().ToStringDecoded() : "fail"),
                    _1, _2))))  // #5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::ThreadedAmendAccountCallback, &tcc,
                true, kAck, account_holders.at(i).node_id().ToStringDecoded(),
                _1, _2))));   // #6
  }

  // Call 0 - not online
  printf(">> Call 0\n");
  ASSERT_TRUE(SessionSingleton::getInstance()->SetConnectionStatus(1));
  ASSERT_EQ(kTaskCancelledOffline, msm.AmendAccount(1234));
  ASSERT_TRUE(SessionSingleton::getInstance()->SetConnectionStatus(0));

  // Call 1 - FindKNodes fails
  printf(">> Call 1\n");
  ASSERT_EQ(kFindAccountHoldersError, msm.AmendAccount(1234));

  // Call 2 - FindKNodes returns too few contacts
  printf(">> Call 2\n");
  ASSERT_EQ(kFindAccountHoldersError, msm.AmendAccount(1234));

  // Call 3 - RPCs return uninitialised responses
  printf(">> Call 3\n");
  ASSERT_EQ(kRequestFailedConsensus, msm.AmendAccount(1234));

  // Call 4 - five return with negative responses
  printf(">> Call 4\n");
  ASSERT_EQ(kRequestFailedConsensus, msm.AmendAccount(1234));

  // Call 5 - five return with wrong PMIDs
  printf(">> Call 5\n");
  ASSERT_EQ(kRequestFailedConsensus, msm.AmendAccount(1234));

  // Call 6 - successful amendment
  printf(">> Call 6\n");
  ASSERT_EQ(kSuccess, msm.AmendAccount(1234));
} */

}  // namespace maidsafe
