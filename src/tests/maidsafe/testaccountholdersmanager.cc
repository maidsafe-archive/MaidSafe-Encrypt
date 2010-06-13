/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for AccountHoldersManager class.
* Version:      1.0
* Created:      2010-05-11-15.10
* Revision:     none
* Compiler:     gcc
* Author:       Team: dev@maidsafe.net
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
#include "maidsafe/utils.h"
#include "maidsafe/accountholdersmanager.h"
#include "maidsafe/chunkstore.h"
#include "tests/maidsafe/mockkadops.h"

namespace maidsafe {

class AccountHoldersManagerTest : public testing::Test {
 public:
  AccountHoldersManagerTest()
      : co_(),
        pmid_(co_.Hash(base::RandomString(100), "",
                       crypto::STRING_STRING, false)),
        account_name_(co_.Hash(pmid_ + kAccount, "", crypto::STRING_STRING,
                               false)),
        transport_handler_(),
        channel_manager_(&transport_handler_),
        chunkstore_(new ChunkStore("Chunkstore", 9999999, 0)),
        mock_kad_ops_(new MockKadOps(&transport_handler_, &channel_manager_,
                      kad::CLIENT, "", "", false, false, chunkstore_)),
        fail_parse_pmids_(),
        fail_pmids_(),
        few_pmids_(),
        good_pmids_(),
        fail_parse_result_(
            mock_kadops::MakeFindNodesResponse(mock_kadops::kFailParse,
                                               &fail_parse_pmids_)),
        fail_result_(
            mock_kadops::MakeFindNodesResponse(mock_kadops::kResultFail,
                                               &fail_pmids_)),
        few_result_(
            mock_kadops::MakeFindNodesResponse(mock_kadops::kTooFewContacts,
                                               &few_pmids_)),
        good_result_(mock_kadops::MakeFindNodesResponse(mock_kadops::kGood,
                                                        &good_pmids_)),
        account_holders_manager_(mock_kad_ops_),
        test_rpcs_in_flight_(0),
        kSingleRpcTimeout_(60),
        test_mutex_(),
        test_cond_var_(),
        test_return_code_(kPendingResult),
        test_account_holders_(),
        test_functor_() {}
 protected:
  void SetUp() {
    ASSERT_EQ(crypto::SHA_512, co_.hash_algorithm());
    test_functor_ =
        boost::bind(&AccountHoldersManagerTest::Callback, this, _1, _2);
  }
  void TearDown() {
    boost::system_time expire = boost::get_system_time() + kSingleRpcTimeout_;
    boost::mutex::scoped_lock lock(test_mutex_);
//    printf("In TDown 1:- test_rpcs_in_flight_: %u\n", test_rpcs_in_flight_);
    while (test_rpcs_in_flight_ > 0 &&
           boost::detail::get_milliseconds_until(expire) > 0) {
      test_cond_var_.timed_wait(lock, expire);
    }
//    printf("In TDown 2:- test_rpcs_in_flight_: %u\n", test_rpcs_in_flight_);
  }
  void Callback(const ReturnCode &return_code,
                const std::vector<kad::Contact> &account_holders) {
//    printf("In Callback:- ");
    boost::this_thread::sleep(boost::posix_time::milliseconds(
        (base::RandomUint32() % 250) + 250));
    boost::mutex::scoped_lock lock(test_mutex_);
    test_return_code_ = return_code;
    test_account_holders_ = account_holders;
    // Check AMH mutex is locked, failed_ids_ is empty and update_in_progress_
    // is set to true
    if (account_holders_manager_.mutex_.try_lock()) {
      account_holders_manager_.mutex_.unlock();
      test_return_code_ = kBPError;
    }
    if (!account_holders_manager_.failed_ids_.empty())
      test_return_code_ = kBPSerialiseError;
    if (!account_holders_manager_.update_in_progress_)
      test_return_code_ = kBPInfoSerialiseError;
    --test_rpcs_in_flight_;
//    printf("return_code: %i, account_holders.size: %u, test_rpcs_in_flight_: "
//           "%u\n", return_code, account_holders.size(), test_rpcs_in_flight_);
    test_cond_var_.notify_one();
  }
  ReturnCode WaitForCallback() {
    boost::mutex::scoped_lock lock(test_mutex_);
    while (test_return_code_ == kPendingResult)
      test_cond_var_.wait(lock);
    ReturnCode result = test_return_code_;
    test_return_code_ = kPendingResult;
    // Allow AMH processes to complete after callback starts (e.g. setting
    // last_update_, etc.)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    return result;
  }
  bool TestVectorsEqual(const std::vector<kad::Contact> &lhs,
                        const std::vector<kad::Contact> &rhs) {
    if (lhs.size() != rhs.size())
      return false;
    for (size_t i = 0; i != lhs.size(); ++i) {
      if (!lhs.at(i).Equals(rhs.at(i)))
        return false;
    }
    return true;
  }
  crypto::Crypto co_;
  std::string pmid_, account_name_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<ChunkStore> chunkstore_;
  boost::shared_ptr<MockKadOps> mock_kad_ops_;
  std::vector<std::string> fail_parse_pmids_, fail_pmids_, few_pmids_;
  std::vector<std::string> good_pmids_;
  std::string fail_parse_result_, fail_result_, few_result_, good_result_;
  AccountHoldersManager account_holders_manager_;
  size_t test_rpcs_in_flight_;
  const boost::posix_time::seconds kSingleRpcTimeout_;
  boost::mutex test_mutex_;
  boost::condition_variable test_cond_var_;
  ReturnCode test_return_code_;
  std::vector<kad::Contact> test_account_holders_;
  AccountHolderGroupFunctor test_functor_;
};

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_Init) {
  // Set up expectations
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(account_name_, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_parse_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));  // Cll 3

  // Uninitialised
  ASSERT_TRUE(account_holders_manager_.account_name().empty());
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 1 - FindNodes fails to parse - still uninitialised (except
  //          account_name_)
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t1(&AccountHoldersManager::Init, &account_holders_manager_,
      pmid_, test_functor_);
  ASSERT_EQ(kFindNodesParseError, WaitForCallback());
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 2 - FindNodes result is failure - still uninitialised
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t2(&AccountHoldersManager::Init, &account_holders_manager_,
      pmid_, test_functor_);
  ASSERT_EQ(kFindNodesFailure, WaitForCallback());
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 3 - FindNodes returns K contacts - now initialised
  ++test_rpcs_in_flight_;
  boost::thread t3(&AccountHoldersManager::Init, &account_holders_manager_,
      pmid_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(boost::posix_time::microsec_clock::universal_time() -
            boost::posix_time::seconds(1),
            account_holders_manager_.last_update_);
  ASSERT_EQ(good_pmids_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  for (size_t i = 0; i != good_pmids_.size(); ++i)
    ASSERT_TRUE(ContactHasId(good_pmids_.at(i), test_account_holders_.at(i)));
}

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_UpdateGroup) {
  // Set up expectations
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(account_name_, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_parse_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result_, _1))))   // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));  // Cll 4
  std::string good_pmid_account(co_.Hash(good_pmids_.back() + kAccount, "",
                                         crypto::STRING_STRING, false));
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(good_pmid_account, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));  // Cll 5

  // Fake initialisation
  account_holders_manager_.do_nothing_ = boost::bind(
      &AccountHoldersManager::DoNothing, &account_holders_manager_, _1, _2);
  account_holders_manager_.pmid_ = pmid_;
  account_holders_manager_.account_name_ = account_name_;
  boost::posix_time::ptime last_confirmed_update =
      boost::posix_time::microsec_clock::universal_time();
  account_holders_manager_.last_update_ = last_confirmed_update;

  // Call 1 - FindNodes fails to parse
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t1(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kFindNodesParseError, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_EQ(last_confirmed_update, account_holders_manager_.last_update_);
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 2 - FindNodes result is failure
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t2(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kFindNodesFailure, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_EQ(last_confirmed_update, account_holders_manager_.last_update_);
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 3 - FindNodes returns only a few contacts
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t3(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(few_pmids_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  for (size_t i = 0; i != few_pmids_.size(); ++i)
    ASSERT_TRUE(ContactHasId(few_pmids_.at(i), test_account_holders_.at(i)));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 4 - FindNodes returns K contacts
  ++test_rpcs_in_flight_;
  boost::thread t4(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(good_pmids_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  for (size_t i = 0; i != good_pmids_.size(); ++i)
    ASSERT_TRUE(ContactHasId(good_pmids_.at(i), test_account_holders_.at(i)));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 5 - FindNodes returns K contacts - set AHM's ID to one of the
  //          good_pmids_' IDs to fake getting our own ID in response.
  account_holders_manager_.pmid_ = good_pmids_.back();
  account_holders_manager_.account_name_ = good_pmid_account;
  ++test_rpcs_in_flight_;
  boost::thread t5(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_EQ(good_pmid_account, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(good_pmids_.size() - 1,
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  for (size_t i = 0; i != good_pmids_.size() - 1; ++i)
    ASSERT_TRUE(ContactHasId(good_pmids_.at(i), test_account_holders_.at(i)));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
}

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_UpdateRequired) {
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time() -
      account_holders_manager_.kMaxUpdateInterval_ +
      boost::posix_time::milliseconds(100);
  ASSERT_FALSE(account_holders_manager_.UpdateRequired());
  boost::this_thread::sleep(boost::posix_time::milliseconds(101));
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());

  ASSERT_LE(account_holders_manager_.kMaxFailedNodes_, kad::K);
  for (boost::uint16_t i = 0; i != kad::K; ++i) {
    std::string name = co_.Hash(base::RandomString(100), "",
                                crypto::STRING_STRING, false);
    if (i < account_holders_manager_.kMaxFailedNodes_ - 1)
      account_holders_manager_.failed_ids_.insert(name);
    kad::Contact node(name, "192.168.1.1", 5000 + i);
    account_holders_manager_.account_holder_group_.push_back(node);
  }
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time();
  ASSERT_FALSE(account_holders_manager_.UpdateRequired());
  account_holders_manager_.failed_ids_.insert(
      account_holders_manager_.account_holder_group_.back().node_id().
      ToStringDecoded());
  ASSERT_EQ(account_holders_manager_.kMaxFailedNodes_,
            account_holders_manager_.failed_ids_.size());
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());

  account_holders_manager_.failed_ids_.clear();
  for (boost::uint16_t i = 0;
       i != account_holders_manager_.kMaxFailsPerNode_ - 1; ++i) {
    account_holders_manager_.failed_ids_.insert(
        account_holders_manager_.account_holder_group_.back().node_id().
        ToStringDecoded());
  }
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time();
  ASSERT_FALSE(account_holders_manager_.UpdateRequired());
  account_holders_manager_.failed_ids_.insert(
      account_holders_manager_.account_holder_group_.back().node_id().
      ToStringDecoded());
  ASSERT_EQ(account_holders_manager_.kMaxFailsPerNode_,
            account_holders_manager_.failed_ids_.count(
                account_holders_manager_.account_holder_group_.back().node_id().
                ToStringDecoded()));
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());
}

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_ReportFailure) {
  // Set up expectations
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(account_name_, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));

  // Fake initialisation
  account_holders_manager_.do_nothing_ = boost::bind(
      &AccountHoldersManager::DoNothing, &account_holders_manager_, _1, _2);
  account_holders_manager_.pmid_ = pmid_;
  account_holders_manager_.account_name_ = account_name_;
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time();
  // Set with 1 extra contact to allow testing only size after update
  for (boost::uint16_t i = 0; i != kad::K + 1; ++i) {
    std::string name = co_.Hash(base::RandomString(100), "",
                                crypto::STRING_STRING, false);
    kad::Contact node(name, "192.168.1.1", 5000 + i);
    account_holders_manager_.account_holder_group_.push_back(node);
  }

  // Call with ID of node not in AccountHolderGroup
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(kad::K, account_holders_manager_.account_holder_group().size());
  std::string non_entry(co_.Hash(base::RandomString(100), "",
                                 crypto::STRING_STRING, false));
  account_holders_manager_.ReportFailure(non_entry);
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(kad::K, account_holders_manager_.account_holder_group().size());

  // Call with good ID, but while already updating
  account_holders_manager_.update_in_progress_ = true;
  std::string good_id = account_holders_manager_.account_holder_group_.
      at(base::RandomUint32() % kad::K).node_id().ToStringDecoded();
  account_holders_manager_.ReportFailure(good_id);
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(kad::K, account_holders_manager_.account_holder_group().size());
  account_holders_manager_.update_in_progress_ = false;

  // Call with kMaxFailedNodes_ single good IDs
  for (boost::uint16_t i = 0; i != account_holders_manager_.kMaxFailedNodes_;
       ++i) {
    account_holders_manager_.ReportFailure(account_holders_manager_.
        account_holder_group_.at(i).node_id().ToStringDecoded());
    if (i != account_holders_manager_.kMaxFailedNodes_ - 1)
      ASSERT_EQ(i + 1, account_holders_manager_.failed_ids_.size());
    else
      ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  }
  ASSERT_EQ(good_pmids_.size(), kad::K);
  ASSERT_EQ(kad::K, account_holders_manager_.account_holder_group().size());

  // Call kMaxFailsPerNode_ times with a good ID
  std::string name = co_.Hash(base::RandomString(100), "",
                              crypto::STRING_STRING, false);
  kad::Contact node(name, "192.168.1.1", 6050);
  account_holders_manager_.account_holder_group_.push_back(node);
  ASSERT_NE(kad::K, account_holders_manager_.account_holder_group().size());
  good_id = account_holders_manager_.account_holder_group_.
            at(base::RandomUint32() % kad::K).node_id().ToStringDecoded();
  for (boost::uint16_t i = 0; i != account_holders_manager_.kMaxFailsPerNode_;
       ++i) {
    account_holders_manager_.ReportFailure(good_id);
    if (i != account_holders_manager_.kMaxFailsPerNode_ - 1)
      ASSERT_EQ(i + 1, account_holders_manager_.failed_ids_.size());
    else
      ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  }
  ASSERT_EQ(kad::K, account_holders_manager_.account_holder_group().size());
}

}  // namespace maidsafe
