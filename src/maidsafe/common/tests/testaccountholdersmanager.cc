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
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/accountholdersmanager.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/sharedtest/mockkadops.h"

namespace test_ahm {
static const boost::uint8_t K(4);
static const boost::uint8_t upper_threshold(static_cast<boost::uint8_t>
             (K * maidsafe::kMinSuccessfulPecentageStore));
static const boost::uint8_t lower_threshold(
             maidsafe::kMinSuccessfulPecentageStore > .25 ?
             static_cast<boost::uint8_t >(K * .25) : upper_threshold);
}  // namespace test_ahm

namespace maidsafe {

namespace test {

class AccountHoldersManagerTest : public testing::Test {
 public:
  AccountHoldersManagerTest()
      : pmid_(SHA512String(base::RandomString(100))),
        account_name_(SHA512String(pmid_ + kAccount)),
        transport_handler_(),
        channel_manager_(&transport_handler_),
        chunkstore_(new ChunkStore("Chunkstore", 9999999, 0)),
        mock_kad_ops_(new MockKadOps(&transport_handler_, &channel_manager_,
                      kad::CLIENT, "", "", false, false, test_ahm::K,
                      chunkstore_)),
        few_far_contacts_(),
        few_close_contacts_(),
        close_contacts_(),
        fail_result_(mock_kadops::MakeFindNodesResponse(
            mock_kadops::kResultFail, account_name_,test_ahm::K, NULL)),
        few_far_result_(mock_kadops::MakeFindNodesResponse(
            mock_kadops::kFarContacts, account_name_, 1, &few_far_contacts_)),
        few_close_result_(mock_kadops::MakeFindNodesResponse(
            mock_kadops::kCloseContacts, account_name_, 1,
            &few_close_contacts_)),
        far_result_(mock_kadops::MakeFindNodesResponse(
            mock_kadops::kFarContacts, account_name_, test_ahm::K, NULL)),
        close_result_(mock_kadops::MakeFindNodesResponse(
            mock_kadops::kCloseContacts, account_name_, test_ahm::K,
            &close_contacts_)),
        account_holders_manager_(mock_kad_ops_, test_ahm::lower_threshold),
        test_rpcs_in_flight_(0),
        kSingleRpcTimeout_(60),
        test_mutex_(),
        test_cond_var_(),
        test_return_code_(kPendingResult),
        test_account_holders_(),
        test_functor_() {}
 protected:
  void SetUp() {
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
    if (!account_holders_manager_.failed_ids_.empty())
      test_return_code_ = kBPSerialiseError;
     if (account_holders_manager_.update_in_progress_)
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
  std::string pmid_, account_name_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<ChunkStore> chunkstore_;
  boost::shared_ptr<MockKadOps> mock_kad_ops_;
  std::vector<kad::Contact> few_far_contacts_, few_close_contacts_,
                            close_contacts_;
  std::string fail_result_, few_far_result_, few_close_result_, far_result_,
              close_result_;
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
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), fail_result_, _1))))        // Call 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), close_result_, _1))));      // Call 2

  // Uninitialised
  ASSERT_TRUE(account_holders_manager_.account_name().empty());
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 1 - FindNodes fails - still uninitialised (except
  //          account_name_)
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t1(&AccountHoldersManager::Init, &account_holders_manager_,
      pmid_, test_functor_);
  ASSERT_NE(kSuccess, WaitForCallback());
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_TRUE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 2 - FindNodes returns K contacts - now initialised
  ++test_rpcs_in_flight_;
  boost::thread t2(&AccountHoldersManager::Init, &account_holders_manager_,
      pmid_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(boost::posix_time::microsec_clock::universal_time() -
            boost::posix_time::seconds(1),
            account_holders_manager_.last_update_);
  ASSERT_EQ(close_contacts_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(TestVectorsEqual(close_contacts_,
      account_holders_manager_.account_holder_group()));
}

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_UpdateGroup) {
  std::string far_inc_result;
  {
    kad::FindResponse find_response;
    find_response.ParseFromString(far_result_);
    kad::Contact contact(pmid_, "127.0.0.1", 0);
    std::string ser_contact;
    contact.SerialiseToString(&ser_contact);
    find_response.set_closest_nodes(0, ser_contact);
    find_response.SerializeToString(&far_inc_result);
  }
  
  // Set up expectations
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(account_name_, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), fail_result_, _1))))        // Call 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), few_close_result_, _1))))   // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), few_far_result_, _1))))     // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), close_result_, _1))))       // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), far_result_, _1))))         // Call 5
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), far_inc_result, _1))));     // Call 6

  // Fake initialisation
  account_holders_manager_.do_nothing_ = boost::bind(
      &AccountHoldersManager::DoNothing, &account_holders_manager_, _1, _2);
  account_holders_manager_.pmid_ = pmid_;
  account_holders_manager_.account_name_ = account_name_;
  boost::posix_time::ptime last_confirmed_update =
      boost::posix_time::microsec_clock::universal_time();
  account_holders_manager_.last_update_ = last_confirmed_update;

  // Call 1 - FindNodes fails
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t1(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_NE(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_TRUE(test_account_holders_.empty());
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_EQ(last_confirmed_update, account_holders_manager_.last_update_);
  ASSERT_TRUE(account_holders_manager_.account_holder_group().empty());

  // Call 2 - FindNodes returns only a few close contacts
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t2(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(few_close_contacts_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(TestVectorsEqual(few_close_contacts_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 3 - FindNodes returns only a few far contacts
  test_account_holders_.push_back(kad::Contact());
  ++test_rpcs_in_flight_;
  boost::thread t3(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(few_far_contacts_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(TestVectorsEqual(few_far_contacts_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 4 - FindNodes returns K contacts close to the account ID
  ++test_rpcs_in_flight_;
  boost::thread t4(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(close_contacts_.size(),
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(TestVectorsEqual(close_contacts_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 5 - FindNodes returns K contacts far from the account ID
  ++test_rpcs_in_flight_;
  boost::thread t5(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(test_ahm::K - 1,
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  boost::this_thread::sleep(boost::posix_time::milliseconds(1));

  // Call 6 - FindNodes returns K far contacts, including our PMID
  ++test_rpcs_in_flight_;
  boost::thread t6(&AccountHoldersManager::UpdateGroup,
      &account_holders_manager_, test_functor_);
  ASSERT_EQ(kSuccess, WaitForCallback());
  ASSERT_FALSE(account_holders_manager_.update_in_progress_);
  ASSERT_EQ(account_name_, account_holders_manager_.account_name());
  ASSERT_FALSE(account_holders_manager_.last_update_.is_neg_infinity());
  ASSERT_LT(last_confirmed_update, account_holders_manager_.last_update_);
  last_confirmed_update = account_holders_manager_.last_update_;
  ASSERT_EQ(test_ahm::K - 1,
            account_holders_manager_.account_holder_group().size());
  ASSERT_TRUE(TestVectorsEqual(test_account_holders_,
      account_holders_manager_.account_holder_group()));
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

  ASSERT_LE(account_holders_manager_.kMaxFailedNodes_, test_ahm::K);
  for (boost::uint16_t i = 0; i != test_ahm::K; ++i) {
    std::string name = SHA512String(base::RandomString(100));
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
      String());
  ASSERT_EQ(account_holders_manager_.kMaxFailedNodes_,
            account_holders_manager_.failed_ids_.size());
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());

  account_holders_manager_.failed_ids_.clear();
  if (account_holders_manager_.kMaxFailedNodes_ > 1U) {
    for (boost::uint16_t i = 0;
         i != account_holders_manager_.kMaxFailsPerNode_ - 1; ++i) {
      account_holders_manager_.failed_ids_.insert(
          account_holders_manager_.account_holder_group_.back().node_id().
          String());
    }
  }
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time();
  ASSERT_FALSE(account_holders_manager_.UpdateRequired());
  account_holders_manager_.failed_ids_.insert(
      account_holders_manager_.account_holder_group_.back().node_id().
      String());
  if (account_holders_manager_.kMaxFailedNodes_ > 1U) {
    ASSERT_EQ(account_holders_manager_.kMaxFailsPerNode_,
        account_holders_manager_.failed_ids_.count(
            account_holders_manager_.account_holder_group_.back().node_id().
            String()));
  }
  ASSERT_TRUE(account_holders_manager_.UpdateRequired());
}

TEST_F(AccountHoldersManagerTest, BEH_MAID_AHM_ReportFailure) {
  // Set up expectations
  EXPECT_CALL(*mock_kad_ops_, FindKClosestNodes(account_name_, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), close_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedFindKClosestNodesCallback,
                      mock_kad_ops_.get(), close_result_, _1))));

  // Fake initialisation
  account_holders_manager_.do_nothing_ = boost::bind(
      &AccountHoldersManager::DoNothing, &account_holders_manager_, _1, _2);
  account_holders_manager_.pmid_ = pmid_;
  account_holders_manager_.account_name_ = account_name_;
  account_holders_manager_.last_update_ =
      boost::posix_time::microsec_clock::universal_time();
  // Set with 1 extra contact to allow testing only size after update
  for (boost::uint16_t i = 0; i != test_ahm::K + 1; ++i) {
    std::string name = SHA512String(base::RandomString(100));
    kad::Contact node(name, "192.168.1.1", 5000 + i);
    account_holders_manager_.account_holder_group_.push_back(node);
  }

  // Call with ID of node not in AccountHolderGroup
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(test_ahm::K,
            account_holders_manager_.account_holder_group().size());
  std::string non_entry(SHA512String(base::RandomString(100)));
  account_holders_manager_.ReportFailure(non_entry);
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(test_ahm::K,
            account_holders_manager_.account_holder_group().size());

  // Call with good ID, but while already updating
  {
    boost::mutex::scoped_lock lock(account_holders_manager_.mutex_);
    ASSERT_FALSE(account_holders_manager_.update_in_progress_);
    account_holders_manager_.update_in_progress_ = true;
  }
  std::string good_id = account_holders_manager_.account_holder_group_.
      at(base::RandomUint32() % test_ahm::K).node_id().String();
  account_holders_manager_.ReportFailure(good_id);
  ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  ASSERT_NE(test_ahm::K,
            account_holders_manager_.account_holder_group().size());
  account_holders_manager_.update_in_progress_ = false;

  // Call with kMaxFailedNodes_ single good IDs
  for (boost::uint16_t i = 0; i != account_holders_manager_.kMaxFailedNodes_;
       ++i) {
    account_holders_manager_.ReportFailure(account_holders_manager_.
        account_holder_group_.at(i).node_id().String());
    if (i != account_holders_manager_.kMaxFailedNodes_ - 1)
      ASSERT_EQ(i + 1, account_holders_manager_.failed_ids_.size());
    else
      ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  }
  ASSERT_EQ(close_contacts_.size(), test_ahm::K);
  {
    // wait for update to finish (replaces contacts)
    boost::mutex::scoped_lock lock(account_holders_manager_.mutex_);
    while (account_holders_manager_.update_in_progress_)
      account_holders_manager_.cond_var_.wait(lock);
  }
  ASSERT_EQ(test_ahm::K,
            account_holders_manager_.account_holder_group().size());

  // Call kMaxFailsPerNode_ times with a good ID
  std::string name = SHA512String(base::RandomString(100));
  kad::Contact node(name, "192.168.1.1", 6050);
  account_holders_manager_.account_holder_group_.push_back(node);
  ASSERT_NE(test_ahm::K,
            account_holders_manager_.account_holder_group().size());
  good_id = account_holders_manager_.account_holder_group_.
            at(base::RandomUint32() % test_ahm::K).node_id().String();
  for (boost::uint16_t i = 0; i != account_holders_manager_.kMaxFailsPerNode_;
       ++i) {
    account_holders_manager_.ReportFailure(good_id);
    if (i != account_holders_manager_.kMaxFailsPerNode_ - 1 && i > 0)
      ASSERT_EQ(i + 1, account_holders_manager_.failed_ids_.size());
    else
      ASSERT_TRUE(account_holders_manager_.failed_ids_.empty());
  }
  {
    // wait for update to finish (replaces contacts)
    boost::mutex::scoped_lock lock(account_holders_manager_.mutex_);
    while (account_holders_manager_.update_in_progress_)
      account_holders_manager_.cond_var_.wait(lock);
  }
  ASSERT_EQ(test_ahm::K,
            account_holders_manager_.account_holder_group().size());
}

}  // namespace test

}  // namespace maidsafe
