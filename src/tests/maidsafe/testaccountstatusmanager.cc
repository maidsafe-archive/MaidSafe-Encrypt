/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for AccountStatusManager class.
* Created:      2010-05-19
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
#include "maidsafe/pdutils.h"
#include "maidsafe/accountstatusmanager.h"

namespace maidsafe {

namespace test {

class AccountStatusManagerTest : public testing::Test {
 public:
  AccountStatusManagerTest() : ahm_(),
                               offered_(-1),
                               given_(-1),
                               taken_(-1),
                               mutex_(),
                               cond_var_(),
                               count_(0) {}
  void ThreadedUpdate() {
      boost::thread thr(&AccountStatusManagerTest::Update, this);
  }
  bool Ready(int expected) { return count_ == expected; }
 protected:
  void Update() {
    boost::this_thread::sleep(boost::posix_time::milliseconds(
        (base::RandomUint32() % 400) + 100));
    boost::mutex::scoped_lock lock(mutex_);
    ++offered_;
    ++given_;
    ++taken_;
    ++count_;
    ahm_.SetAccountStatus(offered_, given_, taken_);
    cond_var_.notify_one();
  }
  AccountStatusManager ahm_;
  boost::uint64_t offered_, given_, taken_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  int count_;
};

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_Init) {
  EXPECT_EQ(0U, ahm_.space_offered_);
  EXPECT_EQ(0U, ahm_.space_given_);
  EXPECT_EQ(0U, ahm_.space_taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_TRUE(ahm_.reserved_values_.empty());
  EXPECT_TRUE(ahm_.update_functor_.empty());
  bool result = boost::thread::id() == ahm_.worker_thread_.get_id();
  EXPECT_TRUE(result);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  EXPECT_EQ(0U, ahm_.amendments_since_update_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AbleToStore) {
  EXPECT_TRUE(ahm_.AbleToStore(0));
  EXPECT_FALSE(ahm_.AbleToStore(1));
  ahm_.space_given_ = 100;
  EXPECT_TRUE(ahm_.AbleToStore(0));
  EXPECT_FALSE(ahm_.AbleToStore(1));
  ahm_.space_offered_ = 1000;
  EXPECT_TRUE(ahm_.AbleToStore(0));
  EXPECT_TRUE(ahm_.AbleToStore(1000));
  EXPECT_FALSE(ahm_.AbleToStore(1001));
  ahm_.space_taken_ = 200;
  EXPECT_TRUE(ahm_.AbleToStore(800));
  EXPECT_FALSE(ahm_.AbleToStore(801));
  ahm_.space_reserved_ = 300;
  EXPECT_TRUE(ahm_.AbleToStore(500));
  EXPECT_FALSE(ahm_.AbleToStore(501));
  ahm_.space_offered_ = 400;
  EXPECT_FALSE(ahm_.AbleToStore(0));
  EXPECT_FALSE(ahm_.AbleToStore(1));
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_SetAndGetAccountStatus) {
  EXPECT_NE(0U, offered_);
  EXPECT_NE(0U, given_);
  EXPECT_NE(0U, taken_);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(0U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);

  ahm_.space_offered_ = 10;
  ahm_.space_given_ = 9;
  ahm_.space_taken_ = 8;
  ahm_.amendments_since_update_ = 20;
  ahm_.awaiting_update_result_ = true;
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(10U, offered_);
  EXPECT_EQ(9U, given_);
  EXPECT_EQ(8U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(20, ahm_.amendments_since_update_);
  EXPECT_TRUE(ahm_.awaiting_update_result_);

  ahm_.space_reserved_ = 5;
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(10U, offered_);
  EXPECT_EQ(9U, given_);
  EXPECT_EQ(13U, taken_);
  EXPECT_EQ(5U, ahm_.space_reserved_);
  EXPECT_EQ(20, ahm_.amendments_since_update_);
  EXPECT_TRUE(ahm_.awaiting_update_result_);

  ahm_.SetAccountStatus(3, 2, 1);
  EXPECT_EQ(3U, ahm_.space_offered_);
  EXPECT_EQ(2U, ahm_.space_given_);
  EXPECT_EQ(1U, ahm_.space_taken_);
  EXPECT_EQ(5U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);

  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(3U, offered_);
  EXPECT_EQ(2U, given_);
  EXPECT_EQ(6U, taken_);
  EXPECT_EQ(5U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_ReserveAndUnReserveSpace) {
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_TRUE(ahm_.reserved_values_.empty());

  // Check reserving values works
  boost::uint64_t kNotReservedValue =
      static_cast<boost::uint64_t>(boost::uint32_t(-1)) + 1 +
      base::RandomUint32();
  const size_t kRepeats(1000);
  std::vector<boost::uint32_t> values;
  boost::uint32_t value(0);
  boost::uint64_t total(0);
  std::multiset<boost::uint64_t>::iterator it = ahm_.reserved_values_.end();
  for (size_t i = 0; i < kRepeats; ++i) {
    if (i != kRepeats - 1)  // force last value to be repeated
      value = base::RandomUint32();
    ahm_.ReserveSpace(value);
    values.push_back(value);
    total += values.at(i);
    EXPECT_EQ(total, ahm_.space_reserved_);
    EXPECT_EQ(i + 1, ahm_.reserved_values_.size());
    it = ahm_.reserved_values_.find(value);
    bool found = it != ahm_.reserved_values_.end();
    EXPECT_TRUE(found);
  }

  // Check value never reserved doesn't affect total when unreserved
  ahm_.UnReserveSpace(kNotReservedValue);
  EXPECT_EQ(total, ahm_.space_reserved_);
  EXPECT_EQ(kRepeats, ahm_.reserved_values_.size());

  // Check all reserved values can be unreserved
  for (size_t i = 0; i < kRepeats; ++i) {
    ahm_.UnReserveSpace(values.at(i));
    total -= values.at(i);
    EXPECT_EQ(total, ahm_.space_reserved_);
    EXPECT_EQ(kRepeats - 1 - i, ahm_.reserved_values_.size());
  }
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_StartAndStopUpdating) {
  EXPECT_TRUE(ahm_.update_functor_.empty());
  bool success = (ahm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (ahm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (ahm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  ahm_.StopUpdating();
  EXPECT_TRUE(ahm_.update_functor_.empty());
  success = (ahm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (ahm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (ahm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  boost::posix_time::ptime expected_expiry_time =
      boost::posix_time::microsec_clock::universal_time() +
      ahm_.kMaxUpdateInterval_;
  ahm_.StartUpdating(boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                 boost::ref(*this)));
  success = (ahm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  boost::posix_time::ptime expiry_time = ahm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  EXPECT_FALSE(ahm_.update_functor_.empty());
  success = (ahm_.work_.get() != NULL);
  EXPECT_TRUE(success);
  success = (ahm_.worker_thread_ != boost::thread());
  EXPECT_TRUE(success);

  ahm_.StopUpdating();
  EXPECT_TRUE(ahm_.update_functor_.empty());
  success = (ahm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (ahm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (ahm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  expected_expiry_time = boost::posix_time::microsec_clock::universal_time() +
                         ahm_.kMaxUpdateInterval_;
  ahm_.StartUpdating(boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                 boost::ref(*this)));
  success = (ahm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  expiry_time = ahm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  EXPECT_FALSE(ahm_.update_functor_.empty());
  success = (ahm_.work_.get() != NULL);
  EXPECT_TRUE(success);
  success = (ahm_.worker_thread_ != boost::thread());
  EXPECT_TRUE(success);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_DoUpdate) {
  // Try before updating started
  boost::system::error_code test_error;
  const boost::posix_time::milliseconds kTestTimeout(1000);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  EXPECT_TRUE(ahm_.update_functor_.empty());
  EXPECT_EQ(0, count_);
  ahm_.DoUpdate(test_error);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0, count_);

  // Start updating and try with error code != operation_aborted
  ahm_.StartUpdating(boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                 boost::ref(*this)));
  ASSERT_FALSE(ahm_.update_functor_.empty());
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  test_error = boost::asio::error::fault;
  ahm_.DoUpdate(test_error);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0, count_);

  // Try with error code == operation_aborted
  EXPECT_FALSE(ahm_.update_functor_.empty());
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  test_error = boost::asio::error::operation_aborted;
  ahm_.DoUpdate(test_error);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0, count_);

  // Try while awaiting_update_result_ == true
  EXPECT_FALSE(ahm_.update_functor_.empty());
  ahm_.awaiting_update_result_ = true;
  test_error = boost::system::error_code();
  boost::posix_time::ptime expiry_before = ahm_.timer_->expires_at();
  ahm_.DoUpdate(test_error);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0, count_);
  boost::posix_time::ptime expiry_after = ahm_.timer_->expires_at();
  EXPECT_TRUE(expiry_before < expiry_after);

  // Try while awaiting_update_result_ == false (should run functor)
  EXPECT_FALSE(ahm_.update_functor_.empty());
  ahm_.awaiting_update_result_ = false;
  expiry_before = expiry_after;
  ahm_.DoUpdate(test_error);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_TRUE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(1, count_);
  expiry_after = ahm_.timer_->expires_at();
  EXPECT_TRUE(expiry_before < expiry_after);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AmendmentDone) {
  ASSERT_LT(9, ahm_.kMaxAmendments_) << "kMaxAmendments is too low to allow "
      "test to run to completion.";
  ahm_.StartUpdating(boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                 boost::ref(*this)));
  ASSERT_FALSE(ahm_.update_functor_.empty());

  // Call AmendmentDone repeatedly, but not enough to trigger an update
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(0U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceOffered, 123);
  EXPECT_EQ(1, ahm_.amendments_since_update_);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(boost::uint64_t(123), offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  EXPECT_EQ(0, count_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceGivenInc, 234);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(234U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, count_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 345);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(234U, given_);
  EXPECT_EQ(345U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, count_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceGivenInc, 67);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 56);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(301U, given_);
  EXPECT_EQ(401U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, count_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceGivenDec, 2);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenDec, 22);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(299U, given_);
  EXPECT_EQ(379U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, count_);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceGivenDec, 300);
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenDec, 500);
  ahm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(9, ahm_.amendments_since_update_);
  EXPECT_EQ(0, count_);

  // Set test to trigger update for next call to AmendmentDone
  const boost::uint64_t kOfferedBefore(offered_);
  const boost::uint64_t kGivenBefore(given_);
  const boost::uint64_t kTakenBefore(taken_);
  const boost::posix_time::milliseconds kTestTimeout(1000);
  const int kRepeats(10);
  for (int i = 0; i < kRepeats; ++i) {
    ahm_.amendments_since_update_ = ahm_.kMaxAmendments_;
    EXPECT_FALSE(ahm_.awaiting_update_result_);
    EXPECT_FALSE(ahm_.update_functor_.empty());
    ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 11);
    try {
      boost::mutex::scoped_lock lock(mutex_);
      bool success = cond_var_.timed_wait(lock, kTestTimeout,
          boost::bind(&AccountStatusManagerTest::Ready, this, 1 + i));
      EXPECT_TRUE(success);
    }
    catch(const std::exception &e) {
      FAIL() << e.what();
    }
    EXPECT_EQ(kOfferedBefore + 1 + i, offered_);
    EXPECT_EQ(kGivenBefore + 1 + i, given_);
    EXPECT_EQ(kTakenBefore + 1 + i, taken_);
    EXPECT_EQ(0U, ahm_.space_reserved_);
    EXPECT_EQ(0, ahm_.amendments_since_update_);
    EXPECT_EQ(1 + i, count_);
  }

  // Try calling AmendmentDone while awaiting_update_result_ == true
  ahm_.amendments_since_update_ = ahm_.kMaxAmendments_;
  ahm_.awaiting_update_result_ = true;
  ahm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 11);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1 + kRepeats));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(kOfferedBefore + kRepeats, offered_);
  EXPECT_EQ(kGivenBefore + kRepeats, given_);
  EXPECT_EQ(kTakenBefore + kRepeats, taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(26, ahm_.amendments_since_update_);
  EXPECT_EQ(kRepeats, count_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_UpdateFailed) {
  ahm_.awaiting_update_result_ = true;
  EXPECT_EQ(0U, ahm_.space_offered_);
  EXPECT_EQ(0U, ahm_.space_given_);
  EXPECT_EQ(0U, ahm_.space_taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_EQ(0, count_);

  // Try before updating started
  const boost::posix_time::milliseconds kTestTimeout(1000);
  ahm_.UpdateFailed();
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0U, ahm_.space_offered_);
  EXPECT_EQ(0U, ahm_.space_given_);
  EXPECT_EQ(0U, ahm_.space_taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_EQ(0, count_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);

  // Start updating
  boost::posix_time::ptime expected_expiry_time =
      boost::posix_time::microsec_clock::universal_time() +
      ahm_.kMaxUpdateInterval_;
  ahm_.StartUpdating(boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                 boost::ref(*this)));
  bool success = (ahm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  boost::posix_time::ptime expiry_time = ahm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  ASSERT_FALSE(ahm_.update_functor_.empty());
  ahm_.awaiting_update_result_ = true;
  // Modify kFailureRetryInterval_ to reduce test time
  const_cast<boost::posix_time::milliseconds&>(ahm_.kFailureRetryInterval_) =
      boost::posix_time::milliseconds(5000);
  expected_expiry_time = boost::posix_time::microsec_clock::universal_time() +
                         ahm_.kFailureRetryInterval_;
  ahm_.UpdateFailed();
  success = (ahm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  expiry_time = ahm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0U, ahm_.space_offered_);
  EXPECT_EQ(0U, ahm_.space_given_);
  EXPECT_EQ(0U, ahm_.space_taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_EQ(0, count_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
  offered_ = given_ = taken_ = 0;

  // Sleep to let failure retry happen
  boost::this_thread::sleep(ahm_.kFailureRetryInterval_);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_TRUE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(1U, ahm_.space_offered_);
  EXPECT_EQ(1U, ahm_.space_given_);
  EXPECT_EQ(1U, ahm_.space_taken_);
  EXPECT_EQ(0U, ahm_.space_reserved_);
  EXPECT_EQ(0, ahm_.amendments_since_update_);
  EXPECT_EQ(1, count_);
  EXPECT_FALSE(ahm_.awaiting_update_result_);
}

}  // namespace test

}  // namespace maidsafe
