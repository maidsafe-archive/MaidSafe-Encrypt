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
#include <algorithm>
#include <limits>
#include "maidsafe/pdutils.h"
#include "maidsafe/accountstatusmanager.h"

namespace maidsafe {

namespace test {

class AccountStatusManagerTest : public testing::Test {
 public:
  AccountStatusManagerTest() : asm_(),
                               offered_(-1),
                               given_(-1),
                               taken_(-1),
                               update_functor_(),
                               mutex_(),
                               cond_var_(),
                               count_(0) {
    update_functor_ = boost::bind(&AccountStatusManagerTest::ThreadedUpdate,
                                  boost::ref(*this));
  }
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
    asm_.SetAccountStatus(offered_, given_, taken_);
    cond_var_.notify_one();
  }
  AccountStatusManager asm_;
  boost::uint64_t offered_, given_, taken_;
  boost::function<void()> update_functor_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  int count_;
};

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_Init) {
  EXPECT_EQ(0U, asm_.space_offered_);
  EXPECT_EQ(0U, asm_.space_given_);
  EXPECT_EQ(0U, asm_.space_taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_TRUE(asm_.reserved_values_.empty());
  EXPECT_TRUE(asm_.update_functor_.empty());
  bool result = boost::thread::id() == asm_.worker_thread_.get_id();
  EXPECT_TRUE(result);
  EXPECT_FALSE(asm_.awaiting_update_result_);
  EXPECT_EQ(0U, asm_.amendments_since_update_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AbleToStore) {
  EXPECT_TRUE(asm_.AbleToStore(0));
  EXPECT_FALSE(asm_.AbleToStore(1));
  asm_.space_given_ = 100;
  EXPECT_TRUE(asm_.AbleToStore(0));
  EXPECT_FALSE(asm_.AbleToStore(1));
  asm_.space_offered_ = 1000;
  EXPECT_TRUE(asm_.AbleToStore(0));
  EXPECT_TRUE(asm_.AbleToStore(1000));
  EXPECT_FALSE(asm_.AbleToStore(1001));
  asm_.space_taken_ = 200;
  EXPECT_TRUE(asm_.AbleToStore(800));
  EXPECT_FALSE(asm_.AbleToStore(801));
  asm_.space_reserved_ = 300;
  EXPECT_TRUE(asm_.AbleToStore(500));
  EXPECT_FALSE(asm_.AbleToStore(501));
  asm_.space_offered_ = 400;
  EXPECT_FALSE(asm_.AbleToStore(0));
  EXPECT_FALSE(asm_.AbleToStore(1));
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_SetAndGetAccountStatus) {
  EXPECT_NE(0U, offered_);
  EXPECT_NE(0U, given_);
  EXPECT_NE(0U, taken_);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(0U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_FALSE(asm_.awaiting_update_result_);

  asm_.space_offered_ = 10;
  asm_.space_given_ = 9;
  asm_.space_taken_ = 8;
  asm_.amendments_since_update_ = 20;
  asm_.awaiting_update_result_ = true;
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(10U, offered_);
  EXPECT_EQ(9U, given_);
  EXPECT_EQ(8U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(20, asm_.amendments_since_update_);
  EXPECT_TRUE(asm_.awaiting_update_result_);

  asm_.space_reserved_ = 5;
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(10U, offered_);
  EXPECT_EQ(9U, given_);
  EXPECT_EQ(13U, taken_);
  EXPECT_EQ(5U, asm_.space_reserved_);
  EXPECT_EQ(20, asm_.amendments_since_update_);
  EXPECT_TRUE(asm_.awaiting_update_result_);

  asm_.SetAccountStatus(3, 2, 1);
  EXPECT_EQ(3U, asm_.space_offered_);
  EXPECT_EQ(2U, asm_.space_given_);
  EXPECT_EQ(1U, asm_.space_taken_);
  EXPECT_EQ(5U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_FALSE(asm_.awaiting_update_result_);

  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(3U, offered_);
  EXPECT_EQ(2U, given_);
  EXPECT_EQ(6U, taken_);
  EXPECT_EQ(5U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_FALSE(asm_.awaiting_update_result_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_ReserveAndUnReserveSpace) {
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_TRUE(asm_.reserved_values_.empty());

  // Check reserving values works
  boost::uint64_t kNotReservedValue =
      static_cast<boost::uint64_t>(boost::uint32_t(-1)) + 1 +
      base::RandomUint32();
  const size_t kRepeats(1000);
  std::vector<boost::uint32_t> values;
  boost::uint32_t value(0);
  boost::uint64_t total(0);
  std::multiset<boost::uint64_t>::iterator it = asm_.reserved_values_.end();
  for (size_t i = 0; i < kRepeats; ++i) {
    if (i != kRepeats - 1)  // force last value to be repeated
      value = base::RandomUint32();
    asm_.ReserveSpace(value);
    values.push_back(value);
    total += values.at(i);
    EXPECT_EQ(total, asm_.space_reserved_);
    EXPECT_EQ(i + 1, asm_.reserved_values_.size());
    it = asm_.reserved_values_.find(value);
    bool found = it != asm_.reserved_values_.end();
    EXPECT_TRUE(found);
  }

  // Check value never reserved doesn't affect total when unreserved
  asm_.UnReserveSpace(kNotReservedValue);
  EXPECT_EQ(total, asm_.space_reserved_);
  EXPECT_EQ(kRepeats, asm_.reserved_values_.size());

  // Check all reserved values can be unreserved
  for (size_t i = 0; i < kRepeats; ++i) {
    asm_.UnReserveSpace(values.at(i));
    total -= values.at(i);
    EXPECT_EQ(total, asm_.space_reserved_);
    EXPECT_EQ(kRepeats - 1 - i, asm_.reserved_values_.size());
  }
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_StartAndStopUpdating) {
  EXPECT_TRUE(asm_.update_functor_.empty());
  bool success = (asm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (asm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (asm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  asm_.StopUpdating();
  EXPECT_TRUE(asm_.update_functor_.empty());
  success = (asm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (asm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (asm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  boost::posix_time::ptime expected_expiry_time =
      boost::posix_time::microsec_clock::universal_time() +
      asm_.kMaxUpdateInterval_;
  asm_.StartUpdating(update_functor_);
  success = (asm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  boost::posix_time::ptime expiry_time = asm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  EXPECT_FALSE(asm_.update_functor_.empty());
  success = (asm_.work_.get() != NULL);
  EXPECT_TRUE(success);
  success = (asm_.worker_thread_ != boost::thread());
  EXPECT_TRUE(success);

  asm_.StopUpdating();
  EXPECT_TRUE(asm_.update_functor_.empty());
  success = (asm_.work_.get() == NULL);
  EXPECT_TRUE(success);
  success = (asm_.worker_thread_ == boost::thread());
  EXPECT_TRUE(success);
  success = (asm_.timer_.get() == NULL);
  EXPECT_TRUE(success);

  expected_expiry_time = boost::posix_time::microsec_clock::universal_time() +
                         asm_.kMaxUpdateInterval_;
  asm_.StartUpdating(update_functor_);
  success = (asm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  expiry_time = asm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  EXPECT_FALSE(asm_.update_functor_.empty());
  success = (asm_.work_.get() != NULL);
  EXPECT_TRUE(success);
  success = (asm_.worker_thread_ != boost::thread());
  EXPECT_TRUE(success);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_DoUpdate) {
  // Try before updating started
  boost::system::error_code test_error;
  const boost::posix_time::milliseconds kTestTimeout(1000);
  EXPECT_FALSE(asm_.awaiting_update_result_);
  EXPECT_TRUE(asm_.update_functor_.empty());
  EXPECT_EQ(0, count_);
  asm_.DoUpdate(test_error);
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
  asm_.StartUpdating(update_functor_);
  ASSERT_FALSE(asm_.update_functor_.empty());
  EXPECT_FALSE(asm_.awaiting_update_result_);
  test_error = boost::asio::error::fault;
  asm_.DoUpdate(test_error);
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
  EXPECT_FALSE(asm_.update_functor_.empty());
  EXPECT_FALSE(asm_.awaiting_update_result_);
  test_error = boost::asio::error::operation_aborted;
  asm_.DoUpdate(test_error);
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
  EXPECT_FALSE(asm_.update_functor_.empty());
  asm_.awaiting_update_result_ = true;
  test_error = boost::system::error_code();
  boost::posix_time::ptime expiry_before = asm_.timer_->expires_at();
  asm_.DoUpdate(test_error);
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
  boost::posix_time::ptime expiry_after = asm_.timer_->expires_at();
  EXPECT_TRUE(expiry_before < expiry_after);

  // Try while awaiting_update_result_ == false (should run functor)
  EXPECT_FALSE(asm_.update_functor_.empty());
  asm_.awaiting_update_result_ = false;
  expiry_before = expiry_after;
  asm_.DoUpdate(test_error);
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
  expiry_after = asm_.timer_->expires_at();
  EXPECT_TRUE(expiry_before < expiry_after);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AmendmentDone) {
  ASSERT_LT(9, asm_.kMaxAmendments_) << "kMaxAmendments is too low to allow "
      "test to run to completion.";
  asm_.StartUpdating(update_functor_);
  ASSERT_FALSE(asm_.update_functor_.empty());

  // Call AmendmentDone repeatedly, but not enough to trigger an update
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(0U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceOffered, 123);
  EXPECT_EQ(1, asm_.amendments_since_update_);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(boost::uint64_t(123), offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_FALSE(asm_.awaiting_update_result_);
  EXPECT_EQ(0, count_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenInc, 234);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(234U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, count_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 345);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(234U, given_);
  EXPECT_EQ(345U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, count_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenInc, 67);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 56);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(301U, given_);
  EXPECT_EQ(401U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, count_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenDec, 2);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenDec, 22);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(299U, given_);
  EXPECT_EQ(379U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, count_);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenDec, 300);
  asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenDec, 500);
  asm_.AccountStatus(&offered_, &given_, &taken_);
  EXPECT_EQ(123U, offered_);
  EXPECT_EQ(0U, given_);
  EXPECT_EQ(0U, taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(9, asm_.amendments_since_update_);
  EXPECT_EQ(0, count_);

  // Set test to trigger update for next call to AmendmentDone
  const boost::uint64_t kOfferedBefore(offered_);
  const boost::uint64_t kGivenBefore(given_);
  const boost::uint64_t kTakenBefore(taken_);
  const boost::posix_time::milliseconds kTestTimeout(1000);
  const int kRepeats(10);
  for (int i = 0; i < kRepeats; ++i) {
    asm_.amendments_since_update_ = asm_.kMaxAmendments_;
    EXPECT_FALSE(asm_.awaiting_update_result_);
    EXPECT_FALSE(asm_.update_functor_.empty());
    asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 11);
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
    EXPECT_EQ(0U, asm_.space_reserved_);
    EXPECT_EQ(0, asm_.amendments_since_update_);
    EXPECT_EQ(1 + i, count_);
  }

  // Try calling AmendmentDone while awaiting_update_result_ == true
  asm_.amendments_since_update_ = asm_.kMaxAmendments_;
  asm_.awaiting_update_result_ = true;
  asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, 11);
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
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(26, asm_.amendments_since_update_);
  EXPECT_EQ(kRepeats, count_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_UpdateFailed) {
  asm_.awaiting_update_result_ = true;
  EXPECT_EQ(0U, asm_.space_offered_);
  EXPECT_EQ(0U, asm_.space_given_);
  EXPECT_EQ(0U, asm_.space_taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_EQ(0, count_);

  // Try before updating started
  const boost::posix_time::milliseconds kTestTimeout(1000);
  asm_.UpdateFailed();
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_FALSE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(0U, asm_.space_offered_);
  EXPECT_EQ(0U, asm_.space_given_);
  EXPECT_EQ(0U, asm_.space_taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_EQ(0, count_);
  EXPECT_FALSE(asm_.awaiting_update_result_);

  // Start updating
  boost::posix_time::ptime expected_expiry_time =
      boost::posix_time::microsec_clock::universal_time() +
      asm_.kMaxUpdateInterval_;
  asm_.StartUpdating(update_functor_);
  bool success = (asm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  boost::posix_time::ptime expiry_time = asm_.timer_->expires_at();
  EXPECT_LE((expiry_time - expected_expiry_time).total_milliseconds(), 50);
  ASSERT_FALSE(asm_.update_functor_.empty());
  asm_.awaiting_update_result_ = true;
  // Modify kFailureRetryInterval_ to reduce test time
  const_cast<boost::posix_time::milliseconds&>(asm_.kFailureRetryInterval_) =
      boost::posix_time::milliseconds(5000);
  expected_expiry_time = boost::posix_time::microsec_clock::universal_time() +
                         asm_.kFailureRetryInterval_;
  asm_.UpdateFailed();
  success = (asm_.timer_.get() != NULL);
  ASSERT_TRUE(success);
  expiry_time = asm_.timer_->expires_at();
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
  EXPECT_EQ(0U, asm_.space_offered_);
  EXPECT_EQ(0U, asm_.space_given_);
  EXPECT_EQ(0U, asm_.space_taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_EQ(0, count_);
  EXPECT_FALSE(asm_.awaiting_update_result_);
  offered_ = given_ = taken_ = 0;

  // Sleep to let failure retry happen
  boost::this_thread::sleep(asm_.kFailureRetryInterval_);
  try {
    boost::mutex::scoped_lock lock(mutex_);
    bool success = cond_var_.timed_wait(lock, kTestTimeout,
        boost::bind(&AccountStatusManagerTest::Ready, this, 1));
    EXPECT_TRUE(success);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  EXPECT_EQ(1U, asm_.space_offered_);
  EXPECT_EQ(1U, asm_.space_given_);
  EXPECT_EQ(1U, asm_.space_taken_);
  EXPECT_EQ(0U, asm_.space_reserved_);
  EXPECT_EQ(0, asm_.amendments_since_update_);
  EXPECT_EQ(1, count_);
  EXPECT_FALSE(asm_.awaiting_update_result_);
}

class FuncAccountStatusManagerTest : public testing::Test {
 public:
  enum JobType { kStoreChunk, kDeleteChunk, kVaultStore, kVaultDelete };
  FuncAccountStatusManagerTest() : given_(10000),
                                   taken_(0),
                                   reserved_(0),
                                   update_thread_(),
                                   mutex_(),
                                   cond_var_(),
                                   thread_count_(0),
                                   update_success_count_(0),
                                   update_failure_count_(0),
                                   kMaxThreadCount_(20),
                                   chunk_sizes_(),
                                   display_output_(false),
                                   asm_() {
    // Set AccountStatusManager's repeat timeouts low for test
    const_cast<boost::posix_time::milliseconds&>(asm_.kMaxUpdateInterval_) =
        boost::posix_time::milliseconds(5000);
    const_cast<boost::posix_time::milliseconds&>(asm_.kFailureRetryInterval_) =
        boost::posix_time::milliseconds(2000);
    asm_.space_given_ = given_;
  }
  ~FuncAccountStatusManagerTest() {
    update_thread_.join();
  }
  void ThreadedJob(JobType job_type, size_t repeats, size_t offset) {
    size_t completed_count(0);
    for (size_t i = offset; i < offset + repeats; ++i) {
      boost::function<void()> functor;
      switch (job_type) {
        case kStoreChunk:
          functor = boost::bind(&FuncAccountStatusManagerTest::StoreChunk,
                                boost::ref(*this), i, &completed_count);
          break;
        case kDeleteChunk:
          functor = boost::bind(&FuncAccountStatusManagerTest::DeleteChunk,
                                boost::ref(*this), i, &completed_count);
          break;
        case kVaultStore:
          functor = boost::bind(&FuncAccountStatusManagerTest::VaultOp,
                                boost::ref(*this), true, &completed_count);
          break;
        case kVaultDelete:
          functor = boost::bind(&FuncAccountStatusManagerTest::VaultOp,
                                boost::ref(*this), false, &completed_count);
          break;
        default:
          return;
      }
      WaitForThread();
      {
        boost::mutex::scoped_lock lock(mutex_);
        ++thread_count_;
      }
      boost::thread thr(functor);
    }
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock, boost::bind(
      &FuncAccountStatusManagerTest::ThreadedJobDone, boost::ref(*this),
      &completed_count, &repeats));
  }
  void ThreadedUpdate() {
    if (!update_thread_.joinable())
      update_thread_ =
          boost::thread(&FuncAccountStatusManagerTest::Update, this);
  }
  bool ThreadAvailable() { return thread_count_ < kMaxThreadCount_; }
  bool ThreadedJobDone(size_t *count, size_t *target) {
    return *count == *target;
  }
 protected:
  void WaitForThread() {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock, boost::bind(
                   &FuncAccountStatusManagerTest::ThreadAvailable, this));
  }
  void StoreChunk(size_t chunk_number, size_t *counter) {
    ASSERT_LT(chunk_number, chunk_sizes_.size()) << "Asked for element " <<
        chunk_number << " in vector of size " << chunk_sizes_.size();
    boost::uint32_t chunk_size(chunk_sizes_.at(chunk_number));
    if (asm_.AbleToStore(chunk_size)) {
      asm_.ReserveSpace(4 * chunk_size);
      {
        boost::mutex::scoped_lock lock(mutex_);
        reserved_ += (4 * chunk_size);
        taken_ += chunk_size;
      }
      boost::this_thread::sleep(boost::posix_time::milliseconds(
          (base::RandomUint32() % 400) + 100));
      asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc, chunk_size);
      asm_.UnReserveSpace(4 * chunk_size);
      boost::mutex::scoped_lock lock(mutex_);
      reserved_ -= (4 * chunk_size);
      --thread_count_;
      ++(*counter);
      if (display_output_)
        printf("StoredChunk OK %u:\t%u\tTotal: %u\n", *counter, chunk_size,
               asm_.space_taken_);
      cond_var_.notify_all();
    } else {
      boost::mutex::scoped_lock lock(mutex_);
      --thread_count_;
      ++(*counter);
      if (display_output_)
        printf("StoredChunk FAIL %u:\t%u\tTotal: %u\n", *counter, chunk_size,
               asm_.space_taken_);
      cond_var_.notify_all();
    }
  }
  void DeleteChunk(size_t chunk_number, size_t *counter) {
    ASSERT_LT(chunk_number, chunk_sizes_.size());
    {
      boost::mutex::scoped_lock lock(mutex_);
      taken_ -= chunk_sizes_.at(chunk_number);
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(
        (base::RandomUint32() % 400) + 100));
    asm_.AmendmentDone(AmendAccountRequest::kSpaceTakenDec,
                       chunk_sizes_.at(chunk_number));
    boost::mutex::scoped_lock lock(mutex_);
    --thread_count_;
    ++(*counter);
    if (display_output_)
      printf("DeletedChunk %u:\t%u\tTotal: %u\n", *counter,
             chunk_sizes_.at(chunk_number), asm_.space_taken_);
    cond_var_.notify_all();
  }
  void VaultOp(bool given, size_t *counter) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (given)
        ++given_;
      else
        --given_;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(
        (base::RandomUint32() % 400) + 100));
    if (given)
      asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenInc, 1);
    else
      asm_.AmendmentDone(AmendAccountRequest::kSpaceGivenDec, 1);
    boost::mutex::scoped_lock lock(mutex_);
    --thread_count_;
    ++(*counter);
    if (display_output_) {
      if (given)
        printf("   VaultStored %u\n", *counter);
      else
        printf("      VaultDeleted %u\n", *counter);
    }
    cond_var_.notify_all();
  }
  void Update() {
    boost::uint32_t rnd((base::RandomUint32() % 400) + 100);
    bool successful_update = rnd < 420;  // Succeed ~ 80% of attempts
    {  // Ensure at least one success and failure
      boost::mutex::scoped_lock lock(mutex_);
      if (update_success_count_ == 0)
        successful_update = true;
      else if (update_failure_count_ == 0)
        successful_update = false;
      if (successful_update)
        ++update_success_count_;
      else
        ++update_failure_count_;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(rnd));
    if (successful_update) {
      // Don't want to modify asm_'s values so that they can be checked at the
      // end of the test.
      if (display_output_)
        printf("\t\t\t\t\t\t\tUpdate SUCCESS\n");
      asm_.SetAccountStatus(asm_.space_offered_, asm_.space_given_,
                            asm_.space_taken_);
    } else {
      if (display_output_)
        printf("\t\t\t\t\t\t\tUpdate FAILURE\n");
      asm_.UpdateFailed();
    }
  }
  boost::uint64_t AsmSpaceOffered() { return asm_.space_offered_; }
  boost::uint64_t AsmSpaceGiven() { return asm_.space_given_; }
  boost::uint64_t AsmSpaceTaken() { return asm_.space_taken_; }
  boost::uint64_t AsmSpaceReserved() { return asm_.space_reserved_; }
  boost::mutex mutex_;
  boost::uint64_t given_, taken_, reserved_;
  boost::thread update_thread_;
  boost::condition_variable cond_var_;
  size_t thread_count_, update_success_count_, update_failure_count_;
  const size_t kMaxThreadCount_;
  std::vector<boost::uint32_t> chunk_sizes_;
  bool display_output_;
  AccountStatusManager asm_;
};

TEST_F(FuncAccountStatusManagerTest, BEH_MAID_ASM_StoreNotEnoughSpace) {
  // Set up vector of chunk sizes
  const size_t kTotalRepeats(100);
  boost::uint64_t total_size_of_chunks(0);
  for (size_t i = 0; i < kTotalRepeats; ++i) {
    chunk_sizes_.push_back(base::RandomUint32());
    total_size_of_chunks += chunk_sizes_.at(i);
  }

  // Start AccountStatusManager updating and set space offered too low
  asm_.StartUpdating(
      boost::bind(&FuncAccountStatusManagerTest::ThreadedUpdate, this));
  asm_.AmendmentDone(AmendAccountRequest::kSpaceOffered,
                     total_size_of_chunks / 2);
  ASSERT_EQ(total_size_of_chunks / 2, AsmSpaceOffered());
  ASSERT_EQ(10000U, given_);
  ASSERT_EQ(given_, AsmSpaceGiven());
  ASSERT_EQ(0U, taken_);
  ASSERT_EQ(taken_, AsmSpaceTaken());
  ASSERT_EQ(0U, reserved_);
  ASSERT_EQ(reserved_, AsmSpaceReserved());

  // "Store" chunks
  ThreadedJob(kStoreChunk, kTotalRepeats, 0);
  EXPECT_EQ(total_size_of_chunks / 2, AsmSpaceOffered());
  EXPECT_EQ(10000U, given_);
  EXPECT_EQ(given_, AsmSpaceGiven());
  EXPECT_LE(taken_, AsmSpaceOffered() + *std::max_element(chunk_sizes_.begin(),
                                                          chunk_sizes_.end()));
  EXPECT_EQ(taken_, AsmSpaceTaken());
  EXPECT_EQ(0U, reserved_);
  EXPECT_EQ(reserved_, AsmSpaceReserved());
}

TEST_F(FuncAccountStatusManagerTest, FUNC_MAID_ASM_MultipleFunctions) {
  // Set up vector of chunk sizes
  const size_t kTotalRepeats(1000), kInitialRepeats(500);
  for (size_t i = 0; i < kTotalRepeats; ++i)
    chunk_sizes_.push_back(base::RandomUint32());

  // Start AccountStatusManager updating and set space offered
  asm_.StartUpdating(
      boost::bind(&FuncAccountStatusManagerTest::ThreadedUpdate, this));
  boost::uint64_t offered = static_cast<boost::uint64_t>(
      std::numeric_limits<boost::uint32_t>::max()) * kTotalRepeats * 4;
  asm_.AmendmentDone(AmendAccountRequest::kSpaceOffered, offered);
  ASSERT_EQ(offered, AsmSpaceOffered());
  ASSERT_EQ(10000U, given_);
  ASSERT_EQ(given_, AsmSpaceGiven());
  ASSERT_EQ(0U, taken_);
  ASSERT_EQ(taken_, AsmSpaceTaken());
  ASSERT_EQ(0U, reserved_);
  ASSERT_EQ(reserved_, AsmSpaceReserved());

  // "Store" first group of chunks
  ThreadedJob(kStoreChunk, kInitialRepeats, 0);
  boost::uint64_t stored_total(0);
  for (size_t i = 0; i < kInitialRepeats; ++i)
    stored_total += chunk_sizes_.at(i);
  EXPECT_EQ(offered, AsmSpaceOffered());
  EXPECT_EQ(10000U, given_);
  EXPECT_EQ(given_, AsmSpaceGiven());
  EXPECT_EQ(stored_total, taken_);
  EXPECT_EQ(taken_, AsmSpaceTaken());
  EXPECT_EQ(0U, reserved_);
  EXPECT_EQ(reserved_, AsmSpaceReserved());

  // Run all four type of jobs concurrently
  boost::thread t1(&FuncAccountStatusManagerTest::ThreadedJob, this,
      kStoreChunk, kTotalRepeats - kInitialRepeats, kInitialRepeats);
  boost::thread t2(&FuncAccountStatusManagerTest::ThreadedJob, this,
                   kDeleteChunk, kInitialRepeats, 0);
  boost::thread t3(&FuncAccountStatusManagerTest::ThreadedJob, this,
                   kVaultStore, kTotalRepeats, 0);
  boost::thread t4(&FuncAccountStatusManagerTest::ThreadedJob, this,
                   kVaultDelete, kInitialRepeats, 0);
  t1.join();
  t2.join();
  t3.join();
  t4.join();
  stored_total = 0;
  for (size_t i = kInitialRepeats; i < kTotalRepeats; ++i)
    stored_total += chunk_sizes_.at(i);
  EXPECT_EQ(offered, AsmSpaceOffered());
  EXPECT_EQ(10000U + kTotalRepeats - kInitialRepeats, given_);
  EXPECT_EQ(given_, AsmSpaceGiven());
  EXPECT_EQ(stored_total, taken_);
  EXPECT_EQ(taken_, AsmSpaceTaken());
  EXPECT_EQ(0U, reserved_);
  EXPECT_EQ(reserved_, AsmSpaceReserved());
}

}  // namespace test

}  // namespace maidsafe
