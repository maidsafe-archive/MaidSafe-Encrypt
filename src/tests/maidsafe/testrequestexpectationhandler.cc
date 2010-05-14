/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for RequestExpectationHandler class
* Version:      1.0
* Created:      2010-05-13-19.39.12
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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
#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/requestexpectationhandler.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe_vault {

class RequestExpectationHandlerTest : public testing::Test {
 public:
  RequestExpectationHandlerTest()
      : co_(),
        chunkname_(co_.Hash(base::RandomString(100), "",
                            crypto::STRING_STRING, false)),
        account_pmid_(co_.Hash(base::RandomString(100), "",
                               crypto::STRING_STRING, false)),
        public_key_("Insignificant"),
        public_key_signature_("Insignificant"),
        request_signature_("Insignificant"),
        amender_pmids_(),
        expect_amendment_request_(),
        request_expectation_handler_(kMaxAccountAmendments,
                                     kMaxRepeatedAccountAmendments, 60000) {}
 protected:
  void SetUp() {
    ASSERT_EQ(crypto::SHA_512, co_.hash_algorithm());
    expect_amendment_request_.set_amendment_type(
        maidsafe::AmendAccountRequest::kSpaceTakenInc);
    expect_amendment_request_.set_chunkname(chunkname_);
    expect_amendment_request_.set_account_pmid(account_pmid_);
    expect_amendment_request_.set_public_key(public_key_);
    expect_amendment_request_.set_public_key_signature(public_key_signature_);
    expect_amendment_request_.set_request_signature(request_signature_);
    for (boost::uint16_t i = 0; i < kad::K; ++i) {
      amender_pmids_.push_back(co_.Hash(base::RandomString(100), "",
                                        crypto::STRING_STRING, false));
      expect_amendment_request_.add_amender_pmids(amender_pmids_.at(i));
    }
  }
  void TearDown() {}
  crypto::Crypto co_;
  std::string chunkname_, account_pmid_, public_key_, public_key_signature_;
  std::string request_signature_;
  std::vector<std::string> amender_pmids_;
  maidsafe::ExpectAmendmentRequest expect_amendment_request_;
  RequestExpectationHandler request_expectation_handler_;
};

TEST_F(RequestExpectationHandlerTest, BEH_MAID_REH_AddSingleExpectation) {
  ASSERT_EQ(kSuccess,
      request_expectation_handler_.AddExpectation(expect_amendment_request_));
  ASSERT_EQ(size_t(1), request_expectation_handler_.expectations_.size());
  bool result = amender_pmids_ ==
      (*request_expectation_handler_.expectations_.begin()).second.callers_ids;
  ASSERT_TRUE(result);
}

TEST_F(RequestExpectationHandlerTest, BEH_MAID_REH_TooManyExpectations) {
  std::string new_name(chunkname_);
  for (size_t j = 0; j != request_expectation_handler_.kMaxExpectations_ + 1;
       ++j) {
    new_name.replace(0, 10, boost::lexical_cast<std::string>(1000000000 + j));
    expect_amendment_request_.set_chunkname(new_name);
    if (j < request_expectation_handler_.kMaxExpectations_) {
      ASSERT_EQ(kSuccess, request_expectation_handler_.AddExpectation(
                          expect_amendment_request_));
      ASSERT_EQ(j + 1, request_expectation_handler_.expectations_.size());
    } else {
      ASSERT_EQ(kRequestExpectationCountError,
                request_expectation_handler_.AddExpectation(
                    expect_amendment_request_));
      ASSERT_EQ(j, request_expectation_handler_.expectations_.size());
    }
  }
}

TEST_F(RequestExpectationHandlerTest, BEH_MAID_REH_TooManyRepeats) {
  for (size_t j = 0;
       j != request_expectation_handler_.kMaxRepeatedExpectations_ + 1; ++j) {
    if (j < request_expectation_handler_.kMaxRepeatedExpectations_) {
      ASSERT_EQ(kSuccess, request_expectation_handler_.AddExpectation(
                          expect_amendment_request_));
      ASSERT_EQ(j + 1, request_expectation_handler_.expectations_.size());
    } else {
      ASSERT_EQ(kRequestExpectationCountError,
                request_expectation_handler_.AddExpectation(
                    expect_amendment_request_));
      ASSERT_EQ(j, request_expectation_handler_.expectations_.size());
    }
  }
}

TEST_F(RequestExpectationHandlerTest, BEH_MAID_REH_GetExpectedCallersIds) {
  // Add expectation to be retrieved later
  ASSERT_EQ(kSuccess,
      request_expectation_handler_.AddExpectation(expect_amendment_request_));

  // Amend the vector of ids and add again
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  std::vector<std::string> second_ids;
  expect_amendment_request_.clear_amender_pmids();
  for (boost::uint16_t i = 0; i < kad::K; ++i) {
    second_ids.push_back(co_.Hash(base::RandomString(100), "",
                                  crypto::STRING_STRING, false));
    expect_amendment_request_.add_amender_pmids(second_ids.at(i));
  }
  ASSERT_EQ(kSuccess,
      request_expectation_handler_.AddExpectation(expect_amendment_request_));

  // Add more expectations
  expect_amendment_request_.clear_amender_pmids();
  for (boost::uint16_t i = 0; i < kad::K; ++i) {
    expect_amendment_request_.add_amender_pmids(co_.Hash(
        base::RandomString(100), "", crypto::STRING_STRING, false));
  }
  std::string new_name(chunkname_);
  for (size_t j = 0; j != request_expectation_handler_.kMaxExpectations_ - 2;
       ++j) {
    new_name.replace(0, 10, boost::lexical_cast<std::string>(1000000000 + j));
    expect_amendment_request_.set_chunkname(new_name);
    ASSERT_EQ(kSuccess, request_expectation_handler_.AddExpectation(
                        expect_amendment_request_));
    ASSERT_EQ(j + 3, request_expectation_handler_.expectations_.size());
  }

  // Retrieve and check first expectation
  maidsafe::AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(
      maidsafe::AmendAccountRequest::kSpaceTakenInc);
  amend_account_request.set_chunkname(chunkname_);
  amend_account_request.set_account_pmid(account_pmid_);
  std::vector<std::string> result_ids =
      request_expectation_handler_.GetExpectedCallersIds(amend_account_request);
  bool result = amender_pmids_ == result_ids;
  ASSERT_TRUE(result);
  ASSERT_EQ(request_expectation_handler_.kMaxExpectations_ - 1,
            request_expectation_handler_.expectations_.size());

  // Retrieve and check second expectation
  result_ids =
      request_expectation_handler_.GetExpectedCallersIds(amend_account_request);
  result = second_ids == result_ids;
  ASSERT_TRUE(result);
  ASSERT_EQ(request_expectation_handler_.kMaxExpectations_ - 2,
            request_expectation_handler_.expectations_.size());

  // Try to retrieve same expectation again
  result_ids =
      request_expectation_handler_.GetExpectedCallersIds(amend_account_request);
  ASSERT_TRUE(result_ids.empty());
  ASSERT_EQ(request_expectation_handler_.kMaxExpectations_ - 2,
            request_expectation_handler_.expectations_.size());

  // Try to retrieve expectation from empty map
  result_ids = second_ids;
  ASSERT_FALSE(result_ids.empty());
  request_expectation_handler_.expectations_.clear();
  ASSERT_TRUE(request_expectation_handler_.expectations_.empty());
  result_ids =
      request_expectation_handler_.GetExpectedCallersIds(amend_account_request);
  ASSERT_TRUE(result_ids.empty());
}

TEST_F(RequestExpectationHandlerTest, BEH_MAID_REH_CleanUp) {
  // Create handler which times out expectations after 1 second
  RequestExpectationHandler another_expectation_handler(kMaxAccountAmendments,
      kMaxRepeatedAccountAmendments, 1000);
  maidsafe::AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(
      maidsafe::AmendAccountRequest::kSpaceTakenInc);
  amend_account_request.set_account_pmid(account_pmid_);

  const size_t test_count(10);
  // We're going to insert test_count expectations - check we can first
  ASSERT_LT(test_count, kMaxAccountAmendments);

  // Add half of all expectations, sleep for 1/2 second then add other half
  std::string new_name(chunkname_), first_id, second_id;
  for (size_t i = 0; i != test_count; ++i) {
    new_name.replace(0, 10, boost::lexical_cast<std::string>(1000000000 + i));
    if (i == 0)
      first_id = new_name;
    if (i == test_count / 2) {
      second_id = new_name;
      boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    }
    expect_amendment_request_.set_chunkname(new_name);
    ASSERT_EQ(kSuccess, another_expectation_handler.AddExpectation(
                        expect_amendment_request_));
  }

  // Check none get removed (none have timed out yet)
  ASSERT_EQ(test_count, another_expectation_handler.expectations_.size());
  ASSERT_EQ(0, another_expectation_handler.CleanUp());
  ASSERT_EQ(test_count, another_expectation_handler.expectations_.size());

  // Check we can retrieve first expectation
  amend_account_request.set_chunkname(first_id);
  std::vector<std::string> result =
      another_expectation_handler.GetExpectedCallersIds(amend_account_request);
  ASSERT_EQ(kad::K, result.size());
  ASSERT_EQ(test_count - 1, another_expectation_handler.expectations_.size());
  result =
      another_expectation_handler.GetExpectedCallersIds(amend_account_request);
  ASSERT_TRUE(result.empty());

  // Wait for 1/2 second and cleanup - should remove remaining first group
  boost::this_thread::sleep(boost::posix_time::milliseconds(510));
  ASSERT_EQ((test_count / 2) - 1,
            static_cast<size_t>(another_expectation_handler.CleanUp()));
  ASSERT_EQ(test_count / 2, another_expectation_handler.expectations_.size());

  // Check we can retrieve second expectation
  amend_account_request.set_chunkname(second_id);
  result =
      another_expectation_handler.GetExpectedCallersIds(amend_account_request);
  ASSERT_EQ(kad::K, result.size());
  ASSERT_EQ((test_count / 2) - 1,
            another_expectation_handler.expectations_.size());

  // Wait for 1/2 second and cleanup - should remove all remaining
  boost::this_thread::sleep(boost::posix_time::milliseconds(510));
  ASSERT_EQ((test_count / 2) - 1,
            static_cast<size_t>(another_expectation_handler.CleanUp()));
  ASSERT_TRUE(another_expectation_handler.expectations_.empty());
}

}  // namespace maidsafe_vault
