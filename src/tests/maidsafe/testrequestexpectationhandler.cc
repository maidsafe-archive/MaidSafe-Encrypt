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
}

}  // namespace maidsafe_vault
