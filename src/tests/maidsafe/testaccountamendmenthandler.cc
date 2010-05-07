/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for AccountAmendmentHandler class using mock
*               VaultServiceLogic class
* Version:      1.0
* Created:      2010-01-12-14.48.34
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "maidsafe/vault/accountamendmenthandler.h"
#include "maidsafe/vault/accountrepository.h"
#include "tests/maidsafe/mockvaultservicelogic.h"
#include "tests/maidsafe/mockkadops.h"

namespace test_aah {

class CallbacksHolder {
 public:
  CallbacksHolder(boost::mutex *mutex, boost::condition_variable *cv)
      : mutex_(mutex), cv_(cv), called_back_count_(0) {}
  void callback() {
    boost::mutex::scoped_lock lock(*mutex_);
    ++called_back_count_;
//    printf("Called back count: %i\n", called_back_count_);
    cv_->notify_one();
  }
  int called_back_count() {
    boost::mutex::scoped_lock lock(*mutex_);
    return called_back_count_;
  }
 private:
  boost::mutex *mutex_;
  boost::condition_variable *cv_;
  int called_back_count_;
};

bool CheckAcc(const std::string &account_pmid,
              const boost::uint64_t &space_offered,
              const boost::uint64_t &vault_used,
              const boost::uint64_t &account_used,
              maidsafe_vault::AccountHandler *ah) {
  boost::uint64_t got_space_offered(0);
  boost::uint64_t got_vault_used(0);
  boost::uint64_t got_account_used(0);
  if (ah->GetAccountInfo(account_pmid, &got_space_offered, &got_vault_used,
      &got_account_used) != maidsafe::kSuccess)
    return false;
//  printf("We think - offer: %llu, v_used: %llu, a_used: %llu\n",
//         space_offered, vault_used, account_used);
//  printf("It says  - offer: %llu, v_used: %llu, a_used: %llu\n",
//         got_space_offered, got_vault_used, got_account_used);
  return (space_offered == got_space_offered &&
          vault_used == got_vault_used &&
          account_used == got_account_used);
}

}  // namespace test_aah

namespace maidsafe_vault {

class AccountAmendmentHandlerTest : public MockVaultServiceLogicTest {
 protected:
  AccountAmendmentHandlerTest()
    : ah_(true),
      vsl_(boost::shared_ptr<VaultRpcs>(), boost::shared_ptr<kad::KNode>()),
      aah_(&ah_, &vsl_) {}
  ~AccountAmendmentHandlerTest() {}
  AccountHandler ah_;
  MockVsl vsl_;
  AccountAmendmentHandler aah_;
};

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_AAH_AssessAmendment) {
  // Setup
  const int kTestRuns(4);
  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  // Set chunk name as far as possible from our ID so we don't get added to
  // vector of close nodes in vsl_.HandleFindKNodesResponse
  std::string far_chunk_name =
      crypto_.Obfuscate(pmid_, std::string(64, -1), crypto::XOR);
  std::string test_account_name = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  std::vector<PendingAmending> pendings;
  for (int i = 0; i < kTestRuns; ++i) {
    maidsafe::AmendAccountResponse response;
    response.set_pmid(pmid_);
    response.set_standby(false);
    responses.push_back(response);
    test_aah::CallbacksHolder cbh(&mutex, &cv);
    maidsafe::AmendAccountRequest request;
    request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
    request.set_account_pmid(test_account_name);
    maidsafe::SignedSize *mutable_signed_size = request.mutable_signed_size();
    mutable_signed_size->set_data_size(1000);
    mutable_signed_size->set_pmid(good_pmids_.at(i));
    mutable_signed_size->set_signature("IrrelevantSig");
    mutable_signed_size->set_public_key("IrrelevantPubKey");
    mutable_signed_size->set_public_key_signature("IrrelevantPubKeySig");
    request.set_chunkname(test_account_name);
    request.set_confirmation_required(false);
    requests.push_back(request);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&requests.at(i), &responses.at(i), done);
    pendings.push_back(pending);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  AccountAmendment test_amendment(test_account_name, 2, 1000, true,
      pendings.at(0));
  test_amendment.account_name = kad::KadId(test_account_name, false);

  // Add account to AccountHolder and amendment to aah_ so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));
  std::pair<AccountAmendmentSet::iterator, bool> p =
      aah_.amendments_.insert(test_amendment);
  ASSERT_TRUE(p.second);
  boost::mutex::scoped_lock lock(aah_.amendment_mutex_);

  // Run 1 - Before FindKNodes response has arrived
  int test_run(1);
  boost::uint64_t exp_time = test_amendment.expiry_time;
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong name
  int result = aah_.AssessAmendment("Wrong", 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong field
  result = aah_.AssessAmendment(test_account_name, 1, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong amount
  result = aah_.AssessAmendment(test_account_name, 2, 1001, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong flag
  result = aah_.AssessAmendment(test_account_name, 2, 1000, false,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Request already pending
  result = aah_.AssessAmendment(test_account_name, 2, 1000, true,
      pendings.at(0), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // OK
  result = aah_.AssessAmendment(test_account_name, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Run 2 - After FindKNodes response has arrived
  ++test_run;
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().find(test_amendment);
  bool found = (it != aah_.amendments_.get<by_timestamp>().end());
  ASSERT_TRUE(found);
  // Set Chunk Info holders so that kKadStoreThreshold - 2 have responded
  ASSERT_LE(kKadUpperThreshold, good_pmids_.size() - 3);
  ASSERT_GE(kKadUpperThreshold, 3);
  for (size_t i = 0; i < static_cast<size_t>(kKadUpperThreshold - 1); ++i)
    test_amendment.chunk_info_holders.insert(std::pair<std::string, bool>
        (good_pmids_.at(i), true));
  for (size_t i = static_cast<size_t>(kKadUpperThreshold - 1);
       i < good_pmids_.size(); ++i)
    test_amendment.chunk_info_holders.insert(std::pair<std::string, bool>
        (good_pmids_.at(i), false));
  test_amendment.success_count = kKadUpperThreshold - 2;
  aah_.amendments_.get<by_timestamp>().replace(it, test_amendment);

  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong name
  result = aah_.AssessAmendment("Wrong", 2, 1000, true, pendings.at(test_run),
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong field
  result = aah_.AssessAmendment(test_account_name, 1, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong amount
  result = aah_.AssessAmendment(test_account_name, 2, 1001, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong flag
  result = aah_.AssessAmendment(test_account_name, 2, 1000,
      false, pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Not in list of Chunk Info holders
  result = aah_.AssessAmendment(test_account_name, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders, but having already been accounted for
  maidsafe::AmendAccountRequest request;
  maidsafe::SignedSize *sz = request.mutable_signed_size();
  sz->set_pmid(good_pmids_.at(0));
  PendingAmending pending1(&request, pendings.at(test_run).response,
      pendings.at(test_run).done);

  result = aah_.AssessAmendment(test_account_name, 2, 1000, true, pending1,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(),
            test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending,
            test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders and not having already been accounted for
  sz->set_pmid(good_pmids_.at(good_pmids_.size() - 3));
  PendingAmending pending2(&request, pendings.at(test_run).response,
      pendings.at(test_run).done);

  result = aah_.AssessAmendment(test_account_name, 2, 1000, true, pending2,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(),
            test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(1), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold - 1),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending,
            test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders and not having already been accounted for
  google::protobuf::Closure *done1 = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  sz->set_pmid(good_pmids_.at(good_pmids_.size() - 2));
  PendingAmending pending3(&request, pendings.at(test_run).response, done1);

  result = aah_.AssessAmendment(test_account_name, 2, 1000, true, pending3,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(kKadUpperThreshold),
            test_amendment.success_count);
  ASSERT_EQ(kSuccess, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Run 3 - After all but one amendment requests have arrived
  ++test_run;
  it = aah_.amendments_.get<by_timestamp>().find(test_amendment);
  found = (it != aah_.amendments_.get<by_timestamp>().end());
  ASSERT_TRUE(found);
  // Set success_count to chunk_info_holders.size() - 1
  test_amendment.success_count = test_amendment.chunk_info_holders.size() - 1;
  aah_.amendments_.get<by_timestamp>().replace(it, test_amendment);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(good_pmids_.size() - 1, test_amendment.success_count);
  ASSERT_EQ(kSuccess, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  google::protobuf::Closure *done2 = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  sz->set_pmid(good_pmids_.at(good_pmids_.size() - 1));
  PendingAmending pending4(&request, pendings.at(test_run).response, done2);

  result = aah_.AssessAmendment(test_account_name, 2, 1000, true, pending4,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentFinished, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.ToStringDecoded());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(good_pmids_.size(), test_amendment.success_count);
  ASSERT_EQ(kSuccess, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_AAH_CreateNewAmendment) {
  // Setup
  const int kTestRuns(6);
  vsl_.our_details_ = our_contact_;

  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  // Set chunk name as far as possible from our ID so we don't get added to
  // vector of close nodes in vsl_.HandleFindKNodesResponse
  std::string far_chunk_name =
      crypto_.Obfuscate(pmid_, std::string(64, -1), crypto::XOR);
  std::string test_account_name = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  for (int i = 0; i < kTestRuns; ++i) {
    maidsafe::AmendAccountRequest request;
    request.set_chunkname(far_chunk_name);
    request.set_confirmation_required(false);
    requests.push_back(request);
    maidsafe::AmendAccountResponse response;
    response.set_pmid(pmid_);
    response.set_standby(false);
    responses.push_back(response);
  }
  std::vector<AccountAmendment> test_amendments;
  for (int i = 0; i < kTestRuns; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&requests.at(i), &responses.at(i), done);
    AccountAmendment amendment(test_account_name, 2, 1000, true, pending);
    amendment.account_name = kad::KadId(test_account_name, false);
    test_amendments.push_back(amendment);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  // Add account to AccountHolder so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));

  // Expectations
  EXPECT_CALL(*vsl_.kadops(), FindKClosestNodes(kad::KadId(far_chunk_name,
                                                           false),
      testing::An<const kad::VoidFunctorOneString&>()))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_parse_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 5
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));  // Cll 6

  // Call 1 - Fail to parse FindNodes response
  int test_run(0);
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
  }
  int expected_called_back_count(1);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 2 - FindNodes response has failed result
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
  }
  ++expected_called_back_count;
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 3 - FindNodes response only has one found node
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
  }
  ++expected_called_back_count;
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 4 - FindNodes response good.  Only send one AmendmentRequest, so
  // handler doesn't call back with response (waiting for further requests)
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
  }
  ++expected_called_back_count;
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(0), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(kad::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kAccountAmendmentPending, (*it).account_amendment_result);
  for (int i = 0; i < kad::K; ++i) {
    AccountAmendment amendment = *it;
    std::map<std::string, bool>::iterator cih_it =
        amendment.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amendment.chunk_info_holders.end() == cih_it;
    ASSERT_FALSE(res);
    ASSERT_FALSE((*cih_it).second);
  }

  // Call 5 - FindNodes response good.  Send kad::K AmendmentRequests, but with
  // mis-matching PMIDs so handler doesn't call back with responses (waiting for
  // further requests from each)
  ++test_run;
//  printf("Run %i\n", test_run);
  // Force further kad::K probable_pendings into test_amendment
  std::vector<maidsafe::AmendAccountRequest> bad_requests;
  std::vector<maidsafe::AmendAccountResponse> bad_responses;
  for (int i = 0; i < kad::K; ++i) {
    maidsafe::AmendAccountRequest request;
    bad_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    resp.set_standby(false);
    bad_responses.push_back(resp);
  }
  for (int i = 0; i < kad::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(
        &cbh, &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&bad_requests.at(i), &bad_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
  }

  expected_called_back_count += (kad::K + 1);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  for (int i = 0; i < kad::K; ++i) {
    ASSERT_TRUE(bad_responses.at(i).IsInitialized());
    ASSERT_EQ(kNack, static_cast<int>(bad_responses.at(i).result()));
  }
  ASSERT_EQ(size_t(2), aah_.amendments_.size());
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(0), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(kad::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kAccountAmendmentPending, (*it).account_amendment_result);
  std::map<std::string, bool>::iterator cih_it;
  for (int i = 0; i < kad::K; ++i) {
    AccountAmendment amendment = *it;
    std::map<std::string, bool>::iterator cih_it =
        amendment.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amendment.chunk_info_holders.end() == cih_it;
    ASSERT_FALSE(res);
    ASSERT_FALSE((*cih_it).second);
  }

  // Call 6 - FindNodes response good.  Send kad::K AmendmentRequests with
  // matching PMIDs to achieve overall success
  ++test_run;
//  printf("Run %i\n", test_run);
  // Force further kad::K probable_pendings into test_amendment
  std::vector<maidsafe::AmendAccountRequest> good_requests;
  std::vector<maidsafe::AmendAccountResponse> good_responses;
  for (int i = 0; i < kad::K; ++i) {
    maidsafe::AmendAccountRequest request;
    maidsafe::SignedSize *sz = request.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    good_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    resp.set_standby(false);
    good_responses.push_back(resp);
  }
  for (int i = 0; i < kad::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&good_requests.at(i), &good_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(3), aah_.amendments_.size());
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!responses.at(test_run).IsInitialized())
      cv.wait(lock);
    for (int i = 0; i < kad::K; ++i) {
      while (!good_responses.at(i).IsInitialized())
        cv.wait(lock);
    }
  }

  expected_called_back_count += (kad::K + 1);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(size_t(kad::K), good_responses.size());
  for (int i = 0; i < kad::K; ++i) {
    ASSERT_TRUE(good_responses.at(i).IsInitialized());
    ASSERT_EQ(kAck, static_cast<int>(good_responses.at(i).result()));
  }
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(kad::K), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(kad::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kSuccess, (*it).account_amendment_result);
  for (int i = 0; i < kad::K; ++i) {
    AccountAmendment amd = *it;
    std::map<std::string, bool>::iterator cih_it =
        amd.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amd.chunk_info_holders.end() != cih_it;
    ASSERT_TRUE(res);
    ASSERT_TRUE((*cih_it).second);
  }

  // Shouldn't re-add amendment
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(3), aah_.amendments_.size());

  // Shouldn't re-add amendment
  aah_.CreateNewAmendmentCallback(test_amendments.at(test_run), good_result_);
  ASSERT_EQ(size_t(3), aah_.amendments_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_AAH_ProcessRequest) {
  // Setup
  vsl_.pmid_ = pmid_;
  vsl_.pmid_public_signature_ = pmid_public_signature_;
  vsl_.pmid_private_ = pmid_private_;
  vsl_.online_ = true;
  vsl_.our_details_ = our_contact_;
  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  std::string account_owner = crypto_.Hash("Owner", "", crypto::STRING_STRING,
      false);
  std::string account_name = crypto_.Hash(account_owner + kAccount, "",
      crypto::STRING_STRING, false);
  std::string chunk_name = crypto_.Hash("Chunk", "", crypto::STRING_STRING,
      false);
  maidsafe::AmendAccountRequest request;
  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
  request.set_account_pmid(account_owner);
  maidsafe::SignedSize *sz = request.mutable_signed_size();
  sz->set_data_size(1000);
  sz->set_pmid("IrrelevantPmid");
  sz->set_signature("IrrelevantSig");
  sz->set_public_key("IrrelevantPubKey");
  sz->set_public_key_signature("IrrelevantPubKeySig");
  request.set_chunkname(chunk_name);
  request.set_confirmation_required(false);
  const maidsafe::AmendAccountRequest kDefaultRequest(request);
  maidsafe::AmendAccountResponse response;
  response.set_pmid(pmid_);
  response.set_standby(false);
  const maidsafe::AmendAccountResponse kDefaultResponse(response);
  google::protobuf::Closure *done;
  // Add account to AccountHolder so amend can succeed
  boost::uint64_t offer(100000);
  boost::uint64_t v_used(0);
  boost::uint64_t acc_used(0);
  ASSERT_EQ(kSuccess, ah_.AddAccount(account_owner, offer));
  // Add another 10 accounts for fun
  std::string other(account_owner);
  for (char x = 'a'; x < 'k'; ++x) {
    ASSERT_EQ(kSuccess,
              ah_.AddAccount(other.replace(other.size() - 1, 1, 1, x), offer));
  }
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, v_used, acc_used, &ah_));
  ASSERT_EQ(size_t(11), ah_.accounts_.size());

  // Expectations
  EXPECT_CALL(*vsl_.kadops(), FindKClosestNodes(kad::KadId(chunk_name, false),
      testing::An<const kad::VoidFunctorOneString&>()))
      .Times(testing::AtLeast(5))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_result_, _1))))  // Call 5
      .WillRepeatedly(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));

  // Call 1 - Request has wrong type
  int test_run(0);
//  printf("Run %i\n", test_run);
  request.set_amendment_type(
      maidsafe::AmendAccountRequest::kSpaceOffered);
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kAmendAccountTypeError, aah_.ProcessRequest(&request, &response,
      done));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 2 - Check we can't exceed kMaxRepeatedAccountAmendments
  ASSERT_LT(kMaxRepeatedAccountAmendments, kMaxAccountAmendments);
  ++test_run;
//  printf("Run %i\n", test_run);
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  for (size_t i = 0; i < kMaxRepeatedAccountAmendments - 1; ++i) {
    PendingAmending pending(&request, &response, done);
    AccountAmendment amendment(account_owner, 2, 1000, true, pending);
    std::pair<AccountAmendmentSet::iterator, bool> p =
        aah_.amendments_.insert(amendment);
    ASSERT_TRUE(p.second);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  ASSERT_EQ(kMaxRepeatedAccountAmendments, aah_.amendments_.size());
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kAmendAccountCountError, aah_.ProcessRequest(&request, &response,
      done));
  ASSERT_EQ(kMaxRepeatedAccountAmendments, aah_.amendments_.size());

  // Call 3 - Check we can't exceed kMaxAccountAmendments
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.amendments_.clear();
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  for (size_t i = 0; i < kMaxAccountAmendments - 1; ++i) {
    PendingAmending pending(&request, &response, done);
    AccountAmendment amendment(account_owner, 2, 1000 + i, true, pending);
    std::pair<AccountAmendmentSet::iterator, bool> p =
        aah_.amendments_.insert(amendment);
    ASSERT_TRUE(p.second);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  ASSERT_EQ(kMaxAccountAmendments, aah_.amendments_.size());
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kAmendAccountCountError, aah_.ProcessRequest(&request, &response,
      done));
  ASSERT_EQ(kMaxAccountAmendments, aah_.amendments_.size());

  // Call 4 - Successfully add new amendment
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.amendments_.clear();
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, v_used, acc_used, &ah_));

  // Call 5 - Add new amendment but FindNodes result fails which removes amendmt
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.amendments_.clear();
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, v_used, acc_used, &ah_));
  ASSERT_EQ(size_t(11), ah_.accounts_.size());

  // Call 6 - Add new amendment and populate FindNodes result with good nodes.
  // Our PMID may get added in vsl->HandleFindKNodesResponse as a closest node.
  // In this case we will end up with 2 amendments pending, the main one (with
  // 15 good requests) and the new one generated by our PMID.
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.amendments_.clear();
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  std::vector<google::protobuf::Closure*> callbacks;
  for (int i = 0; i < kad::K; ++i) {
    maidsafe::AmendAccountRequest req(kDefaultRequest);
    maidsafe::AmendAccountResponse resp(kDefaultResponse);
    maidsafe::SignedSize *sz = req.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    requests.push_back(req);
    responses.push_back(resp);
    google::protobuf::Closure *done2 = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    callbacks.push_back(done2);
  }
  // Send requests
  for (int i = 0; i < kad::K; ++i) {
    ASSERT_EQ(kSuccess, aah_.ProcessRequest(&requests.at(i), &responses.at(i),
              callbacks.at(i)));
  }
  while (cbh.called_back_count() < 7 + kad::K)
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  int success_count(0);
  for (int i = 1; i < kad::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  ASSERT_EQ(success_count, kad::K - 1);
  ASSERT_EQ(aah_.amendments_.size(), size_t(0));
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, 1000, acc_used, &ah_));
  ASSERT_EQ(size_t(11), ah_.accounts_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_AAH_CleanUp) {
  // Empty set
  ASSERT_EQ(0, aah_.CleanUp());

  // Add 100 amendments
  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  std::string account_owner = crypto_.Hash("Owner", "", crypto::STRING_STRING,
      false);
  std::string chunk_name = crypto_.Hash("Chunk", "", crypto::STRING_STRING,
      false);
  maidsafe::AmendAccountRequest request;
  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
  request.set_account_pmid(account_owner);
  maidsafe::SignedSize *sz = request.mutable_signed_size();
  sz->set_data_size(1000);
  request.set_chunkname(chunk_name);
  request.set_confirmation_required(false);
  const maidsafe::AmendAccountRequest kDefaultRequest(request);
  maidsafe::AmendAccountResponse response;
  response.set_pmid(pmid_);
  response.set_standby(false);
  const maidsafe::AmendAccountResponse kDefaultResponse(response);
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  std::vector<google::protobuf::Closure*> callbacks;
  for (int i = 0; i < 100; ++i) {
    maidsafe::AmendAccountRequest req(kDefaultRequest);
    maidsafe::AmendAccountResponse resp(kDefaultResponse);
    requests.push_back(req);
    responses.push_back(resp);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    callbacks.push_back(done);
  }
  for (int i = 0; i < 100; ++i) {
    PendingAmending pending(&requests.at(i), &responses.at(i), callbacks.at(i));
    AccountAmendment amendment(account_owner, 2, 1000, true, pending);
    std::pair<AccountAmendmentSet::iterator, bool> p =
        aah_.amendments_.insert(amendment);
    ASSERT_TRUE(p.second);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(size_t(100), aah_.amendments_.size());
  // Check no fresh ones get removed
  ASSERT_EQ(0, aah_.CleanUp());
  ASSERT_EQ(size_t(100), aah_.amendments_.size());

  // Set expiry time back on one
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().begin();
  ++it;
  AccountAmendment amendment = *it;
  amendment.expiry_time = base::GetEpochMilliseconds() - 1000;
  aah_.amendments_.get<by_timestamp>().replace(it, amendment);
  ASSERT_EQ(1, aah_.CleanUp());
  ASSERT_EQ(size_t(99), aah_.amendments_.size());

  // Set expiry time back on 20
  it = aah_.amendments_.get<by_timestamp>().begin();
  for (int i = 0; i < 20; ++i, ++it) {
    AccountAmendment amendment = *it;
    amendment.expiry_time = base::GetEpochMilliseconds() - 1000;
    aah_.amendments_.get<by_timestamp>().replace(it, amendment);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(20, aah_.CleanUp());
  ASSERT_EQ(size_t(79), aah_.amendments_.size());

  // Set expiry time back on rest
  it = aah_.amendments_.get<by_timestamp>().begin();
  while (it != aah_.amendments_.get<by_timestamp>().end()) {
    AccountAmendment amendment = *it;
    amendment.expiry_time = base::GetEpochMilliseconds() - 1000;
    aah_.amendments_.get<by_timestamp>().replace(it, amendment);
    ++it;
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(79, aah_.CleanUp());
  ASSERT_TRUE(aah_.amendments_.empty());
}

}  // namespace maidsafe_vault
