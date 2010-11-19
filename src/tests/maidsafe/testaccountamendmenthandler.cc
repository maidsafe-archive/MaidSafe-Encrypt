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

#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/accountamendmenthandler.h"
#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/requestexpectationhandler.h"
#include "tests/maidsafe/mockvaultservicelogic.h"
#include "tests/maidsafe/mockkadops.h"

namespace test_aah {

static const boost::uint8_t K(4);
static const boost::uint8_t upper_threshold(static_cast<boost::uint8_t>
                                           (K * kMinSuccessfulPecentageStore));
static const boost::uint8_t lower_threshold(kMinSuccessfulPecentageStore > .25 ?
             static_cast<boost::uint8_t >(K * .25) : upper_threshold);

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

namespace test {

class AccountAmendmentHandlerTest : public MockVaultServiceLogicTest {
 protected:
  AccountAmendmentHandlerTest()
    : MockVaultServiceLogicTest(test_aah::K),
      ah_(true),
      vsl_(boost::shared_ptr<VaultRpcs>(),
           boost::shared_ptr<maidsafe::KadOps>(new maidsafe::MockKadOps(NULL,
           NULL, kad::CLIENT, "", "", false, false, test_aah::K,
           boost::shared_ptr<maidsafe::ChunkStore>()))),
      reh_(kMaxAccountAmendments, kMaxRepeatedAccountAmendments,
           kAccountAmendmentTimeout),
      aah_(&ah_, &reh_, &vsl_, test_aah::upper_threshold) {}
  ~AccountAmendmentHandlerTest() {}
  AccountHandler ah_;
  MockVsl vsl_;
  RequestExpectationHandler reh_;
  AccountAmendmentHandler aah_;
};

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_AssessAmendment) {
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
    requests.push_back(request);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&requests.at(i), &responses.at(i), done);
    pendings.push_back(pending);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  AccountAmendment test_amendment(test_account_name, test_account_name,
                                  maidsafe::AmendAccountRequest::kSpaceGivenInc,
                                  2, 1000, true, pendings.at(0));
  test_amendment.account_name = kad::KadId(test_account_name);

  // Add account to AccountHolder and amendment to aah_ so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));
  std::pair<AccountAmendmentSet::iterator, bool> p;
  p = aah_.amendments_.insert(test_amendment);
  ASSERT_TRUE(p.second);
  boost::mutex::scoped_lock lock(aah_.amendment_mutex_);

  // Run 1 - Before FindKNodes response has arrived
  int test_run(1);
  boost::uint64_t exp_time = test_amendment.expiry_time;
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong name
  int result = aah_.AssessAmendment("Wrong", test_account_name,
    maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
    pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong chunkname
  result = aah_.AssessAmendment(test_account_name, "Wrong",
    maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
    pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong type
  result = aah_.AssessAmendment(test_account_name, test_account_name,
    maidsafe::AmendAccountRequest::kSpaceTakenInc, 2, 1000, true,
    pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong field
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 1, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong amount
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1001, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong flag
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, false,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Request already pending
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
      pendings.at(0), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(1), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // OK
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(size_t(0), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(0), test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // TODO(Team#) make this work with low K
  if (test_aah::upper_threshold <= 3)
    return;

  // Run 2 - After FindKNodes response has arrived
  ++test_run;
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().find(test_amendment);
  bool found = (it != aah_.amendments_.get<by_timestamp>().end());
  ASSERT_TRUE(found);
  // Set Chunk Info holders so that kKadStoreThreshold - 2 have responded
  ASSERT_LE(size_t(test_aah::lower_threshold), good_pmids_.size() - 3);
  for (boost::uint8_t i = 0; i < test_aah::upper_threshold - 1; ++i)
    test_amendment.chunk_info_holders.insert(std::pair<std::string, bool>
        (good_pmids_.at(i), true));
  for (size_t i = static_cast<size_t>(test_aah::upper_threshold - 1);
       i < good_pmids_.size(); ++i)
    test_amendment.chunk_info_holders.insert(std::pair<std::string, bool>
        (good_pmids_.at(i), false));
  test_amendment.success_count = test_aah::upper_threshold - 2;
  aah_.amendments_.get<by_timestamp>().replace(it, test_amendment);

  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong name
  result = aah_.AssessAmendment("Wrong", test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong chunkname
  result = aah_.AssessAmendment(test_account_name, "Wrong",
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong type
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceTakenInc, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong field
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 1, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong amount
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1001, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Wrong flag
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000,
      false, pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // Not in list of Chunk Info holders
  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true,
      pendings.at(test_run), &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders, but having already been accounted for
  maidsafe::AmendAccountRequest request;
  maidsafe::SignedSize *sz = request.mutable_signed_size();
  sz->set_pmid(good_pmids_.at(0));
  PendingAmending pending1(&request, pendings.at(test_run).response,
      pendings.at(test_run).done);

  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending1,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentNotFound, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(),
            test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 2),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending,
            test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders and not having already been accounted for
  sz->set_pmid(good_pmids_.at(good_pmids_.size() - 3));
  PendingAmending pending2(&request, pendings.at(test_run).response,
      pendings.at(test_run).done);

  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending2,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(),
            test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(1), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold - 1),
            test_amendment.success_count);
  ASSERT_EQ(kAccountAmendmentPending,
            test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());

  // In list of Chunk Info holders and not having already been accounted for
  google::protobuf::Closure *done1 = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  sz->set_pmid(good_pmids_.at(good_pmids_.size() - 2));
  PendingAmending pending3(&request, pendings.at(test_run).response, done1);

  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending3,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentUpdated, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(boost::uint16_t(test_aah::upper_threshold),
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
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
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

  result = aah_.AssessAmendment(test_account_name, test_account_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending4,
      &test_amendment);
  ASSERT_EQ(kAccountAmendmentFinished, result);
  ASSERT_EQ(test_account_name, test_amendment.account_name.String());
  ASSERT_EQ(good_pmids_.size(), test_amendment.chunk_info_holders.size());
  ASSERT_EQ(size_t(0), test_amendment.pendings.size());
  ASSERT_EQ(size_t(2), test_amendment.probable_pendings.size());
  ASSERT_EQ(exp_time, test_amendment.expiry_time);
  ASSERT_EQ(good_pmids_.size(), test_amendment.success_count);
  ASSERT_EQ(kSuccess, test_amendment.account_amendment_result);
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_FetchAmendmentResults) {
  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  std::string test_account_name = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  std::string dummy_account_name = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  std::string test_chunkname = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  maidsafe::AmendAccountRequest request;
  maidsafe::AmendAccountResponse response;
  response.set_pmid(pmid_);
  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
  request.set_account_pmid(test_account_name);
  maidsafe::SignedSize *mutable_signed_size = request.mutable_signed_size();
  mutable_signed_size->set_data_size(1000);
  mutable_signed_size->set_pmid(good_pmids_.at(0));
  mutable_signed_size->set_signature("IrrelevantSig");
  mutable_signed_size->set_public_key("IrrelevantPubKey");
  mutable_signed_size->set_public_key_signature("IrrelevantPubKeySig");
  request.set_chunkname(test_chunkname);
  google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  PendingAmending pending(&request, &response, done);

  // Sleep to let timestamps differ.
  boost::this_thread::sleep(boost::posix_time::milliseconds(2));

  AccountAmendment test_amendment(test_account_name, test_chunkname,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending);
  test_amendment.account_name = kad::KadId(test_account_name);
  for (size_t i = 0; i < good_pmids_.size(); ++i)
    test_amendment.chunk_info_holders.insert(std::pair<std::string, bool>
        (good_pmids_.at(i), i > 0));
  test_amendment.success_count = test_aah::upper_threshold;

  // Add account to AccountHolder and amendment to aah_ so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));
  std::pair<AccountAmendmentSet::iterator, bool> p =
      aah_.amendments_.insert(test_amendment);
  ASSERT_TRUE(p.second);

  ASSERT_EQ(size_t(0), aah_.amendment_results_.size());
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());
  ASSERT_EQ(size_t(1), aah_.amendment_results_.size());

  maidsafe::AccountStatusResponse asr;
  aah_.FetchAmendmentResults(dummy_account_name, &asr);
  ASSERT_EQ(0, asr.amendment_results_size());
  aah_.FetchAmendmentResults(test_account_name, &asr);
  ASSERT_EQ(1, asr.amendment_results_size());
  ASSERT_EQ(maidsafe::AmendAccountRequest::kSpaceGivenInc,
            asr.amendment_results(0).amendment_type());
  ASSERT_EQ(test_chunkname, asr.amendment_results(0).chunkname());
  ASSERT_EQ(kAck, asr.amendment_results(0).result());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_CreateNewAmendment) {
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
    requests.push_back(request);
    maidsafe::AmendAccountResponse response;
    response.set_pmid(pmid_);
    responses.push_back(response);
  }
  std::vector<AccountAmendment> test_amendments;
  for (int i = 0; i < kTestRuns; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&requests.at(i), &responses.at(i), done);
    AccountAmendment amendment(test_account_name, far_chunk_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending);
    amendment.account_name = kad::KadId(test_account_name);
    test_amendments.push_back(amendment);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  // Add account to AccountHolder so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));

  // Expectations
  boost::function<void(maidsafe::VoidFuncIntContacts)> fail_parse_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                 vsl_.kadops().get(), fail_parse_result_, _1);
  boost::function<void(maidsafe::VoidFuncIntContacts)> fail_result_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                  vsl_.kadops().get(), fail_result_, _1);
  boost::function<void(maidsafe::VoidFuncIntContacts)> few_result_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                  vsl_.kadops().get(), few_result_, _1);
  boost::function<void(maidsafe::VoidFuncIntContacts)> good_result_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                  vsl_.kadops().get(), good_result_, _1);
  EXPECT_CALL(*vsl_.kadops(), FindKClosestNodes(far_chunk_name,
      testing::An<maidsafe::VoidFuncIntContacts>()))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(fail_parse_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(fail_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(few_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)));

  // Call 1 - Fail to parse FindNodes response
  int test_run(0);
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  EXPECT_TRUE(vsl_.kadops()->Wait());
  int expected_called_back_count(1);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 2 - FindNodes response has failed result
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  EXPECT_TRUE(vsl_.kadops()->Wait());
  ++expected_called_back_count;
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_TRUE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(responses.at(test_run).result()));
  ASSERT_EQ(size_t(0), aah_.amendments_.size());

  // Call 3 - FindNodes response only has one found node
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  EXPECT_TRUE(vsl_.kadops()->Wait());
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
  EXPECT_TRUE(vsl_.kadops()->Wait());
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_FALSE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(0), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kAccountAmendmentPending, (*it).account_amendment_result);
  for (int i = 0; i < test_aah::K; ++i) {
    AccountAmendment amendment = *it;
    std::map<std::string, bool>::iterator cih_it =
        amendment.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amendment.chunk_info_holders.end() == cih_it;
    ASSERT_FALSE(res);
    ASSERT_FALSE((*cih_it).second);
  }

  // Call 5 - FindNodes response good.  Send test_aah::K AmendmentRequests, but
  // with mis-matching PMIDs so handler doesn't call back with responses
  // (waiting for further requests from each)
  ++test_run;
//  printf("Run %i\n", test_run);
  // Force further test_aah::K probable_pendings into test_amendment
  std::vector<maidsafe::AmendAccountRequest> bad_requests;
  std::vector<maidsafe::AmendAccountResponse> bad_responses;
  for (int i = 0; i < test_aah::K; ++i) {
    maidsafe::AmendAccountRequest request;
    bad_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    bad_responses.push_back(resp);
  }
  for (int i = 0; i < test_aah::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(
        &cbh, &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&bad_requests.at(i), &bad_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  EXPECT_TRUE(vsl_.kadops()->Wait());
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_FALSE(responses.at(test_run).IsInitialized());
  for (int i = 0; i < test_aah::K; ++i)
    ASSERT_FALSE(bad_responses.at(i).IsInitialized());
  ASSERT_EQ(size_t(2), aah_.amendments_.size());
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(0), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kAccountAmendmentPending, (*it).account_amendment_result);
  std::map<std::string, bool>::iterator cih_it;
  for (int i = 0; i < test_aah::K; ++i) {
    AccountAmendment amendment = *it;
    std::map<std::string, bool>::iterator cih_it =
        amendment.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amendment.chunk_info_holders.end() == cih_it;
    ASSERT_FALSE(res);
    ASSERT_FALSE((*cih_it).second);
  }

  // Call 6 - FindNodes response good.  Send test_aah::K AmendmentRequests with
  // matching PMIDs to achieve overall success
  ++test_run;
//  printf("Run %i\n", test_run);
  // Force further test_aah::K probable_pendings into test_amendment
  std::vector<maidsafe::AmendAccountRequest> good_requests;
  std::vector<maidsafe::AmendAccountResponse> good_responses;
  for (int i = 0; i < test_aah::K; ++i) {
    maidsafe::AmendAccountRequest request;
    request.set_chunkname(far_chunk_name);
    maidsafe::SignedSize *sz = request.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    good_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    good_responses.push_back(resp);
  }
  test_amendments.at(test_run).probable_pendings.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&good_requests.at(i), &good_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(3), aah_.amendments_.size());
  EXPECT_TRUE(vsl_.kadops()->Wait());

  expected_called_back_count += (test_aah::K);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_EQ(size_t(test_aah::K), good_responses.size());
  for (int i = 0; i < test_aah::K; ++i) {
    ASSERT_TRUE(good_responses.at(i).IsInitialized());
    ASSERT_EQ(kAck, static_cast<int>(good_responses.at(i).result()));
  }
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(test_aah::K), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kSuccess, (*it).account_amendment_result);
  for (int i = 0; i < test_aah::K; ++i) {
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
  aah_.CreateNewAmendmentCallback(test_amendments.at(test_run),
                                  maidsafe::kSuccess, good_contacts_);
  ASSERT_EQ(size_t(3), aah_.amendments_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_CreateNewWithExpecteds) {
  // Setup
  const int kTestRuns(3);
  vsl_.our_details_ = our_contact_;

  boost::mutex mutex;
  boost::condition_variable cv;
  test_aah::CallbacksHolder cbh(&mutex, &cv);
  // Set chunk name as far as possible from our ID so we don't get added to
  // vector of close nodes in vsl_.HandleFindKNodesResponse
  std::string far_chunk_name =
      crypto_.Obfuscate(pmid_, std::string(64, -1), crypto::XOR);
  std::string test_account_pmid = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  std::string test_account_name = crypto_.Hash(test_account_pmid + kAccount, "",
      crypto::STRING_STRING, false);
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  for (int i = 0; i < kTestRuns; ++i) {
    maidsafe::AmendAccountRequest request;
    request.set_chunkname(far_chunk_name);
    request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
    request.set_account_pmid(test_account_pmid);
    requests.push_back(request);
    maidsafe::AmendAccountResponse response;
    response.set_pmid(pmid_);
    responses.push_back(response);
  }
  std::vector<AccountAmendment> test_amendments;
  for (int i = 0; i < kTestRuns; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&requests.at(i), &responses.at(i), done);
    AccountAmendment amendment(test_account_name, far_chunk_name,
      maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending);
    amendment.account_name = kad::KadId(test_account_name);
    test_amendments.push_back(amendment);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  // Add account to AccountHolder so amend can succeed
  ASSERT_EQ(kSuccess, ah_.AddAccount(test_account_name, 999999));

  // Expectations
  EXPECT_CALL(*vsl_.kadops(), FindKClosestNodes(far_chunk_name,
      testing::An<maidsafe::VoidFuncIntContacts>()))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                      vsl_.kadops().get(), good_result_, _1))));

  maidsafe::ExpectAmendmentRequest expect_amendment_request;
  expect_amendment_request.set_amendment_type(
      maidsafe::AmendAccountRequest::kSpaceGivenInc);
  expect_amendment_request.set_chunkname(far_chunk_name);
  expect_amendment_request.set_account_pmid(test_account_pmid);
  expect_amendment_request.set_public_key("Unimportant");
  expect_amendment_request.set_public_key_signature("Unimportant");
  expect_amendment_request.set_request_signature("Unimportant");
  for (boost::uint16_t i = 0; i < test_aah::K; ++i) {
    expect_amendment_request.add_amender_pmids(good_pmids_.at(i));
    // Push first expectation with too few contacts
    if (i == test_aah::upper_threshold - 2)
      ASSERT_EQ(kSuccess, reh_.AddExpectation(expect_amendment_request));
  }
  // Sleep to ensure previous expectation timestamp < this one
  boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  // Good list of pmids
  ASSERT_EQ(kSuccess, reh_.AddExpectation(expect_amendment_request));

  // Sleep to ensure previous expectation timestamp < this one
  boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  // Some good pmids, but not enough
  for (boost::uint16_t i = 0; i < test_aah::K - test_aah::upper_threshold + 1;
       ++i) {
    std::string *bad_pmid = expect_amendment_request.mutable_amender_pmids(i);
    *bad_pmid = crypto_.Hash(
        base::RandomString(100), "", crypto::STRING_STRING, false);
  }
  ASSERT_EQ(kSuccess, reh_.AddExpectation(expect_amendment_request));

  // Call 1 - REH fails to provide enough contacts.  FindNodes response good.
  // Send test_aah::K AmendmentRequests with matching PMIDs to achieve success.
  int test_run(0);
  // Force further test_aah::K probable_pendings into test_amendment
  std::vector<maidsafe::AmendAccountRequest> good_requests;
  std::vector<maidsafe::AmendAccountResponse> good_responses;
  for (int i = 0; i < test_aah::K; ++i) {
    maidsafe::AmendAccountRequest request;
    maidsafe::SignedSize *sz = request.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    request.set_chunkname(far_chunk_name);
    request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
    request.set_account_pmid(test_account_pmid);
    good_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    good_responses.push_back(resp);
  }
  test_amendments.at(test_run).probable_pendings.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&good_requests.at(i), &good_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(1), aah_.amendments_.size());
  EXPECT_TRUE(vsl_.kadops()->Wait());

  int expected_called_back_count(test_aah::K);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_EQ(size_t(test_aah::K), good_responses.size());
  for (int i = 0; i < test_aah::K; ++i) {
    ASSERT_TRUE(good_responses.at(i).IsInitialized());
    ASSERT_EQ(kAck, static_cast<int>(good_responses.at(i).result()));
  }
  AmendmentsByTimestamp::iterator it =
      aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(test_aah::K), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kSuccess, (*it).account_amendment_result);
  for (int i = 0; i < test_aah::K; ++i) {
    AccountAmendment amd = *it;
    std::map<std::string, bool>::iterator cih_it =
        amd.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amd.chunk_info_holders.end() != cih_it;
    ASSERT_TRUE(res);
    ASSERT_TRUE((*cih_it).second);
  }

  // Call 2 - REH provides enough contacts - FindNodes not called.
  // Send test_aah::K AmendmentRequests with matching PMIDs to achieve success.
  ++test_run;
  good_requests.clear();
  good_responses.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    maidsafe::AmendAccountRequest request;
    maidsafe::SignedSize *sz = request.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    request.set_chunkname(far_chunk_name);
    request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
    request.set_account_pmid(test_account_pmid);
    good_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    good_responses.push_back(resp);
  }
  test_amendments.at(test_run).probable_pendings.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&good_requests.at(i), &good_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(2), aah_.amendments_.size());
  {
    boost::mutex::scoped_lock lock(mutex);
    for (int i = 0; i < test_aah::K; ++i) {
      cv.wait(lock,
              boost::bind(&maidsafe::AmendAccountResponse::IsInitialized,
                          &good_responses.at(i)));
    }
  }

  expected_called_back_count += (test_aah::K);
  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_FALSE(responses.at(test_run).IsInitialized());
  ASSERT_EQ(size_t(test_aah::K), good_responses.size());
  for (int i = 0; i < test_aah::K; ++i) {
    ASSERT_TRUE(good_responses.at(i).IsInitialized());
    ASSERT_EQ(kAck, static_cast<int>(good_responses.at(i).result()));
  }
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(test_aah::K), (*it).success_count);
  ASSERT_EQ(size_t(0), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kSuccess, (*it).account_amendment_result);
  for (int i = 0; i < test_aah::K; ++i) {
    AccountAmendment amd = *it;
    std::map<std::string, bool>::iterator cih_it =
        amd.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amd.chunk_info_holders.end() != cih_it;
    ASSERT_TRUE(res);
    ASSERT_TRUE((*cih_it).second);
  }

  // Call 3 - REH provides enough contacts, but some wrong pmids - FindNodes not
  // called.
  ++test_run;
  good_requests.clear();
  good_responses.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    maidsafe::AmendAccountRequest request;
    maidsafe::SignedSize *sz = request.mutable_signed_size();
    sz->set_pmid(good_pmids_.at(i));
    request.set_chunkname(far_chunk_name);
    request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
    request.set_account_pmid(test_account_pmid);
    good_requests.push_back(request);
    maidsafe::AmendAccountResponse resp;
    resp.set_pmid(pmid_);
    good_responses.push_back(resp);
  }
  test_amendments.at(test_run).probable_pendings.clear();
  for (int i = 0; i < test_aah::K; ++i) {
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cbh,
        &test_aah::CallbacksHolder::callback);
    PendingAmending pending(&good_requests.at(i), &good_responses.at(i), done);
    test_amendments.at(test_run).probable_pendings.push_back(pending);
  }
  aah_.CreateNewAmendment(test_amendments.at(test_run));
  ASSERT_EQ(size_t(3), aah_.amendments_.size());
  {
    boost::mutex::scoped_lock lock(mutex);
    for (int i = 0; i < test_aah::K - test_aah::upper_threshold + 1; ++i) {
      cv.timed_wait(lock, boost::posix_time::milliseconds(100),
                    boost::bind(&maidsafe::AmendAccountResponse::IsInitialized,
                                &good_responses.at(i)));
    }
  }

  ASSERT_EQ(expected_called_back_count, cbh.called_back_count());
  ASSERT_EQ(size_t(test_aah::K), good_responses.size());
//  int kacks(0), knacks(0);
  for (int i = 0; i < test_aah::K; ++i) {
    if (i < test_aah::upper_threshold + 2) {
      ASSERT_EQ(kNack, static_cast<int>(good_responses.at(i).result()));
    } else {
      ASSERT_FALSE(good_responses.at(i).IsInitialized());
    }
  }
  it = aah_.amendments_.get<by_timestamp>().find(test_amendments.at(test_run));
  ASSERT_EQ(size_t(test_aah::upper_threshold - 1), (*it).success_count);
  ASSERT_EQ(size_t(test_aah::upper_threshold - 1), (*it).pendings.size());
  ASSERT_EQ(size_t(0), (*it).probable_pendings.size());
  ASSERT_EQ(size_t(test_aah::K), (*it).chunk_info_holders.size());
  ASSERT_EQ(kAccountAmendmentPending, (*it).account_amendment_result);
  for (int i = 0; i < test_aah::K - test_aah::upper_threshold + 1; ++i) {
    AccountAmendment amd = *it;
    std::map<std::string, bool>::iterator cih_it =
        amd.chunk_info_holders.find(good_pmids_.at(i));
    bool res = amd.chunk_info_holders.end() == cih_it;
    if (i < test_aah::upper_threshold + 2) {
      EXPECT_TRUE(res);
    } else {
      EXPECT_FALSE(res);
      EXPECT_TRUE((*cih_it).second);
    }
  }
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_ProcessRequest) {
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
  const maidsafe::AmendAccountRequest kDefaultRequest(request);
  maidsafe::AmendAccountResponse response;
  response.set_pmid(pmid_);
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
  boost::function<void(maidsafe::VoidFuncIntContacts)> fail_result_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                  vsl_.kadops().get(), fail_result_, _1);
  boost::function<void(maidsafe::VoidFuncIntContacts)> good_result_functor =
      boost::bind(&maidsafe::MockKadOps::ThreadedFindKClosestNodesCallback,
                  vsl_.kadops().get(), good_result_, _1);
  EXPECT_CALL(*vsl_.kadops(), FindKClosestNodes(chunk_name,
      testing::An<maidsafe::VoidFuncIntContacts>()))
      .Times(testing::AtLeast(5))  // Calls 2 onwards
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(good_result_functor)))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(fail_result_functor)))
      .WillRepeatedly(testing::WithArgs<1>(
          testing::Invoke(good_result_functor)));

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
    AccountAmendment amendment(account_owner, chunk_name,
        maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending);
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
  EXPECT_TRUE(vsl_.kadops()->Wait());

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
    AccountAmendment amendment(account_owner, chunk_name,
        maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000 + i, true,
        pending);
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
  EXPECT_TRUE(vsl_.kadops()->Wait());

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
  EXPECT_TRUE(vsl_.kadops()->Wait());

  // Call 5 - Add new amendment but FindNodes result fails which removes amendmt
  ++test_run;
//  printf("Run %i\n", test_run);
  aah_.amendments_.clear();
  request = kDefaultRequest;
  response = kDefaultResponse;
  done = google::protobuf::NewCallback(&cbh,
      &test_aah::CallbacksHolder::callback);
  ASSERT_EQ(kSuccess, aah_.ProcessRequest(&request, &response, done));
  EXPECT_TRUE(vsl_.kadops()->Wait());
  ASSERT_EQ(size_t(0), aah_.amendments_.size());
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, v_used, acc_used, &ah_));
  ASSERT_EQ(size_t(11), ah_.accounts_.size());

  // Call 6 - Add new amendment and populate FindNodes result with good nodes.
  // Our PMID may get added in vsl->HandleFindKNodesResponse as a closest node.
  // In this case we will end up with 2 amendments pending, the main one (with
  // k - 1 good requests) and the new one generated by our PMID.
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
  for (int i = 0; i < test_aah::K; ++i) {
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
  for (int i = 0; i < test_aah::K; ++i) {
    ASSERT_EQ(kSuccess, aah_.ProcessRequest(&requests.at(i), &responses.at(i),
              callbacks.at(i)));
    ASSERT_GE(size_t(1), aah_.amendments_.size());
  }
  EXPECT_TRUE(vsl_.kadops()->Wait());
  ASSERT_EQ(4 + test_aah::K, cbh.called_back_count());
  int success_count(0);
  for (int i = 1; i < test_aah::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  ASSERT_EQ(success_count, test_aah::K - 1);
  ASSERT_GE(size_t(1), aah_.amendments_.size());
  ASSERT_TRUE(test_aah::CheckAcc(account_owner, offer, 1000, acc_used, &ah_));
  ASSERT_EQ(size_t(11), ah_.accounts_.size());
}

TEST_F(AccountAmendmentHandlerTest, BEH_MAID_CleanUp) {
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
  const maidsafe::AmendAccountRequest kDefaultRequest(request);
  maidsafe::AmendAccountResponse response;
  response.set_pmid(pmid_);
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
    AccountAmendment amendment(account_owner, chunk_name,
        maidsafe::AmendAccountRequest::kSpaceGivenInc, 2, 1000, true, pending);
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

  // Set expiry time back on 50
  it = aah_.amendments_.get<by_timestamp>().begin();
  for (int i = 0; i < 50; ++i, ++it) {
    AccountAmendment amendment = *it;
    amendment.expiry_time = base::GetEpochMilliseconds() - 1000;
    aah_.amendments_.get<by_timestamp>().replace(it, amendment);
    // Sleep to let timestamps differ.
    boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
  ASSERT_EQ(50, aah_.CleanUp());
  ASSERT_EQ(size_t(29), aah_.amendments_.size());
  
  aah_.Clear();
  ASSERT_TRUE(aah_.amendments_.empty());
}

}  // namespace test

}  // namespace maidsafe_vault
