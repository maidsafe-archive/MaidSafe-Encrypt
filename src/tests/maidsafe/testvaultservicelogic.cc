/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for VaultServiceLogic class using mock RPCs
* Version:      1.0
* Created:      2010-01-08-12.33.18
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

#include "tests/maidsafe/mockvaultservicelogic.h"

namespace maidsafe_vault {

class VaultServiceLogicTest : public MockVaultServiceLogicTest {};

TEST_F(VaultServiceLogicTest, BEH_MAID_VSL_Offline) {
  boost::shared_ptr<MockVaultRpcs> mock_rpcs(new MockVaultRpcs(NULL, NULL));
  VaultServiceLogic vsl(mock_rpcs, boost::shared_ptr<kad::KNode>());

  maidsafe::StoreContract sc;
  ASSERT_EQ(kVaultOffline, vsl.AddToRemoteRefList("x", sc, 0));

  maidsafe::AmendAccountRequest aar;
  boost::mutex mutex;
  boost::condition_variable cv;
  int result(kGeneralError);
  VoidFuncOneInt cb =
      boost::bind(&mock_vsl::CopyResult, _1, &mutex, &cv, &result);
  vsl.AmendRemoteAccount(aar, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kVaultOffline, result);

  maidsafe::AccountStatusRequest asr;
  ASSERT_EQ(kVaultOffline, vsl.RemoteVaultAbleToStore(asr, 0));
}

TEST_F(VaultServiceLogicTest, BEH_MAID_VSL_FindKNodes) {
  // Setup
  boost::shared_ptr<MockVaultRpcs> mock_rpcs(new MockVaultRpcs(NULL, NULL));
  MockVsl vsl(mock_rpcs, boost::shared_ptr<kad::KNode>());
  vsl.online_ = true;
  std::vector<kad::Contact> contacts;
  kad::Contact dummy_contact = kad::Contact(crypto_.Hash("Dummy", "",
      crypto::STRING_STRING, false), "192.168.1.0", 4999);

  // Expectations
  EXPECT_CALL(*vsl.kadops(), FindCloseNodes("x", testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_parse_result_, _1))))  // 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, few_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 5
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))));  // Call 6

  // Call 1
  ASSERT_EQ(kVaultServiceError, vsl.FindKNodes("x", NULL));

  // Call 2
  contacts.push_back(dummy_contact);
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_EQ(kVaultServiceFindNodesError, vsl.FindKNodes("x", &contacts));
  ASSERT_EQ(size_t(0), contacts.size());

  // Call 3
  contacts.push_back(dummy_contact);
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_EQ(kVaultServiceFindNodesFailure, vsl.FindKNodes("x", &contacts));
  ASSERT_EQ(size_t(0), contacts.size());

  // Call 4
  ASSERT_EQ(kSuccess, vsl.FindKNodes("x", &contacts));
  ASSERT_EQ(size_t(2), contacts.size());

  // Call 5
  ASSERT_EQ(kSuccess, vsl.FindKNodes("x", &contacts));
  ASSERT_EQ(size_t(16), contacts.size());

  // Call 6
  contacts.push_back(dummy_contact);
  ASSERT_EQ(kSuccess, vsl.FindKNodes("x", &contacts));
  ASSERT_EQ(size_t(16), contacts.size());
}

TEST_F(VaultServiceLogicTest, FUNC_MAID_VSL_AddToRemoteRefList) {
  // Setup
  boost::shared_ptr<MockVaultRpcs> mock_rpcs(new MockVaultRpcs(NULL, NULL));
  MockVsl vsl(mock_rpcs, boost::shared_ptr<kad::KNode>());
  vsl.pmid_ = pmid_;
  vsl.pmid_public_signature_ = pmid_public_signature_;
  vsl.pmid_private_ = pmid_private_;
  vsl.online_ = true;
  vsl.our_details_ = our_contact_;
  maidsafe::StoreContract store_contract;

  std::vector<maidsafe::AddToReferenceListResponse> good_responses;
  std::vector<maidsafe::AddToReferenceListResponse> good_responses_less_one;
  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    maidsafe::AddToReferenceListResponse add_ref_response;
    add_ref_response.set_result(kAck);
    add_ref_response.set_pmid(good_contacts_.at(i).node_id());
    good_responses.push_back(add_ref_response);
    if (i < good_contacts_.size() - 1)
      good_responses_less_one.push_back(add_ref_response);
  }
  std::vector<maidsafe::AddToReferenceListResponse>
      bad_pmid_responses(good_responses);
  std::vector<maidsafe::AddToReferenceListResponse>
      too_few_ack_responses(good_responses);
  std::vector<maidsafe::AddToReferenceListResponse>
      fail_initialise_responses(good_responses);
  for (size_t i = kKadStoreThreshold - 1; i < good_contacts_.size(); ++i) {
    bad_pmid_responses.at(i).set_pmid(good_contacts_.at(i - 1).node_id());
    too_few_ack_responses.at(i).set_result(kNack);
    fail_initialise_responses.at(i).clear_result();
  }
  // Set chunkname as far as possible from our ID so we don't get added to
  // vector of close nodes in vsl.HandleFindKNodesResponse
  std::string far_chunkname =
      crypto_.Obfuscate(pmid_, std::string(64, -1), crypto::XOR);

  // Expectations
  EXPECT_CALL(vsl, AddToRemoteRefList(testing::_, testing:: _, testing:: _))
      .WillRepeatedly(testing::Invoke(&vsl, &MockVsl::AddToRemoteRefListReal));
  EXPECT_CALL(*vsl.kadops(), FindCloseNodes(far_chunkname, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_parse_result_, _1))))  // 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, few_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 6
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 7
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))));  // Call 8
  EXPECT_CALL(*vsl.kadops(), FindCloseNodes(pmid_, testing::_))  // Call 5
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_less_one_, _1))));

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    if (i < good_contacts_.size() - 1) {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(false))  // Call 5
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    } else {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    }
  }

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
      EXPECT_CALL(*mock_rpcs, AddToReferenceList(good_contacts_.at(i), true, 0,
          testing::_, testing::_, testing::_, testing::_))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses.at(i)),  // Call 4
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    bad_pmid_responses.at(i)),  // Call 6
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    too_few_ack_responses.at(i)),  // Call 7
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    fail_initialise_responses.at(i)),  // Call 8
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }
  for (size_t i = 0; i < good_contacts_.size() - 1; ++i) {
      EXPECT_CALL(*mock_rpcs, AddToReferenceList(good_contacts_.at(i), false, 0,
          testing::_, testing::_, testing::_, testing::_))  // Call 5
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses_less_one.at(i)),
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1 - FindKNodes fails (NULL pointer)
  ASSERT_EQ(kVaultServiceFindNodesError,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 2 - FindKNodes returns kNack
  ASSERT_EQ(kVaultServiceFindNodesFailure,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 3 - FindKnodes only returns 1 node
  ASSERT_EQ(kVaultServiceFindNodesTooFew,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 4 - All OK
  ASSERT_EQ(kSuccess, vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 5 - All OK - we're close to chunkname, so we replace contact 16
  ASSERT_EQ(kSuccess, vsl.AddToRemoteRefList(pmid_, store_contract, 0));

  // Call 6 - Five responses have incorrect PMID
  ASSERT_EQ(kAddToRefResponseError,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 7 - Five responses return kNack
  ASSERT_EQ(kAddToRefResponseFailed,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));

  // Call 8 - Five responses don't have result set
  ASSERT_EQ(kAddToRefResponseUninitialised,
            vsl.AddToRemoteRefList(far_chunkname, store_contract, 0));
}

TEST_F(VaultServiceLogicTest, FUNC_MAID_VSL_AmendRemoteAccount) {
  // Setup
  boost::shared_ptr<MockVaultRpcs> mock_rpcs(new MockVaultRpcs(NULL, NULL));
  MockVsl vsl(mock_rpcs, boost::shared_ptr<kad::KNode>());
  vsl.pmid_ = pmid_;
  vsl.pmid_public_signature_ = pmid_public_signature_;
  vsl.pmid_private_ = pmid_private_;
  vsl.online_ = true;
  vsl.our_details_ = our_contact_;

  std::vector<maidsafe::AmendAccountResponse> good_responses;
  std::vector<maidsafe::AmendAccountResponse> good_responses_less_one;
  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    maidsafe::AmendAccountResponse amend_acc_response;
    amend_acc_response.set_result(kAck);
    amend_acc_response.set_pmid(good_contacts_.at(i).node_id());
    good_responses.push_back(amend_acc_response);
    if (i < good_contacts_.size() - 1)
      good_responses_less_one.push_back(amend_acc_response);
  }
  std::vector<maidsafe::AmendAccountResponse>
      bad_pmid_responses(good_responses);
  std::vector<maidsafe::AmendAccountResponse>
      too_few_ack_responses(good_responses);
  std::vector<maidsafe::AmendAccountResponse>
      fail_initialise_responses(good_responses);
  for (size_t i = kKadStoreThreshold - 1; i < good_contacts_.size(); ++i) {
    bad_pmid_responses.at(i).set_pmid(good_contacts_.at(i - 1).node_id());
    too_few_ack_responses.at(i).set_result(kNack);
    fail_initialise_responses.at(i).clear_result();
  }

  std::string account_owner(crypto_.Hash("Account Owner", "",
      crypto::STRING_STRING, false));
  std::string account_name(crypto_.Hash(account_owner + kAccount, "",
      crypto::STRING_STRING, false));
  maidsafe::AmendAccountRequest request;
  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
  request.set_account_pmid(account_owner);
  maidsafe::SignedSize *mutable_signed_size = request.mutable_signed_size();
  mutable_signed_size->set_data_size(10);
  mutable_signed_size->set_pmid(pmid_);
  mutable_signed_size->set_signature(crypto_.AsymSign(base::itos_ull(10), "",
                                     pmid_private_, crypto::STRING_STRING));
  mutable_signed_size->set_public_key(pmid_public_);
  mutable_signed_size->set_public_key_signature(pmid_public_signature_);
  request.set_chunkname(crypto_.Hash("Chunkname", "", crypto::STRING_STRING,
      false));

  boost::mutex mutex;
  boost::condition_variable cv;
  int result(kGeneralError);
  VoidFuncOneInt cb =
      boost::bind(&mock_vsl::CopyResult, _1, &mutex, &cv, &result);

  // Expectations
  EXPECT_CALL(vsl, AmendRemoteAccount(testing::_, testing::_, testing::_,
                                      testing::_))
      .WillRepeatedly(testing::Invoke(&vsl, &MockVsl::AmendRemoteAccountReal));
  EXPECT_CALL(*vsl.kadops(), FindCloseNodes(account_name, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_parse_result_, _1))))  // 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, few_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_less_one_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 6
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 7
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))));  // Call 8

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    if (i < good_contacts_.size() - 1) {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(false))  // Call 5
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    } else {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    }
  }

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
      EXPECT_CALL(*mock_rpcs, AmendAccount(good_contacts_.at(i), true, 0,
          testing::_, testing::_, testing::_, testing::_))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses.at(i)),  // Call 4
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    bad_pmid_responses.at(i)),  // Call 6
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    too_few_ack_responses.at(i)),  // Call 7
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    fail_initialise_responses.at(i)),  // Call 8
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }
  for (size_t i = 0; i < good_contacts_.size() - 1; ++i) {
      EXPECT_CALL(*mock_rpcs, AmendAccount(good_contacts_.at(i), false, 0,
          testing::_, testing::_, testing::_, testing::_))  // Call 5
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses_less_one.at(i)),
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1 - FindKNodes fails (NULL pointer)
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kVaultServiceFindNodesError, result);

  // Call 2 - FindKNodes returns kNack
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kVaultServiceFindNodesFailure, result);

  // Call 3 - FindKnodes only returns 1 node
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kVaultServiceFindNodesTooFew, result);

  // Call 4 - All OK
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kSuccess, result);

  // Call 5 - All OK - we're close to chunkname, so we replace contact 16
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kSuccess, result);

  // Call 6 - Five responses have incorrect PMID
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kAmendAccountResponseError, result);

  // Call 7 - Five responses return kNack
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kAmendAccountResponseFailed, result);

  // Call 8 - Five responses don't have result set
  result = kGeneralError;
  vsl.AmendRemoteAccount(request, kSuccess, cb, 0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kGeneralError) {
      cv.wait(lock);
    }
  }
  ASSERT_EQ(kAmendAccountResponseUninitialised, result);
}

TEST_F(VaultServiceLogicTest, FUNC_MAID_VSL_RemoteVaultAbleToStore) {
  // Setup
  boost::shared_ptr<MockVaultRpcs> mock_rpcs(new MockVaultRpcs(NULL, NULL));
  MockVsl vsl(mock_rpcs, boost::shared_ptr<kad::KNode>());
  vsl.pmid_ = pmid_;
  vsl.pmid_public_signature_ = pmid_public_signature_;
  vsl.pmid_private_ = pmid_private_;
  vsl.online_ = true;
  vsl.our_details_ = our_contact_;
  maidsafe::StoreContract store_contract;

  std::vector<maidsafe::AccountStatusResponse> good_responses;
  std::vector<maidsafe::AccountStatusResponse> good_responses_less_one;
  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    maidsafe::AccountStatusResponse acc_status_response;
    acc_status_response.set_result(kAck);
    acc_status_response.set_pmid(good_contacts_.at(i).node_id());
    good_responses.push_back(acc_status_response);
    if (i < good_contacts_.size() - 1)
      good_responses_less_one.push_back(acc_status_response);
  }
  std::vector<maidsafe::AccountStatusResponse>
      bad_pmid_responses(good_responses);
  std::vector<maidsafe::AccountStatusResponse>
      too_few_ack_responses(good_responses);
  std::vector<maidsafe::AccountStatusResponse>
      fail_initialise_responses(good_responses);
  for (size_t i = kKadTrustThreshold - 1; i < good_contacts_.size(); ++i) {
    bad_pmid_responses.at(i).set_pmid(good_contacts_.at(i - 1).node_id());
    too_few_ack_responses.at(i).set_result(kNack);
    fail_initialise_responses.at(i).clear_result();
  }
  std::string account_owner(crypto_.Hash("Account Owner", "",
      crypto::STRING_STRING, false));
  std::string account_name(crypto_.Hash(account_owner + kAccount, "",
      crypto::STRING_STRING, false));
  maidsafe::AccountStatusRequest request;
  request.set_account_pmid(account_owner);

  // Expectations
  EXPECT_CALL(*vsl.kadops(), FindCloseNodes(account_name, testing::_))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_parse_result_, _1))))  // 1
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, fail_result_, _1))))  // Call 2
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, few_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_less_one_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 6
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))))  // Call 7
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_vsl::RunCallback, good_result_, _1))));  // Call 8

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
    if (i < good_contacts_.size() - 1) {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(false))  // Call 5
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    } else {
      EXPECT_CALL(*vsl.kadops(), AddressIsLocal(good_contacts_.at(i)))
          .WillOnce(testing::Return(true))  // Call 4
          .WillOnce(testing::Return(true))  // Call 6
          .WillOnce(testing::Return(true))  // Call 7
          .WillOnce(testing::Return(true));  // Call 8
    }
  }

  for (size_t i = 0; i < good_contacts_.size(); ++i) {
      EXPECT_CALL(*mock_rpcs, AccountStatus(good_contacts_.at(i), true, 0,
          testing::_, testing::_, testing::_, testing::_))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses.at(i)),  // Call 4
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    bad_pmid_responses.at(i)),  // Call 6
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    too_few_ack_responses.at(i)),  // Call 7
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))))
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    fail_initialise_responses.at(i)),  // Call 8
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }
  for (size_t i = 0; i < good_contacts_.size() - 1; ++i) {
      EXPECT_CALL(*mock_rpcs, AccountStatus(good_contacts_.at(i), false, 0,
          testing::_, testing::_, testing::_, testing::_))  // Call 5
              .WillOnce(DoAll(testing::SetArgumentPointee<4>(
                                    good_responses_less_one.at(i)),
                              testing::WithArgs<6>(testing::Invoke(
                  boost::bind(&mock_vsl::ThreadedDoneRun, 100, 5000, _1)))));
  }

  // Call 1 - FindKNodes fails (NULL pointer)
  ASSERT_EQ(kVaultServiceFindNodesError,
            vsl.RemoteVaultAbleToStore(request, 0));

  // Call 2 - FindKNodes returns kNack
  ASSERT_EQ(kVaultServiceFindNodesFailure,
            vsl.RemoteVaultAbleToStore(request, 0));

  // Call 3 - FindKnodes only returns 1 node
  ASSERT_EQ(kVaultServiceFindNodesTooFew,
            vsl.RemoteVaultAbleToStore(request, 0));

  // Call 4 - All OK
  ASSERT_EQ(kSuccess, vsl.RemoteVaultAbleToStore(request, 0));

  // Call 5 - All OK - FindKNodes only returns 15 nodes, so we're contact 16
  ASSERT_EQ(kSuccess, vsl.RemoteVaultAbleToStore(request, 0));

  // Call 6 - Fourteen responses have incorrect PMID
  ASSERT_EQ(kAccountStatusResponseError,
            vsl.RemoteVaultAbleToStore(request, 0));

  // Call 7 - Fourteen responses return kNack
  ASSERT_EQ(kAccountStatusResponseFailed,
            vsl.RemoteVaultAbleToStore(request, 0));

  // Call 8 - Fourteen responses don't have result set
  ASSERT_EQ(kAccountStatusResponseUninitialised,
            vsl.RemoteVaultAbleToStore(request, 0));
}

}  // namespace maidsafe_vault
