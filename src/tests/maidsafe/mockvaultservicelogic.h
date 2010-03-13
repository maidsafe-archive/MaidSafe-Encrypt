/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Common functions used in tests which have a mock
*               VaultServiceLogic object
* Version:      1.0
* Created:      2010-01-12-16.03.33
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

#ifndef TESTS_MAIDSAFE_MOCKVAULTSERVICELOGIC_H_
#define TESTS_MAIDSAFE_MOCKVAULTSERVICELOGIC_H_

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <gmock/gmock.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <string>
#include <vector>

#include "maidsafe/client/packetfactory.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/vaultrpc.h"
#include "maidsafe/vault/vaultservicelogic.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "tests/maidsafe/mockkadops.h"

namespace mock_vsl {

typedef boost::function<void (const maidsafe_vault::ReturnCode&)>
    VoidFuncOneInt;

class KGroup {
 public:
  struct Member {
    Member(const std::string &pmid_in,
           const std::string &pmid_private_in,
           const std::string &pmid_public_in,
           const std::string &pmid_public_signature_in)
        : pmid(pmid_in),
          pmid_private(pmid_private_in),
          pmid_public(pmid_public_in),
          pmid_public_signature(pmid_public_signature_in) {}
    Member() : pmid(), pmid_private(), pmid_public(), pmid_public_signature() {
      crypto::RsaKeyPair kp;
      kp.GenerateKeys(maidsafe::kRsaKeySize);
      pmid_private = kp.private_key();
      pmid_public = kp.public_key();
      crypto::Crypto co;
      co.set_symm_algorithm(crypto::AES_256);
      co.set_hash_algorithm(crypto::SHA_512);
      pmid_public_signature = co.AsymSign(pmid_public, "", pmid_private,
                                          crypto::STRING_STRING);
      pmid = co.Hash(pmid_public + pmid_public_signature, "",
                     crypto::STRING_STRING, false);
    }
    std::string pmid, pmid_private, pmid_public, pmid_public_signature;
  };
  KGroup() : co_(), members_(), serialised_find_nodes_response_() {
    co_.set_symm_algorithm(crypto::AES_256);
    co_.set_hash_algorithm(crypto::SHA_512);
    kad::FindResponse find_response;
    find_response.set_result(kad::kRpcResultSuccess);
    for (int i = 0; i < kad::K; ++i) {
      Member member;
      members_.push_back(member);
      kad::Contact node(member.pmid, "192.168.1.1", 5000 + i);
      node.SerialiseToString(&serialised_find_nodes_response_);
      find_response.add_closest_nodes(serialised_find_nodes_response_);
    }
    find_response.SerializeToString(&serialised_find_nodes_response_);
  }
  std::string serialised_find_nodes_response() {
    return serialised_find_nodes_response_;
  }
  void MakeAmendAccountRequests(
      const maidsafe::AmendAccountRequest::Amendment &type,
      const std::string &account_pmid,
      const boost::uint64_t &data_size,
      const std::string &chunkname,
      std::vector<maidsafe::AmendAccountRequest> *requests);
 private:
  crypto::Crypto co_;
  std::vector<Member> members_;
  std::string serialised_find_nodes_response_;
};

void CopyResult(const int &response,
                boost::mutex *mutex,
                boost::condition_variable *cv,
                int *result);

void RunVaultCallback(const maidsafe_vault::ReturnCode &result,
                      const VoidFuncOneInt &callback);

void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback);

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback);

}  // namespace mock_vsl

namespace maidsafe_vault {

class MockVaultRpcs : public VaultRpcs {
 public:
  MockVaultRpcs(transport::TransportHandler *transport_handler,
                rpcprotocol::ChannelManager *channel_manager)
                     : VaultRpcs(transport_handler, channel_manager) {}
  MOCK_METHOD7(AddToReferenceList, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      maidsafe::AddToReferenceListRequest *add_to_reference_list_request,
      maidsafe::AddToReferenceListResponse *add_to_reference_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(AmendAccount, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      maidsafe::AmendAccountRequest *amend_account_request,
      maidsafe::AmendAccountResponse *amend_account_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(AccountStatus, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      maidsafe::AccountStatusRequest *get_account_status_request,
      maidsafe::AccountStatusResponse *get_account_status_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
};

class MockVsl : public VaultServiceLogic {
 public:
  MockVsl(const boost::shared_ptr<VaultRpcs> &vault_rpcs,
          const boost::shared_ptr<kad::KNode> &knode)
      : VaultServiceLogic(vault_rpcs, knode) {
    kad_ops_.reset(new maidsafe::MockKadOps(knode));
  }
  boost::shared_ptr<maidsafe::MockKadOps> kadops() {
      return boost::static_pointer_cast<maidsafe::MockKadOps>(kad_ops_);
  }
  MOCK_METHOD4(AddToRemoteRefList, int(const std::string &chunkname,
                   const maidsafe::StoreContract &store_contract,
                   const int &found_local_result,
                   const boost::int16_t &transport_id));
  MOCK_METHOD4(AmendRemoteAccount,
               void(const maidsafe::AmendAccountRequest &request,
                    const int &found_local_result,
                    const VoidFuncOneInt &callback,
                    const boost::int16_t &transport_id));
  int AddToRemoteRefListReal(const std::string &chunkname,
                             const maidsafe::StoreContract &store_contract,
                             const int &found_local_result,
                             const boost::int16_t &transport_id) {
    return VaultServiceLogic::AddToRemoteRefList(chunkname, store_contract,
                                                 found_local_result,
                                                 transport_id);
  }
  void AmendRemoteAccountReal(const maidsafe::AmendAccountRequest &request,
                              const int &found_local_result,
                              const VoidFuncOneInt &callback,
                              const boost::int16_t &transport_id) {
    VaultServiceLogic::AmendRemoteAccount(request, found_local_result, callback,
                                          transport_id);
  }
};

class MockVaultServiceLogicTest : public testing::Test {
 protected:
  MockVaultServiceLogicTest()
      : pmid_(),
        pmid_private_(),
        pmid_public_(),
        pmid_public_signature_(),
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
        good_result_less_one_(),
        our_contact_(),
        good_contacts_() {}
  virtual ~MockVaultServiceLogicTest() {}
  virtual void SetUp() {
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    pmid_keys_.GenerateKeys(maidsafe::kRsaKeySize);
    pmid_private_ = pmid_keys_.private_key();
    pmid_public_ = pmid_keys_.public_key();
    // PMID isn't signed by its own private key in production code, but this
    // is quicker rather than generating a new set of keys
    pmid_public_signature_ = crypto_.AsymSign(pmid_public_, "", pmid_private_,
        crypto::STRING_STRING);
    pmid_ = crypto_.Hash(pmid_public_ + pmid_public_signature_, "",
        crypto::STRING_STRING, false);
    our_contact_ = kad::Contact(pmid_, "192.168.10.10", 8008);
    std::string ser_our_contact;
    our_contact_.SerialiseToString(&ser_our_contact);
    kad::FindResponse find_response, good_find_response_less_one;
    kad::Contact contact;
    std::string ser_contact;
    ASSERT_TRUE(find_response.ParseFromString(good_result_));
    good_find_response_less_one.set_result(kad::kRpcResultSuccess);
    for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
      ser_contact = find_response.closest_nodes(i);
      ASSERT_TRUE(contact.ParseFromString(ser_contact));
      good_contacts_.push_back(contact);
      if (i < find_response.closest_nodes_size() - 1) {
        good_find_response_less_one.add_closest_nodes(ser_contact);
      }
    }
    good_find_response_less_one.SerializeToString(&good_result_less_one_);
  }

  crypto::RsaKeyPair pmid_keys_;
  std::string pmid_, pmid_private_, pmid_public_, pmid_public_signature_;
  std::vector<std::string> fail_parse_pmids_, fail_pmids_, few_pmids_;
  std::vector<std::string> good_pmids_;
  crypto::Crypto crypto_;
  std::string fail_parse_result_, fail_result_, few_result_, good_result_;
  std::string good_result_less_one_;
  kad::Contact our_contact_;
  std::vector<kad::Contact> good_contacts_;

 private:
  MockVaultServiceLogicTest(const MockVaultServiceLogicTest&);
  MockVaultServiceLogicTest &operator=(const MockVaultServiceLogicTest&);
};

}  // namespace maidsafe_vault

#endif  // TESTS_MAIDSAFE_MOCKVAULTSERVICELOGIC_H_
