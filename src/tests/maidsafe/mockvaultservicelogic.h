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

#include <vector>
#include <string>

#include "maidsafe/client/packetfactory.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/vaultrpc.h"
#include "maidsafe/vault/vaultservicelogic.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace mock_vsl {

enum FindNodesResponseType {
  kFailParse,
  kResultFail,
  kTooFewContacts,
  kGood
};
void CopyResult(const int &response,
                boost::mutex *mutex,
                boost::condition_variable *cv,
                int *result);
std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  std::vector<std::string> *pmids);
void RunCallback(const std::string &find_nodes_response,
                 const base::callback_func_type &callback);
void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback);
void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback);

}  // namespace mock_vsl

namespace maidsafe_vault {

typedef boost::function<void (const int&)> Callback;

class MockVaultRpcs : public VaultRpcs {
 public:
  MockVaultRpcs(transport::Transport *transport,
                rpcprotocol::ChannelManager *channel_manager)
                     : VaultRpcs(transport, channel_manager) {}
  MOCK_METHOD6(AddToReferenceList, void(
      const kad::Contact &peer,
      bool local,
      maidsafe::AddToReferenceListRequest *add_to_reference_list_request,
      maidsafe::AddToReferenceListResponse *add_to_reference_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD6(AmendAccount, void(
      const kad::Contact &peer,
      bool local,
      maidsafe::AmendAccountRequest *amend_account_request,
      maidsafe::AmendAccountResponse *amend_account_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD6(AccountStatus, void(
      const kad::Contact &peer,
      bool local,
      maidsafe::AccountStatusRequest *get_account_status_request,
      maidsafe::AccountStatusResponse *get_account_status_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
};

class MockVsl : public VaultServiceLogic {
 public:
  MockVsl(VaultRpcs *vault_rpcs, kad::KNode *knode)
      : VaultServiceLogic(vault_rpcs, knode) {}
  MOCK_METHOD2(FindCloseNodes, void(const std::string &kad_key,
                                    const base::callback_func_type &callback));
  MOCK_METHOD1(AddressIsLocal, bool(const kad::Contact &peer));
};

class MockVaultServiceLogicTest : public testing::Test {
 protected:
  MockVaultServiceLogicTest()
      : pmid_(),
        hex_pmid_(),
        pmid_private_(),
        pmid_public_(),
        pmid_public_signature_(),
        fail_parse_pmids_(),
        fail_pmids_(),
        few_pmids_(),
        good_pmids_(),
        fail_parse_result_(
            mock_vsl::MakeFindNodesResponse(mock_vsl::kFailParse,
                                            &fail_parse_pmids_)),
        fail_result_(mock_vsl::MakeFindNodesResponse(mock_vsl::kResultFail,
                                                     &fail_pmids_)),
        few_result_(mock_vsl::MakeFindNodesResponse(mock_vsl::kTooFewContacts,
                                                    &few_pmids_)),
        good_result_(mock_vsl::MakeFindNodesResponse(mock_vsl::kGood,
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
    hex_pmid_ = crypto_.Hash(pmid_public_ + pmid_public_signature_, "",
        crypto::STRING_STRING, true);
    pmid_ = base::DecodeFromHex(hex_pmid_);
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
  std::string pmid_, hex_pmid_, pmid_private_, pmid_public_;
  std::string pmid_public_signature_;
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
