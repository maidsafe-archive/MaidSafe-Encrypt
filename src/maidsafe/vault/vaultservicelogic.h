/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  This class implements lengthy methods to be used by VaultService
* Version:      1.0
* Created:      2010-01-06-13.54.11
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

#ifndef MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_
#define MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/channel-api.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace kad {
class KNode;
class Contact;
}  // namespace kad

namespace maidsafe_vault {

typedef boost::function<void (const int&)> Callback;

class VaultRpcs;

// This is used to hold the data required to perform a Kad lookup to get a
// group of Chunk Info holders, send each an AddToReferenceListRequest and
// assess the responses.  It's a big-ass callback struct :-(
struct AddRefCallbackData {
  struct AddRefDataHolder {
    explicit AddRefDataHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    maidsafe::AddToReferenceListResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  AddRefCallbackData()
      : mutex(),
        cv(),
        contacts(),
        data_holders(),
        success_count(0),
        failure_count(0),
        callback_done(false),
        result(kVaultServiceError) {}
  Callback callback;
  boost::mutex mutex;
  boost::condition_variable cv;
  std::vector<kad::Contact> contacts;
  std::vector<AddRefDataHolder> data_holders;
  boost::uint16_t success_count;
  boost::uint16_t failure_count;
  bool callback_done;
  int result;
};

// This is used to hold the data required to perform a Kad lookup to get a
// vault's remote account holders, send each an AmendAccountRequest and assess
// the responses.  It's another big-ass callback struct :-(
struct AmendRemoteAccountOpData {
  struct AmendRemoteAccountOpHolder {
    explicit AmendRemoteAccountOpHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    maidsafe::AmendAccountResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  AmendRemoteAccountOpData(maidsafe::AmendAccountRequest req,
                           std::string name,
                           int found_local_res,
                           Callback cb)
      : request(req),
        account_name(name),
        found_local_result(found_local_res),
        callback(cb),
        mutex(),
        contacts(),
        data_holders(),
        success_count(0),
        failure_count(0),
        callback_done(false) {}
  maidsafe::AmendAccountRequest request;
  std::string account_name;  // non-hex version
  int found_local_result;
  Callback callback;
  boost::mutex mutex;
  std::vector<kad::Contact> contacts;
  std::vector<AmendRemoteAccountOpHolder> data_holders;
  boost::uint16_t success_count;
  boost::uint16_t failure_count;
  bool callback_done;
};

// This is used to hold the data required to perform a Kad lookup to get a
// vault's remote account holders, send each an AccountStatusRequest and assess
// the responses.  Yup - it's yet another big-ass callback struct :-(
struct AccountStatusCallbackData {
  struct AccountStatusHolder {
    explicit AccountStatusHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    maidsafe::AccountStatusResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  explicit AccountStatusCallbackData(std::string name)
      : account_name(name),
        mutex(),
        cv(),
        contacts(),
        data_holders(),
        success_count(0),
        failure_count(0),
        callback_done(false),
        result(kVaultServiceError) {}
  std::string account_name;  // non-hex version
  Callback callback;
  boost::mutex mutex;
  boost::condition_variable cv;
  std::vector<kad::Contact> contacts;
  std::vector<AccountStatusHolder> data_holders;
  boost::uint16_t success_count;
  boost::uint16_t failure_count;
  bool callback_done;
  int result;
};

class VaultServiceLogic {
 public:
  VaultServiceLogic(VaultRpcs *vault_rpcs,
                    kad::KNode *knode);
  virtual ~VaultServiceLogic() {}
  bool Init(const std::string &non_hex_pmid,
            const std::string &pmid_public_signature,
            const std::string &pmid_private);
  bool online();
  void SetOnlineStatus(bool online);
  void SetKThreshold(const boost::uint16_t &threshold);
  // Blocking call which looks up Chunk Info holders and sends each an
  // AddToReferenceListRequest to add this vault's ID to ref list for chunkname.
  int AddToRemoteRefList(const std::string &chunkname,
                         const maidsafe::StoreContract &store_contract);
  // Blocking call to Kademlia FindCloseNodes
  int FindKNodes(const std::string &kad_key,
                 std::vector<kad::Contact> *contacts);
  // Wrapper for knode method - virtual to allow mock testing
  virtual void FindCloseNodes(const std::string &kad_key,
                              const base::callback_func_type &callback);
  void HandleFindKNodesResponse(const std::string &response,
                                const std::string &kad_key,
                                std::vector<kad::Contact> *contacts,
                                boost::mutex *mutex,
                                boost::condition_variable *cv,
                                int *result);
  // Amend account of PMID requesting to be added to Watch List or Ref List.
  virtual void AmendRemoteAccount(const maidsafe::AmendAccountRequest &request,
                                  const int &found_local_result,
                                  const Callback &callback);
  // Blocking call which looks up account holders and sends each an
  // AccountStatusRequest to establish if the account owner has space to store
  int RemoteVaultAbleToStore(maidsafe::AccountStatusRequest request);
 private:
  VaultServiceLogic(const VaultServiceLogic&);
  VaultServiceLogic &operator=(const VaultServiceLogic&);
  FRIEND_TEST(VaultServiceLogicTest, BEH_MAID_VSL_FindKNodes);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_AddToRemoteRefList);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_AmendRemoteAccount);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_RemoteVaultAbleToStore);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_AssessAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_CreateNewAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_ProcessRequest);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesAmendAccount);
  friend class MockVaultServicesTest;

  // Method called by each AddToReferenceList response in AddToRemoteRefList.
  // index indicates the position in data's internal vectors of the respondent.
  void AddToRemoteRefListCallback(boost::uint16_t index,
                                  boost::shared_ptr<AddRefCallbackData> data);
  // First callback method in AmendRemoteAccount operation.  Called once by
  // knode_->FindKNodes (when finding account holders details)
  void AmendRemoteAccountStageTwo(
      boost::shared_ptr<AmendRemoteAccountOpData> data,
      const std::string &find_nodes_response);
  // Second callback method in AmendRemoteAccount operation.  Called repeatedly
  // by each AmendAccount RPC response.  index indicates the position in data's
  // internal vectors of the respondent.
  void AmendRemoteAccountStageThree(
      boost::uint16_t index,
      boost::shared_ptr<AmendRemoteAccountOpData> data);
  // Method called by each AccountStatus response in RemoteVaultAbleToStore.
  // index indicates the position in data's internal vectors of the respondent.
  void AccountStatusCallback(boost::uint16_t index,
                             boost::shared_ptr<AccountStatusCallbackData> data);
  // Returns a signature for validation by recipient of RPC
  std::string GetSignedRequest(const std::string &non_hex_name,
                               const std::string &recipient_id);
  // Wrapper for knode method - virtual to allow mock testing
  virtual bool AddressIsLocal(const kad::Contact &peer);
  VaultRpcs *vault_rpcs_;
  kad::KNode *knode_;
  kad::Contact our_details_;
  std::string non_hex_pmid_, pmid_public_signature_, pmid_private_;
  bool online_;
  boost::mutex online_mutex_;
  boost::uint16_t kKadStoreThreshold_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_
