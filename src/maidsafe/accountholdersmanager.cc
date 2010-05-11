/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for managing client or vault's account holders' contact
*               details.
* Created:      2010-05-10
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

#include "maidsafe/accountholdersmanager.h"

#include <maidsafe/base/crypto.h>

#include "maidsafe/kadops.h"

namespace maidsafe {

void AccountHoldersManager::Init(const std::string &pmid,
                                 const AccountHolderSetFunctor &callback) {
  pmid_ = pmid;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  account_name_ = co.Hash(pmid_ + kAccount, "", crypto::STRING_STRING, false);
  UpdateMap(callback);
}

void AccountHoldersManager::UpdateMap(AccountHolderSetFunctor callback) {
  kad_ops_->FindKClosestNodes(kad::KadId(account_name_, false), boost::bind(
      &AccountHoldersManager::FindNodesCallback, this, _1, callback));
}

void AccountHoldersManager::FindNodesCallback(
    const std::string &response,
    AccountHolderSetFunctor callback) {
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(response)) {
#ifdef DEBUG
    printf("In AHM::FindNodesCallback, can't parse result.\n");
#endif
    AccountHolderSet empty_account_holder_set;
    callback(kFindNodesParseError, empty_account_holder_set);
    return;
  }

  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In AHM::FindNodesCallback, Kademlia RPC failed.\n");
#endif
    AccountHolderSet empty_account_holder_set;
    callback(kFindNodesFailure, empty_account_holder_set);
    return;
  }

  AccountHolderSet new_account_holder_set(boost::bind(
            &AccountHoldersManager::CompareHolders, this, _1, _2));
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    // Vault cannot be AccountHolder for self
    if(contact.node_id().ToStringDecoded() != pmid_) {
      new_account_holder_set.insert(AccountHolderSet::value_type(
          contact, kad_ops_->AddressIsLocal(contact)));
    }
  }

  callback(kSuccess, new_account_holder_set);
  boost::mutex::scoped_lock lock(mutex_);
  account_holder_set_.swap(new_account_holder_set);
  last_update_ = boost::posix_time::microsec_clock::universal_time();
}

}  // namespace maidsafe
