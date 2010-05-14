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

#include <algorithm>

#include "maidsafe/kadops.h"
#include "maidsafe/utils.h"

namespace maidsafe {

AccountHoldersManager::~AccountHoldersManager() {
  boost::mutex::scoped_lock lock(mutex_);
  while (update_in_progress_)
    cond_var_.wait(lock);
}

void AccountHoldersManager::Init(const std::string &pmid,
                                 const AccountHolderGroupFunctor &callback) {
  do_nothing_ = boost::bind(&AccountHoldersManager::DoNothing, this, _1, _2);
  pmid_ = pmid;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  account_name_ = co.Hash(pmid_ + kAccount, "", crypto::STRING_STRING, false);
  UpdateGroup(callback);
}

void AccountHoldersManager::Update() {
  UpdateGroup(do_nothing_);
}

void AccountHoldersManager::UpdateGroup(AccountHolderGroupFunctor callback) {
  if(account_name_.empty())
    return;
  {
    boost::mutex::scoped_lock lock(mutex_);
    failed_ids_.clear();
    update_in_progress_ = true;
  }
  // TODO(Fraser#5#): 2010-05-12 - Implement better way of updating, e.g. send a
  //                  single request to a good account holder for his closest
  //                  contacts to account_name_;
  kad_ops_->FindKClosestNodes(kad::KadId(account_name_, false), boost::bind(
      &AccountHoldersManager::FindNodesCallback, this, _1, callback));
}

void AccountHoldersManager::FindNodesCallback(
    const std::string &response,
    AccountHolderGroupFunctor callback) {
  kad::FindResponse find_response;
  ReturnCode result = kSuccess;
  if (!find_response.ParseFromString(response)) {
#ifdef DEBUG
    printf("In AHM::FindNodesCallback, can't parse result.\n");
#endif
    result = kFindNodesParseError;
  } else if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In AHM::FindNodesCallback, Kademlia RPC failed.\n");
#endif
    result = kFindNodesFailure;
  }

  boost::mutex::scoped_lock lock(mutex_);
  if (result == kSuccess) {
    account_holder_group_.clear();
    for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
      kad::Contact contact;
      contact.ParseFromString(find_response.closest_nodes(i));
      // Vault cannot be AccountHolder for self
      if (contact.node_id().ToStringDecoded() != pmid_)
        account_holder_group_.push_back(contact);
    }
    callback(kSuccess, account_holder_group_);
    last_update_ = boost::posix_time::microsec_clock::universal_time();
  } else {
    std::vector<kad::Contact> empty_account_holder_group;
    callback(result, empty_account_holder_group);
  }
  update_in_progress_ = false;
  cond_var_.notify_one();
}

bool AccountHoldersManager::UpdateRequired() {
  boost::mutex::scoped_lock lock(mutex_);
  if (boost::posix_time::microsec_clock::universal_time() >=
      last_update_ + kMaxUpdateInterval_)
    return true;
  std::set<std::string> unique_ids(failed_ids_.begin(), failed_ids_.end());
  if (unique_ids.size() >= kMaxFailedNodes_)
    return true;
  size_t max_single_count(1);
  for (std::set<std::string>::iterator it = unique_ids.begin();
       it != unique_ids.end(); ++it) {
    size_t this_count = failed_ids_.count(*it);
    if (this_count > max_single_count)
      max_single_count = this_count;
  }
  return max_single_count >= kMaxFailsPerNode_;
}

void AccountHoldersManager::ReportFailure(
    const std::string &account_holders_pmid) {
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (update_in_progress_)
      return;
    // Check node is in current vector of account holders
    std::vector<kad::Contact>::iterator it = std::find_if(
        account_holder_group_.begin(), account_holder_group_.end(),
        boost::bind(&ContactHasId, account_holders_pmid, _1));
    if (it == account_holder_group_.end())
      return;
    failed_ids_.insert(account_holders_pmid);
  }
  if (UpdateRequired())
    UpdateGroup(do_nothing_);
}


}  // namespace maidsafe
