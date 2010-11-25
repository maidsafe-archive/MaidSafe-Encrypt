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

#include "maidsafe/common/accountholdersmanager.h"

#include <maidsafe/kademlia/contact.h>
#include <maidsafe/kademlia/kadid.h>

#include <algorithm>

#include "maidsafe/common/kadops.h"
#include "maidsafe/common/commonutils.h"

namespace maidsafe {

AccountHoldersManager::~AccountHoldersManager() {
  boost::mutex::scoped_lock lock(mutex_);
  while (update_in_progress_) {
#ifdef DEBUG
    printf("In AHM::~AccountHoldersManager, waiting for update...\n");
#endif
    cond_var_.wait(lock);
  }
}

void AccountHoldersManager::Init(const std::string &pmid,
                                 const AccountHolderGroupFunctor &callback) {
  boost::mutex::scoped_lock lock(mutex_);
  do_nothing_ = boost::bind(&AccountHoldersManager::DoNothing, this, _1, _2);
  pmid_ = pmid;
  account_name_ = SHA512String(pmid_ + kAccount);
  UpdateGroup(callback);
}

void AccountHoldersManager::Update() {
  boost::mutex::scoped_lock lock(mutex_);
  UpdateGroup(do_nothing_);
}

void AccountHoldersManager::UpdateGroup(AccountHolderGroupFunctor callback) {
  if (account_name_.empty()) {
#ifdef DEBUG
    printf("In AHM::UpdateGroup, no account name set!\n");
#endif
    return;
  }
  if (update_in_progress_)
    return;
  failed_ids_.clear();
  update_in_progress_ = true;
  // TODO(Fraser#5#): 2010-05-12 - Implement better way of updating, e.g. send a
  //                  single request to a good account holder for his closest
  //                  contacts to account_name_;
  kad_ops_->FindKClosestNodes(account_name_, boost::bind(
      &AccountHoldersManager::FindNodesCallback, this, _1, _2, callback));
}

void AccountHoldersManager::FindNodesCallback(
    const ReturnCode &result,
    const std::vector<kad::Contact> &closest_nodes,
    AccountHolderGroupFunctor callback) {
  std::vector<kad::Contact> account_holder_group;
  {
    boost::mutex::scoped_lock lock(mutex_);
    if (result == kSuccess) {
      last_update_ = boost::posix_time::microsec_clock::universal_time();
      account_holder_group = closest_nodes;
      // Vault cannot be AccountHolder for self
      RemoveKadContact(pmid_, &account_holder_group);
//      if (!RemoveKadContact(pmid_, &account_holder_group))
//        if (ContactWithinClosest(account_name_, kad::Contact(pmid_, "", 0),
//                                 account_holder_group))
//          account_holder_group.pop_back();
    }
    account_holder_group_ = account_holder_group;
    update_in_progress_ = false;
    cond_var_.notify_all();
  }
  callback(result, account_holder_group);
}

bool AccountHoldersManager::UpdateRequired() {
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
  if (UpdateRequired())
    UpdateGroup(do_nothing_);
}


}  // namespace maidsafe
