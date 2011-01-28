/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for managing a node's contact details.
* Created:      2010-11-11
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

#include "maidsafe/common/contactcache.h"
#include "maidsafe-dht/kademlia/node-api.h"

namespace maidsafe {

ContactCache::~ContactCache() {
  WaitForUpdate();
}

void ContactCache::Init(const kademlia::NodeId& pmid) {
  if (!pmid.IsValid()) {
#ifdef DEBUG
    printf("In ContactCache::Init, no valid PMID set.\n");
#endif
    return;
  }
  boost::mutex::scoped_lock lock(mutex_);
  while (update_in_progress_)
    cond_var_.wait(lock);
  last_update_ = boost::posix_time::neg_infin;
  active_ = false;
  pmid_ = pmid;
  DoUpdate();
}

void ContactCache::Update() {
  boost::mutex::scoped_lock lock(mutex_);
  if (!pmid_.IsValid()) {
#ifdef DEBUG
    printf("In ContactCache::Update, no valid PMID set.\n");
#endif
    return;
  }
  if (!update_in_progress_ &&
      boost::posix_time::microsec_clock::universal_time() >=
          last_update_ + kMaxUpdateInterval_)
    DoUpdate();
}

void ContactCache::WaitForUpdate() {
  boost::mutex::scoped_lock lock(mutex_);
  while (update_in_progress_)
    cond_var_.wait(lock);
}

bool ContactCache::GetContact(kademlia::Contact *contact) {
  boost::mutex::scoped_lock lock(mutex_);
  if (active_ && contact != NULL) {
    *contact = contact_;
    return true;
  }
  return false;
}

void ContactCache::DoUpdate() {
  update_in_progress_ = true;
  node_->GetContact(pmid_, boost::bind(&ContactCache::GetContactCallback, this,
                                       _1, _2));
}

void ContactCache::GetContactCallback(const int& result,
                                      const kademlia::Contact& contact) {
  boost::mutex::scoped_lock lock(mutex_);
  if (result == kSuccess) {
    last_update_ = boost::posix_time::microsec_clock::universal_time();
    active_ = true;
#ifdef DEBUG
//     printf("In ContactCache::GetNodeContactDetailsCallback, "
//            "contact %s updated.\n", HexSubstr(pmid_).c_str());
#endif
  } else {
    active_ = false;
#ifdef DEBUG
//     printf("In ContactCache::GetNodeContactDetailsCallback, "
//            "contact %s not found.\n", HexSubstr(pmid_).c_str());
#endif
  }
  contact_ = contact;
  update_in_progress_ = false;
  cond_var_.notify_all();
}


}  // namespace maidsafe
