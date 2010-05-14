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

#ifndef MAIDSAFE_ACCOUNTHOLDERSMANAGER_H_
#define MAIDSAFE_ACCOUNTHOLDERSMANAGER_H_

#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/function.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/kademlia/contact.h>
#include <maidsafe/kademlia/kadid.h>
#include <string>
#include <vector>
#include "maidsafe/returncodes.h"

namespace maidsafe {

class KadOps;

typedef boost::function<void(const ReturnCode&,
    const std::vector<kad::Contact>&)> AccountHolderGroupFunctor;

class AccountHoldersManager {
 public:
  explicit AccountHoldersManager(boost::shared_ptr<KadOps> kad_ops)
      : kad_ops_(kad_ops),
        pmid_(),
        account_name_(),
        account_holder_group_(),
        mutex_(),
        last_update_(boost::posix_time::neg_infin) {}
  void Init(const std::string &pmid,
            const AccountHolderGroupFunctor &callback);
  std::vector<kad::Contact> account_holder_group() {
    boost::mutex::scoped_lock lock(mutex_);
    return account_holder_group_;
  }
  std::string account_name() { return account_name_; }
  void UpdateMap(AccountHolderGroupFunctor callback);
 private:
  AccountHoldersManager &operator=(const AccountHoldersManager&);
  AccountHoldersManager(const AccountHoldersManager&);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList);
  void FindNodesCallback(const std::string &response,
                         AccountHolderGroupFunctor callback);
  bool CompareHolders(kad::Contact lhs, kad::Contact rhs) {
    return kad::KadId::CloserToTarget(lhs.node_id(), rhs.node_id(),
                                      kad::KadId(account_name_, false));
  }
  boost::shared_ptr<KadOps> kad_ops_;
  std::string pmid_, account_name_;
  std::vector<kad::Contact> account_holder_group_;
  boost::mutex mutex_;
  boost::posix_time::ptime last_update_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_ACCOUNTHOLDERSMANAGER_H_
