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
#include <boost/thread/condition_variable.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/function.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/kademlia/contact.h>
#include <maidsafe/kademlia/kadid.h>

#include <set>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "maidsafe/returncodes.h"

namespace maidsafe {

class KadOps;
class AccountHoldersManagerTest;

typedef boost::function<void(const ReturnCode&,
    const std::vector<kad::Contact>&)> AccountHolderGroupFunctor;

class AccountHoldersManager {
 public:
  explicit AccountHoldersManager(const boost::shared_ptr<KadOps> &kad_ops)
      : kMaxFailedNodes_(kKadLowerThreshold - 1),
        kMaxFailsPerNode_(2),
        kMaxUpdateInterval_(600),
        kad_ops_(kad_ops),
        pmid_(),
        account_name_(),
        account_holder_group_(),
        failed_ids_(),
        mutex_(),
        cond_var_(),
        last_update_(boost::posix_time::neg_infin),
        update_in_progress_(false),
        do_nothing_() {}
  ~AccountHoldersManager();
  void Init(const std::string &pmid,
            const AccountHolderGroupFunctor &callback);
  void Update();
  std::vector<kad::Contact> account_holder_group() {
    boost::mutex::scoped_lock lock(mutex_);
    return account_holder_group_;
  }
  std::string account_name() { return account_name_; }
  void ReportFailure(const std::string &account_holders_pmid);
 private:
  AccountHoldersManager &operator=(const AccountHoldersManager&);
  AccountHoldersManager(const AccountHoldersManager&);
  friend class AccountHoldersManagerTest;
  FRIEND_TEST(AccountHoldersManagerTest, BEH_MAID_AHM_Init);
  FRIEND_TEST(AccountHoldersManagerTest, BEH_MAID_AHM_UpdateGroup);
  FRIEND_TEST(AccountHoldersManagerTest, BEH_MAID_AHM_UpdateRequired);
  FRIEND_TEST(AccountHoldersManagerTest, BEH_MAID_AHM_ReportFailure);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_RemoveFromWatchList);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_UpdateAccountStatus);
  void FindNodesCallback(const std::string &response,
                         AccountHolderGroupFunctor callback);
  void UpdateGroup(AccountHolderGroupFunctor callback);
  bool UpdateRequired();
  void DoNothing(const ReturnCode&, const std::vector<kad::Contact>&) {}
  const boost::uint16_t kMaxFailedNodes_, kMaxFailsPerNode_;
  const boost::posix_time::seconds kMaxUpdateInterval_;
  boost::shared_ptr<KadOps> kad_ops_;
  std::string pmid_, account_name_;
  std::vector<kad::Contact> account_holder_group_;
  std::multiset<std::string> failed_ids_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::posix_time::ptime last_update_;
  bool update_in_progress_;
  AccountHolderGroupFunctor do_nothing_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_ACCOUNTHOLDERSMANAGER_H_
