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

#ifndef MAIDSAFE_COMMON_ACCOUNTHOLDERSMANAGER_H_
#define MAIDSAFE_COMMON_ACCOUNTHOLDERSMANAGER_H_

#include <set>
#include <string>
#include <vector>
#include <functional>
#include <memory>

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "maidsafe/common/returncodes.h"
#include "maidsafe-dht/kademlia/node_id.h"

namespace maidsafe {

namespace kademlia {
class Contact;
class Node;
}  // namespace kademlia

namespace test {
class AccountHoldersManagerTest;
class AccountHoldersManagerTest_BEH_MAID_AHM_Init_Test;
class AccountHoldersManagerTest_BEH_MAID_AHM_UpdateGroup_Test;
class AccountHoldersManagerTest_BEH_MAID_AHM_UpdateRequired_Test;
class AccountHoldersManagerTest_BEH_MAID_AHM_ReportFailure_Test;
class MaidStoreManagerTest_BEH_MAID_MSM_ExpectAmendment_Test;
class MaidStoreManagerTest_BEH_MAID_MSM_AddToWatchList_Test;
class MaidStoreManagerTest_BEH_MAID_MSM_RemoveFromWatchList_Test;
class MaidStoreManagerTest_BEH_MAID_MSM_UpdateAccountStatus_Test;
}  // namespace test

typedef std::function<void(const ReturnCode&,
    const std::vector<kademlia::Contact>&)> AccountHolderGroupFunctor;

class AccountHoldersManager {
 public:
  AccountHoldersManager(const std::shared_ptr<kademlia::Node> &node,
                        const boost::uint8_t &lower_threshold)
      : kMaxFailedNodes_(lower_threshold > 1 ? lower_threshold - 1 : 1),
        kMaxFailsPerNode_(2),
        kMaxUpdateInterval_(600),
        node_(node),
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
  void Init(const kademlia::NodeId &pmid,
            const AccountHolderGroupFunctor &callback);
  void Update();
  std::vector<kademlia::Contact> account_holder_group() {
    boost::mutex::scoped_lock lock(mutex_);
    return account_holder_group_;
  }
  kademlia::NodeId account_name() {
    boost::mutex::scoped_lock lock(mutex_);
    return account_name_;
  }
  void ReportFailure(const kademlia::NodeId &account_holders_pmid);
 private:
  AccountHoldersManager &operator=(const AccountHoldersManager&);
  AccountHoldersManager(const AccountHoldersManager&);
  friend class test::AccountHoldersManagerTest;
  friend class test::AccountHoldersManagerTest_BEH_MAID_AHM_Init_Test;
  friend class test::AccountHoldersManagerTest_BEH_MAID_AHM_UpdateGroup_Test;
  friend class test::AccountHoldersManagerTest_BEH_MAID_AHM_UpdateRequired_Test;
  friend class test::AccountHoldersManagerTest_BEH_MAID_AHM_ReportFailure_Test;
  friend class test::MaidStoreManagerTest_BEH_MAID_MSM_ExpectAmendment_Test;
  friend class test::MaidStoreManagerTest_BEH_MAID_MSM_AddToWatchList_Test;
  friend class test::MaidStoreManagerTest_BEH_MAID_MSM_RemoveFromWatchList_Test;
  friend class test::MaidStoreManagerTest_BEH_MAID_MSM_UpdateAccountStatus_Test;
  void FindNodesCallback(const int &result,
                         const std::vector<kademlia::Contact> &closest_nodes,
                         AccountHolderGroupFunctor callback);
  void UpdateGroup(AccountHolderGroupFunctor callback);
  bool UpdateRequired();
  void DoNothing(const ReturnCode&, const std::vector<kademlia::Contact>&) {}
  const boost::uint16_t kMaxFailedNodes_, kMaxFailsPerNode_;
  const boost::posix_time::seconds kMaxUpdateInterval_;
  std::shared_ptr<kademlia::Node> node_;
  kademlia::NodeId pmid_, account_name_;
  std::vector<kademlia::Contact> account_holder_group_;
  std::multiset<kademlia::NodeId> failed_ids_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::posix_time::ptime last_update_;
  bool update_in_progress_;
  AccountHolderGroupFunctor do_nothing_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_ACCOUNTHOLDERSMANAGER_H_
