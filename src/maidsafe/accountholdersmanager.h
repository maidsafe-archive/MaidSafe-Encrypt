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
#include <maidsafe/kademlia/contact.h>
#include <maidsafe/kademlia/kadid.h>
#include <set>
#include <string>
#include "maidsafe/returncodes.h"

namespace maidsafe {

class KadOps;

class AccountHolderDetails {
 public:
  AccountHolderDetails(const kad::Contact &contact, bool local)
      : contact_(contact),
        local_(local),
        last_contacted_(boost::posix_time::microsec_clock::universal_time()) {}
  AccountHolderDetails(const AccountHolderDetails &other)
      : contact_(other.contact_),
        local_(other.local_),
        last_contacted_(other.last_contacted_) {}
  AccountHolderDetails &operator=(const AccountHolderDetails &other) {
    contact_ = other.contact_;
    local_ = other.local_;
    last_contacted_ = other.last_contacted_;
    return *this;
  }
  kad::Contact contact() { return contact_; }
  bool local() { return local_; }
  boost::posix_time::ptime last_contacted() { return last_contacted_; }
  void UpdateLastContactedToNow() {
    last_contacted_ = boost::posix_time::microsec_clock::universal_time();
  }
 private:
  kad::Contact contact_;
  bool local_;
  boost::posix_time::ptime last_contacted_;
};

typedef std::set< AccountHolderDetails,
    boost::function<bool(const AccountHolderDetails&,
                         const AccountHolderDetails&)> > AccountHolderSet;

typedef boost::function<void(const ReturnCode&, const AccountHolderSet&)>
    AccountHolderSetFunctor;

class AccountHoldersManager {
 public:
  explicit AccountHoldersManager(boost::shared_ptr<KadOps> kad_ops)
      : kad_ops_(kad_ops),
        pmid_(),
        account_name_(),
        account_holder_set_(),
        mutex_(),
        last_update_(boost::posix_time::neg_infin) {}
  void Init(const std::string &pmid,
            const AccountHolderSetFunctor &callback);
  AccountHolderSet account_holder_set() {
    boost::mutex::scoped_lock lock(mutex_);
    return account_holder_set_;
  }
  std::string account_name() { return account_name_; }
  void UpdateMap(AccountHolderSetFunctor callback);
 private:
  AccountHoldersManager &operator=(const AccountHoldersManager&);
  AccountHoldersManager(const AccountHoldersManager&);
  void FindNodesCallback(const std::string &response,
                         AccountHolderSetFunctor callback);
  bool CompareHolders(AccountHolderDetails lhs,
                      AccountHolderDetails rhs) {
    return kad::KadId::CloserToTarget(lhs.contact().node_id(),
        rhs.contact().node_id(), kad::KadId(account_name_, false));
  }
  boost::shared_ptr<KadOps> kad_ops_;
  std::string pmid_, account_name_;
  AccountHolderSet account_holder_set_;
  boost::mutex mutex_;
  boost::posix_time::ptime last_update_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_ACCOUNTHOLDERSMANAGER_H_
