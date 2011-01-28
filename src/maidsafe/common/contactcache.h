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

// TODO(Steve#) auto-update contact

#ifndef MAIDSAFE_COMMON_CONTACTCACHE_H_
#define MAIDSAFE_COMMON_CONTACTCACHE_H_

#include <set>
#include <string>
#include <vector>
#include <functional>

#include "boost/thread/condition_variable.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/thread/mutex.hpp"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe/common/returncodes.h"

namespace maidsafe {

namespace test { class ContactCacheTest_BEH_MAID_CTC_Update_Test; }
namespace kademlia { class Node; }

class ContactCache {
 public:
  explicit ContactCache(const boost::shared_ptr<kademlia::Node> &node)
      : kMaxUpdateInterval_(10),
        node_(node),
        pmid_(),
        contact_(),
        mutex_(),
        cond_var_(),
        last_update_(boost::posix_time::neg_infin),
        active_(false),
        update_in_progress_(false) {}
  ~ContactCache();
  void Init(const kademlia::NodeId &pmid_);
  void Update();
  void WaitForUpdate();
  bool GetContact(kademlia::Contact *contact);
  kademlia::NodeId pmid() {
    boost::mutex::scoped_lock lock(mutex_);
    return pmid_;
  }
  bool active() {
    boost::mutex::scoped_lock lock(mutex_);
    return active_;
  }
 private:
  ContactCache &operator=(const ContactCache&);
  ContactCache(const ContactCache&);
  friend class test::ContactCacheTest_BEH_MAID_CTC_Update_Test;
  void DoUpdate();
  void GetContactCallback(const int &result,
                          const kademlia::Contact &contact);
  const boost::posix_time::seconds kMaxUpdateInterval_;
  boost::shared_ptr<kademlia::Node> node_;
  kademlia::NodeId pmid_;
  kademlia::Contact contact_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::posix_time::ptime last_update_;
  bool active_, update_in_progress_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_CONTACTCACHE_H_
