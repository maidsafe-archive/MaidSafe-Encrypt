/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Object with Kademlia function wrappers for use in PDvault/MSM
* Created:      2010-02-08
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

#ifndef MAIDSAFE_KADOPS_H_
#define MAIDSAFE_KADOPS_H_

#include <boost/thread/locks.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/kademlia_service_messages.pb.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace maidsafe {

class CallbackObj {
 public:
  CallbackObj() : mutex_(), called_(false), result_("") {}
  ~CallbackObj() {}
  void CallbackFunc(const std::string &result) {
    boost::mutex::scoped_lock lock(mutex_);
    result_ = result;
    called_ = true;
  }
  std::string result() {
//    printf("Callback obj result() - afore lock\n");
    boost::mutex::scoped_lock lock(mutex_);
//    printf("Callback obj result() - after lock\n");
    return called_ ? result_ : "";
  }
  bool called() {
    boost::mutex::scoped_lock lock(mutex_);
    return called_;
  }
  //  Block until callback happens or timeout (milliseconds) passes.
  void WaitForCallback(const int &timeout) {
    int count = 0;
    while (!called() && count < timeout) {
      count += 10;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
  }
  //  Block until callback happens.
  void WaitForCallback() {
//    printf("Callback obj WaitForCallback() - start\n");
    while (!called()) {
//      printf("Callback obj WaitForCallback() - afore sleep\n");
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//      printf("Callback obj WaitForCallback() - after slepp\n");
    }
  }
 private:
  boost::mutex mutex_;
  bool called_;
  std::string result_;
};

class KadOps {
 public:
  explicit KadOps(const boost::shared_ptr<kad::KNode> &knode);
  virtual ~KadOps() {};
  /**
   * Returns true if the peer is on the local network.
   */
  virtual bool AddressIsLocal(const kad::Contact &peer);
  /**
   * Returns true if the peer is on the local network.
   */
  virtual bool AddressIsLocal(const kad::ContactInfo &peer);
  /**
   * Blocking call to Kademlia Find Nodes.
   */
  virtual int FindKNodes(const std::string &kad_key,
                         std::vector<kad::Contact> *contacts);
  /**
   * Blocking call to Kademlia Find Value.  If the maidsafe value is cached,
   * this may yield serialised contact details for a cache copy holder.
   * Otherwise it should yield the values (which may represent chunk holders'
   * IDs).  It also yields the details of the last kad node to not return the
   * value during the lookup.  If check_local is true, it also checks the local
   * chunkstore first.  The values are loaded in reverse order.
   */
  virtual int FindValue(const std::string &kad_key,
                        bool check_local,
                        kad::ContactInfo *cache_holder,
                        std::vector<std::string> *values,
                        std::string *needs_cache_copy_id);
  /**
   * Simple wrapper for the Kademlia function.
   */
  virtual void FindValue(const std::string &kad_key,
                        bool check_local,
                        const base::callback_func_type &cb);
  /**
   * Simple wrapper for the Kademlia function.
   */
  virtual void FindCloseNodes(const std::string &kad_key,
                              const base::callback_func_type &callback);
  /**
   * Get a new contact from the routing table to try and store a chunk on.  The
   * closest to the ideal_rtt will be chosen from those not in the vector to
   * exclude.  If the ideal_rtt is -1.0, then the contact with the highest rtt
   * will be chosen.
   */
  virtual int GetStorePeer(const float &ideal_rtt,
                           const std::vector<kad::Contact> &exclude,
                           kad::Contact *new_peer,
                           bool *local);
 private:
  KadOps(const KadOps&);
  KadOps& operator=(const KadOps&);
  boost::shared_ptr<kad::KNode> knode_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_KADOPS_H_
