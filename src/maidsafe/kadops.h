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

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace maidsafe {

class CallbackObj {
 public:
  CallbackObj() : mutex_(), called_(false), result_() {}
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
  virtual ~KadOps() {}
  /**
   * Returns true if the peer is on the local network.
   */
  virtual bool AddressIsLocal(const kad::Contact &peer);
  /**
   * Returns true if the peer is on the local network.
   */
  virtual bool AddressIsLocal(const kad::ContactInfo &peer);
  /**
   * Wrapper for the non-blocking Kademlia function.
   */
  virtual void GetNodeContactDetails(const kad::KadId &node_id,
                        kad::VoidFunctorOneString cb,
                        const bool &local);
  /**
   * Wrapper for the non-blocking Kademlia function.
   */
  virtual void FindKClosestNodes(const kad::KadId &kad_key,
                              const kad::VoidFunctorOneString &callback);
  /**
   * Blocking call to Kademlia's FindCloseNodes.
   */
  virtual int FindKClosestNodes(const kad::KadId &kad_key,
                             std::vector<kad::Contact> *contacts);
  /**
   * A callback handler for passing to FindCloseNodes.
   */
  void HandleFindCloseNodesResponse(const std::string &response,
                                    const kad::KadId &kad_key,
                                    std::vector<kad::Contact> *contacts,
                                    boost::mutex *mutex,
                                    boost::condition_variable *cv,
                                    ReturnCode *result);
  /**
   * Blocking call to Kademlia Find Value.  If the maidsafe value is cached,
   * this may yield serialised contact details for a cache copy holder.
   * Otherwise it should yield the values.  It also yields the details of the
   * closest nodes and the last kad node to not return the value during the
   * lookup.  If check_local is true, it also checks the local chunkstore first.
   * The values are loaded in reverse order.
   */
  virtual int FindValue(const kad::KadId &kad_key,
                        bool check_local,
                        kad::ContactInfo *cache_holder,
                        std::vector<std::string> *values,
                        std::string *needs_cache_copy_id);
  /**
   * Simple wrapper for the Kademlia function.
   */
  virtual void FindValue(const kad::KadId &kad_key,
                         bool check_local,
                         const kad::VoidFunctorOneString &cb);
  /**
   * Get a new contact from the routing table to try and store a chunk on.  The
   * closest to the ideal_rtt will be chosen from those not in the vector to
   * exclude.  If the ideal_rtt is -1.0, then the contact with the highest rtt
   * will be chosen.
   */
  virtual int GetStorePeer(const double &ideal_rtt,
                           const std::vector<kad::Contact> &exclude,
                           kad::Contact *new_peer,
                           bool *local);
 private:
  KadOps(const KadOps&);
  KadOps& operator=(const KadOps&);
  boost::shared_ptr<kad::KNode> knode_;
};

/**
 * Determine whether a contact is closer to a key than at least one of the
 * contacts in a given vector.
 * @param key Kademlia key for calculating the distance
 * @param new_contact the reference contact to compare the others to
 * @param closest_contacts a vector of contacts to compare new_contact to
 * @return true if new_contact is closer to key than one of closest_contacts
 */
bool ContactWithinClosest(const kad::KadId &key,
    const kad::Contact &new_contact,
    const std::vector<kad::Contact> &closest_contacts);

/**
 * Removes the contact with a given ID from a vector of contacts, if included.
 * @param id the contact ID to search for and remove
 * @param contacts pointer to a contact vector to remove the contact from
 * @return true if contact found and removed, otherwise false
 */
bool RemoveKadContact(const kad::KadId &id,
                      std::vector<kad::Contact> *contacts);

}  // namespace maidsafe

#endif  // MAIDSAFE_KADOPS_H_
