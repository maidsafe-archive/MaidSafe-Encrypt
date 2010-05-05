/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Kademlia function wrappers for use in PDvault and MSM
* Created:      2010-02-09
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

#include "maidsafe/kadops.h"

namespace maidsafe {

KadOps::KadOps(const boost::shared_ptr<kad::KNode> &knode) : knode_(knode) {}

bool KadOps::AddressIsLocal(const kad::Contact &peer) {
  return knode_->CheckContactLocalAddress(peer.node_id(), peer.local_ip(),
      peer.local_port(), peer.host_ip()) == kad::LOCAL;
}

bool KadOps::AddressIsLocal(const kad::ContactInfo &peer) {
  return knode_->CheckContactLocalAddress(kad::KadId(peer.node_id(), false),
      peer.local_ip(), peer.local_port(), peer.ip()) == kad::LOCAL;
}

void KadOps::GetNodeContactDetails(const kad::KadId &node_id,
                      kad::VoidFunctorOneString cb,
                      const bool &local) {
  knode_->GetNodeContactDetails(node_id, cb, local);
}

void KadOps::FindKClosestNodes(const kad::KadId &kad_key,
                            const kad::VoidFunctorOneString &callback) {
  knode_->FindKClosestNodes(kad_key, callback);
}

int KadOps::FindKClosestNodes(const kad::KadId &kad_key,
                           std::vector<kad::Contact> *contacts) {
  if (contacts == NULL) {
#ifdef DEBUG
    printf("In KadOps::FindKNodes, NULL pointer passed.\n");
#endif
    return kFindNodesError;
  }
  contacts->clear();
  boost::mutex mutex;
  boost::condition_variable cv;
  ReturnCode result(kFindNodesError);
  FindKClosestNodes(kad_key, boost::bind(
      &KadOps::HandleFindCloseNodesResponse, this, _1, kad_key, contacts,
      &mutex, &cv, &result));
  boost::mutex::scoped_lock lock(mutex);
  while (result == kFindNodesError)
    cv.wait(lock);
  return result;
}

void KadOps::HandleFindCloseNodesResponse(
    const std::string &response,
    const kad::KadId&,  //  &kad_key,
    std::vector<kad::Contact> *contacts,
    boost::mutex *mutex,
    boost::condition_variable *cv,
    ReturnCode *result) {
  if (contacts == NULL || mutex == NULL || cv == NULL || result == NULL) {
#ifdef DEBUG
    printf("In KadOps::HandleFindCloseNodesResponse, NULL pointer passed.\n");
#endif
    return;
  }

  kad::FindResponse find_response;
  if (!find_response.ParseFromString(response)) {
#ifdef DEBUG
    printf("In KadOps::HandleFindCloseNodesResponse, can't parse result.\n");
#endif
    boost::mutex::scoped_lock lock(*mutex);
    *result = kFindNodesParseError;
    cv->notify_one();
    return;
  }

  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In KadOps::HandleFindCloseNodesResponse, Kademlia RPC failed.\n");
#endif
    boost::mutex::scoped_lock lock(*mutex);
    *result = kFindNodesFailure;
    cv->notify_one();
    return;
  }

  boost::mutex::scoped_lock lock(*mutex);
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }

  *result = kSuccess;
  cv->notify_one();
}

bool KadOps::ConfirmCloseNode(const kad::KadId & /* kad_key */,
                              const kad::Contact & /* contact */) {
  // TODO(Team#) implement estimator for ConfirmCloseNode
  return true;
}

bool KadOps::ConfirmCloseNodes(const kad::KadId &kad_key,
    const std::vector<kad::Contact> &contacts) {
  std::vector<kad::Contact>::const_iterator it = contacts.begin();
  while (it != contacts.end() && ConfirmCloseNode(kad_key, *it))
    ++it;
  return it == contacts.end();
}

void KadOps::FindValue(const kad::KadId &kad_key,
                       bool check_local,
                       const kad::VoidFunctorOneString &cb) {
  knode_->FindValue(kad_key, check_local, cb);
}

int KadOps::FindValue(const kad::KadId &kad_key,
                      bool check_local,
                      kad::ContactInfo *cache_holder,
                      std::vector<std::string> *values,
                      std::string *needs_cache_copy_id) {
  cache_holder->Clear();
  values->clear();
  // closest_nodes->clear();
  needs_cache_copy_id->clear();

  CallbackObj kad_cb_obj;
  knode_->FindValue(kad_key, check_local,
                    boost::bind(&CallbackObj::CallbackFunc, &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();

  if (kad_cb_obj.result().empty()) {
#ifdef DEBUG
    printf("In KadOps::FindValue, fail - timeout.\n");
#endif
    return kFindValueError;
  }

  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In KadOps::FindValue, can't parse result.\n");
#endif
    return kFindValueParseError;
  }

  /* for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    closest_nodes->push_back(contact);
    // printf("+-- node %s\n", HexSubstr(contact.node_id()).c_str());
  } */

  if (find_response.has_needs_cache_copy())
    *needs_cache_copy_id = find_response.needs_cache_copy();

  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
//    printf("In KadOps::FindValue, failed to find value for key %s"
//           " (found %i nodes, %i values and %i signed vals)\n",
//           HexSubstr(kad_key).c_str(), find_response.closest_nodes_size(),
//           find_response.values_size(), find_response.signed_values_size());

//    printf("Found alt val holder: %i\n",
//           find_response.has_alternative_value_holder());
#endif
    return kFindValueFailure;
  }

  // If the response has an alternative_value, then the value is the ID of a
  // peer which has a cached copy of the chunk.
  if (find_response.result() == kad::kRpcResultSuccess &&
      find_response.has_alternative_value_holder()) {
    *cache_holder = find_response.alternative_value_holder();
#ifdef DEBUG
    printf("In KadOps::FindValue, node %s has cached the value.\n",
           HexSubstr(cache_holder->node_id()).c_str());
#endif
    return kSuccess;
  }

  bool empty(true);
  for (int i = 0; i < find_response.signed_values_size(); ++i) {
    if (!find_response.signed_values(i).value().empty()) {
      empty = false;
      values->push_back(find_response.signed_values(i).value());
    }
  }
#ifdef DEBUG
  printf("In KadOps::FindValue, %i values have returned.\n", values->size());
#endif
  return (empty) ? kFindValueFailure : kSuccess;
}

int KadOps::GetStorePeer(const double&,
                         const std::vector<kad::Contact> &exclude,
                         kad::Contact *new_peer,
                         bool *local) {
// TODO(Fraser#5#): 2009-08-08 - Complete this so that rtt & rank is considered.
  std::vector<kad::Contact> result;
  knode_->GetRandomContacts(1, exclude, &result);
  if (result.size() == size_t(0))
    return kGetStorePeerError;
  *new_peer = result.at(0);
  *local = AddressIsLocal(*new_peer);
  return kSuccess;
}

bool ContactWithinClosest(const kad::KadId &key,
    const kad::Contact &new_contact,
    const std::vector<kad::Contact> &closest_contacts) {
  kad::KadId dist(new_contact.node_id() ^ key);
  for (size_t i = 0; i < closest_contacts.size(); ++i) {
    if (dist < (closest_contacts[i].node_id() ^ key))
      return true;
  }
  return false;
}

bool RemoveKadContact(const kad::KadId &id,
                      std::vector<kad::Contact> *contacts) {
  // TODO(Team#) move to DHT
  for (size_t i = 0; i < contacts->size(); ++i) {
    if (contacts->at(i).node_id() == id) {
      contacts->erase(contacts->begin() + i);
      return true;
    }
  }
  return false;
}

}  // namespace maidsafe
