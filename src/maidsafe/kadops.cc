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
  return knode_->CheckContactLocalAddress(peer.node_id(), peer.local_ip(),
      peer.local_port(), peer.ip()) == kad::LOCAL;
}

int KadOps::FindKNodes(const std::string &kad_key,
                       std::vector<kad::Contact> *contacts) {
  CallbackObj kad_cb_obj;
  knode_->FindCloseNodes(kad_key, boost::bind(&CallbackObj::CallbackFunc,
                                              &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
  if (kad_cb_obj.result().empty()) {
#ifdef DEBUG
    printf("In KadOps::FindKNodes, fail - timeout.\n");
#endif
    return kFindNodesError;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In KadOps::FindKNodes, can't parse result.\n");
#endif
    return kFindNodesParseError;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In KadOps::FindKNodes, Kademlia operation failed.\n");
#endif
    return kFindNodesFailure;
  }
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }
  return kSuccess;
}

void KadOps::FindValue(const std::string &kad_key,
                       bool check_local,
                       const base::callback_func_type &cb) {
  knode_->FindValue(kad_key, check_local, cb);
}

int KadOps::FindValue(const std::string &kad_key,
                      bool check_local,
                      kad::ContactInfo *cache_holder,
                      std::vector<std::string> *values,
                      std::string *needs_cache_copy_id) {
  cache_holder->Clear();
  values->clear();
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
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In KadOps::FindValue, Kademlia op failed to find the value for key "
           "%s.\n", HexSubstr(kad_key).c_str());
    printf("  Found %i nodes\n", find_response.closest_nodes_size());
    printf("  Found %i values\n", find_response.values_size());
//    printf("Found alt val holder: %i\n",
//           find_response.has_alternative_value_holder());
#endif
    return kFindValueFailure;
  }
  if (find_response.has_needs_cache_copy())
    *needs_cache_copy_id = find_response.needs_cache_copy();
  // If the response has an alternative_value, then the value is the ID of a
  // peer which has a cached copy of the chunk.
  if (find_response.has_alternative_value_holder()) {
    *cache_holder = find_response.alternative_value_holder();
#ifdef DEBUG
    printf("In KadOps::FindValue, node %s has cached the value.\n",
           HexSubstr(cache_holder->node_id()).c_str());
#endif
    return kSuccess;
  }
  bool empty(true);
  for (int i = 0; i < find_response.values_size(); ++i) {
    if (!find_response.values(i).empty()) {
      empty = false;
      values->push_back(find_response.values(i));
    }
  }
#ifdef DEBUG
  printf("In KadOps::FindValue, %i values have returned.\n", values->size());
#endif
  return (empty) ? kFindValueFailure : kSuccess;
}

void KadOps::FindCloseNodes(const std::string &kad_key,
                            const base::callback_func_type &callback) {
  knode_->FindCloseNodes(kad_key, callback);
}

int KadOps::GetStorePeer(const float &,
                         const std::vector<kad::Contact> &exclude,
                         kad::Contact *new_peer,
                         bool *local) {
// TODO(Fraser#5#): 2009-08-08 - Complete this so that rtt & rank is considered.
  std::vector<kad::Contact> result;
  knode_->GetRandomContacts(1, exclude, &result);
  if (result.size() == static_cast<unsigned int>(0))
    return kGetStorePeerError;
  *new_peer = result.at(0);
  *local = AddressIsLocal(*new_peer);
  return kSuccess;
}

}  // namespace maidsafe
