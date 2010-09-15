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

#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/protobuf/signed_kadvalue.pb.h>

#include <algorithm>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "protobuf/packet.pb.h"

namespace maidsafe {

KadOps::KadOps(transport::TransportHandler *transport_handler,
               rpcprotocol::ChannelManager *channel_manager,
               kad::NodeType type,
               const std::string &private_key,
               const std::string &public_key,
               bool port_forwarded,
               bool use_upnp,
               boost::uint8_t k,
               boost::shared_ptr<ChunkStore> chunkstore)
    : K_(k),
      knode_(channel_manager, transport_handler, type, private_key,
             public_key, port_forwarded, use_upnp, K_),
      node_type_(type),
      default_time_to_live_(31556926) {
  knode_.set_alternative_store(chunkstore.get());
}

void KadOps::Init(const boost::filesystem::path &kad_config,
                  bool first_node,
                  const std::string &pmid,
                  const boost::uint16_t &port,
                  boost::mutex *mutex,
                  boost::condition_variable *cond_var,
                  ReturnCode *result) {
  boost::filesystem::path kad_config_path(".kadconfig");
  try {
    if (boost::filesystem::exists(kad_config)) {
      kad_config_path = kad_config;
    } else if (!boost::filesystem::exists(kad_config_path)) {
      kad_config_path = (file_system::ApplicationDataDir() / ".kadconfig");
    }
    if (!first_node && !boost::filesystem::exists(kad_config_path)) {
#ifdef DEBUG
      printf("In KadOps::Init, can't find kadconfig at %s - Failed to start "
             "knode.\n", kad_config_path.string().c_str());
#endif
    }
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("In KadOps::Init - %s\n", ex.what());
#endif
    boost::mutex::scoped_lock lock(*mutex);
    *result = kKadConfigException;
    cond_var->notify_one();
    return;
  }
  if (node_type_ == kad::CLIENT) {
    knode_.Join(kad_config_path.string(), boost::bind(&KadOps::InitCallback,
        this, _1, mutex, cond_var, result));
  } else {
    if (first_node) {
      boost::asio::ip::address local_ip;
      base::GetLocalAddress(&local_ip);
      knode_.Join(kad::KadId(pmid), kad_config_path.string(),
          local_ip.to_string(), port, boost::bind(&KadOps::InitCallback, this,
          _1, mutex, cond_var, result));
    } else {
      knode_.Join(kad::KadId(pmid), kad_config_path.string(),
          boost::bind(&KadOps::InitCallback, this, _1, mutex, cond_var,
          result));
    }
  }
}

void KadOps::InitCallback(const std::string &response,
                          boost::mutex *mutex,
                          boost::condition_variable *cond_var,
                          ReturnCode *result) {
  base::GeneralResponse kad_response;
  boost::mutex::scoped_lock lock(*mutex);
  if (!kad_response.ParseFromString(response) ||
      kad_response.result() != kad::kRpcResultSuccess) {
    *result = kKadOpsInitFailure;
  } else {
    *result = kSuccess;
  }
  cond_var->notify_one();
}

bool KadOps::AddressIsLocal(const kad::Contact &peer) {
  return knode_.CheckContactLocalAddress(peer.node_id(), peer.local_ip(),
      peer.local_port(), peer.host_ip()) == kad::LOCAL;
}

bool KadOps::AddressIsLocal(const kad::ContactInfo &peer) {
  return knode_.CheckContactLocalAddress(kad::KadId(peer.node_id()),
                                         peer.local_ip(), peer.local_port(),
                                         peer.ip()) == kad::LOCAL;
}

void KadOps::GetNodeContactDetails(const std::string &node_id,
                                   kad::VoidFunctorOneString callback,
                                   bool local) {
  kad::KadId kad_id;
  if (!GetKadId(node_id, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.GetNodeContactDetails(kad_id, callback, local);
}

void KadOps::FindKClosestNodes(const std::string &key,
                               kad::VoidFunctorOneString callback) {
  kad::KadId kad_id;
  if (!GetKadId(key, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.FindKClosestNodes(kad_id, callback);
}

int KadOps::BlockingFindKClosestNodes(const std::string &key,
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
  FindKClosestNodes(key, boost::bind(&KadOps::HandleFindCloseNodesResponse,
                                     this, _1, contacts, &mutex, &cv, &result));
  boost::mutex::scoped_lock lock(mutex);
  while (result == kFindNodesError)
    cv.wait(lock);
  return result;
}

void KadOps::HandleFindCloseNodesResponse(
    const std::string &response,
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

bool KadOps::ConfirmCloseNode(const std::string & /* key */,
                              const kad::Contact & /* contact */) {
  // TODO(Team#) implement estimator for ConfirmCloseNode
  return true;
}

bool KadOps::ConfirmCloseNodes(
    const std::string &key,
    const std::vector<kad::Contact> &contacts) {
  std::vector<kad::Contact>::const_iterator it = contacts.begin();
  while (it != contacts.end() && ConfirmCloseNode(key, *it))
    ++it;
  return it == contacts.end();
}

void KadOps::StoreValue(const std::string &key,
                        const kad::SignedValue &signed_value,
                        const kad::SignedRequest &signed_request,
                        kad::VoidFunctorOneString callback) {
  kad::KadId kad_id;
  if (!GetKadId(key, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.StoreValue(kad_id, signed_value, signed_request, default_time_to_live_,
                    callback);
}

void KadOps::DeleteValue(const std::string &key,
                         const kad::SignedValue &signed_value,
                         const kad::SignedRequest &signed_request,
                         kad::VoidFunctorOneString callback) {
  kad::KadId kad_id;
  if (!GetKadId(key, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.DeleteValue(kad_id, signed_value, signed_request, callback);
}

void KadOps::UpdateValue(const std::string &key,
                         const kad::SignedValue &old_value,
                         const kad::SignedValue &new_value,
                         const kad::SignedRequest &signed_request,
                         kad::VoidFunctorOneString callback) {
  kad::KadId kad_id;
  if (!GetKadId(key, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.UpdateValue(kad_id, old_value, new_value, signed_request,
                     default_time_to_live_, callback);
}

void KadOps::FindValue(const std::string &key,
                       bool check_local,
                       kad::VoidFunctorOneString callback) {
  kad::KadId kad_id;
  if (!GetKadId(key, &kad_id)) {
    callback(kad::kRpcResultFailure);
    return;
  }
  knode_.FindValue(kad_id, check_local, callback);
}

int KadOps::GetStorePeer(const double & /* ideal_rtt */,
                         const std::vector<kad::Contact> &exclude,
                         kad::Contact *new_peer,
                         bool *local) {
// TODO(Fraser#5#): 2009-08-08 - Complete this so that rtt & rank is considered.
  std::vector<kad::Contact> result;
  knode_.GetRandomContacts(1, exclude, &result);
  if (result.empty())
    return kGetStorePeerError;
  *new_peer = result.at(0);
  *local = AddressIsLocal(*new_peer);
  return kSuccess;
}

void KadOps::SetThisEndpoint(EndPoint *this_endpoint) {
  this_endpoint->add_ip(knode_.host_ip());
  this_endpoint->add_ip(knode_.local_host_ip());
  this_endpoint->add_ip(knode_.rendezvous_ip());
  this_endpoint->add_port(knode_.host_port());
  this_endpoint->add_port(knode_.local_host_port());
  this_endpoint->add_port(knode_.rendezvous_port());
}

bool KadOps::GetKadId(const std::string &key, kad::KadId *kad_id) {
  *kad_id = kad::KadId(key);
  if (kad_id->IsValid()) {
    return true;
  } else {
    *kad_id = kad::KadId();
    return false;
  }
}

bool ContactWithinClosest(
    const std::string &key,
    const kad::Contact &new_contact,
    const std::vector<kad::Contact> &closest_contacts) {
  kad::KadId kad_id;
  try {
    kad_id = kad::KadId(key);
  }
  catch(const std::exception&) {
    return false;
  }
  kad::KadId dist(new_contact.node_id() ^ kad_id);
  std::vector<kad::Contact>::const_reverse_iterator rit =
      closest_contacts.rbegin();
  while (rit != closest_contacts.rend()) {
    if (dist < ((*rit).node_id() ^ kad_id))
      return true;
    else
      ++rit;
  }
  return false;
}

bool RemoveKadContact(const std::string &key,
                      std::vector<kad::Contact> *contacts) {
  // TODO(Team#) move to DHT
  kad::Contact contact(key, "127.0.0.1", 1);
  std::vector<kad::Contact>::iterator it = std::find_if(contacts->begin(),
      contacts->end(), boost::bind(&kad::Contact::Equals, &contact, _1));
  if (it != contacts->end()) {
    contacts->erase(it);
    return true;
  } else {
    return false;
  }
}

}  // namespace maidsafe
