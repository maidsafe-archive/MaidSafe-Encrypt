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

#include <boost/filesystem.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <maidsafe/maidsafe-dht_config.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace transport {
class TransportHandler;
}  // namespace transport

namespace rpcprotocol {
class ChannelManager;
}  // namespace rpcprotocol

namespace kad {
class SignedValue;
class SignedRequest;
}  // namespace kad

namespace maidsafe {

class TestClientBP;

namespace test {
class CBPHandlerTest;
}  // namespace test

class ChunkStore;
class EndPoint;

class KadOps {
 public:
  KadOps(transport::TransportHandler *transport_handler,
         rpcprotocol::ChannelManager *channel_manager,
         kad::NodeType type,
         const std::string &private_key,
         const std::string &public_key,
         bool port_forwarded,
         bool use_upnp,
         boost::uint8_t k,
         boost::shared_ptr<ChunkStore> chunkstore);
  virtual ~KadOps() {}
  void Init(const boost::filesystem::path &kad_config,
            bool first_node,
            const std::string &pmid,
            const boost::uint16_t &port,
            boost::mutex *mutex,
            boost::condition_variable *cond_var,
            ReturnCode *result);
  void Leave() { knode_.Leave(); }
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
  virtual void GetNodeContactDetails(const std::string &node_id,
                                     kad::VoidFunctorOneString callback,
                                     bool local);
  /**
   * Wrapper for the non-blocking Kademlia function.
   */
  virtual void FindKClosestNodes(const std::string &key,
                                 kad::VoidFunctorOneString callback);
  /**
   * Blocking call to Kademlia's FindKClosestNodes.
   */
  int BlockingFindKClosestNodes(const std::string &key,
                                std::vector<kad::Contact> *contacts);
  /**
   * A callback handler for passing to FindKClosestNodes.
   */
  void HandleFindCloseNodesResponse(const std::string &response,
                                    std::vector<kad::Contact> *contacts,
                                    boost::mutex *mutex,
                                    boost::condition_variable *cv,
                                    ReturnCode *result);
  /**
   * Estimates whether a given node is within the K closest to a key.
   */
  virtual bool ConfirmCloseNode(const std::string &key,
                                const kad::Contact &contact);
  /**
   * Estimates whether a given set of nodes is within the K closest to a key.
   */
  bool ConfirmCloseNodes(const std::string &key,
                         const std::vector<kad::Contact> &contacts);
  /**
  * Stores a <key,signed_value> in the network.
  */
  void StoreValue(const std::string &key,
                  const kad::SignedValue &signed_value,
                  const kad::SignedRequest &signed_request,
                  kad::VoidFunctorOneString callback);
  /**
  * Deletes a <key,signed_value> from the network.
  */
  void DeleteValue(const std::string &key,
                   const kad::SignedValue &signed_value,
                   const kad::SignedRequest &signed_request,
                   kad::VoidFunctorOneString callback);
  /**
  * Updates (overwrites) a <key,signed_value> from the network.
  */
  void UpdateValue(const std::string &key,
                   const kad::SignedValue &old_value,
                   const kad::SignedValue &new_value,
                   const kad::SignedRequest &signed_request,
                   kad::VoidFunctorOneString callback);
  /**
   * Simple wrapper for the Kademlia function.
   */
  virtual void FindValue(const std::string &key,
                         bool check_local,
                         kad::VoidFunctorOneString callback);
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
  /**
  * Notifier that is passed to the transport object for the case where the
  * node's randezvous server goes down.
  * @param dead_server notification of status of the rendezvous server: True
  * server is up, False server is down
  */
  void HandleDeadRendezvousServer(bool dead_server) {
    knode_.HandleDeadRendezvousServer(dead_server);
  }
  void SetThisEndpoint(EndPoint *this_endpoint);
  void set_transport_id(const boost::int16_t &transport_id) {
    knode_.set_transport_id(transport_id);
  }
  void set_signature_validator(base::SignatureValidator *validator) {
    knode_.set_signature_validator(validator);
  }
  boost::uint16_t Port() const { return knode_.host_port(); }
  kad::ContactInfo contact_info() const { return knode_.contact_info(); }
  boost::uint8_t k() const { return K_; }
  friend class test::CBPHandlerTest;
  friend class TestClientBP;
 private:
  KadOps(const KadOps&);
  KadOps& operator=(const KadOps&);
  bool GetKadId(const std::string &key, kad::KadId *kad_id);
  void InitCallback(const std::string &response,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var,
                    ReturnCode *result);
  const boost::uint8_t K_;
  kad::KNode knode_;
  kad::NodeType node_type_;
  boost::int32_t default_time_to_live_;
};

/**
 * Determine whether a contact is closer to a key than at least one of the
 * contacts in a given vector.
 * @param key Kademlia key for calculating the distance
 * @param new_contact the reference contact to compare the others to
 * @param closest_contacts a vector of contacts to compare new_contact to
 * @return true if new_contact is closer to key than one of closest_contacts
 */
bool ContactWithinClosest(
    const std::string &key,
    const kad::Contact &new_contact,
    const std::vector<kad::Contact> &closest_contacts);

/**
 * Removes the contact with a given ID from a vector of contacts, if included.
 * @param id the contact ID to search for and remove
 * @param contacts pointer to a contact vector to remove the contact from
 * @return true if contact found and removed, otherwise false
 */
bool RemoveKadContact(const std::string &key,
                      std::vector<kad::Contact> *contacts);

}  // namespace maidsafe

#endif  // MAIDSAFE_KADOPS_H_
