/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*******************************************************************************
 * This is the API for maidsafe-dht and is the only program access for         *
 * developers.  The maidsafe-dht_config.h file included is where configuration *
 * may be saved.  You MUST link the maidsafe-dht library.                      *
 *                                                                             *
 * NOTE: These APIs may be amended or deleted in future releases until this    *
 * notice is removed.                                                          *
 ******************************************************************************/

#ifndef MAIDSAFE_MAIDSAFE_DHT_H_
#define MAIDSAFE_MAIDSAFE_DHT_H_

#include "maidsafe/maidsafe-dht_config.h"

//  int StartListening(port);
//  trans::localport()
//  internal declerations
//  bool message_rec(std::string msg, int ip);


//  actual API
//  Transport
//  int LocalPort() {return trans::localport(); } // XXXX is declared above
//  LocalIP()
//    ExternalPort()
//    External_IP()
//  test


// RPC


// Kademlia
namespace kad {

class KNode {
 public:
  KNode(const std::string &datastore_dir,
        boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
        node_type type);
  // constructor used to set up parameters K, alpha, and beta for kademlia
  KNode(const std::string &datastore_dir,
        boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
        node_type type,
        const boost::uint16_t k,
        const int &alpha,
        const int &beta);
  ~KNode();
  // if node_id is "", it will be randomly generated
  void Join(const std::string &node_id,
            const std::string &kad_config_file,
            base::callback_func_type cb,
            const bool &port_forwarded);
  void Leave();
  void StoreValue(const std::string &key,
                  const std::string &value,
                  const std::string &public_key,
                  const std::string &signed_public_key,
                  const std::string &signed_request,
                  base::callback_func_type cb);
  void FindValue(const std::string &key, base::callback_func_type cb);
  void FindNode(const std::string &node_id,
                base::callback_func_type cb,
                const bool &local);
  void FindCloseNodes(const std::string &node_id,
                      base::callback_func_type cb);
  void FindKClosestNodes(const std::string &key,
                         std::vector<Contact> *close_nodes,
                         const std::vector<Contact> &exclude_contacts);
  void Ping(const std::string &node_id, base::callback_func_type cb);
  void Ping(const Contact &remote, base::callback_func_type cb);
  void AddContact(Contact new_contact, bool only_db);
  void RemoveContact(const std::string &node_id);
  bool GetContact(const std::string &id, Contact *contact);
  void FindValueLocal(const std::string &key,
                      std::vector<std::string> &values);
  void StoreValueLocal(const std::string &key,
                       const std::string &value);
  void GetRandomContacts(const int &count,
                         const std::vector<Contact> &exclude_contacts,
                         std::vector<Contact> *contacts);
  void HandleDeadRendezvousServer(const bool &dead_server,
                                  const std::string &ip,
                                  const uint16_t &port);
  connect_to_node CheckContactLocalAddress(const std::string &id,
                                           const std::string &ip,
                                           const uint16_t &port,
                                           const std::string &ext_ip);
  void UpdatePDRTContactToRemote(const std::string &node_id);
  ContactInfo contact_info() const;
  std::string node_id() const;
  std::string host_ip() const;
  boost::uint16_t host_port() const;
  std::string local_host_ip() const;
  boost::uint16_t local_host_port() const;
  std::string rv_ip() const;
  boost::uint16_t rv_port() const;
  bool is_joined() const;
  KadRpcs* kadrpcs();
 private:
  boost::shared_ptr<KNodeImpl> pimpl_;
};
}  // namespace kad


// RPC
namespace rpcprotocol {

class ChannelManager {
 public:
  ChannelManager();
  ~ChannelManager();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void ClearChannels();
  int StartTransport(
      boost::uint16_t port,
      boost::function<void(const bool&, const std::string&,
                           const boost::uint16_t&)> notify_dead_server);
  int StopTransport();
  void MessageArrive(const std::string &message,
                     const boost::uint32_t &connection_id);
  void MessageSentResult(boost::uint32_t , bool );
  boost::uint32_t CreateNewId();
  void AddPendingRequest(const boost::uint32_t &req_id, PendingReq req);
  void DeleteRequest(const boost::uint32_t &req_id);
  void AddReqToTimer(const boost::uint32_t &req_id, const int &timeout);
  boost::shared_ptr<transport::Transport> ptransport();
  boost::uint16_t external_port() const;
  std::string external_ip() const;
  bool CheckConnection(const std::string &ip, const uint16_t &port);
 private:
  boost::shared_ptr<ChannelManagerImpl> pimpl_;
};

class Controller : public google::protobuf::RpcController {
 public:
  Controller();
  ~Controller();
  void SetFailed(const std::string&);
  void Reset();
  bool Failed() const;
  std::string ErrorText() const;
  void StartCancel();
  bool IsCanceled() const;
  void NotifyOnCancel(google::protobuf::Closure*);
  void set_remote_ip(const std::string &ip);
  void set_remote_port(const uint16_t &port);
  std::string remote_ip() const;
  uint16_t remote_port() const;
  void set_timeout(const int &seconds);
  int timeout() const;
 private:
  boost::shared_ptr<ControllerImpl> controller_pimpl_;
};

class Channel : public google::protobuf::RpcChannel {
 public:
  explicit Channel(rpcprotocol::ChannelManager *channelmanager);
  Channel(rpcprotocol::ChannelManager *channelmanager,
          const std::string &ip,
          const boost::uint16_t &port,
          const bool &local);
  ~Channel();
  void CallMethod(const google::protobuf::MethodDescriptor *method,
                  google::protobuf::RpcController *controller,
                  const google::protobuf::Message *request,
                  google::protobuf::Message *response,
                  google::protobuf::Closure *done);
  void SetService(google::protobuf::Service* service);
  void HandleRequest(const RpcMessage &request,
                     const boost::uint32_t &connection_id);
 private:
  boost::shared_ptr<ChannelImpl> pimpl_;
};
}  // namespace rpcprotocol

//callbacks section
// link our callback funtions to lower level
bool LostNet();
bool ChangedIP();




#endif  // MAIDSAFE_MAIDSAFE_DHT_H_
