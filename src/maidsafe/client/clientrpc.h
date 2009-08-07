/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  RPCs used by maidsafe client
* Version:      1.0
* Created:      2009-02-22-00.18.57
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_CLIENTRPC_H_
#define MAIDSAFE_CLIENT_CLIENTRPC_H_

#include <maidsafe/maidsafe-dht.h>

#include <string>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

class ClientRpcs {
 public:
  explicit ClientRpcs(boost::shared_ptr<rpcprotocol::ChannelManager>
      channel_manager);
  ~ClientRpcs() {}
  void StorePrep(const std::string &chunkname,
                 const boost::uint64_t &data_size,
                 const std::string &pmid,
                 const std::string &public_key,
                 const std::string &signed_public_key,
                 const std::string &signed_request,
                 const std::string &remote_ip,
                 const boost::uint16_t &remote_port,
                 const std::string &rendezvous_ip,
                 const boost::uint16_t &rendezvous_port,
                 StorePrepResponse *response,
                 rpcprotocol::Controller *controller,
                 google::protobuf::Closure *done);
  void Store(const std::string &chunkname,
             const std::string &data,
             const std::string &public_key,
             const std::string &signed_public_key,
             const std::string &signed_request,
             const ValueType &data_type,
             const std::string &remote_ip,
             const boost::uint16_t &remote_port,
             const std::string &rendezvous_ip,
             const boost::uint16_t &rendezvous_port,
             StoreResponse *response,
             rpcprotocol::Controller *controller,
             google::protobuf::Closure *done);
  void CheckChunk(const std::string &chunkname,
                  const std::string &remote_ip,
                  const boost::uint16_t &remote_port,
                  const std::string &rendezvous_ip,
                  const boost::uint16_t &rendezvous_port,
                  CheckChunkResponse *response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void Get(const std::string &chunkname,
           const std::string &remote_ip,
           const boost::uint16_t &remote_port,
           const std::string &rendezvous_ip,
           const boost::uint16_t &rendezvous_port,
           GetResponse *response,
           rpcprotocol::Controller *controller,
           google::protobuf::Closure *done);
  void Update(const std::string &chunkname,
              const std::string &data,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const ValueType &data_type,
              const std::string &remote_ip,
              const boost::uint16_t &remote_port,
              const std::string &rendezvous_ip,
              const boost::uint16_t &rendezvous_port,
              UpdateResponse *response,
              rpcprotocol::Controller *controller,
              google::protobuf::Closure *done);
  void Delete(const std::string &chunkname,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const ValueType &data_type,
              const std::string &remote_ip,
              const boost::uint16_t &remote_port,
              const std::string &rendezvous_ip,
              const boost::uint16_t &rendezvous_port,
              DeleteResponse *response,
              rpcprotocol::Controller *controller,
              google::protobuf::Closure *done);
  void GetMessages(const std::string &buffer_packet_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &remote_ip,
                   const boost::uint16_t &remote_port,
                   const std::string &rendezvous_ip,
                   const boost::uint16_t &rendezvous_port,
                   GetMessagesResponse *response,
                   rpcprotocol::Controller *controller,
                   google::protobuf::Closure *done);
 private:
  ClientRpcs(const ClientRpcs&);
  ClientRpcs& operator=(const ClientRpcs&);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTRPC_H_
