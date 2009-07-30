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
  ~ClientRpcs() {
//  printf("In ClientRpcs destructor.\n");
}
  void Store(const std::string &chunkname,
             const std::string &data,
             const std::string &public_key,
             const std::string &signed_public_key,
             const std::string &signed_request,
             const value_types &data_type,
             const std::string &remote_ip,
             const uint16_t &remote_port,
             StoreResponse* response,
             google::protobuf::Closure* done,
             const bool &local);
  void CheckChunk(const std::string &chunkname,
                  const std::string &remote_ip,
                  const uint16_t &remote_port,
                  CheckChunkResponse* response,
                  google::protobuf::Closure* done,
                  const bool &local);
  void Get(const std::string &chunkname,
           const std::string &remote_ip,
           const uint16_t &remote_port,
           GetResponse* response,
           google::protobuf::Closure* done,
           const bool &local);
  void Update(const std::string &chunkname,
              const std::string &data,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const value_types &data_type,
              const std::string &remote_ip,
              const uint16_t &remote_port,
              UpdateResponse* response,
              google::protobuf::Closure* done,
              const bool &local);
  void Delete(const std::string &chunkname,
              const std::string &public_key,
              const std::string &signed_public_key,
              const std::string &signed_request,
              const value_types &data_type,
              const std::string &remote_ip,
              const uint16_t &remote_port,
              DeleteResponse* response,
              google::protobuf::Closure* done,
              const bool &local);
  void GetMessages(const std::string &buffer_packet_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &remote_ip,
                   const uint16_t &remote_port,
                   GetMessagesResponse* response,
                   google::protobuf::Closure* done,
                   const bool &local);
 private:
  ClientRpcs(const ClientRpcs&);
  ClientRpcs& operator=(const ClientRpcs&);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTRPC_H_
