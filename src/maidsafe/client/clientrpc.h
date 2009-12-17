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
  ClientRpcs(transport::Transport *transport,
             rpcprotocol::ChannelManager *channel_manager)
      : transport_(transport),
        channel_manager_(channel_manager) {}
  virtual ~ClientRpcs() {}
  void StorePrep(const kad::Contact &peer,
                 bool local,
                 StorePrepRequest *store_prep_request,
                 StorePrepResponse *store_prep_response,
                 rpcprotocol::Controller *controller,
                 google::protobuf::Closure *done);
  void StoreChunk(const kad::Contact &peer,
                  bool local,
                  StoreRequest *store_request,
                  StoreResponse *store_response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  virtual void StorePacket(const kad::Contact &peer,
                           bool local,
                           StorePacketRequest *store_packet_request,
                           StorePacketResponse *store_packet_response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done);
  virtual void StoreIOU(const kad::Contact &peer,
                        bool local,
                        StoreIOURequest *store_iou_request,
                        StoreIOUResponse *store_iou_response,
                        rpcprotocol::Controller *controller,
                        google::protobuf::Closure *done);
  void IOUDone(const kad::Contact &peer,
               bool local,
               IOUDoneRequest *iou_done_request,
               IOUDoneResponse *iou_done_response,
               rpcprotocol::Controller *controller,
               google::protobuf::Closure *done);
  void CheckChunk(const kad::Contact &peer,
                  bool local,
                  CheckChunkRequest *check_chunk_request,
                  CheckChunkResponse *check_chunk_response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void Get(const kad::Contact &peer,
           bool local,
           GetRequest *get_request,
           GetResponse *get_response,
           rpcprotocol::Controller *controller,
           google::protobuf::Closure *done);
  virtual void GetPacket(const kad::Contact &peer,
                         bool local,
                         GetPacketRequest *get_request,
                         GetPacketResponse *get_response,
                         rpcprotocol::Controller *controller,
                         google::protobuf::Closure *done);
  void Update(const kad::Contact &peer,
              bool local,
              UpdateRequest *update_request,
              UpdateResponse *update_response,
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
  void IsVaultOwned(IsOwnedResponse *response,
                    rpcprotocol::Controller *controller,
                    rpcprotocol::Channel *channel,
                    google::protobuf::Closure *done);
  void OwnVault(const std::string &priv_key,
                const std::string &pub_key,
                const std::string &signed_pub_key,
                const boost::uint32_t &port,
                const std::string &chunkstore_dir,
                const boost::uint64_t &space,
                OwnVaultResponse *response,
                rpcprotocol::Controller *controller,
                rpcprotocol::Channel *channel,
                google::protobuf::Closure *done);
  void PollVaultInfo(const std::string &enc_ser_request,
                     VaultStatusResponse *response,
                     rpcprotocol::Controller *controller,
                     rpcprotocol::Channel *channel,
                     google::protobuf::Closure *done);
 private:
  ClientRpcs(const ClientRpcs&);
  ClientRpcs& operator=(const ClientRpcs&);
  transport::Transport *transport_;
  rpcprotocol::ChannelManager *channel_manager_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTRPC_H_
