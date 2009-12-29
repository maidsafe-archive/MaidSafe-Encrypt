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
                  StoreChunkRequest *store_chunk_request,
                  StoreChunkResponse *store_chunk_response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  virtual void StorePacket(const kad::Contact &peer,
                           bool local,
                           StorePacketRequest *store_packet_request,
                           StorePacketResponse *store_packet_response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done);
  void AddToWatchList(const kad::Contact &peer,
                      bool local,
                      AddToWatchListRequest *add_to_watch_list_request,
                      AddToWatchListResponse *add_to_watch_list_response,
                      rpcprotocol::Controller *controller,
                      google::protobuf::Closure *done);
  void RemoveFromWatchList(
      const kad::Contact &peer,
      bool local,
      RemoveFromWatchListRequest *remove_from_watch_list_request,
      RemoveFromWatchListResponse *remove_from_watch_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done);
  void AmendAccount(const kad::Contact &peer,
                    bool local,
                    AmendAccountRequest *amend_account_request,
                    AmendAccountResponse *amend_account_response,
                    rpcprotocol::Controller *controller,
                    google::protobuf::Closure *done);
  void AccountStatus(const kad::Contact &peer,
                     bool local,
                     AccountStatusRequest *account_status_request,
                     AccountStatusResponse *account_status_response,
                     rpcprotocol::Controller *controller,
                     google::protobuf::Closure *done);
  void CheckChunk(const kad::Contact &peer,
                  bool local,
                  CheckChunkRequest *check_chunk_request,
                  CheckChunkResponse *check_chunk_response,
                  rpcprotocol::Controller *controller,
                  google::protobuf::Closure *done);
  void GetChunk(const kad::Contact &peer,
                bool local,
                GetChunkRequest *get_chunk_request,
                GetChunkResponse *get_chunk_response,
                rpcprotocol::Controller *controller,
                google::protobuf::Closure *done);
  virtual void GetPacket(const kad::Contact &peer,
                         bool local,
                         GetPacketRequest *get_request,
                         GetPacketResponse *get_response,
                         rpcprotocol::Controller *controller,
                         google::protobuf::Closure *done);
  void UpdateChunk(const kad::Contact &peer,
                   bool local,
                   UpdateChunkRequest *update_chunk_request,
                   UpdateChunkResponse *update_chunk_response,
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
