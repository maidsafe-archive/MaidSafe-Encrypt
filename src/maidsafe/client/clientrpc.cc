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

#include "maidsafe/client/clientrpc.h"

namespace maidsafe {

void ClientRpcs::StorePrep(const kad::Contact &peer,
                           bool local,
                           StorePrepRequest *store_prep_request,
                           StorePrepResponse *store_prep_response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StorePrep(controller, store_prep_request, store_prep_response, done);
}

void ClientRpcs::StoreChunk(const kad::Contact &peer,
                            bool local,
                            StoreChunkRequest *store_chunk_request,
                            StoreChunkResponse *store_chunk_response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StoreChunk(controller, store_chunk_request, store_chunk_response,
                     done);
}

void ClientRpcs::StorePacket(const kad::Contact &peer,
                             bool local,
                             StorePacketRequest *store_packet_request,
                             StorePacketResponse *store_packet_response,
                             rpcprotocol::Controller *controller,
                             google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StorePacket(controller, store_packet_request, store_packet_response,
                      done);
}

void ClientRpcs::CheckChunk(const kad::Contact &peer,
                            bool local,
                            CheckChunkRequest *check_chunk_request,
                            CheckChunkResponse *check_chunk_response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.CheckChunk(controller, check_chunk_request, check_chunk_response,
                     done);
}

void ClientRpcs::GetChunk(const kad::Contact &peer,
                          bool local,
                          GetChunkRequest *get_chunk_request,
                          GetChunkResponse *get_chunk_response,
                          rpcprotocol::Controller *controller,
                          google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetChunk(controller, get_chunk_request, get_chunk_response, done);
}

void ClientRpcs::GetPacket(const kad::Contact &peer,
                           bool local,
                           GetPacketRequest *get_request,
                           GetPacketResponse *get_response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetPacket(controller, get_request, get_response, done);
}

void ClientRpcs::UpdateChunk(const kad::Contact &peer,
                             bool local,
                             UpdateChunkRequest *update_chunk_request,
                             UpdateChunkResponse *update_chunk_response,
                             rpcprotocol::Controller *controller,
                             google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.UpdateChunk(controller, update_chunk_request, update_chunk_response,
                      done);
}

void ClientRpcs::DeleteChunk(const kad::Contact &peer,
                             bool local,
                             DeleteChunkRequest *delete_chunk_request,
                             DeleteChunkResponse *delete_chunk_response,
                             rpcprotocol::Controller *controller,
                             google::protobuf::Closure *done) {
  std::string local_ip("");
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.DeleteChunk(controller, delete_chunk_request, delete_chunk_response,
                      done);
}

void ClientRpcs::IsVaultOwned(IsOwnedResponse *response,
                              rpcprotocol::Controller *controller,
                              rpcprotocol::Channel *channel,
                              google::protobuf::Closure *done) {
  IsOwnedRequest request;
  maidsafe::VaultRegistration::Stub service(channel);
  service.IsVaultOwned(controller, &request, response, done);
}

void ClientRpcs::OwnVault(const std::string &priv_key,
                          const std::string &pub_key,
                          const std::string &signed_pub_key,
                          const boost::uint32_t &port,
                          const std::string &chunkstore_dir,
                          const boost::uint64_t &space,
                          OwnVaultResponse *response,
                          rpcprotocol::Controller *controller,
                          rpcprotocol::Channel *channel,
                          google::protobuf::Closure *done) {
  OwnVaultRequest request;
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_pub_key);
  request.set_chunkstore_dir(chunkstore_dir);
  request.set_port(port);
  request.set_space(space);
  maidsafe::VaultRegistration::Stub service(channel);
  service.OwnVault(controller, &request, response, done);
}

void ClientRpcs::PollVaultInfo(const std::string &enc_ser_request,
                               VaultStatusResponse *response,
                               rpcprotocol::Controller *controller,
                               rpcprotocol::Channel *channel,
                               google::protobuf::Closure *done) {
  VaultStatusRequest vsreq;
  vsreq.set_encrypted_request(enc_ser_request);
  maidsafe::MaidsafeService::Stub service(channel);
  service.VaultStatus(controller, &vsreq, response, done);
}

}  // namespace maidsafe
