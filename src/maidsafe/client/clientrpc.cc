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
  service.StoreChunkPrep(controller, store_prep_request, store_prep_response,
                         done);
}

void ClientRpcs::StoreChunk(const kad::Contact &peer,
                            bool local,
                            StoreRequest *store_request,
                            StoreResponse *store_response,
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
  service.StoreChunk(controller, store_request, store_response, done);
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

void ClientRpcs::Get(const kad::Contact &peer,
                     bool local,
                     GetRequest *get_request,
                     GetResponse *get_response,
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
  service.Get(controller, get_request, get_response, done);
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

void ClientRpcs::Update(const kad::Contact &peer,
                        bool local,
                        UpdateRequest *update_request,
                        UpdateResponse *update_response,
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
  service.Update(controller, update_request, update_response, done);
}

void ClientRpcs::Delete(const std::string &chunkname,
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
                        google::protobuf::Closure *done) {
  DeleteRequest args;
  args.set_chunkname(chunkname);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Delete(controller, &args, response, done);
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
