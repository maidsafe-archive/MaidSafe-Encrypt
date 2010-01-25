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
  std::string local_ip;
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
  std::string local_ip;
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
  std::string local_ip;
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

void ClientRpcs::AddToWatchList(
    const kad::Contact &peer,
    bool local,
    AddToWatchListRequest *add_to_watch_list_request,
    AddToWatchListResponse *add_to_watch_list_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.AddToWatchList(controller, add_to_watch_list_request,
                         add_to_watch_list_response, done);
}

void ClientRpcs::RemoveFromWatchList(
    const kad::Contact &peer,
    bool local,
    RemoveFromWatchListRequest *remove_from_watch_list_request,
    RemoveFromWatchListResponse *remove_from_watch_list_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.RemoveFromWatchList(controller, remove_from_watch_list_request,
                              remove_from_watch_list_response, done);
}

void ClientRpcs::AmendAccount(const kad::Contact &peer,
                              bool local,
                              AmendAccountRequest *amend_account_request,
                              AmendAccountResponse *amend_account_response,
                              rpcprotocol::Controller *controller,
                              google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.AmendAccount(controller, amend_account_request,
                       amend_account_response, done);
}

void ClientRpcs::AccountStatus(
    const kad::Contact &peer,
    bool local,
    AccountStatusRequest *account_status_request,
    AccountStatusResponse *account_status_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, peer.host_ip(),
      peer.host_port(), local_ip, local_port, peer.rendezvous_ip(),
      peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.AccountStatus(controller, account_status_request,
                        account_status_response, done);
}

void ClientRpcs::CheckChunk(const kad::Contact &peer,
                            bool local,
                            CheckChunkRequest *check_chunk_request,
                            CheckChunkResponse *check_chunk_response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  std::string local_ip;
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
  std::string local_ip;
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
  std::string local_ip;
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

void ClientRpcs::LocalVaultOwned(LocalVaultOwnedResponse *response,
                                 rpcprotocol::Controller *controller,
                                 rpcprotocol::Channel *channel,
                                 google::protobuf::Closure *done) {
  LocalVaultOwnedRequest request;
  maidsafe::VaultRegistration::Stub service(channel);
  service.LocalVaultOwned(controller, &request, response, done);
}

void ClientRpcs::SetLocalVaultOwned(SetLocalVaultOwnedRequest *request,
                                    SetLocalVaultOwnedResponse *response,
                                    rpcprotocol::Controller *controller,
                                    rpcprotocol::Channel *channel,
                                    google::protobuf::Closure *done) {
  maidsafe::VaultRegistration::Stub service(channel);
  service.SetLocalVaultOwned(controller, request, response, done);
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
