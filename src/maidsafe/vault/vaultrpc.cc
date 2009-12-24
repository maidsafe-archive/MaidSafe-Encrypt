/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  RPCs used by vault
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

#include "maidsafe/vault/vaultrpc.h"

namespace maidsafe_vault {

void VaultRpcs::StoreChunk(const std::string &chunkname,
                           const std::string &data,
                           const std::string &public_key,
                           const std::string &public_key_signature,
                           const std::string &request_signature,
                           const maidsafe::ValueType &data_type,
                           const std::string &remote_ip,
                           const boost::uint16_t &remote_port,
                           const std::string &rendezvous_ip,
                           const boost::uint16_t &rendezvous_port,
                           maidsafe::StoreChunkResponse *response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done) {
  maidsafe::StoreChunkRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_public_key_signature(public_key_signature);
  args.set_request_signature(request_signature);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StoreChunk(controller, &args, response, done);
}

void VaultRpcs::AddToReferenceList(
    const kad::Contact &peer,
    bool local,
    maidsafe::AddToReferenceListRequest *add_to_reference_list_request,
    maidsafe::AddToReferenceListResponse *add_to_reference_list_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  if (peer.node_id() == own_non_hex_id_) {
    add_to_reference_list_response->set_result(kNotRemote);
    done->Run();
    return;
  }
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
  service.AddToReferenceList(controller, add_to_reference_list_request,
                             add_to_reference_list_response, done);
}

void VaultRpcs::RemoveFromReferenceList(
    const kad::Contact &peer,
    bool local,
    maidsafe::RemoveFromReferenceListRequest
        *remove_from_reference_list_request,
    maidsafe::RemoveFromReferenceListResponse
        *remove_from_reference_list_response,
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
  service.RemoveFromReferenceList(controller,
      remove_from_reference_list_request, remove_from_reference_list_response,
      done);
}

void VaultRpcs::AmendAccount(
    const kad::Contact &peer,
    bool local,
    maidsafe::AmendAccountRequest *amend_account_request,
    maidsafe::AmendAccountResponse *amend_account_response,
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

void VaultRpcs::GetAccountStatus(
    const kad::Contact &peer,
    bool local,
    maidsafe::AccountStatusRequest *get_account_status_request,
    maidsafe::AccountStatusResponse *get_account_status_response,
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
  service.AccountStatus(controller, get_account_status_request,
                           get_account_status_response, done);
}

void VaultRpcs::CheckChunk(const std::string &chunkname,
                           const std::string &remote_ip,
                           const boost::uint16_t &remote_port,
                           const std::string &rendezvous_ip,
                           const boost::uint16_t &rendezvous_port,
                           maidsafe::CheckChunkResponse *response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done) {
  maidsafe::CheckChunkRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.CheckChunk(controller, &args, response, done);
}

void VaultRpcs::GetChunk(const std::string &chunkname,
                         const std::string &remote_ip,
                         const boost::uint16_t &remote_port,
                         const std::string &rendezvous_ip,
                         const boost::uint16_t &rendezvous_port,
                         maidsafe::GetChunkResponse *response,
                         rpcprotocol::Controller *controller,
                         google::protobuf::Closure *done) {
  maidsafe::GetChunkRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetChunk(controller, &args, response, done);
}

void VaultRpcs::UpdateChunk(const std::string &chunkname,
                            const std::string &data,
                            const std::string &public_key,
                            const std::string &public_key_signature,
                            const std::string &request_signature,
                            const maidsafe::ValueType &data_type,
                            const std::string &remote_ip,
                            const boost::uint16_t &remote_port,
                            const std::string &rendezvous_ip,
                            const boost::uint16_t &rendezvous_port,
                            maidsafe::UpdateChunkResponse *response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  maidsafe::UpdateChunkRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_public_key_signature(public_key_signature);
  args.set_request_signature(request_signature);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.UpdateChunk(controller, &args, response, done);
}

void VaultRpcs::DeleteChunk(const std::string &chunkname,
                            const std::string &public_key,
                            const std::string &public_key_signature,
                            const std::string &request_signature,
                            const maidsafe::ValueType &data_type,
                            const std::string &remote_ip,
                            const boost::uint16_t &remote_port,
                            const std::string &rendezvous_ip,
                            const boost::uint16_t &rendezvous_port,
                            maidsafe::DeleteChunkResponse *response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  maidsafe::DeleteChunkRequest args;
  args.set_chunkname(chunkname);
/*  args.set_public_key(public_key);
  args.set_public_key_signature(public_key_signature);*/
  args.set_request_signature(request_signature);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.DeleteChunk(controller, &args, response, done);
}

void VaultRpcs::ValidityCheck(const std::string &chunkname,
                              const std::string &random_data,
                              const std::string &remote_ip,
                              const boost::uint16_t &remote_port,
                              const std::string &rendezvous_ip,
                              const boost::uint16_t &rendezvous_port,
                              maidsafe::ValidityCheckResponse *response,
                              rpcprotocol::Controller *controller,
                              google::protobuf::Closure *done) {
  maidsafe::ValidityCheckRequest args;
  args.set_chunkname(chunkname);
  args.set_random_data(random_data);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.ValidityCheck(controller, &args, response, done);
}

void VaultRpcs::SwapChunk(const boost::uint32_t request_type,
                          const std::string &chunkname1,
                          const std::string &chunkcontent1,
                          const boost::uint32_t size1,
                          const std::string &remote_ip,
                          const boost::uint16_t &remote_port,
                          const std::string &rendezvous_ip,
                          const boost::uint16_t &rendezvous_port,
                          maidsafe::SwapChunkResponse *response,
                          rpcprotocol::Controller *controller,
                          google::protobuf::Closure *done) {
  maidsafe::SwapChunkRequest args;
  args.set_request_type(request_type);
  args.set_chunkname1(chunkname1);
  if (request_type == 0) {
    args.set_size1(size1);
  } else {
    args.set_chunkcontent1(chunkcontent1);
  }
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.SwapChunk(controller, &args, response, done);
}

void VaultRpcs::GetBPMessages(const std::string &buffer_packet_name,
                              const std::string &public_key,
                              const std::string &public_key_signature,
                              const std::string &remote_ip,
                              const boost::uint16_t &remote_port,
                              const std::string &rendezvous_ip,
                              const boost::uint16_t &rendezvous_port,
                              maidsafe::GetBPMessagesResponse *response,
                              rpcprotocol::Controller *controller,
                              google::protobuf::Closure *done) {
  maidsafe::GetBPMessagesRequest args;
  args.set_bufferpacket_name(buffer_packet_name);
  args.set_public_key(public_key);
  args.set_signed_public_key(public_key_signature);
  rpcprotocol::Channel channel(channel_manager_, transport_, remote_ip,
      remote_port, "", 0, rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetBPMessages(controller, &args, response, done);
}
}  // namespace maidsafe_vault
