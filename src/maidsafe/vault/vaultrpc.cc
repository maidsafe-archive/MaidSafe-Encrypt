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

#include <boost/shared_ptr.hpp>

namespace maidsafe_vault {

VaultRpcs::VaultRpcs(boost::shared_ptr<rpcprotocol::ChannelManager>
    channel_manager) : channel_manager_(channel_manager) {}

void VaultRpcs::StoreChunk(const std::string &chunkname,
                      const std::string &data,
                      const std::string &public_key,
                      const std::string &signed_public_key,
                      const std::string &signed_request,
                      const maidsafe::ValueType &data_type,
                      const std::string &remote_ip,
                      const boost::uint16_t &remote_port,
                      const std::string &rendezvous_ip,
                      const boost::uint16_t &rendezvous_port,
                      maidsafe::StoreResponse *response,
                      rpcprotocol::Controller *controller,
                      google::protobuf::Closure *done) {
  maidsafe::StoreRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StoreChunk(controller, &args, response, done);
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
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.CheckChunk(controller, &args, response, done);
}

void VaultRpcs::Get(const std::string &chunkname,
                    const std::string &remote_ip,
                    const boost::uint16_t &remote_port,
                    const std::string &rendezvous_ip,
                    const boost::uint16_t &rendezvous_port,
                    maidsafe::GetResponse *response,
                    rpcprotocol::Controller *controller,
                    google::protobuf::Closure *done) {
  maidsafe::GetRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Get(controller, &args, response, done);
}

void VaultRpcs::Update(const std::string &chunkname,
                       const std::string &data,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const maidsafe::ValueType &data_type,
                       const std::string &remote_ip,
                       const boost::uint16_t &remote_port,
                       const std::string &rendezvous_ip,
                       const boost::uint16_t &rendezvous_port,
                       maidsafe::UpdateResponse *response,
                       rpcprotocol::Controller *controller,
                       google::protobuf::Closure *done) {
  maidsafe::UpdateRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Update(controller, &args, response, done);
}

void VaultRpcs::Delete(const std::string &chunkname,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const maidsafe::ValueType &data_type,
                       const std::string &remote_ip,
                       const boost::uint16_t &remote_port,
                       const std::string &rendezvous_ip,
                       const boost::uint16_t &rendezvous_port,
                       maidsafe::DeleteResponse *response,
                       rpcprotocol::Controller *controller,
                       google::protobuf::Closure *done) {
  maidsafe::DeleteRequest args;
  args.set_chunkname(chunkname);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Delete(controller, &args, response, done);
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
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.ValidityCheck(controller, &args, response, done);
}

void VaultRpcs::GetMessages(const std::string &buffer_packet_name,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const std::string &remote_ip,
                            const boost::uint16_t &remote_port,
                            const std::string &rendezvous_ip,
                            const boost::uint16_t &rendezvous_port,
                            maidsafe::GetMessagesResponse *response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  maidsafe::GetMessagesRequest args;
  args.set_buffer_packet_name(buffer_packet_name);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetMessages(controller, &args, response, done);
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
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.SwapChunk(controller, &args, response, done);
}
}  // namespace maidsafe_vault
