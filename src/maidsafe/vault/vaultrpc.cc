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
                      const maidsafe::value_types &data_type,
                      const std::string &remote_ip,
                      const uint16_t &remote_port,
                      maidsafe::StoreResponse* response,
                      google::protobuf::Closure* done,
                      const bool &local) {
  maidsafe::StoreRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.StoreChunk(&controller, &args, response, done);
}

void VaultRpcs::CheckChunk(const std::string &chunkname,
                           const std::string &remote_ip,
                           const uint16_t &remote_port,
                           maidsafe::CheckChunkResponse* response,
                           google::protobuf::Closure* done,
                           const bool &local) {
  maidsafe::CheckChunkRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.CheckChunk(&controller, &args, response, done);
}

void VaultRpcs::Get(const std::string &chunkname,
                    const std::string &remote_ip,
                    const uint16_t &remote_port,
                    maidsafe::GetResponse* response,
                    google::protobuf::Closure* done,
                    const bool &local) {
  maidsafe::GetRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.Get(&controller, &args, response, done);
}

void VaultRpcs::Update(const std::string &chunkname,
                       const std::string &data,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const maidsafe::value_types &data_type,
                       const std::string &remote_ip,
                       const uint16_t &remote_port,
                       maidsafe::UpdateResponse* response,
                       google::protobuf::Closure* done,
                       const bool &local) {
  maidsafe::UpdateRequest args;
  args.set_chunkname(chunkname);
  args.set_data(data);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.Update(&controller, &args, response, done);
}

void VaultRpcs::Delete(const std::string &chunkname,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const maidsafe::value_types &data_type,
                       const std::string &remote_ip,
                       const uint16_t &remote_port,
                       maidsafe::DeleteResponse* response,
                       google::protobuf::Closure* done,
                       const bool &local) {
  maidsafe::DeleteRequest args;
  args.set_chunkname(chunkname);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  args.set_data_type(data_type);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.Delete(&controller, &args, response, done);
}

void VaultRpcs::ValidityCheck(const std::string &chunkname,
                              const std::string &random_data,
                              const std::string &remote_ip,
                              const uint16_t &remote_port,
                              maidsafe::ValidityCheckResponse* response,
                              google::protobuf::Closure* done,
                              const bool &local) {
  maidsafe::ValidityCheckRequest args;
  args.set_chunkname(chunkname);
  args.set_random_data(random_data);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.ValidityCheck(&controller, &args, response, done);
}

void VaultRpcs::GetMessages(const std::string &buffer_packet_name,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const std::string &remote_ip,
                            const uint16_t &remote_port,
                            maidsafe::GetMessagesResponse* response,
                            google::protobuf::Closure* done,
                            const bool &local) {
  maidsafe::GetMessagesRequest args;
  args.set_buffer_packet_name(buffer_packet_name);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.GetMessages(&controller, &args, response, done);
}

void VaultRpcs::SwapChunk(const boost::uint32_t request_type,
                          const std::string &chunkname1,
                          const std::string &chunkcontent1,
                          const boost::uint32_t size1,
                          const std::string &remote_ip,
                          const uint16_t &remote_port,
                          maidsafe::SwapChunkResponse* response,
                          google::protobuf::Closure* done,
                          const bool &local) {
  maidsafe::SwapChunkRequest args;
  args.set_request_type(request_type);
  args.set_chunkname1(chunkname1);
  if (request_type == 0) {
    args.set_size1(size1);
  } else {
    args.set_chunkcontent1(chunkcontent1);
  }
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  maidsafe::MaidsafeService::Stub service(channel.get());
  service.SwapChunk(&controller, &args, response, done);
}
}  // namespace maidsafe_vault
