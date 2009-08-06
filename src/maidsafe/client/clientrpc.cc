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

#include <boost/shared_ptr.hpp>

namespace maidsafe {

ClientRpcs::ClientRpcs(boost::shared_ptr<rpcprotocol::ChannelManager>
    channel_manager)
        : channel_manager_(channel_manager) {
//  printf("In ClientRpcs constructor.\n");
}

void ClientRpcs::StorePrep(const std::string &chunkname,
                           const boost::uint64_t &data_size,
                           const std::string &pmid,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const std::string &signed_request,
                           const std::string &remote_ip,
                           const uint16_t &remote_port,
                           StorePrepResponse* response,
                           google::protobuf::Closure* done,
                           const bool &local) {
  StorePrepRequest args;
  args.set_chunkname(chunkname);
  args.set_data_size(data_size);
  args.set_pmid(pmid);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  args.set_signed_request(signed_request);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  MaidsafeService::Stub service(channel.get());
  service.StoreChunkPrep(&controller, &args, response, done);
}

void ClientRpcs::Store(const std::string &chunkname,
                       const std::string &data,
                       const std::string &public_key,
                       const std::string &signed_public_key,
                       const std::string &signed_request,
                       const ValueType &data_type,
                       const std::string &remote_ip,
                       const uint16_t &remote_port,
                       StoreResponse* response,
                       google::protobuf::Closure* done,
                       const bool &local) {
  StoreRequest args;
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
  MaidsafeService::Stub service(channel.get());
  service.StoreChunk(&controller, &args, response, done);
}

void ClientRpcs::CheckChunk(const std::string &chunkname,
                            const std::string &remote_ip,
                            const uint16_t &remote_port,
                            CheckChunkResponse* response,
                            google::protobuf::Closure* done,
                            const bool &local) {
  CheckChunkRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  MaidsafeService::Stub service(channel.get());
  service.CheckChunk(&controller, &args, response, done);
}

void ClientRpcs::Get(const std::string &chunkname,
                     const std::string &remote_ip,
                     const uint16_t &remote_port,
                     GetResponse* response,
                     google::protobuf::Closure* done,
                     const bool &local) {
  GetRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  MaidsafeService::Stub service(channel.get());
  service.Get(&controller, &args, response, done);
}

void ClientRpcs::Update(const std::string &chunkname,
                        const std::string &data,
                        const std::string &public_key,
                        const std::string &signed_public_key,
                        const std::string &signed_request,
                        const ValueType &data_type,
                        const std::string &remote_ip,
                        const uint16_t &remote_port,
                        UpdateResponse* response,
                        google::protobuf::Closure* done,
                        const bool &local) {
  UpdateRequest args;
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
  MaidsafeService::Stub service(channel.get());
  service.Update(&controller, &args, response, done);
}

void ClientRpcs::Delete(const std::string &chunkname,
                        const std::string &public_key,
                        const std::string &signed_public_key,
                        const std::string &signed_request,
                        const ValueType &data_type,
                        const std::string &remote_ip,
                        const uint16_t &remote_port,
                        DeleteResponse* response,
                        google::protobuf::Closure* done,
                        const bool &local) {
  DeleteRequest args;
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
  MaidsafeService::Stub service(channel.get());
  service.Delete(&controller, &args, response, done);
}

void ClientRpcs::GetMessages(const std::string &buffer_packet_name,
                             const std::string &public_key,
                             const std::string &signed_public_key,
                             const std::string &remote_ip,
                             const uint16_t &remote_port,
                             GetMessagesResponse* response,
                             google::protobuf::Closure* done,
                             const bool &local) {
  GetMessagesRequest args;
  args.set_buffer_packet_name(buffer_packet_name);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  rpcprotocol::Controller controller;
  boost::shared_ptr<rpcprotocol::Channel> channel(new rpcprotocol::Channel(
      channel_manager_.get(),
      remote_ip,
      remote_port,
      local));
  MaidsafeService::Stub service(channel.get());
  service.GetMessages(&controller, &args, response, done);
}

}  // namespace maidsafe
