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
    channel_manager) : channel_manager_(channel_manager) {}

void ClientRpcs::StorePrep(const kad::Contact &peer,
                           bool local,
                           StorePrepRequest *store_prep_request,
                           StorePrepResponse *response,
                           rpcprotocol::Controller *controller,
                           google::protobuf::Closure *done) {
  std::string ip = peer.host_ip();
  boost::uint16_t port = peer.host_port();
  if (local) {
    ip = peer.local_ip();
    port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_.get(), ip, port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StoreChunkPrep(controller, store_prep_request, response, done);
}

void ClientRpcs::Store(const kad::Contact &peer,
                       bool local,
                       StoreRequest *store_request,
                       StoreResponse *response,
                       rpcprotocol::Controller *controller,
                       google::protobuf::Closure *done) {
  std::string ip = peer.host_ip();
  boost::uint16_t port = peer.host_port();
  if (local) {
    ip = peer.local_ip();
    port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_.get(), ip, port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.StoreChunk(controller, store_request, response, done);
}

void ClientRpcs::CheckChunk(const std::string &chunkname,
                            const std::string &remote_ip,
                            const boost::uint16_t &remote_port,
                            const std::string &rendezvous_ip,
                            const boost::uint16_t &rendezvous_port,
                            CheckChunkResponse *response,
                            rpcprotocol::Controller *controller,
                            google::protobuf::Closure *done) {
  CheckChunkRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.CheckChunk(controller, &args, response, done);
}

void ClientRpcs::Get(const std::string &chunkname,
                     const std::string &remote_ip,
                     const boost::uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const boost::uint16_t &rendezvous_port,
                     GetResponse *response,
                     rpcprotocol::Controller *controller,
                     google::protobuf::Closure *done) {
  GetRequest args;
  args.set_chunkname(chunkname);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Get(controller, &args, response, done);
}

void ClientRpcs::Update(const std::string &chunkname,
                        const std::string &data,
                        const std::string &public_key,
                        const std::string &signed_public_key,
                        const std::string &signed_request,
                        const ValueType &data_type,
                        const std::string &remote_ip,
                        const boost::uint16_t &remote_port,
                        const std::string &rendezvous_ip,
                        const boost::uint16_t &rendezvous_port,
                        UpdateResponse *response,
                        rpcprotocol::Controller *controller,
                        google::protobuf::Closure *done) {
  UpdateRequest args;
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
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.Delete(controller, &args, response, done);
}

void ClientRpcs::GetMessages(const std::string &buffer_packet_name,
                             const std::string &public_key,
                             const std::string &signed_public_key,
                             const std::string &remote_ip,
                             const boost::uint16_t &remote_port,
                             const std::string &rendezvous_ip,
                             const boost::uint16_t &rendezvous_port,
                             GetMessagesResponse *response,
                             rpcprotocol::Controller *controller,
                             google::protobuf::Closure *done) {
  GetMessagesRequest args;
  args.set_buffer_packet_name(buffer_packet_name);
  args.set_public_key(public_key);
  args.set_signed_public_key(signed_public_key);
  rpcprotocol::Channel channel(channel_manager_.get(), remote_ip, remote_port,
      rendezvous_ip, rendezvous_port);
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetMessages(controller, &args, response, done);
}

}  // namespace maidsafe
