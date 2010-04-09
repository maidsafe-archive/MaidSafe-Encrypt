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

#include "maidsafe/bufferpacketrpc.h"

namespace maidsafe {

void BufferPacketRpcsImpl::CreateBP(const kad::Contact &peer,
                                    const bool &local,
                                    const boost::int16_t &transport_id,
                                    const CreateBPRequest *create_request,
                                    CreateBPResponse *create_response,
                                    rpcprotocol::Controller *controller,
                                    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
                               transport_id, peer.host_ip(),
                               peer.host_port(), local_ip, local_port,
                               peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.CreateBP(controller, create_request, create_response, done);
}

void BufferPacketRpcsImpl::ModifyBPInfo(
    const kad::Contact &peer,
    const bool &local,
    const boost::int16_t &transport_id,
    const ModifyBPInfoRequest *modify_request,
    ModifyBPInfoResponse *modify_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
      transport_id, peer.host_ip(), peer.host_port(), local_ip, local_port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.ModifyBPInfo(controller, modify_request, modify_response, done);
}

void BufferPacketRpcsImpl::GetBPMessages(
    const kad::Contact &peer,
    const bool &local,
    const boost::int16_t &transport_id,
    const GetBPMessagesRequest *get_messages_request,
    GetBPMessagesResponse *get_messages_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
      transport_id, peer.host_ip(), peer.host_port(), local_ip, local_port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetBPMessages(controller, get_messages_request, get_messages_response,
                        done);
}

void BufferPacketRpcsImpl::AddBPMessage(
    const kad::Contact &peer,
    const bool &local,
    const boost::int16_t &transport_id,
    const AddBPMessageRequest *add_message_request,
    AddBPMessageResponse *add_message_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
      transport_id, peer.host_ip(), peer.host_port(), local_ip, local_port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.AddBPMessage(controller, add_message_request, add_message_response,
                       done);
}

void BufferPacketRpcsImpl::GetBPPresence(
    const kad::Contact &peer,
    const bool &local,
    const boost::int16_t &transport_id,
    const GetBPPresenceRequest *get_presence_request,
    GetBPPresenceResponse *get_presence_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
      transport_id, peer.host_ip(), peer.host_port(), local_ip, local_port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.GetBPPresence(controller, get_presence_request, get_presence_response,
                        done);
}

void BufferPacketRpcsImpl::AddBPPresence(
    const kad::Contact &peer,
    const bool &local,
    const boost::int16_t &transport_id,
    const AddBPPresenceRequest *add_presence_request,
    AddBPPresenceResponse *add_presence_response,
    rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) {
  std::string local_ip;
  boost::uint16_t local_port(0);
  if (local) {
    local_ip = peer.local_ip();
    local_port = peer.local_port();
  }
  rpcprotocol::Channel channel(channel_manager_, transport_handler_,
      transport_id, peer.host_ip(), peer.host_port(), local_ip, local_port,
      peer.rendezvous_ip(), peer.rendezvous_port());
  maidsafe::MaidsafeService::Stub service(&channel);
  service.AddBPPresence(controller, add_presence_request, add_presence_response,
                        done);
}

}  // namespace maidsafe
