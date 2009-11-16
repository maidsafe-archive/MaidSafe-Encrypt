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

#ifndef MAIDSAFE_BUFFERPACKETRPC_H_
#define MAIDSAFE_BUFFERPACKETRPC_H_

#include <maidsafe/maidsafe-dht.h>

#include <string>

#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_service.pb.h"

namespace maidsafe {

class BufferPacketRpcs {
 public:
  virtual ~BufferPacketRpcs() {}
  virtual void CreateBP(const kad::Contact &peer, bool local,
    const CreateBPRequest *create_request, CreateBPResponse *create_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done) = 0;
  virtual void ModifyBPInfo(const kad::Contact &peer, bool local,
    const ModifyBPInfoRequest *modify_request,
    ModifyBPInfoResponse *modify_response, rpcprotocol::Controller *controller,
    google::protobuf::Closure *done) = 0;
  virtual void GetBPMessages(const kad::Contact &peer, bool local,
    const GetBPMessagesRequest *get_messages_request,
    GetBPMessagesResponse *get_messages_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done) = 0;
  virtual void AddBPMessage(const kad::Contact &peer, bool local,
    const AddBPMessageRequest *add_message_request,
    AddBPMessageResponse *add_message_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done) = 0;
};

class BufferPacketRpcsImpl : public BufferPacketRpcs {
 public:
  BufferPacketRpcsImpl(transport::Transport *transport,
    rpcprotocol::ChannelManager *channel_manager): transport_(transport),
    channel_manager_(channel_manager) {}
  ~BufferPacketRpcsImpl() {}
  void CreateBP(const kad::Contact &peer, bool local,
    const CreateBPRequest *create_request, CreateBPResponse *create_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done);
  void ModifyBPInfo(const kad::Contact &peer, bool local,
    const ModifyBPInfoRequest *modify_request,
    ModifyBPInfoResponse *modify_response, rpcprotocol::Controller *controller,
    google::protobuf::Closure *done);
  void GetBPMessages(const kad::Contact &peer, bool local,
    const GetBPMessagesRequest *get_messages_request,
    GetBPMessagesResponse *get_messages_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done);
  void AddBPMessage(const kad::Contact &peer, bool local,
    const AddBPMessageRequest *add_message_request,
    AddBPMessageResponse *add_message_response,
    rpcprotocol::Controller *controller, google::protobuf::Closure *done);
 private:
  BufferPacketRpcsImpl(const BufferPacketRpcsImpl&);
  BufferPacketRpcsImpl& operator=(const BufferPacketRpcsImpl&);
  transport::Transport *transport_;
  rpcprotocol::ChannelManager *channel_manager_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_BUFFERPACKETRPC_H_
