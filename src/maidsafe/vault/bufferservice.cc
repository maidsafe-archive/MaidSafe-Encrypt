/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class providing Buffer services.
* Created:      2011-01-18
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

#include "maidsafe/vault/bufferservice.h"

#include "maidsafe/common/buffer_messages.pb.h"

namespace maidsafe {

namespace vault {

void BufferService::CreateBuffer(const transport::Info &info,
                                 const protobuf::CreateBufferRequest &request,
                                 protobuf::CreateBufferResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::CreateBuffer body
}

void BufferService::ModifyBufferInfo(
    const transport::Info &info,
    const protobuf::ModifyBufferInfoRequest &request,
    protobuf::ModifyBufferInfoResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::ModifyBufferInfo body
}

void BufferService::GetBufferMessages(
    const transport::Info &info,
    const protobuf::GetBufferMessagesRequest &request,
    protobuf::GetBufferMessagesResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::GetBufferMessages body
}

void BufferService::AddBufferMessage(
    const transport::Info &info,
    const protobuf::AddBufferMessageRequest &request,
    protobuf::AddBufferMessageResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::AddBufferMessage body
}

void BufferService::GetBufferPresence(
    const transport::Info &info,
    const protobuf::GetBufferPresenceRequest &request,
    protobuf::GetBufferPresenceResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::GetBufferPresence body
}

void BufferService::AddBufferPresence(
    const transport::Info &info,
    const protobuf::AddBufferPresenceRequest &request,
    protobuf::AddBufferPresenceResponse *response) {
  // response->set_result(false);
  // TODO implement BufferService::AddBufferPresence body
}

}

}  // namespace maidsafe
