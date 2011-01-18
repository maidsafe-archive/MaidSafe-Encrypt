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

#ifndef MAIDSAFE_COMMON_BUFFERSERVICE_H_
#define MAIDSAFE_COMMON_BUFFERSERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
class CreateBufferRequest;
class CreateBufferResponse;
class ModifyBufferInfoRequest;
class ModifyBufferInfoResponse;
class GetBufferMessagesRequest;
class GetBufferMessagesResponse;
class AddBufferMessageRequest;
class AddBufferMessageResponse;
class GetBufferPresenceRequest;
class GetBufferPresenceResponse;
class AddBufferPresenceRequest;
class AddBufferPresenceResponse;
}  // namespace protobuf

namespace vault {

class BufferService {
 public:
  BufferService() {}
  void CreateBuffer(const transport::Info &info,
                    const protobuf::CreateBufferRequest &request,
                    protobuf::CreateBufferResponse *response);
  void ModifyBufferInfo(const transport::Info &info,
                        const protobuf::ModifyBufferInfoRequest &request,
                        protobuf::ModifyBufferInfoResponse *response);
  void GetBufferMessages(const transport::Info &info,
                         const protobuf::GetBufferMessagesRequest &request,
                         protobuf::GetBufferMessagesResponse *response);
  void AddBufferMessage(const transport::Info &info,
                        const protobuf::AddBufferMessageRequest &request,
                        protobuf::AddBufferMessageResponse *response);
  void GetBufferPresence(const transport::Info &info,
                         const protobuf::GetBufferPresenceRequest &request,
                         protobuf::GetBufferPresenceResponse *response);
  void AddBufferPresence(const transport::Info &info,
                         const protobuf::AddBufferPresenceRequest &request,
                         protobuf::AddBufferPresenceResponse *response);
  // TODO setters...
 private:
  BufferService(const BufferService&);
  BufferService& operator=(const BufferService&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_BUFFERSERVICE_H_
