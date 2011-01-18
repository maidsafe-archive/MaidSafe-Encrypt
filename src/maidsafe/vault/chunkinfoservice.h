/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class providing ChunkInfo services.
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

#ifndef MAIDSAFE_COMMON_CHUNKINFOSERVICE_H_
#define MAIDSAFE_COMMON_CHUNKINFOSERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
class AddToWatchListRequest;
class AddToWatchListResponse;
class RemoveFromWatchListRequest;
class RemoveFromWatchListResponse;
class AddToReferenceListRequest;
class AddToReferenceListResponse;
class GetChunkReferencesRequest;
class GetChunkReferencesResponse;
}  // namespace protobuf

namespace vault {

class ChunkInfoService {
 public:
  ChunkInfoService() {}
  void AddToWatchList(const transport::Info &info,
                      const protobuf::AddToWatchListRequest &request,
                      protobuf::AddToWatchListResponse *response);
  void RemoveFromWatchList(const transport::Info &info,
                           const protobuf::RemoveFromWatchListRequest &request,
                           protobuf::RemoveFromWatchListResponse *response);
  void AddToReferenceList(const transport::Info &info,
                          const protobuf::AddToReferenceListRequest &request,
                          protobuf::AddToReferenceListResponse *response);
  void GetChunkReferences(const transport::Info &info,
                          const protobuf::GetChunkReferencesRequest &request,
                          protobuf::GetChunkReferencesResponse *response);
  // TODO setters...
 private:
  ChunkInfoService(const ChunkInfoService&);
  ChunkInfoService& operator=(const ChunkInfoService&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_CHUNKINFOSERVICE_H_
