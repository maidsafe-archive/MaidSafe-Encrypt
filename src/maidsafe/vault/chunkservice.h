/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class providing Chunk services.
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

#ifndef MAIDSAFE_COMMON_CHUNKSERVICE_H_
#define MAIDSAFE_COMMON_CHUNKSERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
class ArrangeStoreRequest;
class ArrangeStoreResponse;
class StoreChunkRequest;
class StoreChunkResponse;
class GetChunkRequest;
class GetChunkResponse;
class HasChunkRequest;
class HasChunkResponse;
class ValidateChunkRequest;
class ValidateChunkResponse;
class DeleteChunkRequest;
class DeleteChunkResponse;
class DuplicateChunkRequest;
class DuplicateChunkResponse;
class CacheChunkRequest;
class CacheChunkResponse;
}  // namespace protobuf

namespace vault {

class ChunkService {
 public:
  ChunkService() {}
  void ArrangeStore(const transport::Info &info,
                    const protobuf::ArrangeStoreRequest &request,
                    protobuf::ArrangeStoreResponse *response);
  void StoreChunk(const transport::Info &info,
                  const protobuf::StoreChunkRequest &request,
                  protobuf::StoreChunkResponse *response);
  void GetChunk(const transport::Info &info,
                const protobuf::GetChunkRequest &request,
                protobuf::GetChunkResponse *response);
  void HasChunk(const transport::Info &info,
                const protobuf::HasChunkRequest &request,
                protobuf::HasChunkResponse *response);
  void ValidateChunk(const transport::Info &info,
                     const protobuf::ValidateChunkRequest &request,
                     protobuf::ValidateChunkResponse *response);
  void DeleteChunk(const transport::Info &info,
                   const protobuf::DeleteChunkRequest &request,
                   protobuf::DeleteChunkResponse *response);
  void DuplicateChunk(const transport::Info &info,
                      const protobuf::DuplicateChunkRequest &request,
                      protobuf::DuplicateChunkResponse *response);
  void CacheChunk(const transport::Info &info,
                  const protobuf::CacheChunkRequest &request,
                  protobuf::CacheChunkResponse *response);
  // TODO setters...
 private:
  ChunkService(const ChunkService&);
  ChunkService& operator=(const ChunkService&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_CHUNKSERVICE_H_
