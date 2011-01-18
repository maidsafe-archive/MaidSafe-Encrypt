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

#include "maidsafe/vault/chunkservice.h"

#include "maidsafe/common/chunk_messages.pb.h"

namespace maidsafe {

namespace vault {

void ChunkService::ArrangeStore(const transport::Info &info,
                                const protobuf::ArrangeStoreRequest &request,
                                protobuf::ArrangeStoreResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::ArrangeStore body
}

void ChunkService::StoreChunk(const transport::Info &info,
                              const protobuf::StoreChunkRequest &request,
                              protobuf::StoreChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::StoreChunk body
}

void ChunkService::GetChunk(const transport::Info &info,
                            const protobuf::GetChunkRequest &request,
                            protobuf::GetChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::GetChunk body
}

void ChunkService::HasChunk(const transport::Info &info,
                            const protobuf::HasChunkRequest &request,
                            protobuf::HasChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::HasChunk body
}

void ChunkService::ValidateChunk(const transport::Info &info,
                                 const protobuf::ValidateChunkRequest &request,
                                 protobuf::ValidateChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::ValidateChunk body
}

void ChunkService::DeleteChunk(const transport::Info &info,
                               const protobuf::DeleteChunkRequest &request,
                               protobuf::DeleteChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::DeleteChunk body
}

void ChunkService::DuplicateChunk(
    const transport::Info &info,
    const protobuf::DuplicateChunkRequest &request,
    protobuf::DuplicateChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::DuplicateChunk body
}

void ChunkService::CacheChunk(const transport::Info &info,
                              const protobuf::CacheChunkRequest &request,
                              protobuf::CacheChunkResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkService::CacheChunk body
}

}

}  // namespace maidsafe
