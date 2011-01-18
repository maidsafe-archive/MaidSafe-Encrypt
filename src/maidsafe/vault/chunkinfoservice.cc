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

#include "maidsafe/vault/chunkinfoservice.h"

#include "maidsafe/common/chunk_info_messages.pb.h"

namespace maidsafe {

namespace vault {

void ChunkInfoService::AddToWatchList(
    const transport::Info &info,
    const protobuf::AddToWatchListRequest &request,
    protobuf::AddToWatchListResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkInfoService::AddToWatchList body
}

void ChunkInfoService::RemoveFromWatchList(
    const transport::Info &info,
    const protobuf::RemoveFromWatchListRequest &request,
    protobuf::RemoveFromWatchListResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkInfoService::RemoveFromWatchList body
}

void ChunkInfoService::AddToReferenceList(
    const transport::Info &info,
    const protobuf::AddToReferenceListRequest &request,
    protobuf::AddToReferenceListResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkInfoService::AddToReferenceList body
}

void ChunkInfoService::GetChunkReferences(
    const transport::Info &info,
    const protobuf::GetChunkReferencesRequest &request,
    protobuf::GetChunkReferencesResponse *response) {
  // response->set_result(false);
  // TODO implement ChunkInfoService::GetChunkReferences body
}

}

}  // namespace maidsafe
