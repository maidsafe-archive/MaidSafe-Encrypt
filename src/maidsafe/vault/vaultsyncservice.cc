/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class providing VaultSync services.
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

#include "maidsafe/vault/vaultsyncservice.h"

#include "maidsafe/common/vault_sync_messages.pb.h"

namespace maidsafe {

namespace vault {

void VaultSyncService::GetSyncData(const transport::Info &info,
                                   const protobuf::GetSyncDataRequest &request,
                                   protobuf::GetSyncDataResponse *response) {
  // response->set_result(false);
  // TODO implement VaultSyncService::GetSyncData body
}

void VaultSyncService::GetAccount(const transport::Info &info,
                                  const protobuf::GetAccountRequest &request,
                                  protobuf::GetAccountResponse *response) {
  // response->set_result(false);
  // TODO implement VaultSyncService::GetAccount body
}

void VaultSyncService::GetChunkInfo(
    const transport::Info &info,
    const protobuf::GetChunkInfoRequest &request,
    protobuf::GetChunkInfoResponse *response) {
  // response->set_result(false);
  // TODO implement VaultSyncService::GetChunkInfo body
}

void VaultSyncService::GetBuffer(const transport::Info &info,
                                 const protobuf::GetBufferRequest &request,
                                 protobuf::GetBufferResponse *response) {
  // response->set_result(false);
  // TODO implement VaultSyncService::GetBuffer body
}

}

}  // namespace maidsafe
