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

#ifndef MAIDSAFE_COMMON_VAULTSYNCSERVICE_H_
#define MAIDSAFE_COMMON_VAULTSYNCSERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
class GetSyncDataRequest;
class GetSyncDataResponse;
class GetAccountRequest;
class GetAccountResponse;
class GetChunkInfoRequest;
class GetChunkInfoResponse;
class GetBufferRequest;
class GetBufferResponse;
}  // namespace protobuf

namespace vault {

class VaultSyncService {
 public:
  VaultSyncService() {}
  void GetSyncData(const transport::Info &info,
                   const protobuf::GetSyncDataRequest &request,
                   protobuf::GetSyncDataResponse *response);
  void GetAccount(const transport::Info &info,
                  const protobuf::GetAccountRequest &request,
                  protobuf::GetAccountResponse *response);
  void GetChunkInfo(const transport::Info &info,
                    const protobuf::GetChunkInfoRequest &request,
                    protobuf::GetChunkInfoResponse *response);
  void GetBuffer(const transport::Info &info,
                 const protobuf::GetBufferRequest &request,
                 protobuf::GetBufferResponse *response);
  // TODO setters...
 private:
  VaultSyncService(const VaultSyncService&);
  VaultSyncService& operator=(const VaultSyncService&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_VAULTSYNCSERVICE_H_
