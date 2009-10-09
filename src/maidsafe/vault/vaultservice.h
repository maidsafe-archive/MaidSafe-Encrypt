    /*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Services provided by vault
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

#ifndef MAIDSAFE_VAULT_VAULTSERVICE_H_
#define MAIDSAFE_VAULT_VAULTSERVICE_H_

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <maidsafe/crypto.h>
#include <maidsafe/utils.h>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/pendingoperations.h"
#include "protobuf/maidsafe_service.pb.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace maidsafe_vault {

struct IsOwnedPendingResponse {
  IsOwnedPendingResponse() : callback(NULL), args(NULL) {}
  google::protobuf::Closure* callback;
  maidsafe::OwnVaultResponse* args;
};

class VaultChunkStore;

class VaultService : public maidsafe::MaidsafeService {
 public:
  VaultService(const std::string &pmid_public,
               const std::string &pmid_private,
               const std::string &signed_pmid_public,
               VaultChunkStore *vault_chunkstore,
               kad::KNode *knode,
               PendingOperationsHandler *poh);
  ~VaultService() { }

  virtual void StoreChunkPrep(google::protobuf::RpcController* controller,
                              const maidsafe::StorePrepRequest* request,
                              maidsafe::StorePrepResponse* response,
                              google::protobuf::Closure* done);
  virtual void StoreChunk(google::protobuf::RpcController* controller,
                          const maidsafe::StoreRequest* request,
                          maidsafe::StoreResponse* response,
                          google::protobuf::Closure* done);
  virtual void StorePacket(google::protobuf::RpcController* controller,
                          const maidsafe::StoreRequest* request,
                          maidsafe::StoreResponse* response,
                          google::protobuf::Closure* done);
  virtual void IOUDone(google::protobuf::RpcController*,
                       const maidsafe::IOUDoneRequest* request,
                       maidsafe::IOUDoneResponse* response,
                       google::protobuf::Closure* done);
  virtual void StoreIOU(google::protobuf::RpcController* controller,
                        const maidsafe::StoreIOURequest* request,
                        maidsafe::StoreIOUResponse* response,
                        google::protobuf::Closure* done);
  virtual void StoreChunkReference(google::protobuf::RpcController*,
      const maidsafe::StoreReferenceRequest* request,
      maidsafe::StoreReferenceResponse* response,
      google::protobuf::Closure* done);
  virtual void Get(google::protobuf::RpcController* controller,
                   const maidsafe::GetRequest* request,
                   maidsafe::GetResponse* response,
                   google::protobuf::Closure* done);
  virtual void CheckChunk(google::protobuf::RpcController* controller,
                          const maidsafe::CheckChunkRequest* request,
                          maidsafe::CheckChunkResponse* response,
                          google::protobuf::Closure* done);
  virtual void Update(google::protobuf::RpcController* controller,
                      const maidsafe::UpdateRequest* request,
                      maidsafe::UpdateResponse* response,
                      google::protobuf::Closure* done);
//  virtual void GetMessages(google::protobuf::RpcController* controller,
//                           const maidsafe::GetBPMessagesRequest* request,
//                           maidsafe::GetBPMessagesResponse* response,
//                           google::protobuf::Closure* done);
  virtual void Delete(google::protobuf::RpcController* controller,
                      const maidsafe::DeleteRequest* request,
                      maidsafe::DeleteResponse* response,
                      google::protobuf::Closure* done);
  virtual void ValidityCheck(google::protobuf::RpcController* controller,
                             const maidsafe::ValidityCheckRequest* request,
                             maidsafe::ValidityCheckResponse* response,
                             google::protobuf::Closure* done);
  virtual void SwapChunk(google::protobuf::RpcController* controller,
                         const maidsafe::SwapChunkRequest* request,
                         maidsafe::SwapChunkResponse* response,
                         google::protobuf::Closure* done);
  virtual void VaultStatus(google::protobuf::RpcController* controller,
                           const maidsafe::VaultStatusRequest* request,
                           maidsafe::VaultStatusResponse* response,
                           google::protobuf::Closure* done);

  // BP services
  virtual void CreateBP(google::protobuf::RpcController* controller,
                        const maidsafe::CreateBPRequest* request,
                        maidsafe::CreateBPResponse* response,
                        google::protobuf::Closure* done);
  virtual void ModifyBPInfo(google::protobuf::RpcController* controller,
                            const maidsafe::ModifyBPInfoRequest* request,
                            maidsafe::ModifyBPInfoResponse* response,
                            google::protobuf::Closure* done);
  virtual void GetBPMessages(google::protobuf::RpcController* controller,
                             const maidsafe::GetBPMessagesRequest* request,
                             maidsafe::GetBPMessagesResponse* response,
                             google::protobuf::Closure* done);
  virtual void AddBPMessage(google::protobuf::RpcController* controller,
                            const maidsafe::AddBPMessageRequest* request,
                            maidsafe::AddBPMessageResponse* response,
                            google::protobuf::Closure* done);

 private:
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateSignedRequest);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateSystemPacket);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateDataChunk);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesStorable);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesLocalStorage);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesRankAuthorityGenerator);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesGetCheck);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesUpdate);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesGetMessages);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesDelete);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidityCheck);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesCreateBP);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesModifyBPInfo);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesGetBPMessages);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesAddBPMessages);
  VaultService(const VaultService&);
  VaultService &operator=(const VaultService&);
  bool ValidateSignedRequest(const std::string &public_key,
                             const std::string &signed_public_key,
                             const std::string &signed_request,
                             const std::string &key,
                             const std::string &pmid);
  bool ValidateSystemPacket(const std::string &ser_content,
                            const std::string &public_key);
  bool ValidateDataChunk(const std::string &chunkname,
                         const std::string &content);
  int Storable(const boost::uint64_t &data_size);
  bool ModifyBufferPacketInfo(const std::string &new_info,
                              const std::string &pub_key,
                              std::string *updated_bp);
  bool HasChunkLocal(const std::string &chunkname);
  bool StoreChunkLocal(const std::string &chunkname,
                       const std::string &content);
  bool UpdateChunkLocal(const std::string &chunkname,
                        const std::string &content);
  bool LoadChunkLocal(const std::string &chunkname, std::string *content);
  bool DeleteChunkLocal(const std::string &chunkname);
  void StoreChunkReference(const std::string &non_hex_chunkname);
  void FindCloseNodesCallback(const std::string &result,
                              std::vector<std::string> *close_nodes);
  void RankAuthorityGenerator(const std::string &chunkname,
                              const boost::uint64_t &data_size,
                              const std::string &pmid,
                              std::string *rank_authority,
                              std::string *signed_rank_authority);
  std::string pmid_public_, pmid_private_, signed_pmid_public_, pmid_;
  std::string non_hex_pmid_;
  VaultChunkStore *vault_chunkstore_;
  kad::KNode *knode_;
  PendingOperationsHandler *poh_;
};

class RegistrationService : public maidsafe::VaultRegistration {
 public:
  RegistrationService(boost::function<void(const maidsafe::VaultConfig&)>
      notifier);
  virtual void OwnVault(google::protobuf::RpcController* controller,
      const maidsafe::OwnVaultRequest* request,
      maidsafe::OwnVaultResponse* response, google::protobuf::Closure* done);
  virtual void IsVaultOwned(google::protobuf::RpcController* controller,
      const maidsafe::IsOwnedRequest* request,
      maidsafe::IsOwnedResponse* response, google::protobuf::Closure* done);
  void ReplyOwnVaultRequest(const bool &fail_to_start);
  inline void set_status(const maidsafe::VaultStatus &status) {
      status_ = status;
  }
  inline maidsafe::VaultStatus status() { return status_; }
 private:
  boost::function<void(const maidsafe::VaultConfig&)> notifier_;
  maidsafe::VaultStatus status_;
  IsOwnedPendingResponse pending_response_;
};
}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTSERVICE_H_
