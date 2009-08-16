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

namespace maidsafe_vault {

class VaultChunkStore;

class VaultService : public maidsafe::MaidsafeService {
 public:
  VaultService(const std::string &pmid_public,
               const std::string &pmid_private,
               const std::string &signed_pmid_public,
               boost::shared_ptr<VaultChunkStore> vault_chunkstore,
               kad::KNode *knode,
               PendingOperationsHandler *poh);
  ~VaultService() {
//    printf("In VaultService destructor.\n");
  }
  virtual void StoreChunkPrep(google::protobuf::RpcController* controller,
             const maidsafe::StorePrepRequest* request,
             maidsafe::StorePrepResponse* response,
             google::protobuf::Closure* done);
  virtual void StoreChunk(google::protobuf::RpcController* controller,
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
  virtual void GetMessages(google::protobuf::RpcController* controller,
                   const maidsafe::GetMessagesRequest* request,
                   maidsafe::GetMessagesResponse* response,
                   google::protobuf::Closure* done);
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
 private:
  VaultService(const VaultService&);
  VaultService &operator=(const VaultService&);
  bool ValidateSignedRequest(const std::string &public_key,
                             const std::string &signed_public_key,
                             const std::string &signed_request,
                             const std::string &key);
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
  boost::shared_ptr<VaultChunkStore> vault_chunkstore_;
  kad::KNode *knode_;
  PendingOperationsHandler *poh_;
};
}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTSERVICE_H_
