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

#include <boost/compressed_pair.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <maidsafe/contact_info.pb.h>
#include <maidsafe/crypto.h>
#include <maidsafe/utils.h>
#include <QThreadPool>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/accountamendmenthandler.h"
#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/chunkinfohandler.h"
#include "protobuf/maidsafe_service.pb.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace maidsafe_vault {

class VaultServiceLogic;

struct IsOwnedPendingResponse {
  IsOwnedPendingResponse() : callback(NULL), args(NULL) {}
  google::protobuf::Closure* callback;
  maidsafe::SetLocalVaultOwnedResponse* args;
};

template <typename T>
class RemoteTask : public QRunnable {
 public:
  RemoteTask(
      const T &request,
      const int &found_local_result,
      VoidFuncOneInt callback,
      VaultServiceLogic *vault_service_logic,
      const boost::int16_t &transport_id)
          : request_(request),
            found_local_result_(found_local_result),
            callback_(callback),
            vault_service_logic_(vault_service_logic),
            transport_id_(transport_id) {}
  void run();
 private:
  RemoteTask &operator=(const RemoteTask&);
  RemoteTask(const RemoteTask&);
  T request_;
  int found_local_result_;
  VoidFuncOneInt callback_;
  VaultServiceLogic *vault_service_logic_;
  boost::int16_t transport_id_;
};

class SendCachableChunkTask : public QRunnable {
 public:
  SendCachableChunkTask(const std::string chunkname,
                        const std::string chunkcontent,
                        const kad::ContactInfo cacher,
                        VaultServiceLogic *vault_service_logic,
                        VoidFuncOneInt callback)
      : chunkname_(chunkname), chunkcontent_(chunkcontent), cacher_(cacher),
        vault_service_logic_(vault_service_logic), callback_(callback),
        transport_id_(0) {}
  void run();

 private:
  std::string chunkname_;
  std::string chunkcontent_;
  kad::ContactInfo cacher_;
  VaultServiceLogic *vault_service_logic_;
  VoidFuncOneInt callback_;
  boost::uint16_t transport_id_;
};

class VaultChunkStore;

class VaultService : public maidsafe::MaidsafeService {
 public:
  VaultService(const std::string &pmid_public,
               const std::string &pmid_private,
               const std::string &pmid_public_signature,
               VaultChunkStore *vault_chunkstore,
               kad::KNode *knode,
               VaultServiceLogic *vault_service_logic,
               const boost::int16_t &transport_id);
  ~VaultService() {}
  void AddStartupSyncData(
      const maidsafe::GetSyncDataResponse &get_sync_data_response);
  virtual void StorePrep(google::protobuf::RpcController* controller,
                         const maidsafe::StorePrepRequest *request,
                         maidsafe::StorePrepResponse *response,
                         google::protobuf::Closure *done);
  virtual void StoreChunk(google::protobuf::RpcController* controller,
                          const maidsafe::StoreChunkRequest *request,
                          maidsafe::StoreChunkResponse *response,
                          google::protobuf::Closure *done);
  virtual void AddToWatchList(google::protobuf::RpcController* controller,
                              const maidsafe::AddToWatchListRequest *request,
                              maidsafe::AddToWatchListResponse *response,
                              google::protobuf::Closure *done);
  virtual void RemoveFromWatchList(
      google::protobuf::RpcController* controller,
      const maidsafe::RemoveFromWatchListRequest *request,
      maidsafe::RemoveFromWatchListResponse *response,
      google::protobuf::Closure *done);
  virtual void AddToReferenceList(
      google::protobuf::RpcController* controller,
      const maidsafe::AddToReferenceListRequest *request,
      maidsafe::AddToReferenceListResponse *response,
      google::protobuf::Closure *done);
  virtual void RemoveFromReferenceList(
      google::protobuf::RpcController* controller,
      const maidsafe::RemoveFromReferenceListRequest *request,
      maidsafe::RemoveFromReferenceListResponse *response,
      google::protobuf::Closure *done);
  virtual void AmendAccount(google::protobuf::RpcController* controller,
                            const maidsafe::AmendAccountRequest *request,
                            maidsafe::AmendAccountResponse *response,
                            google::protobuf::Closure *done);
  virtual void AccountStatus(google::protobuf::RpcController* controller,
                             const maidsafe::AccountStatusRequest *request,
                             maidsafe::AccountStatusResponse *response,
                             google::protobuf::Closure *done);
  virtual void CheckChunk(google::protobuf::RpcController* controller,
                          const maidsafe::CheckChunkRequest *request,
                          maidsafe::CheckChunkResponse *response,
                          google::protobuf::Closure *done);
  virtual void GetChunk(google::protobuf::RpcController* controller,
                        const maidsafe::GetChunkRequest *request,
                        maidsafe::GetChunkResponse *response,
                        google::protobuf::Closure *done);
  virtual void DeleteChunk(google::protobuf::RpcController* controller,
                           const maidsafe::DeleteChunkRequest *request,
                           maidsafe::DeleteChunkResponse *response,
                           google::protobuf::Closure *done);
  virtual void ValidityCheck(google::protobuf::RpcController* controller,
                             const maidsafe::ValidityCheckRequest *request,
                             maidsafe::ValidityCheckResponse *response,
                             google::protobuf::Closure *done);
  virtual void SwapChunk(google::protobuf::RpcController* controller,
                         const maidsafe::SwapChunkRequest *request,
                         maidsafe::SwapChunkResponse *response,
                         google::protobuf::Closure *done);
  virtual void CacheChunk(google::protobuf::RpcController* controller,
                         const maidsafe::CacheChunkRequest *request,
                         maidsafe::CacheChunkResponse *response,
                         google::protobuf::Closure *done);
  virtual void GetSyncData(google::protobuf::RpcController* controller,
                           const maidsafe::GetSyncDataRequest *request,
                           maidsafe::GetSyncDataResponse *response,
                           google::protobuf::Closure *done);
  virtual void GetAccount(google::protobuf::RpcController* controller,
                           const maidsafe::GetAccountRequest *request,
                           maidsafe::GetAccountResponse *response,
                           google::protobuf::Closure *done);
  virtual void GetChunkInfo(google::protobuf::RpcController* controller,
                           const maidsafe::GetChunkInfoRequest *request,
                           maidsafe::GetChunkInfoResponse *response,
                           google::protobuf::Closure *done);
  virtual void VaultStatus(google::protobuf::RpcController* controller,
                           const maidsafe::VaultStatusRequest *request,
                           maidsafe::VaultStatusResponse *response,
                           google::protobuf::Closure *done);
  virtual void CreateBP(google::protobuf::RpcController* controller,
                        const maidsafe::CreateBPRequest *request,
                        maidsafe::CreateBPResponse *response,
                        google::protobuf::Closure *done);
  virtual void ModifyBPInfo(google::protobuf::RpcController* controller,
                            const maidsafe::ModifyBPInfoRequest *request,
                            maidsafe::ModifyBPInfoResponse *response,
                            google::protobuf::Closure *done);
  virtual void GetBPMessages(google::protobuf::RpcController* controller,
                             const maidsafe::GetBPMessagesRequest *request,
                             maidsafe::GetBPMessagesResponse *response,
                             google::protobuf::Closure *done);
  virtual void AddBPMessage(google::protobuf::RpcController* controller,
                            const maidsafe::AddBPMessageRequest* request,
                            maidsafe::AddBPMessageResponse* response,
                            google::protobuf::Closure* done);
  virtual void ContactInfo(google::protobuf::RpcController* controller,
                           const maidsafe::ContactInfoRequest* request,
                           maidsafe::ContactInfoResponse* response,
                           google::protobuf::Closure* done);
  int AddAccount(const std::string &pmid, const boost::uint64_t &offer);
 private:
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateSignedRequest);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateIdentity);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateSystemPacket);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidateDataChunk);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesStorable);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesLocalStorage);
  FRIEND_TEST(MockVaultServicesTest, BEH_MAID_ServicesStoreChunk);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesGetCheckChunk);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesDeleteChunk);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesAmendAccount);
  FRIEND_TEST(MockVaultServicesTest, BEH_MAID_ServicesAddToWatchList);
  FRIEND_TEST(MockVaultServicesTest, FUNC_MAID_ServicesRemoveFromWatchList);
  FRIEND_TEST(MockVaultServicesTest, BEH_MAID_ServicesAddToReferenceList);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesValidityCheck);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesCreateBP);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesModifyBPInfo);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesGetBPMessages);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesAddBPMessages);
  FRIEND_TEST(VaultServicesTest, BEH_MAID_ServicesCacheChunk);
  VaultService(const VaultService&);
  VaultService &operator=(const VaultService&);
  void DiscardResult(const int&) {}
  bool ValidateSignedSize(const maidsafe::SignedSize &sz);
  bool ValidateStoreContract(const maidsafe::StoreContract &sc);
  bool ValidateAmendRequest(const maidsafe::AmendAccountRequest *request,
                            boost::uint64_t *account_delta,
                            std::string *pmid);
  bool ValidateSignedRequest(const std::string &public_key,
                             const std::string &public_key_signature,
                             const std::string &request_signature,
                             const std::string &key,
                             const std::string &pmid);
  bool ValidateIdentity(const std::string &id,
                        const std::string &public_key,
                        const std::string &public_key_signature);
  bool ValidateSystemPacket(const std::string &ser_content,
                            const std::string &public_key);
  bool ValidateDataChunk(const std::string &chunkname,
                         const std::string &content);
  int Storable(const boost::uint64_t &data_size);
  bool HasChunkLocal(const std::string &chunkname);
  bool StoreChunkLocal(const std::string &chunkname,
                       const std::string &content);
  bool UpdateBPChunkLocal(const std::string &bufferpacket_name,
                          const std::string &content);
  bool LoadChunkLocal(const std::string &chunkname, std::string *content);
  bool DeleteChunkLocal(const std::string &chunkname);
  boost::uint64_t GetChunkSizeLocal(const std::string &chunkname);
  void FindCloseNodesCallback(const std::string &result,
                              std::vector<std::string> *close_nodes);
  void FinalisePayment(const std::string &chunk_name,
                       const std::string &pmid,
                       const int &chunk_size,
                       const int &permission_result);
  void DoneAddToReferenceList(const maidsafe::StoreContract &store_contract,
                              const std::string &chunk_name);
  // This method returns immediately after the task is added to the thread pool.
  // The result of the amendment is discarded.
  void AmendRemoteAccount(
      const maidsafe::AmendAccountRequest::Amendment &amendment_type,
      const boost::uint64_t &size,
      const std::string &account_pmid,
      const std::string &chunkname);
  // This method returns immediately after the task is added to the thread pool.
  // The result of the amendment is called back.
  void AmendRemoteAccount(
      const maidsafe::AmendAccountRequest::Amendment &amendment_type,
      const boost::uint64_t &size,
      const std::string &account_pmid,
      const std::string &chunkname,
      const VoidFuncOneInt &callback);
  void AddToRemoteRefList(const std::string &chunkname,
                          const maidsafe::StoreContract &contract);
  void RemoteVaultAbleToStore(const boost::uint64_t &size,
                              const std::string &account_pmid,
                              const VoidFuncOneInt &callback);
  // Returns whether the node is within "count" closest nodes (Kademlia closest)
  bool NodeWithinClosest(const std::string &peer_pmid,
                         const boost::uint16_t &count);
  std::string pmid_public_, pmid_private_, pmid_public_signature_, pmid_;
  VaultChunkStore *vault_chunkstore_;
  kad::KNode *knode_;
  VaultServiceLogic *vault_service_logic_;
  boost::int16_t transport_id_;
  typedef std::map<std::string, maidsafe::StoreContract> PrepsReceivedMap;
  PrepsReceivedMap prm_;
  AccountHandler ah_;
  AccountAmendmentHandler aah_;
  ChunkInfoHandler cih_;
  QThreadPool thread_pool_;
};

class RegistrationService : public maidsafe::VaultRegistration {
 public:
  RegistrationService(
      boost::function<void(const maidsafe::VaultConfig&)> notifier);
  virtual void SetLocalVaultOwned(
      google::protobuf::RpcController* controller,
      const maidsafe::SetLocalVaultOwnedRequest *request,
      maidsafe::SetLocalVaultOwnedResponse *response,
      google::protobuf::Closure *done);
  virtual void LocalVaultOwned(
      google::protobuf::RpcController* controller,
      const maidsafe::LocalVaultOwnedRequest *request,
      maidsafe::LocalVaultOwnedResponse *response,
      google::protobuf::Closure *done);
  void ReplySetLocalVaultOwnedRequest(const bool &fail_to_start);
  inline void set_status(const maidsafe::VaultStatus &status) {
      status_ = status;
  }
  inline maidsafe::VaultStatus status() { return status_; }
 private:
  RegistrationService(const RegistrationService&);
  RegistrationService &operator=(const RegistrationService&);
  boost::function<void(const maidsafe::VaultConfig&)> notifier_;
  maidsafe::VaultStatus status_;
  IsOwnedPendingResponse pending_response_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTSERVICE_H_
