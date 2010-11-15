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

//#include <boost/compressed_pair.hpp>
//#include <boost/thread/condition_variable.hpp>
//#include <boost/tuple/tuple.hpp>
//#include <boost/tuple/tuple_comparison.hpp>
//#include <maidsafe/protobuf/contact_info.pb.h>
//#include <maidsafe/base/crypto.h>
//#include <maidsafe/base/utils.h>
#include <QThreadPool>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/maidsafe_service.pb.h"
#include "maidsafe/vault/accountamendmenthandler.h"
#include "maidsafe/vault/accountrepository.h"
#include "maidsafe/vault/chunkinfohandler.h"
#include "maidsafe/vault/bufferpacketstore.h"
#include "maidsafe/vault/infosynchroniser.h"
#include "maidsafe/vault/requestexpectationhandler.h"
#include "maidsafe/vault/vaultservicelogic.h"

namespace maidsafe { class VaultConfig; }

namespace maidsafe {

namespace vault {

namespace test {
class PDVaultTest_FUNC_MAID_NET_StoreAndGetChunks_Test;
class VaultServicesTest_BEH_MAID_ValidateSignedSize_Test;
class VaultServicesTest_BEH_MAID_ValidateStoreContract_Test;
class VaultServicesTest_BEH_MAID_ValidateAmendRequest_Test;
class VaultServicesTest_BEH_MAID_ValidateIdAndRequest_Test;
class VaultServicesTest_BEH_MAID_ValidateRequestSignature_Test;
class VaultServicesTest_BEH_MAID_ValidateIdentity_Test;
class VaultServicesTest_BEH_MAID_ValidateSystemPacket_Test;
class VaultServicesTest_BEH_MAID_ValidateDataChunk_Test;
class VaultServicesTest_BEH_MAID_Storable_Test;
class VaultServicesTest_BEH_MAID_LocalStorage_Test;
class VaultServicesTest_BEH_MAID_StorePrep_Test;
class VaultServicesTest_BEH_MAID_NodeWithinClosest_Test;
class MockVaultServicesTest_BEH_MAID_StoreChunk_Test;
class VaultServicesTest_BEH_MAID_GetCheckChunk_Test;
class VaultServicesTest_BEH_MAID_DeleteChunk_Test;
class VaultServicesTest_BEH_MAID_ValidityCheck_Test;
class VaultServicesTest_BEH_MAID_CacheChunk_Test;
class VaultServicesTest_BEH_MAID_GetChunkReferences_Test;
class MockVaultServicesTest_BEH_MAID_AddToWatchList_Test;
class MockVaultServicesTest_FUNC_MAID_RemoveFromWatchList_Test;
class MockVaultServicesTest_BEH_MAID_AddToReferenceList_Test;
class MockVaultServicesTest_FUNC_MAID_AmendAccount_Test;
class VaultServicesTest_BEH_MAID_ExpectAmendment_Test;
class VaultServicesTest_BEH_MAID_GetSyncData_Test;
class VaultServicesTest_BEH_MAID_GetAccount_Test;
class VaultServicesTest_BEH_MAID_GetChunkInfo_Test;
class VaultServicesTest_BEH_MAID_GetBufferPacket_Test;
class VaultServicesTest_BEH_MAID_CreateBP_Test;
class VaultServicesTest_BEH_MAID_ModifyBPInfo_Test;
class VaultServicesTest_BEH_MAID_GetBPMessages_Test;
class VaultServicesTest_BEH_MAID_AddBPMessages_Test;
class VaultServicesTest_BEH_MAID_GetBPPresence_Test;
class VaultServicesTest_BEH_MAID_AddBPPresence_Test;
}  // namespace test

struct IsOwnedPendingResponse {
  IsOwnedPendingResponse() : callback(NULL), args(NULL) {}
  google::protobuf::Closure* callback;
  SetLocalVaultOwnedResponse* args;
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
                        VoidFuncOneInt callback,
                        const boost::int16_t &transport_id)
      : chunkname_(chunkname),
        chunkcontent_(chunkcontent),
        cacher_(cacher),
        vault_service_logic_(vault_service_logic),
        callback_(callback),
        transport_id_(transport_id) {}
  void run();
 private:
  SendCachableChunkTask &operator=(const SendCachableChunkTask&);
  SendCachableChunkTask(const SendCachableChunkTask&);
  std::string chunkname_;
  std::string chunkcontent_;
  kad::ContactInfo cacher_;
  VaultServiceLogic *vault_service_logic_;
  VoidFuncOneInt callback_;
  boost::uint16_t transport_id_;
};

template <typename T1, typename T2>
class GetRemoteInfoTask : public QRunnable {
 public:
  GetRemoteInfoTask(const std::vector<kad::Contact> &close_contacts,
                    const std::vector<T1> &requests,
                    VaultServiceLogic *vault_service_logic,
                    T2 callback,
                    const boost::int16_t &transport_id)
      : close_contacts_(close_contacts),
        get_info_requests_(requests),
        vault_service_logic_(vault_service_logic),
        callback_(callback),
        transport_id_(transport_id) {}
  void run();
 private:
  GetRemoteInfoTask &operator=(const GetRemoteInfoTask&);
  GetRemoteInfoTask(const GetRemoteInfoTask&);
  std::vector<kad::Contact> close_contacts_;
  std::vector<T1> get_info_requests_;
  VaultServiceLogic *vault_service_logic_;
  T2 callback_;
  boost::int16_t transport_id_;
};

typedef GetRemoteInfoTask<GetAccountRequest, VoidFuncIntAccount>
    GetRemoteAccountTask;

typedef GetRemoteInfoTask<GetChunkInfoRequest, VoidFuncIntChunkInfo>
    GetRemoteChunkInfoTask;

typedef GetRemoteInfoTask<GetBufferPacketRequest, VoidFuncIntBufferPacket>
    GetRemoteBufferPacketTask;

class VaultChunkStore;

class VaultService : public MaidsafeService {
 public:
  VaultService(const std::string &pmid,
               const std::string &pmid_public,
               const std::string &pmid_private,
               const std::string &pmid_public_signature,
               boost::shared_ptr<VaultChunkStore> vault_chunkstore,
               VaultServiceLogic *vault_service_logic,
               const boost::int16_t &transport_id,
               boost::shared_ptr<KadOps> kadops);
  ~VaultService() {}
  void AddStartupSyncData(const GetSyncDataResponse &get_sync_data_response);
  virtual void StorePrep(google::protobuf::RpcController *controller,
                         const StorePrepRequest *request,
                         StorePrepResponse *response,
                         google::protobuf::Closure *done);
  virtual void StoreChunk(google::protobuf::RpcController *controller,
                          const StoreChunkRequest *request,
                          StoreChunkResponse *response,
                          google::protobuf::Closure *done);
  virtual void GetChunk(google::protobuf::RpcController *controller,
                        const GetChunkRequest *request,
                        GetChunkResponse *response,
                        google::protobuf::Closure *done);
  virtual void CheckChunk(google::protobuf::RpcController *controller,
                          const CheckChunkRequest *request,
                          CheckChunkResponse *response,
                          google::protobuf::Closure *done);
  virtual void DeleteChunk(google::protobuf::RpcController *controller,
                           const DeleteChunkRequest *request,
                           DeleteChunkResponse *response,
                           google::protobuf::Closure *done);
  virtual void ValidityCheck(google::protobuf::RpcController *controller,
                             const ValidityCheckRequest *request,
                             ValidityCheckResponse *response,
                             google::protobuf::Closure *done);
  virtual void SwapChunk(google::protobuf::RpcController *controller,
                         const SwapChunkRequest *request,
                         SwapChunkResponse *response,
                         google::protobuf::Closure *done);
  virtual void CacheChunk(google::protobuf::RpcController *controller,
                          const CacheChunkRequest *request,
                          CacheChunkResponse *response,
                          google::protobuf::Closure *done);
  virtual void GetChunkReferences(google::protobuf::RpcController *controller,
                                  const GetChunkReferencesRequest *request,
                                  GetChunkReferencesResponse *response,
                                  google::protobuf::Closure *done);
  virtual void AddToWatchList(google::protobuf::RpcController *controller,
                              const AddToWatchListRequest *request,
                              AddToWatchListResponse *response,
                              google::protobuf::Closure *done);
  virtual void RemoveFromWatchList(google::protobuf::RpcController *controller,
                                   const RemoveFromWatchListRequest *request,
                                   RemoveFromWatchListResponse *response,
                                   google::protobuf::Closure *done);
  virtual void AddToReferenceList(google::protobuf::RpcController *controller,
                                  const AddToReferenceListRequest *request,
                                  AddToReferenceListResponse *response,
                                  google::protobuf::Closure *done);
  virtual void AmendAccount(google::protobuf::RpcController *controller,
                            const AmendAccountRequest *request,
                            AmendAccountResponse *response,
                            google::protobuf::Closure *done);
  virtual void ExpectAmendment(google::protobuf::RpcController *controller,
                               const ExpectAmendmentRequest *request,
                               ExpectAmendmentResponse *response,
                               google::protobuf::Closure *done);
  virtual void AccountStatus(google::protobuf::RpcController *controller,
                             const AccountStatusRequest *request,
                             AccountStatusResponse *response,
                             google::protobuf::Closure *done);
  virtual void GetSyncData(google::protobuf::RpcController *controller,
                           const GetSyncDataRequest *request,
                           GetSyncDataResponse *response,
                           google::protobuf::Closure *done);
  virtual void GetAccount(google::protobuf::RpcController *controller,
                          const GetAccountRequest *request,
                          GetAccountResponse *response,
                          google::protobuf::Closure *done);
  virtual void GetChunkInfo(google::protobuf::RpcController *controller,
                            const GetChunkInfoRequest *request,
                            GetChunkInfoResponse *response,
                            google::protobuf::Closure *done);
  virtual void GetBufferPacket(google::protobuf::RpcController *controller,
                               const GetBufferPacketRequest *request,
                               GetBufferPacketResponse *response,
                               google::protobuf::Closure *done);
  virtual void VaultStatus(google::protobuf::RpcController *controller,
                           const VaultStatusRequest *request,
                           VaultStatusResponse *response,
                           google::protobuf::Closure *done);
  virtual void CreateBP(google::protobuf::RpcController *controller,
                        const CreateBPRequest *request,
                        CreateBPResponse *response,
                        google::protobuf::Closure *done);
  virtual void ModifyBPInfo(google::protobuf::RpcController *controller,
                            const ModifyBPInfoRequest *request,
                            ModifyBPInfoResponse *response,
                            google::protobuf::Closure *done);
  virtual void GetBPMessages(google::protobuf::RpcController *controller,
                             const GetBPMessagesRequest *request,
                             GetBPMessagesResponse *response,
                             google::protobuf::Closure *done);
  virtual void AddBPMessage(google::protobuf::RpcController *controller,
                            const AddBPMessageRequest *request,
                            AddBPMessageResponse *response,
                            google::protobuf::Closure *done);
  virtual void GetBPPresence(google::protobuf::RpcController *controller,
                             const GetBPPresenceRequest *request,
                             GetBPPresenceResponse *response,
                             google::protobuf::Closure *done);
  virtual void AddBPPresence(google::protobuf::RpcController *controller,
                             const AddBPPresenceRequest *request,
                             AddBPPresenceResponse *response,
                             google::protobuf::Closure *done);
  int AddAccount(const std::string &pmid, const boost::uint64_t &offer);
  bool HaveAccount(const std::string &pmid);
 private:
  VaultService(const VaultService&);
  VaultService &operator=(const VaultService&);
  friend class test::VaultServicesTest_BEH_MAID_ValidateSignedSize_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateStoreContract_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateAmendRequest_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateIdAndRequest_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateRequestSignature_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateIdentity_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateSystemPacket_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidateDataChunk_Test;
  friend class test::VaultServicesTest_BEH_MAID_Storable_Test;
  friend class test::VaultServicesTest_BEH_MAID_LocalStorage_Test;
  friend class test::VaultServicesTest_BEH_MAID_StorePrep_Test;
  friend class test::VaultServicesTest_BEH_MAID_NodeWithinClosest_Test;
  friend class test::MockVaultServicesTest_BEH_MAID_StoreChunk_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetCheckChunk_Test;
  friend class test::VaultServicesTest_BEH_MAID_DeleteChunk_Test;
  friend class test::VaultServicesTest_BEH_MAID_ValidityCheck_Test;
  friend class test::VaultServicesTest_BEH_MAID_CacheChunk_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetChunkReferences_Test;
  friend class test::MockVaultServicesTest_BEH_MAID_AddToWatchList_Test;
  friend class test::MockVaultServicesTest_FUNC_MAID_RemoveFromWatchList_Test;
  friend class test::MockVaultServicesTest_BEH_MAID_AddToReferenceList_Test;
  friend class test::MockVaultServicesTest_FUNC_MAID_AmendAccount_Test;
  friend class test::VaultServicesTest_BEH_MAID_ExpectAmendment_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetSyncData_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetAccount_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetChunkInfo_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetBufferPacket_Test;
  friend class test::VaultServicesTest_BEH_MAID_CreateBP_Test;
  friend class test::VaultServicesTest_BEH_MAID_ModifyBPInfo_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetBPMessages_Test;
  friend class test::VaultServicesTest_BEH_MAID_AddBPMessages_Test;
  friend class test::VaultServicesTest_BEH_MAID_GetBPPresence_Test;
  friend class test::VaultServicesTest_BEH_MAID_AddBPPresence_Test;
  friend class test::PDVaultTest_FUNC_MAID_NET_StoreAndGetChunks_Test;
  void DiscardResult(const int&) {}
  bool ValidateSignedSize(const SignedSize &sz);
  bool ValidateStoreContract(const StoreContract &sc);
  bool ValidateAmendRequest(const AmendAccountRequest *request,
                            boost::uint64_t *account_delta,
                            std::string *pmid);
  bool ValidateIdAndRequest(const std::string &public_key,
                            const std::string &public_key_signature,
                            const std::string &request_signature,
                            const std::string &key,
                            const std::string &signing_id);
  bool ValidateRequestSignature(const std::string &public_key,
                                const std::string &public_key_signature,
                                const std::string &request_signature,
                                const std::string &key);
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
  bool LoadChunkLocal(const std::string &chunkname, std::string *content);
  bool DeleteChunkLocal(const std::string &chunkname);
  boost::uint64_t GetChunkSizeLocal(const std::string &chunkname);
  void FindCloseNodesCallback(const std::string &result,
                              std::vector<std::string> *close_nodes);
  void FinalisePayment(const std::string &chunk_name,
                       const std::string &pmid,
                       const boost::uint64_t &chunk_size,
                       const int &permission_result);
  void DoneAddToReferenceList(const StoreContract &store_contract,
                              const std::string &chunk_name);
  // This method returns immediately after the task is added to the thread pool.
  // The result of the amendment is discarded.
  void AmendRemoteAccount(const AmendAccountRequest::Amendment &amendment_type,
                          const boost::uint64_t &size,
                          const std::string &account_pmid,
                          const std::string &chunkname);
  // This method returns immediately after the task is added to the thread pool.
  // The result of the amendment is called back.
  void AmendRemoteAccount(const AmendAccountRequest::Amendment &amendment_type,
                          const boost::uint64_t &size,
                          const std::string &account_pmid,
                          const std::string &chunkname,
                          const VoidFuncOneInt &callback);
  void AddToRemoteRefList(const std::string &chunkname,
                          const StoreContract &contract,
                          const VoidFuncOneInt &callback);
  void RemoteVaultAbleToStore(const boost::uint64_t &size,
                              const std::string &account_pmid,
                              const VoidFuncOneInt &callback);
  void GetRemoteAccount(const std::string &account_pmid,
                        const std::vector<kad::Contact> &close_contacts);
  template <typename T>
  void ConstructGetInfoRequests(const kad::Contact &contact,
                                const std::string &key,
                                const T &partial_request,
                                std::vector<T> *requests);
  void AddToRemoteRefListCallback(const int &result,
                                  const std::string &chunkname);
  void GetRemoteAccountCallback(
      const int &result,
      const VaultAccountSet::VaultAccount &vault_account);
  void GetRemoteChunkInfo(const std::string &chunk_name,
                          const std::vector<kad::Contact> &close_contacts);
  void GetRemoteChunkInfoCallback(
      const int &result,
      const ChunkInfoMap::VaultChunkInfo &vault_chunk_info);
  void GetRemoteBufferPacket(
      const std::string &bp_name,
      const std::vector<kad::Contact> &close_contacts);
  void GetRemoteBufferPacketCallback(
      const int &result,
      const VaultBufferPacketMap::VaultBufferPacket &buffer_packet);
  // Returns whether the node is within "count" closest nodes (Kademlia closest)
  bool NodeWithinClosest(const std::string &peer_pmid,
                         const boost::uint16_t &count);
  const boost::uint8_t K_;
  const boost::uint16_t kUpperThreshold_;
  std::string pmid_, pmid_public_, pmid_private_, pmid_public_signature_;
  boost::shared_ptr<VaultChunkStore> vault_chunkstore_;
  VaultServiceLogic *vault_service_logic_;
  boost::int16_t transport_id_;
  boost::shared_ptr<KadOps> kad_ops_;
  typedef std::map<std::string, StoreContract> PrepsReceivedMap;
  PrepsReceivedMap prm_;
  AccountHandler ah_;
  RequestExpectationHandler request_expectation_handler_;
  AccountAmendmentHandler aah_;
  ChunkInfoHandler cih_;
  BufferPacketStore bps_;
  QThreadPool thread_pool_;
  boost::shared_ptr<base::PublicRoutingTableHandler> routing_table_;
  InfoSynchroniser info_synchroniser_;
};

class RegistrationService : public VaultRegistration {
 public:
  RegistrationService(
      boost::function<void(const VaultConfig&)> notifier);
  virtual void SetLocalVaultOwned(
      google::protobuf::RpcController* controller,
      const SetLocalVaultOwnedRequest *request,
      SetLocalVaultOwnedResponse *response,
      google::protobuf::Closure *done);
  virtual void LocalVaultOwned(
      google::protobuf::RpcController* controller,
      const LocalVaultOwnedRequest *request,
      LocalVaultOwnedResponse *response,
      google::protobuf::Closure *done);
  void ReplySetLocalVaultOwnedRequest(const bool &fail_to_start);
  void set_status(const VaultOwnershipStatus &status) { status_ = status; }
  VaultOwnershipStatus status() const { return status_; }
 private:
  RegistrationService(const RegistrationService&);
  RegistrationService &operator=(const RegistrationService&);
  boost::function<void(const VaultConfig&)> notifier_;
  VaultOwnershipStatus status_;
  IsOwnedPendingResponse pending_response_;
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_VAULTSERVICE_H_
