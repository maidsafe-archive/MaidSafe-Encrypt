/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  This class implements lengthy methods to be used by VaultService
* Version:      1.0
* Created:      2010-01-06-13.54.11
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

#ifndef MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_
#define MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/rpcprotocol/channel-api.h>
#include <maidsafe/protobuf/contact_info.pb.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "maidsafe/kadops.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace kad {
class KNode;
class Contact;
}  // namespace kad

namespace maidsafe_vault {

class VaultRpcs;

// This is used to hold the data required to perform a Kad lookup to get a
// vault's remote account holders, send each an AmendAccountRequest or
// AccountStatusRequest and assess the responses.
// T1 is request and T2 is response.
template <typename T1, typename T2>
struct RemoteOpData {
  struct RemoteOpHolder {
    explicit RemoteOpHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {
      controller->set_timeout(20);
    }
    std::string node_id;
    T2 response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  RemoteOpData(T1 req,
               kad::KadId kadkey,
               int found_local_res,
               VoidFuncOneInt cb,
               boost::int16_t trans_id)
      : request(req),
        kad_key(kadkey),
        found_local_result(found_local_res),
        callback(cb),
        transport_id(trans_id),
        mutex(),
        contacts(),
        data_holders(),
        success_count(0),
        failure_count(0),
        callback_done(false) {
    contacts.reserve(kad::K);
    data_holders.reserve(kad::K);
  }
  T1 request;
  kad::KadId kad_key;
  int found_local_result;
  VoidFuncOneInt callback;
  boost::int16_t transport_id;
  boost::mutex mutex;
  std::vector<kad::Contact> contacts;
  std::vector<RemoteOpHolder> data_holders;
  boost::uint16_t success_count;
  boost::uint16_t failure_count;
  bool callback_done;
};

typedef RemoteOpData<maidsafe::AddToReferenceListRequest,
    maidsafe::AddToReferenceListResponse> AddToReferenceListOpData;

typedef RemoteOpData<maidsafe::AmendAccountRequest,
    maidsafe::AmendAccountResponse> AmendRemoteAccountOpData;

typedef RemoteOpData<maidsafe::AccountStatusRequest,
    maidsafe::AccountStatusResponse> RemoteAccountStatusOpData;

struct CacheChunkData {
  CacheChunkData() : chunkname(),
                     kc(),
                     cb(),
                     request(),
                     response(),
                     controller() {}
  std::string chunkname;
  kad::ContactInfo kc;
  VoidFuncOneInt cb;
  maidsafe::CacheChunkRequest request;
  maidsafe::CacheChunkResponse response;
  rpcprotocol::Controller controller;
};

// This is used to hold the data required to send each close peer a
// GetAccountRequest or GetChunkInfoRequest and run the callback.  The contacts
// are called in order from first to last.
// T1 is request, T2 response and T3 callback.
template <typename T1, typename T2, typename T3>
struct GetInfoData {
  struct GetInfoOpHolder {
    GetInfoOpHolder(const kad::Contact &contct, const T1 &req)
        : contact(contct),
          request(req),
          response(),
          controller(new rpcprotocol::Controller) {}
    kad::Contact contact;
    T1 request;
    T2 response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  GetInfoData(T3 cb,
              const boost::int16_t &trans_id,
              const std::vector<kad::Contact> &contcts,
              const std::vector<T1> &reqs)
      : callback(cb),
        transport_id(trans_id),
        mutex(),
        callback_done(false),
        op_holders() {
    std::vector<kad::Contact>::const_iterator contacts_it = contcts.begin();
    typename std::vector<T1>::const_iterator requests_it = reqs.begin();
    while (contacts_it != contcts.end() && requests_it != reqs.end()) {
      op_holders.push_back(GetInfoOpHolder((*contacts_it), (*requests_it)));
      ++contacts_it;
      ++requests_it;
    }
  }
  T3 callback;
  boost::int16_t transport_id;
  boost::mutex mutex;
  bool callback_done;
  std::vector<GetInfoOpHolder> op_holders;
  boost::uint16_t index_of_last_request_sent;
  boost::uint16_t response_count;
};

typedef boost::function<void (const ReturnCode&,
    const VaultAccountSet::VaultAccount&)> VoidFuncIntAccount;

typedef boost::function<void (const ReturnCode&,
    const ChunkInfoMap::VaultChunkInfo&)> VoidFuncIntChunkInfo;

typedef boost::function<void (const ReturnCode&,
    const VaultBufferPacketMap::VaultBufferPacket&)> VoidFuncIntBufferPacket;

typedef GetInfoData<maidsafe::GetAccountRequest,
    maidsafe::GetAccountResponse, VoidFuncIntAccount> GetAccountData;

typedef GetInfoData<maidsafe::GetChunkInfoRequest,
    maidsafe::GetChunkInfoResponse, VoidFuncIntChunkInfo> GetChunkInfoData;

typedef GetInfoData<maidsafe::GetBufferPacketRequest,
    maidsafe::GetBufferPacketResponse, VoidFuncIntBufferPacket>
    GetBufferPacketData;

const size_t kParallelRequests(2);

class VaultServiceLogic {
 public:
  VaultServiceLogic(const boost::shared_ptr<VaultRpcs> &vault_rpcs,
                    const boost::shared_ptr<kad::KNode> &knode);
  virtual ~VaultServiceLogic() {}
  bool Init(const std::string &pmid,
            const std::string &pmid_public_key,
            const std::string &pmid_public_signature,
            const std::string &pmid_private);
  bool online();
  boost::shared_ptr<maidsafe::KadOps> kadops() { return kad_ops_; }
  void SetOnlineStatus(bool online);
  // Call which looks up Chunk Info holders and sends each an
  // AddToReferenceListRequest to add this vault's ID to ref list for chunkname.
  virtual void AddToRemoteRefList(
      const maidsafe::AddToReferenceListRequest &request,
      const int &found_local_result,
      const VoidFuncOneInt &callback,
      const boost::int16_t &transport_id);
  // Amend account of PMID requesting to be added to Watch List or Ref List.
  virtual void AmendRemoteAccount(const maidsafe::AmendAccountRequest &request,
                                  const int &found_local_result,
                                  const VoidFuncOneInt &callback,
                                  const boost::int16_t &transport_id);
  // Call which looks up account holders and sends each an
  // AccountStatusRequest to establish if the account owner has space to store
  void RemoteVaultAbleToStore(maidsafe::AccountStatusRequest request,
                              const int &found_local_result,
                              const VoidFuncOneInt &callback,
                              const boost::int16_t &transport_id);
  void CacheChunk(const std::string &chunkname,
                  const std::string &chunkcontent,
                  const kad::ContactInfo &cacher,
                  VoidFuncOneInt callback,
                  const boost::int16_t &transport_id);
  void GetAccount(const std::vector<kad::Contact> &close_contacts,
                  const std::vector<maidsafe::GetAccountRequest> &requests,
                  VoidFuncIntAccount callback,
                  const boost::int16_t &transport_id);
  void GetChunkInfo(const std::vector<kad::Contact> &close_contacts,
                    const std::vector<maidsafe::GetChunkInfoRequest> &requests,
                    VoidFuncIntChunkInfo callback,
                    const boost::int16_t &transport_id);
  void GetBufferPacket(const std::vector<kad::Contact> &close_contacts,
      const std::vector<maidsafe::GetBufferPacketRequest> &requests,
      VoidFuncIntBufferPacket callback,
      const boost::int16_t &transport_id);
 private:
  VaultServiceLogic(const VaultServiceLogic&);
  VaultServiceLogic &operator=(const VaultServiceLogic&);
  FRIEND_TEST(VaultServiceLogicTest, BEH_MAID_VSL_FindKNodes);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_AddToRemoteRefList);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_AmendRemoteAccount);
  FRIEND_TEST(VaultServiceLogicTest, FUNC_MAID_VSL_RemoteVaultAbleToStore);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_AssessAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_CreateNewAmendment);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_CreateNewWithExpecteds);
  FRIEND_TEST(AccountAmendmentHandlerTest, BEH_MAID_AAH_ProcessRequest);
  FRIEND_TEST(MockVaultServicesTest, BEH_MAID_ServicesAmendAccount);
  friend class MockVsl;
  friend class MockVaultServicesTest;
  // First callback method in e.g. AmendRemoteAccount operation.  Called once by
  // knode_->FindKNodes (when finding account holders' details).  T is
  // AmendRemoteAccountOpData or RemoteAccountStatusOpData.
  template <typename T>
  void RemoteOpStageTwo(boost::shared_ptr<T> data,
                        const std::string &find_nodes_response);
  // Specialisations for sending appropriate RPCs
  template <typename T>
  void SendRpcs(boost::shared_ptr<T> data);
  // Specialisations for removing contact of operation subject from vector
  template<typename T>
  bool RemoveSubjectContact(boost::shared_ptr<T> data);
  // Second callback method in e.g. AmendRemoteAccount operation.  Called
  // repeatedly by each RPC response.  index indicates the position in data's
  // internal vectors of the respondent.
  template <typename T>
  void RemoteOpStageThree(boost::uint16_t index, boost::shared_ptr<T> data);
  // Specialisations defining appropriate success conditions
  template <typename T>
  void AssessResult(const ReturnCode &result, boost::shared_ptr<T> data);
  void CacheChunkCallback(boost::shared_ptr<CacheChunkData> data);
  template <typename T>
  void GetInfoCallback(const boost::uint16_t &index, boost::shared_ptr<T> data);
  void SendInfoRpc(const boost::uint16_t &index,
                   boost::shared_ptr<GetAccountData> data);
  void SendInfoRpc(const boost::uint16_t &index,
                   boost::shared_ptr<GetChunkInfoData> data);
  void SendInfoRpc(const boost::uint16_t &index,
                   boost::shared_ptr<GetBufferPacketData> data);
  // Returns a signature for validation by recipient of RPC
  std::string GetSignedRequest(const std::string &name,
                               const std::string &recipient_id);

  boost::shared_ptr<VaultRpcs> vault_rpcs_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<maidsafe::KadOps> kad_ops_;
  kad::Contact our_details_;
  std::string pmid_, pmid_public_key_, pmid_public_signature_, pmid_private_;
  bool online_;
  boost::mutex online_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTSERVICELOGIC_H_
