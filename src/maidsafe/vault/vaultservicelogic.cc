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

#include "maidsafe/vault/vaultservicelogic.h"

#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/online.h>

#include <algorithm>
#include <list>

#include "maidsafe/maidsafevalidator.h"
#include "maidsafe/vault/vaultrpc.h"

namespace maidsafe_vault {

VaultServiceLogic::VaultServiceLogic(
    const boost::shared_ptr<VaultRpcs> &vault_rpcs,
    const boost::shared_ptr<kad::KNode> &knode)
        : vault_rpcs_(vault_rpcs),
          knode_(knode),
          kad_ops_(new maidsafe::KadOps(knode)),
          our_details_(),
          pmid_(),
          pmid_public_key_(),
          pmid_public_signature_(),
          pmid_private_(),
          online_(false),
          online_mutex_() {
  base::OnlineController::instance()->RegisterObserver(0, boost::bind(
      &VaultServiceLogic::SetOnlineStatus, this, _1));
}

bool VaultServiceLogic::Init(const std::string &pmid,
                             const std::string &pmid_public_key,
                             const std::string &pmid_public_signature,
                             const std::string &pmid_private) {
  if (knode_.get() == NULL)
    return false;
  pmid_ = pmid;
  pmid_public_key_ = pmid_public_key;
  pmid_public_signature_ = pmid_public_signature;
  pmid_private_ = pmid_private;
  kad::Contact our_details(knode_->contact_info());
  our_details_ = our_details;
  SetOnlineStatus(true);
  return true;
}

bool VaultServiceLogic::online() {
  boost::mutex::scoped_lock lock(online_mutex_);
  return online_;
}

void VaultServiceLogic::SetOnlineStatus(bool online) {
  boost::mutex::scoped_lock lock(online_mutex_);
  online_ = online;
}

void VaultServiceLogic::AddToRemoteRefList(
    const maidsafe::AddToReferenceListRequest &request,
    const int &found_local_result,
    const VoidFuncOneInt &callback,
    const boost::int16_t &transport_id) {
// printf("1. Vault %s - contacts size: %u\n", HexSubstr(pmid_).c_str(),
//         (*base::PDRoutingTable::getInstance())[base::itos(port_)]->size());
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefList (%s), offline.\n",
           HexSubstr(pmid_).c_str());
#endif
    callback(kVaultOffline);
    return;
  }
  boost::shared_ptr<AddToReferenceListOpData> data(new AddToReferenceListOpData(
      request, request.chunkname(), found_local_result, callback,
      transport_id));
  kad_ops_->FindCloseNodes(request.chunkname(), boost::bind(
      static_cast< void(VaultServiceLogic::*)
          (boost::shared_ptr<AddToReferenceListOpData>, const std::string &) >
          (&VaultServiceLogic::RemoteOpStageTwo), this, data, _1));
}

void VaultServiceLogic::AmendRemoteAccount(
    const maidsafe::AmendAccountRequest &request,
    const int &found_local_result,
    const VoidFuncOneInt &callback,
    const boost::int16_t &transport_id) {
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccount (%s), offline.\n",
           HexSubstr(pmid_).c_str());
#endif
    callback(kVaultOffline);
    return;
  }
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name(co.Hash(request.account_pmid() + kAccount, "",
      crypto::STRING_STRING, false));
  boost::shared_ptr<AmendRemoteAccountOpData> data(new AmendRemoteAccountOpData(
      request, account_name, found_local_result, callback, transport_id));
  kad_ops_->FindCloseNodes(account_name, boost::bind(
      static_cast< void(VaultServiceLogic::*)
          (boost::shared_ptr<AmendRemoteAccountOpData>, const std::string &) >
          (&VaultServiceLogic::RemoteOpStageTwo), this, data, _1));
}

void VaultServiceLogic::RemoteVaultAbleToStore(
    maidsafe::AccountStatusRequest request,
    const int &found_local_result,
    const VoidFuncOneInt &callback,
    const boost::int16_t &transport_id) {
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::RemoteVaultAbleToStore (%s), offline.\n",
           HexSubstr(pmid_).c_str());
#endif
    callback(kVaultOffline);
    return;
  }
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name(co.Hash(request.account_pmid() + kAccount, "",
      crypto::STRING_STRING, false));
  boost::shared_ptr<RemoteAccountStatusOpData>
      data(new RemoteAccountStatusOpData(request, account_name,
          found_local_result, callback, transport_id));
  kad_ops_->FindCloseNodes(account_name, boost::bind(
      static_cast< void(VaultServiceLogic::*)
          (boost::shared_ptr<RemoteAccountStatusOpData>, const std::string &) >
          (&VaultServiceLogic::RemoteOpStageTwo), this, data, _1));
}

template <typename T>
void VaultServiceLogic::RemoteOpStageTwo(
    boost::shared_ptr<T> data,
    const std::string &find_nodes_response) {
  // Handle result of Kademlia FindCloseNodes
  boost::mutex mutex;
  boost::condition_variable cv;
  maidsafe::ReturnCode result(maidsafe::kFindNodesError);
  kad_ops_->HandleFindCloseNodesResponse(find_nodes_response,
                                         data->kad_key, &data->contacts,
                                         &mutex, &cv, &result);
  if (result != maidsafe::kSuccess) {
#ifdef DEBUG
    printf("In VSL::RemoteOpStageTwo for %s (%s), Kad lookup failed -- "
           "error %i\n", typeid(data).name(), HexSubstr(pmid_).c_str(), result);
#endif
    switch (result) {
      case maidsafe::kFindNodesError:
      case maidsafe::kFindNodesParseError:
        data->callback(kVaultServiceFindNodesError);
        break;
      case maidsafe::kFindNodesFailure:
        data->callback(kVaultServiceFindNodesFailure);
        break;
      default:
        data->callback(kVaultServiceError);
    }
    return;
  }

#ifdef DEBUG
//  printf("\nIn VSL::RemoteOpStageTwo (%s) - %s\n", HexSubstr(pmid_).c_str(),
//         typeid(data).name());
//  for (size_t i = 0; i < data->contacts.size(); ++i) {
//    printf("In VSL::RemoteOpStageTwo (%s), contact #%d is %s.\n",
//           HexSubstr(pmid_).c_str(), i,
//           HexSubstr(data->contacts[i].node_id()).c_str());
//  }
#endif

  size_t less_contacts(0);

  // ensure account holder != account subject
  if (RemoveSubjectContact(data))
    ++less_contacts;

  bool within_k_closest = maidsafe::ContactWithinClosest(data->kad_key,
                                                         our_details_,
                                                         data->contacts);
  if (within_k_closest)
    ++less_contacts;

  if (data->contacts.size() + less_contacts < size_t(kKadUpperThreshold)) {
#ifdef DEBUG
    printf("In VSL::RemoteOpStageTwo for %s (%s), Kad lookup failed to find "
           "%u nodes; found %u nodes.\n", typeid(data).name(),
           HexSubstr(pmid_).c_str(), kKadUpperThreshold, data->contacts.size());
#endif
    data->callback(kVaultServiceFindNodesTooFew);
    return;
  }

  if (within_k_closest) {
    while (data->contacts.size() + less_contacts > kad::K)
      data->contacts.pop_back();  // only need K-x closest now
    // We've already queried/amended the account if we happen to hold it.
    if (data->found_local_result == kSuccess)
      ++data->success_count;
    else
      ++data->failure_count;
  } else if (data->found_local_result == kSuccess) {
    // We found the account locally, but shouldn't even have it!
    // TODO(Team#) trigger transfer of account data to closer node
  }

  // Set up holders for forthcoming individual RPCs
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    typename T::RemoteOpHolder holder(data->contacts.at(i).node_id());
    data->data_holders.push_back(holder);
  }

  SendRpcs(data);
}

template<>
bool VaultServiceLogic::RemoveSubjectContact(
    boost::shared_ptr<AddToReferenceListOpData>) {
  return false;
}

template<typename T>
bool VaultServiceLogic::RemoveSubjectContact(boost::shared_ptr<T> data) {
  return maidsafe::RemoveKadContact(data->request.account_pmid(),
                                    &data->contacts);
}

template<>
void VaultServiceLogic::SendRpcs(
    boost::shared_ptr<AddToReferenceListOpData> data) {
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    data->request.set_request_signature(GetSignedRequest(data->kad_key,
        data->contacts.at(j).node_id()));
    google::protobuf::Closure* done = google::protobuf::NewCallback<
        VaultServiceLogic, boost::uint16_t,
        boost::shared_ptr<AddToReferenceListOpData> > (this,
        &VaultServiceLogic::RemoteOpStageThree, j, data);
    vault_rpcs_->AddToReferenceList(data->contacts.at(j),
        kad_ops_->AddressIsLocal(data->contacts.at(j)), data->transport_id,
        &data->request, &data->data_holders.at(j).response,
        data->data_holders.at(j).controller.get(), done);
  }
}

template<>
void VaultServiceLogic::SendRpcs(
    boost::shared_ptr<AmendRemoteAccountOpData> data) {
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* done = google::protobuf::NewCallback<
        VaultServiceLogic, boost::uint16_t,
        boost::shared_ptr<AmendRemoteAccountOpData> > (this,
        &VaultServiceLogic::RemoteOpStageThree, j, data);
    vault_rpcs_->AmendAccount(data->contacts.at(j),
                              kad_ops_->AddressIsLocal(data->contacts.at(j)),
                              data->transport_id, &data->request,
                              &data->data_holders.at(j).response,
                              data->data_holders.at(j).controller.get(), done);
  }
}

template<>
void VaultServiceLogic::SendRpcs(
    boost::shared_ptr<RemoteAccountStatusOpData> data) {
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* done = google::protobuf::NewCallback<
        VaultServiceLogic, boost::uint16_t,
        boost::shared_ptr<RemoteAccountStatusOpData> > (this,
        &VaultServiceLogic::RemoteOpStageThree, j, data);
    vault_rpcs_->AccountStatus(data->contacts.at(j),
                               kad_ops_->AddressIsLocal(data->contacts.at(j)),
                               data->transport_id, &data->request,
                               &data->data_holders.at(j).response,
                               data->data_holders.at(j).controller.get(), done);
  }
}

template <typename T>
void VaultServiceLogic::RemoteOpStageThree(boost::uint16_t index,
                                           boost::shared_ptr<T> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  typename T::RemoteOpHolder *holder = &data->data_holders.at(index);
  ReturnCode result(kSuccess);
  if (!holder->response.IsInitialized()) {
#ifdef DEBUG
    printf("In VSL::RemoteOpStageThree for %s (%s), response %u from %s "
           "is uninitialised.\n", typeid(data).name(), HexSubstr(pmid_).c_str(),
           index, HexSubstr(holder->node_id).c_str());
#endif
    result = kRemoteOpResponseUninitialised;
  }

  if (result == kSuccess && holder->response.result() != kAck) {
#ifdef DEBUG
    printf("In VSL::RemoteOpStageThree for %s (%s), response %u from %s "
           "is negative (%i).\n", typeid(data).name(), HexSubstr(pmid_).c_str(),
           index, HexSubstr(holder->node_id).c_str(),
           holder->response.result());
#endif
    result = kRemoteOpResponseFailed;
  }

  if (result == kSuccess && holder->response.pmid() != holder->node_id) {
#ifdef DEBUG
    printf("In VSL::RemoteOpStageThree for %s (%s), response %u from %s "
           "has PMID %s.\n", typeid(data).name(), HexSubstr(pmid_).c_str(),
           index, HexSubstr(holder->node_id).c_str(),
           HexSubstr(holder->response.pmid()).c_str());
#endif
    result = kRemoteOpResponseError;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder->node_id's A/C holders
  }

  if (result == kSuccess)
    ++data->success_count;
  else
    ++data->failure_count;
  AssessResult(result, data);
}

template<typename T>
void VaultServiceLogic::AssessResult(const ReturnCode &result,
                                     boost::shared_ptr<T> data) {
  if (data->success_count >= kKadUpperThreshold ||
      data->failure_count > data->data_holders.size() - kKadUpperThreshold) {
    data->callback(result);
    data->callback_done = true;
  }
}

template<>
void VaultServiceLogic::AssessResult(
    const ReturnCode &result,
    boost::shared_ptr<RemoteAccountStatusOpData> data) {
  if (data->success_count - data->failure_count >= kKadLowerThreshold ||
      data->failure_count > data->data_holders.size() - kKadLowerThreshold) {
    data->callback(result);
    data->callback_done = true;
  }
}

void VaultServiceLogic::CacheChunk(const std::string &chunkname,
                                   const std::string &chunkcontent,
                                   const kad::ContactInfo &cacher,
                                   VoidFuncOneInt callback,
                                   const boost::int16_t &transport_id) {
  boost::shared_ptr<CacheChunkData> data(new CacheChunkData());
  data->chunkname = chunkname;
  data->kc = cacher;
  data->cb = callback;

  data->request.set_chunkname(chunkname);
  data->request.set_chunkcontent(chunkcontent);
  data->request.set_pmid(pmid_);
  data->request.set_public_key(pmid_public_key_);
  data->request.set_public_key_signature(pmid_public_signature_);

  maidsafe::MaidsafeValidator msv;
  std::string request_signature;
  std::list<std::string> parameters;
  parameters.push_back(pmid_public_signature_);
  parameters.push_back(chunkname);
  parameters.push_back(cacher.node_id());
  msv.CreateRequestSignature(pmid_private_, parameters, &request_signature);
  data->request.set_request_signature(request_signature);

  google::protobuf::Closure *done =
      google::protobuf::NewCallback<VaultServiceLogic,
                                    boost::shared_ptr<CacheChunkData> >
      (this, &VaultServiceLogic::CacheChunkCallback, data);
  vault_rpcs_->CacheChunk(cacher.ip(), cacher.port(), cacher.rv_ip(),
                          cacher.rv_port(), transport_id, &data->request,
                          &data->response, &data->controller, done);
}

void VaultServiceLogic::CacheChunkCallback(
    boost::shared_ptr<CacheChunkData> data) {
  if (!data->response.IsInitialized())
    data->cb(kCacheChunkResponseUninitialised);
  if (data->response.result() == kNack)
    data->cb(kCacheChunkResponseError);

  data->cb(kSuccess);
}

void VaultServiceLogic::GetAccount(
    const std::vector<kad::Contact> &close_contacts,
    const std::vector<maidsafe::GetAccountRequest> &requests,
    VoidFuncIntAccount callback,
    const boost::int16_t &transport_id) {
  boost::shared_ptr<GetAccountData> data(new GetAccountData(callback,
      transport_id, close_contacts, requests));
  if (data->op_holders.empty()) {
    callback(kRemoteOpResponseError, VaultAccountSet::VaultAccount());
    return;
  }
  const size_t kMaxParallel(std::min(data->op_holders.size(),
      kParallelRequests));
  for (boost::uint16_t i = 0; i < kMaxParallel; ++i)
    SendInfoRpc(i, data);
}

void VaultServiceLogic::GetChunkInfo(
    const std::vector<kad::Contact> &close_contacts,
    const std::vector<maidsafe::GetChunkInfoRequest> &requests,
    VoidFuncIntChunkInfo callback,
    const boost::int16_t &transport_id) {
  boost::shared_ptr<GetChunkInfoData> data(new GetChunkInfoData(callback,
      transport_id, close_contacts, requests));
  if (data->op_holders.empty()) {
    callback(kRemoteOpResponseError, ChunkInfoMap::VaultChunkInfo());
    return;
  }
  const size_t kMaxParallel(std::min(data->op_holders.size(),
      kParallelRequests));
  for (boost::uint16_t i = 0; i < kMaxParallel; ++i)
    SendInfoRpc(i, data);
}

template <>
void VaultServiceLogic::GetInfoCallback(
    const boost::uint16_t &index,
    boost::shared_ptr<GetAccountData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  maidsafe::GetAccountResponse &get_account_response =
      data->op_holders.at(index).response;
  if (get_account_response.IsInitialized() &&
      get_account_response.result() == kAck &&
      get_account_response.has_vault_account() &&
      get_account_response.vault_account().IsInitialized()) {  // Success
    data->callback_done = true;
    data->callback(kSuccess, get_account_response.vault_account());
  } else {
    if (data->response_count == data->op_holders.size()) {  // Overall failure
      data->callback_done = true;
      data->callback(kRemoteOpResponseFailed, VaultAccountSet::VaultAccount());
    } else {  // Try another contact
      boost::uint16_t next_index(data->index_of_last_request_sent + 1);
      size_t op_holders_size(data->op_holders.size());
      lock.unlock();
      if (next_index < op_holders_size)
        SendInfoRpc(next_index, data);
    }
  }
}

template <>
void VaultServiceLogic::GetInfoCallback(
    const boost::uint16_t &index,
    boost::shared_ptr<GetChunkInfoData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  ++data->response_count;
  maidsafe::GetChunkInfoResponse &get_chunk_info_response =
      data->op_holders.at(index).response;
  if (get_chunk_info_response.IsInitialized() &&
      get_chunk_info_response.result() == kAck &&
      get_chunk_info_response.has_vault_chunk_info() &&
      get_chunk_info_response.vault_chunk_info().IsInitialized()) {  // Success
    data->callback_done = true;
    data->callback(kSuccess,
        get_chunk_info_response.vault_chunk_info());
  } else {
    if (data->response_count == data->op_holders.size()) {  // Overall failure
      data->callback_done = true;
      data->callback(kRemoteOpResponseFailed, ChunkInfoMap::VaultChunkInfo());
    } else {  // Try another contact
      boost::uint16_t next_index(data->index_of_last_request_sent + 1);
      size_t op_holders_size(data->op_holders.size());
      lock.unlock();
      if (next_index < op_holders_size)
        SendInfoRpc(next_index, data);
    }
  }
}

void VaultServiceLogic::SendInfoRpc(const boost::uint16_t &index,
                                    boost::shared_ptr<GetAccountData> data) {
  GetAccountData::GetInfoOpHolder &holder = data->op_holders.at(index);
  {
    boost::mutex::scoped_lock lock(data->mutex);
    data->index_of_last_request_sent = index;
  }
  GetInfoCallback(index, data);
  google::protobuf::Closure* done = google::protobuf::NewCallback<
      VaultServiceLogic, const boost::uint16_t&,
      boost::shared_ptr<GetAccountData> >
      (this, &VaultServiceLogic::GetInfoCallback, index, data);
  vault_rpcs_->GetAccount(holder.contact,
      kad_ops_->AddressIsLocal(holder.contact), data->transport_id,
      &holder.request, &holder.response, holder.controller.get(), done);
}

void VaultServiceLogic::SendInfoRpc(const boost::uint16_t &index,
                                    boost::shared_ptr<GetChunkInfoData> data) {
  GetChunkInfoData::GetInfoOpHolder &holder = data->op_holders.at(index);
  {
    boost::mutex::scoped_lock lock(data->mutex);
    data->index_of_last_request_sent = index;
  }
  google::protobuf::Closure* done = google::protobuf::NewCallback<
      VaultServiceLogic, const boost::uint16_t&,
      boost::shared_ptr<GetChunkInfoData> >
      (this, &VaultServiceLogic::GetInfoCallback, index, data);
  vault_rpcs_->GetChunkInfo(holder.contact,
      kad_ops_->AddressIsLocal(holder.contact), data->transport_id,
      &holder.request, &holder.response, holder.controller.get(), done);
}

std::string VaultServiceLogic::GetSignedRequest(
    const std::string &name,
    const std::string &recipient_id) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  return co.AsymSign(co.Hash(pmid_public_signature_ + name + recipient_id, "",
      crypto::STRING_STRING, false), "", pmid_private_, crypto::STRING_STRING);
}

}  // namespace maidsafe_vault
