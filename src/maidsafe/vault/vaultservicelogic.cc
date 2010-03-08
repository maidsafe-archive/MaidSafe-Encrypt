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

int VaultServiceLogic::AddToRemoteRefList(
    const std::string &chunkname,
    const maidsafe::StoreContract &store_contract,
    const boost::int16_t &transport_id) {
// printf("1. Vault %s - contacts size: %u\n", HexSubstr(pmid_).c_str(),
//         (*base::PDRoutingTable::getInstance())[base::itos(port_)]->size());
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefList, offline %s\n",
           HexSubstr(pmid_).c_str());
#endif
    return kVaultOffline;
  }
  // Find the Chunk Info holders
  boost::shared_ptr<AddRefCallbackData> data(new AddRefCallbackData());
  int result = FindKNodes(chunkname, &data->contacts);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefList (%s), Kad lookup failed -- "
           "error %i\n", HexSubstr(pmid_).c_str(), result);
#endif
    return result;
  }
  if (data->contacts.size() < size_t(kKadStoreThreshold)) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefList (%s), Kad lookup failed to "
           "find %u nodes; found %u nodes.\n", HexSubstr(pmid_).c_str(),
           kKadStoreThreshold, data->contacts.size());
#endif
    return kVaultServiceFindNodesTooFew;
  }
  for (std::vector<kad::Contact>::iterator it = data->contacts.begin();
       it != data->contacts.end(); ++it) {
    if ((*it).node_id() == our_details_.node_id()) {
#ifdef DEBUG
//      printf("Vault %s listed as a ref holder to itself for chunk %s\n",
//             HexSubstr((*it).node_id()).c_str(),
//             HexSubstr(chunkname).c_str());
#endif
      data->contacts.erase(it);
      break;
    }
  }
#ifdef DEBUG
//  for (boost::uint16_t h = 0; h < data->contacts.size(); ++h) {
//    printf("After - Vault %s,  chunk %s,  info holder %i: %s\n",
//           HexSubstr(pmid_).c_str(),
//           HexSubstr(chunkname).c_str(), h,
//           HexSubstr(data->contacts.at(h).node_id()).c_str());
//  }
#endif
  // Set up holders for forthcoming individual RPCs
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    AddRefCallbackData::AddRefDataHolder holder(data->contacts.at(i).node_id());
    data->data_holders.push_back(holder);
  }
  // Send RPCs
  maidsafe::AddToReferenceListRequest request;
  request.set_chunkname(chunkname);
  maidsafe::StoreContract *sc = request.mutable_store_contract();
  *sc = store_contract;
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
#ifdef DEBUG
//    printf("In VSL::AddToRemoteRefList (%s), trying to add reference to "
//           "chunk %s to vault %s...\n", HexSubstr(pmid_).c_str(),
//           HexSubstr(chunkname).c_str(),
//           HexSubstr(data->contacts.at(j).node_id()).c_str());
#endif
    request.set_request_signature(GetSignedRequest(chunkname,
        data->contacts.at(j).node_id()));
    google::protobuf::Closure* done = google::protobuf::NewCallback(this,
        &VaultServiceLogic::AddToRemoteRefListCallback, j, data);
    vault_rpcs_->AddToReferenceList(data->contacts.at(j),
        kad_ops_->AddressIsLocal(data->contacts.at(j)), transport_id, &request,
                                 &data->data_holders.at(j).response,
                                 data->data_holders.at(j).controller.get(),
                                 done);
  }
  boost::mutex::scoped_lock lock(data->mutex);
  while (!data->callback_done)
    data->cv.wait(lock);
  return data->result;
}

void VaultServiceLogic::AddToRemoteRefListCallback(
    boost::uint16_t index,
    boost::shared_ptr<AddRefCallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  AddRefCallbackData::AddRefDataHolder *holder = &data->data_holders.at(index);
  int result(kSuccess);
  if (!holder->response.IsInitialized()) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefListCallback (%s), response %u "
           "is uninitialised.\n", HexSubstr(pmid_).c_str(), index);
#endif
    result = kAddToRefResponseUninitialised;
  }
  if (result == kSuccess && holder->response.result() != kAck) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefListCallback (%s), response %u "
           "has result %i.\n", HexSubstr(pmid_).c_str(), index,
           holder->response.result());
#endif
    result = kAddToRefResponseFailed;
  }
  if (result == kSuccess && holder->response.pmid() != holder->node_id) {
#ifdef DEBUG
    printf("In VSL::AddToRemoteRefListCallback (%s), response %u "
           "from %s has pmid %s.\n", HexSubstr(pmid_).c_str(), index,
           HexSubstr(holder->node_id).c_str(),
           HexSubstr(holder->response.pmid()).c_str());
#endif
    result = kAddToRefResponseError;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder->node_id's A/C holders
  }
  if (result == kSuccess)
    ++data->success_count;
  else
    ++data->failure_count;
  if (data->success_count >= kKadStoreThreshold ||
      data->failure_count > data->data_holders.size() - kKadStoreThreshold) {
    data->result = result;
    data->callback_done = true;
    data->cv.notify_one();
  }
}

int VaultServiceLogic::FindKNodes(const std::string &kad_key,
                                  std::vector<kad::Contact> *contacts) {
  if (contacts == NULL) {
#ifdef DEBUG
    printf("In VSL::FindKNodes, (%s) NULL pointer passed.\n",
           HexSubstr(pmid_).c_str());
#endif
    return kVaultServiceError;
  }
  contacts->clear();
  boost::mutex mutex;
  boost::condition_variable cv;
  ReturnCode result(kVaultServiceError);
  kad_ops_->FindCloseNodes(kad_key, boost::bind(
      &VaultServiceLogic::HandleFindKNodesResponse, this, _1, kad_key, contacts,
      &mutex, &cv, &result));
  boost::mutex::scoped_lock lock(mutex);
  while (result == kVaultServiceError)
    cv.wait(lock);
  return result;
}

void VaultServiceLogic::HandleFindKNodesResponse(
    const std::string &response,
    const std::string &kad_key,
    std::vector<kad::Contact> *contacts,
    boost::mutex *mutex,
    boost::condition_variable *cv,
    ReturnCode *result) {
  if (contacts == NULL || mutex == NULL || cv == NULL || result == NULL) {
#ifdef DEBUG
    printf("In VSL::HandleFindKNodesResponse, (%s) NULL pointer(s) passed.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(response)) {
#ifdef DEBUG
    printf("In VSL::HandleFindKNodesResponse, can't parse result.\n");
#endif
    boost::mutex::scoped_lock lock(*mutex);
    *result = kVaultServiceFindNodesError;
    cv->notify_one();
    return;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In VSL::HandleFindKNodesResponse, Kademlia operation failed.\n");
#endif
    boost::mutex::scoped_lock lock(*mutex);
    *result = kVaultServiceFindNodesFailure;
    cv->notify_one();
    return;
  }
  boost::mutex::scoped_lock lock(*mutex);
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }
  // Insert our own contact details if we are within the k closest.
  kad::InsertKadContact(kad_key, our_details_, contacts);
  if (contacts->size() > kad::K)
    contacts->pop_back();
  *result = kSuccess;
  cv->notify_one();
}

void VaultServiceLogic::AmendRemoteAccount(
    const maidsafe::AmendAccountRequest &request,
    const int &found_local_result,
    const VoidFuncOneInt &callback,
    const boost::int16_t &transport_id) {
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccount, offline %s\n",
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
      &VaultServiceLogic::AmendRemoteAccountStageTwo, this, data, _1));
}

void VaultServiceLogic::AmendRemoteAccountStageTwo(
    boost::shared_ptr<AmendRemoteAccountOpData> data,
    const std::string &find_nodes_response) {
  // Handle result of Kad FindKNodes
  boost::mutex mutex;
  boost::condition_variable cv;
  ReturnCode result(kVaultServiceError);
  HandleFindKNodesResponse(find_nodes_response, data->account_name,
      &data->contacts, &mutex, &cv, &result);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccountStageTwo (%s), Kad lookup failed -- "
           "error %i\n", HexSubstr(pmid_).c_str(), result);
#endif
    data->callback(result);
    return;
  }
  if (data->contacts.size() < size_t(kKadStoreThreshold)) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccountStageTwo (%s), Kad lookup failed to "
           "find %u nodes; found %u nodes.\n", HexSubstr(pmid_).c_str(),
           kKadStoreThreshold, data->contacts.size());
#endif
    data->callback(kVaultServiceFindNodesTooFew);
    return;
  }
  for (std::vector<kad::Contact>::iterator it = data->contacts.begin();
       it != data->contacts.end(); ++it) {
    if ((*it).node_id() == our_details_.node_id()) {
      // We've already tried to amend the account if we happen to hold it in
      // VaultService::AmendRemoteAccount function.
      if (data->found_local_result == kSuccess)
        ++data->success_count;
      else
        ++data->failure_count;
#ifdef DEBUG
//      printf("Vault %s listed as an account holder for PMID %s\n",
//             HexSubstr((*it).node_id()).c_str(),
//             HexSubstr(pmid_).c_str());
#endif
      data->contacts.erase(it);
      break;
    }
  }
  // Set up holders for forthcoming individual RPCs
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    AmendRemoteAccountOpData::AmendRemoteAccountOpHolder
        holder(data->contacts.at(i).node_id());
    data->data_holders.push_back(holder);
  }
  // Send RPCs
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* done = google::protobuf::NewCallback(this,
        &VaultServiceLogic::AmendRemoteAccountStageThree, j, data);
    vault_rpcs_->AmendAccount(data->contacts.at(j),
                              kad_ops_->AddressIsLocal(data->contacts.at(j)),
                              data->transport_id, &data->request,
                              &data->data_holders.at(j).response,
                              data->data_holders.at(j).controller.get(), done);
  }
}

void VaultServiceLogic::AmendRemoteAccountStageThree(
    boost::uint16_t index,
    boost::shared_ptr<AmendRemoteAccountOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  AmendRemoteAccountOpData::AmendRemoteAccountOpHolder
      *holder = &data->data_holders.at(index);
  ReturnCode result(kSuccess);
  if (!holder->response.IsInitialized()) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccountStageThree (%s), response %u from %s "
           "is uninitialised.\n", HexSubstr(pmid_).c_str(), index,
           HexSubstr(holder->node_id).c_str());
#endif
    result = kAmendAccountResponseUninitialised;
  }
  if (result == kSuccess && holder->response.result() != kAck) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccountStageThree (%s), response %u from %s "
           "is negative (%i).\n", HexSubstr(pmid_).c_str(), index,
           HexSubstr(holder->node_id).c_str(), holder->response.result());
#endif
    result = kAmendAccountResponseFailed;
  }
  if (result == kSuccess && holder->response.pmid() != holder->node_id) {
#ifdef DEBUG
    printf("In VSL::AmendRemoteAccountStageThree (%s), response %u from %s "
           "has PMID %s.\n", HexSubstr(pmid_).c_str(), index,
           HexSubstr(holder->node_id).c_str(),
           HexSubstr(holder->response.pmid()).c_str());
#endif
    result = kAmendAccountResponseError;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder->node_id's A/C holders
  }
  if (result == kSuccess)
    ++data->success_count;
  else
    ++data->failure_count;
  if (data->success_count >= kKadStoreThreshold ||
      data->failure_count > data->data_holders.size() - kKadStoreThreshold) {
    data->callback(result);
    data->callback_done = true;
  }
}

int VaultServiceLogic::RemoteVaultAbleToStore(
    maidsafe::AccountStatusRequest request,
    const boost::int16_t &transport_id) {
  if (!online()) {
#ifdef DEBUG
    printf("In VSL::RemoteVaultAbleToStore, offline %s\n",
           HexSubstr(pmid_).c_str());
#endif
    return kVaultOffline;
  }
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name(co.Hash(request.account_pmid() + kAccount, "",
      crypto::STRING_STRING, false));
  boost::shared_ptr<AccountStatusCallbackData>
      data(new AccountStatusCallbackData(account_name));
  int result = FindKNodes(account_name, &data->contacts);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In VSL::RemoteVaultAbleToStore (%s), Kad lookup failed -- "
           "error %i\n", HexSubstr(pmid_).c_str(), result);
#endif
    return result;
  }
  if (data->contacts.size() < size_t(kKadTrustThreshold)) {
#ifdef DEBUG
    printf("In VSL::RemoteVaultAbleToStore (%s), Kad lookup failed to "
           "find %i nodes; found %u nodes.\n", HexSubstr(pmid_).c_str(),
           kKadTrustThreshold, data->contacts.size());
#endif
    return kVaultServiceFindNodesTooFew;
  }
  for (std::vector<kad::Contact>::iterator it = data->contacts.begin();
       it != data->contacts.end(); ++it) {
    if ((*it).node_id() == our_details_.node_id()) {
      // TODO(Fraser#5#): 2010-01-11 - Query own account handler to get result
      // in VaultService::RemoteVaultAbleToStore and pass result through to here
#ifdef DEBUG
//      printf("Vault %s listed as an account holder for PMID %s\n",
//             HexSubstr((*it).node_id()).c_str(),
//             HexSubstr(pmid_).c_str());
#endif
      data->contacts.erase(it);
      break;
    }
  }
  // Set up holders for forthcoming individual RPCs
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    AccountStatusCallbackData::AccountStatusHolder
        holder(data->contacts.at(i).node_id());
    data->data_holders.push_back(holder);
  }
  // Send RPCs
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* done = google::protobuf::NewCallback(this,
        &VaultServiceLogic::AccountStatusCallback, j, data);
    vault_rpcs_->AccountStatus(data->contacts.at(j),
        kad_ops_->AddressIsLocal(data->contacts.at(j)), transport_id, &request,
                                 &data->data_holders.at(j).response,
                                 data->data_holders.at(j).controller.get(),
                                 done);
  }
  boost::mutex::scoped_lock lock(data->mutex);
  while (!data->callback_done)
    data->cv.wait(lock);
  return data->result;
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

void VaultServiceLogic::AccountStatusCallback(
    boost::uint16_t index,
    boost::shared_ptr<AccountStatusCallbackData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->callback_done)
    return;
  AccountStatusCallbackData::AccountStatusHolder
      *holder = &data->data_holders.at(index);
  int result(kSuccess);
  if (!holder->response.IsInitialized()) {
#ifdef DEBUG
    printf("In VSL::AccountStatusCallback (%s), response %u "
           "is uninitialised.\n", HexSubstr(pmid_).c_str(), index);
#endif
    result = kAccountStatusResponseUninitialised;
  }
  if (result == kSuccess && holder->response.result() != kAck) {
#ifdef DEBUG
    printf("In VSL::AccountStatusCallback (%s), response %u "
           "has result %i.\n", HexSubstr(pmid_).c_str(), index,
           holder->response.result());
#endif
    result = kAccountStatusResponseFailed;
  }
  if (result == kSuccess && holder->response.pmid() != holder->node_id) {
#ifdef DEBUG
    printf("In VSL::AccountStatusCallback (%s), response %u "
           "from %s has pmid %s.\n", HexSubstr(pmid_).c_str(), index,
           HexSubstr(holder->node_id).c_str(),
           HexSubstr(holder->response.pmid()).c_str());
#endif
    result = kAccountStatusResponseError;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder->node_id's A/C holders
  }
  if (result == kSuccess)
    ++data->success_count;
  else
    ++data->failure_count;
  if (data->success_count - data->failure_count >= kKadTrustThreshold ||
      data->failure_count > data->data_holders.size() - kKadTrustThreshold) {
    data->result = result;
    data->callback_done = true;
    data->cv.notify_one();
  }
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
