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
* Author:       Team maidsafe
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

#include "maidsafe/vault/vaultservice.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/routingtable.h>
#include <maidsafe/transportudt.h>

#include <list>

#include "maidsafe/maidsafe.h"
#include "maidsafe/maidsafevalidator.h"
#include "maidsafe/vaultbufferpackethandler.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultservicelogic.h"

namespace maidsafe_vault {

void vsvc_dummy_callback(const std::string &result) {
#ifdef DEBUG
  kad::StoreResponse result_msg;
  if (!result_msg.ParseFromString(result))
    printf("Can't parse store result.\n");
//  printf("%s\n", result_msg.DebugString().c_str());
  if (result_msg.result() != kad::kRpcResultSuccess)
    printf("Storing chunk reference failed.\n");
//  else
//    printf("Storing chunk reference succeeded.\n");
#endif
}

void int_dummy_callback(const int &result) {
#ifdef DEBUG
  if (result != 0)
    printf("int_dummy_callback: something failed (%i).\n", result);
#endif
}

template<>
void RemoteTask<maidsafe::AmendAccountRequest>::run() {
  vault_service_logic_->AmendRemoteAccount(request_, found_local_result_,
                                           callback_, transport_id_);
}

template <>
void RemoteTask<maidsafe::AccountStatusRequest>::run() {
  vault_service_logic_->RemoteVaultAbleToStore(request_, found_local_result_,
                                               callback_, transport_id_);
}

template <>
void RemoteTask<maidsafe::AddToReferenceListRequest>::run() {
  vault_service_logic_->AddToRemoteRefList(request_, found_local_result_,
                                           callback_, transport_id_);
}

void SendCachableChunkTask::run() {
  if (vault_service_logic_ != NULL)
    vault_service_logic_->CacheChunk(chunkname_, chunkcontent_, cacher_,
                                     callback_, transport_id_);
}

VaultService::VaultService(const std::string &pmid_public,
                           const std::string &pmid_private,
                           const std::string &pmid_public_signature,
                           VaultChunkStore *vault_chunkstore,
                           kad::KNode *knode,
                           VaultServiceLogic *vault_service_logic,
                           const boost::int16_t &transport_id)
    : pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      pmid_public_signature_(pmid_public_signature),
      pmid_(),
      vault_chunkstore_(vault_chunkstore),
      knode_(knode),
      vault_service_logic_(vault_service_logic),
      transport_id_(transport_id),
      prm_(),
      ah_(true),
      aah_(&ah_, vault_service_logic_),
      cih_(true),
      thread_pool_() {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  pmid_ = co.Hash(pmid_public_ + pmid_public_signature_, "",
                  crypto::STRING_STRING, false);
  thread_pool_.setMaxThreadCount(1);
}

void VaultService::AddStartupSyncData(
    const maidsafe::GetSyncDataResponse &get_sync_data_response) {
  if (!get_sync_data_response.IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AddStartupSyncData(%s), response is not "
           "initialized.\n", HexSubstr(pmid_).c_str());
#endif
    ah_.set_started(true);
    cih_.set_started(true);
    return;
  }

  if (get_sync_data_response.result() != kAck) {
#ifdef DEBUG
    printf("In VaultService::AddStartupSyncData(%s), result is not kAck.\n",
           HexSubstr(pmid_).c_str());
#endif
    ah_.set_started(true);
    cih_.set_started(true);
    return;
  }

  if (get_sync_data_response.has_vault_account_set()) {
    ah_.GetSetFromPb(get_sync_data_response.vault_account_set());
  } else {
#ifdef DEBUG
    printf("In VaultService::AddStartupSyncData(%s), missing "
           "vault_account_set.\n", HexSubstr(pmid_).c_str());
#endif
    ah_.set_started(true);
  }

  if (get_sync_data_response.has_chunk_info_map()) {
    cih_.GetMapFromPb(get_sync_data_response.chunk_info_map());
  } else {
#ifdef DEBUG
    printf("In VaultService::AddStartupSyncData(%s), missing "
           "chunk_info_map.\n", HexSubstr(pmid_).c_str());
#endif
    cih_.set_started(true);
  }
}

void VaultService::StorePrep(google::protobuf::RpcController*,
                             const maidsafe::StorePrepRequest *request,
                             maidsafe::StorePrepResponse *response,
                             google::protobuf::Closure *done) {
  maidsafe::StoreContract *response_sc = response->mutable_store_contract();
  response_sc->set_pmid(pmid_);
  response_sc->set_public_key(pmid_public_);
  response_sc->set_public_key_signature(pmid_public_signature_);
  maidsafe::StoreContract::InnerContract *response_ic =
      response_sc->mutable_inner_contract();
  maidsafe::SignedSize *response_sz = response_ic->mutable_signed_size();
  const maidsafe::SignedSize &request_sz = request->signed_size();
  response_sz->set_data_size(request_sz.data_size());
  response_sz->set_pmid(request_sz.pmid());
  response_sz->set_public_key(request_sz.public_key());
  response_sz->set_public_key_signature(request_sz.public_key_signature());
  response_sz->set_signature(request_sz.signature());

  crypto::Crypto co;
  response_ic->set_result(kNack);
  std::string ser_response_ic;
  response_ic->SerializeToString(&ser_response_ic);
  response_sc->set_signature(co.AsymSign(ser_response_ic, "", pmid_private_,
                             crypto::STRING_STRING));
  std::string ser_response_sc;
  response_sc->SerializeToString(&ser_response_sc);
  response->set_response_signature(co.AsymSign(ser_response_sc, "",
                                   pmid_private_, crypto::STRING_STRING));

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), ", HexSubstr(pmid_).c_str());
    printf("request is not initialized.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate chunk name.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedSize(request_sz)) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), failed to validate signed size "
           "(chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  PrepsReceivedMap::iterator it = prm_.find(request->chunkname());
  if (it != prm_.end()) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), chunk name %s was in map.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request_sz.public_key(),
       request_sz.public_key_signature(), request->request_signature(),
       request->chunkname(), request_sz.pmid())) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), failed to validate signed request "
           "(chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  // Check we're not being asked to store ourselves as a chunk holder for
  // ourself.
  if (request_sz.pmid() == pmid_) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), trying to store in ourselves "
           "(chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  // TODO(Team#5#): check peer's available space

  if (Storable(request_sz.data_size()) != 0) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), not enough space for %s.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  response_ic->set_result(kAck);
  response_ic->SerializeToString(&ser_response_ic);
  response_sc->set_signature(co.AsymSign(ser_response_ic, "", pmid_private_,
                             crypto::STRING_STRING));
  response_sc->SerializeToString(&ser_response_sc);
  response->set_response_signature(co.AsymSign(ser_response_sc, "",
                                   pmid_private_, crypto::STRING_STRING));

  std::string peer_pmid(request_sz.pmid());
  std::pair<PrepsReceivedMap::iterator, bool> cp =
      prm_.insert(std::pair<std::string, maidsafe::StoreContract>(
      request->chunkname(), *response_sc));

  if (!cp.second) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%s), failed to insert prep for %s "
           "into map.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    response_ic->set_result(kNack);
    response_ic->SerializeToString(&ser_response_ic);
    response_sc->set_signature(co.AsymSign(ser_response_ic, "", pmid_private_,
                               crypto::STRING_STRING));
    response_sc->SerializeToString(&ser_response_sc);
    response->set_response_signature(co.AsymSign(ser_response_sc, "",
                                     pmid_private_, crypto::STRING_STRING));
    done->Run();
    return;
  }

  done->Run();
}

void VaultService::StoreChunk(google::protobuf::RpcController*,
                              const maidsafe::StoreChunkRequest *request,
                              maidsafe::StoreChunkResponse *response,
                              google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("Chunk name: %s\n", request->chunkname().c_str());
//  printf("Chunk content: %s\n", request->data().c_str());
//  printf("In VaultService::StoreChunk, Public Key: %s\n",
//    request->public_key().c_str());
//  printf("Signed Pub Key: %s\n", request->public_key_signature().c_str());
//  printf("Signed Request: %s\n", request->request_signature().c_str());

//  printf("In VaultService::StoreChunk (%i), Chunk name: %s\n",
//         knode_->host_port(), HexSubstr(request->chunkname()).c_str());
#endif
  // TODO(Fraser#5#): 2009-12-28 - if this fails more than kMinStoreRetries for
  //                               same chunkname & peer, delete from prm_?
  response->set_pmid(pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%s), failed to validate signed "
           "request (chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  PrepsReceivedMap::iterator it = prm_.find(request->chunkname());
  if (it == prm_.end()) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%s), chunk name (%s) wasn't in map - "
           "no prep.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  // TODO(Team#5#): Decide on which types of data should come through here

  if (!StoreChunkLocal(request->chunkname(), request->data())) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%s), failed to store chunk %s "
           "locally.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  AddToRemoteRefList(request->chunkname(), it->second);
  prm_.erase(request->chunkname());
  response->set_result(kAck);
  done->Run();
}

void VaultService::AddToWatchList(
    google::protobuf::RpcController*,
    const maidsafe::AddToWatchListRequest *request,
    maidsafe::AddToWatchListResponse *response,
    google::protobuf::Closure *done) {

  response->set_pmid(pmid_);
  response->set_upload_count(0);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%s), ", HexSubstr(pmid_).c_str());
    printf("request is not initialized.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate chunk name.\n");
#endif
    done->Run();
    return;
  }

  const maidsafe::SignedSize &sz = request->signed_size();

  if (!ValidateSignedSize(sz)) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%s), failed to validate signed "
           "size (chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(sz.public_key(),
                             sz.public_key_signature(),
                             request->request_signature(),
                             request->chunkname(),
                             sz.pmid())) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%s), failed to validate signed "
           "request (chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  int required_references, required_payments;
  if (0 != cih_.PrepareAddToWatchList(request->chunkname(), sz.pmid(),
                                      sz.data_size(), &required_references,
                                      &required_payments)) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%s), failed adding to waiting "
           "list for %s.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  response->set_upload_count(required_references);
  response->set_result(kAck);
  done->Run();

  if (required_payments > 0) {
    // amend account for watcher
    AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenInc,
                       required_payments * sz.data_size(), sz.pmid(),
                       request->chunkname(),
                       boost::bind(&VaultService::FinalisePayment, this,
                                   request->chunkname(), sz.pmid(),
                                   sz.data_size(), _1));
  } else {
    // verify storing permission
    RemoteVaultAbleToStore(sz.data_size(), sz.pmid(),
                           boost::bind(&VaultService::FinalisePayment, this,
                                       request->chunkname(), sz.pmid(),
                                       sz.data_size(), _1));
  }
}

void VaultService::FinalisePayment(const std::string &chunk_name,
                                   const std::string &pmid,
                                   const int &chunk_size,
                                   const int &permission_result) {
  if (permission_result != kSuccess) {
#ifdef DEBUG
    printf("In VaultService::FinalisePayment (%s), failed to obtain storing "
           "permission for client %s and chunk %s  -- result %i.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(pmid).c_str(),
           HexSubstr(chunk_name).c_str(), permission_result);
#endif
    std::list<std::string> creditors, references;
    cih_.ResetAddToWatchList(chunk_name, pmid, kReasonPaymentFailed, &creditors,
                             &references);
    for (std::list<std::string>::iterator it = creditors.begin();
         it != creditors.end(); ++it) {
      // amend account for remaining entry
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         chunk_size, *it, chunk_name);
    }

    for (std::list<std::string>::iterator it = references.begin();
         it != references.end(); ++it) {
      // TODO(Team#) delete ref packet and remote chunks
      // amend account for former chunk holder
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceGivenDec,
                         chunk_size, *it, chunk_name);
    }

    return;
  }

  cih_.SetPaymentsDone(chunk_name, pmid);
  std::string creditor;
  int refunds;
  if (cih_.TryCommitToWatchList(chunk_name, pmid, &creditor, &refunds)) {
    if (refunds > 0) {
      // amend account for watcher, in case he wasn't first after all
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         refunds * chunk_size, pmid, chunk_name);
    }
    if (!creditor.empty()) {
      // amend account for replaced entry
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         chunk_size, creditor, chunk_name);
    }
  } else {
#ifdef DEBUG
    printf("In VaultService::FinalisePayment (%s), couldn't commit to watch "
           "list yet (%s hasn't stored chunk %s).\n", HexSubstr(pmid_).c_str(),
           HexSubstr(pmid).c_str(), HexSubstr(chunk_name).c_str());
#endif
  }
}

void VaultService::RemoveFromWatchList(
    google::protobuf::RpcController*,
    const maidsafe::RemoveFromWatchListRequest *request,
    maidsafe::RemoveFromWatchListResponse *response,
    google::protobuf::Closure *done) {

  response->set_pmid(pmid_);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%s), request is not "
           "initialized.\n", HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(),
      request->chunkname(), request->pmid())) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%s), failed to validate "
           "signed request (chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  int chunk_size;
  std::list<std::string> creditors, references;
  if (0 != cih_.RemoveFromWatchList(request->chunkname(), request->pmid(),
                                    &chunk_size, &creditors, &references)) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%s), failed to remove %s "
           "from watch list for chunk %s.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->pmid()).c_str(),
           HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  response->set_result(kAck);
  done->Run();

  for (std::list<std::string>::iterator it = creditors.begin();
       it != creditors.end(); ++it) {
    // amend account for remaining entry
    AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                       chunk_size, *it, request->chunkname());
  }

  for (std::list<std::string>::iterator it = references.begin();
       it != references.end(); ++it) {
    // TODO(Steve#) delete remote chunk
    // amend account for former chunk holder
    AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceGivenDec,
                       chunk_size, *it, request->chunkname());
  }
}

void VaultService::AddToReferenceList(
    google::protobuf::RpcController*,
    const maidsafe::AddToReferenceListRequest *request,
    maidsafe::AddToReferenceListResponse *response,
    google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::AddToReferenceList (%i), Chunk name: %s, "
//         "PMID: %s\n", knode_->host_port(),
//         HexSubstr(request->chunkname()).c_str(),
//         base::EncodeToHex(request->pmid()).substr(0, 10).c_str());
#endif
  response->set_pmid(pmid_);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%s), request is not "
           "initialized.\n", HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  const maidsafe::StoreContract &store_contract = request->store_contract();
  if (!ValidateStoreContract(store_contract)) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%s), failed to validate store "
           "contract for chunk %s.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(store_contract.public_key(),
      store_contract.public_key_signature(), request->request_signature(),
      request->chunkname(), store_contract.pmid())) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%s), failed to validate "
           "signed request (chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
    done->Run();
    return;
  }

  int res = cih_.AddToReferenceList(request->chunkname(), store_contract.pmid(),
                     store_contract.inner_contract().signed_size().data_size());
  if (res != 0) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%s), failed to add %s to "
           "reference list for %s: %s.\n", HexSubstr(pmid_).c_str(),
           HexSubstr(store_contract.pmid()).c_str(),
           HexSubstr(request->chunkname()).c_str(),
           (res = kChunkInfoInvalidName) ? "no watchers" : "wrong size");
#endif
    done->Run();
    return;
  }

  response->set_result(kAck);
  done->Run();

  DoneAddToReferenceList(store_contract, request->chunkname());
}

void VaultService::DoneAddToReferenceList(
    const maidsafe::StoreContract &store_contract,
    const std::string &chunk_name) {
  int chunk_size(store_contract.inner_contract().signed_size().data_size());
  std::string client_pmid(store_contract.inner_contract().signed_size().pmid());

  // amend account for chunk holder (= sender)
  AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceGivenInc,
                     chunk_size, store_contract.pmid(), chunk_name);

  cih_.SetStoringDone(chunk_name, client_pmid);
  std::string creditor;
  int refunds;
  if (cih_.TryCommitToWatchList(chunk_name, client_pmid, &creditor, &refunds)) {
    if (refunds > 0) {
      // amend account for watcher, in case he wasn't first after all
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         refunds * chunk_size, client_pmid, chunk_name);
    }
    if (!creditor.empty()) {
      // amend account for replaced entry
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         chunk_size, creditor, chunk_name);
    }
  } else {
#ifdef DEBUG
    printf("In VaultService::DoneAddToReferenceList (%s), couldn't commit to "
           "watch list yet (%s hasn't paid for chunk %s).\n",
           HexSubstr(pmid_).c_str(), HexSubstr(client_pmid).c_str(),
           HexSubstr(chunk_name).c_str());
#endif
  }
}

void VaultService::GetChunkReferences(
    google::protobuf::RpcController*,
    const maidsafe::GetChunkReferencesRequest *request,
    maidsafe::GetChunkReferencesResponse *response,
    google::protobuf::Closure *done) {
  response->set_pmid(pmid_);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::GetChunkReferences (%s), request is not "
           "initialized.\n", HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  std::list<std::string> references;
  int result = cih_.GetActiveReferences(request->chunkname(), &references);
  if (result != kSuccess) {
#ifdef DEBUG
    if (result == kChunkInfoInvalidName) {
      printf("In VaultService::GetChunkReferences (%s), chunk info for %s "
             "does not exist.\n", HexSubstr(pmid_).c_str(),
             HexSubstr(request->chunkname()).c_str());
    } else if (result == kChunkInfoNoActiveWatchers) {
      printf("In VaultService::GetChunkReferences (%s), chunk info for %s "
             "has no active watchers.\n", HexSubstr(pmid_).c_str(),
             HexSubstr(request->chunkname()).c_str());
    }
#endif
    done->Run();
    return;
  }

  for (std::list<std::string>::iterator it = references.begin();
       it != references.end(); ++it) {
    response->add_references(*it);
  }

  response->set_result(kAck);
  done->Run();
}

void VaultService::AmendAccount(google::protobuf::RpcController*,
                                const maidsafe::AmendAccountRequest *request,
                                maidsafe::AmendAccountResponse *response,
                                google::protobuf::Closure *done) {
  response->set_pmid(pmid_);
  response->set_result(kNack);
  // Validate request and extract data
  boost::uint64_t account_delta;
  std::string pmid;
  if (!ValidateAmendRequest(request, &account_delta, &pmid)) {
#ifdef DEBUG
    printf("In VaultService::AmendAccount (%s), problem with request.\n",
           HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  /* printf("VaultService::AmendAccount - from %s to %s\n",
         HexSubstr(pmid).c_str(),
         HexSubstr(knode_->node_id()).c_str()); */
  if (ah_.HaveAccount(pmid) == kAccountNotFound) {
    if (request->amendment_type() ==
        maidsafe::AmendAccountRequest::kSpaceOffered) {
      if (ah_.AddAccount(pmid, account_delta) == 0) {
        response->set_result(kAck);
#ifdef DEBUG
//      printf("In VaultService::AmendAccount (%s), successfully created a new "
//               "account (%s) of size %llu.\n", HexSubstr(pmid_).c_str(),
//               HexSubstr(pmid).c_str(), account_delta);
#endif
      } else {
#ifdef DEBUG
        printf("In VaultService::AmendAccount (%s), failed adding account (%s)."
               "\n", HexSubstr(pmid_).c_str(), HexSubstr(pmid).c_str());
#endif
      }
    } else {
#ifdef DEBUG
      printf("In VaultService::AmendAccount (%s), account to amend (%s) does "
             "not exist.\n", HexSubstr(pmid_).c_str(), HexSubstr(pmid).c_str());
#endif
    }
  } else if (request->amendment_type() ==
             maidsafe::AmendAccountRequest::kSpaceOffered) {
    int result = ah_.AmendAccount(pmid, 1, account_delta, false);
    if (result == 0) {
      response->set_result(kAck);
    } else {
#ifdef DEBUG
      printf("In VaultService::AmendAccount (%s), failed amending space "
             "offered by %s (error %d).\n", HexSubstr(pmid_).c_str(),
             HexSubstr(pmid).c_str(), result);
#endif
    }
  } else {
    // aah_->ProcessRequest() calls done->Run();
    int result = aah_.ProcessRequest(request, response, done);
    if (result != 0) {
#ifdef DEBUG
      printf("In VaultService::AmendAccount (%s), failed amending account (%s) "
             "- error %i\n", HexSubstr(pmid_).c_str(), HexSubstr(pmid).c_str(),
             result);
#endif
    }
    return;
  }
  done->Run();
  return;
}

void VaultService::AccountStatus(google::protobuf::RpcController*,
                                 const maidsafe::AccountStatusRequest *request,
                                 maidsafe::AccountStatusResponse *response,
                                 google::protobuf::Closure *done) {
  response->set_pmid(pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AccountStatus (%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  boost::uint64_t space_offered(0), space_given(0), space_taken(0);
  int n = ah_.GetAccountInfo(request->account_pmid(), &space_offered,
                             &space_given, &space_taken);
  if (n != 0) {
#ifdef DEBUG
    printf("In VaultService::AccountStatus (%s), ", HexSubstr(pmid_).c_str());
    printf("don't have the account for %s.\n",
           HexSubstr(request->account_pmid()).c_str());
#endif
    done->Run();
    return;
  }

  if (request->has_space_requested()) {
    if (space_taken + request->space_requested() <= space_offered) {
      response->set_result(kAck);
    } else {
#ifdef DEBUG
      printf("In VaultService::AccountStatus (%s), ", HexSubstr(pmid_).c_str());
      printf("requested space (%s) not available (> %s).\n",
             base::itos_ull(request->space_requested()).c_str(),
             base::itos_ull(space_offered - space_taken).c_str());
#endif
    }
    done->Run();
  } else {
    response->set_result(kAck);
    if (!ValidateSignedRequest(request->public_key(),
        request->public_key_signature(), request->request_signature(),
        request->account_pmid() + kAccount, request->account_pmid())) {
  #ifdef DEBUG
      printf("In VaultService::AccountStatus (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate signed request.\n");
  #endif
      // TODO(Team#5#): return info that we consider "public" from the account
      done->Run();
      return;
    }

    response->set_space_offered(space_offered);
    response->set_space_given(space_given);
    response->set_space_taken(space_taken);
    done->Run();
  }
}

void VaultService::CheckChunk(google::protobuf::RpcController*,
                              const maidsafe::CheckChunkRequest *request,
                              maidsafe::CheckChunkResponse *response,
                              google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::CheckChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  if (HasChunkLocal(request->chunkname()))
    response->set_result(kAck);
  else
    response->set_result(kNack);
  done->Run();
}

void VaultService::GetChunk(google::protobuf::RpcController*,
                            const maidsafe::GetChunkRequest *request,
                            maidsafe::GetChunkResponse *response,
                            google::protobuf::Closure *done) {
#ifdef DEBUG
  // printf("In VaultService::GetChunk (%s)...\n", HexSubstr(pmid_).c_str());
#endif
  response->set_pmid(pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::Get (%s), request isn't initialised.\n",
           HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }
  std::string content;
  if (LoadChunkLocal(request->chunkname(), &content)) {
    response->set_result(kAck);
    response->set_content(content);
  } else {
#ifdef DEBUG
    printf("In VaultService::Get (%s), couldn't find chunk %s locally.\n",
           HexSubstr(pmid_).c_str(), HexSubstr(request->chunkname()).c_str());
#endif
  }
  done->Run();

  std::string chunkname = request->chunkname();
  std::string details;
  if (request->has_serialised_cacher_contact())
    details = request->serialised_cacher_contact();

  kad::ContactInfo kc;
  if (!details.empty() && kc.ParseFromString(details)) {
    SendCachableChunkTask *task = new SendCachableChunkTask(chunkname, content,
                                  kc, vault_service_logic_,
                                  &int_dummy_callback);
    thread_pool_.start(task);
  }
}

void VaultService::DeleteChunk(google::protobuf::RpcController*,
                               const maidsafe::DeleteChunkRequest *request,
                               maidsafe::DeleteChunkResponse *response,
                               google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::DeleteChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("request not initialised.\n");
#endif
    done->Run();
    return;
  }

  const maidsafe::SignedSize &sz = request->signed_size();

  if (!ValidateSignedSize(sz)) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate signed size.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate chunk name.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(sz.public_key(),
                             sz.public_key_signature(),
                             request->request_signature(),
                             request->chunkname(),
                             sz.pmid())) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  if (!HasChunkLocal(request->chunkname())) {
    response->set_result(kAck);
    done->Run();
    return;
  }

  if (sz.data_size() != GetChunkSizeLocal(request->chunkname())) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("invalid chunk size.\n");
#endif
    done->Run();
    return;
  }

  // TODO(Steve#) check request comes from ChunkInfo holder

  if (!DeleteChunkLocal(request->chunkname())) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to delete chunk.\n");
#endif
    done->Run();
    return;
  }

  response->set_result(kAck);
  done->Run();
}

void VaultService::ValidityCheck(google::protobuf::RpcController*,
                                 const maidsafe::ValidityCheckRequest *request,
                                 maidsafe::ValidityCheckResponse *response,
                                 google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::ValidityCheck (%i)\n", knode_->host_port());
#endif
  response->set_pmid(pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  std::string chunk_content;
  if (!LoadChunkLocal(request->chunkname(), &chunk_content)) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  // TODO(Fraser#5#): 2009-03-18 - We should probably do a self-check here and
  //                  return kNack if we fail and try and get another
  //                  uncorrupted copy.
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string hcontent = co.Hash(chunk_content + request->random_data(), "",
                                 crypto::STRING_STRING, false);
  response->set_result(kAck);
  response->set_hash_content(hcontent);
  done->Run();
}

void VaultService::SwapChunk(google::protobuf::RpcController*,
                             const maidsafe::SwapChunkRequest *request,
                             maidsafe::SwapChunkResponse *response,
                             google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::SwapChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    response->set_request_type(0);
    done->Run();
    return;
  }
  response->set_request_type(request->request_type());
  response->set_chunkname1(request->chunkname1());
  if (request->request_type() == 0) {
    // negotiate, Make request type constant layer
    if (HasChunkLocal(request->chunkname1())) {
      response->set_result(kNack);
      done->Run();
      return;
    }
    // Select a local chunk of a similar size +-10%
    // Use random chunk temporarily
    std::string chunkname2;
    std::string chunkcontent2;
    if (vault_chunkstore_->LoadRandomChunk(&chunkname2, &chunkcontent2) !=
        kSuccess) {
      response->set_result(kNack);
      done->Run();
      return;
    }
    response->set_chunkname2(chunkname2);
    response->set_size2(chunkcontent2.size());
  } else if (request->request_type() == 1) {
    // swap chunk
    if (request->has_chunkname2() && request->has_chunkcontent1()) {
      std::string key = request->chunkname1();
      if (!StoreChunkLocal(key, request->chunkcontent1())) {
        response->set_result(kNack);
        done->Run();
        return;
      }
//      StoreChunkReference(key);
      std::string chunkcontent2;
      if (!LoadChunkLocal(request->chunkname2(), &chunkcontent2)) {
        response->set_result(kNack);
        done->Run();
        return;
      }
      response->set_chunkname2(request->chunkname2());
      response->set_chunkcontent2(chunkcontent2);
    }
  } else {
      response->set_result(kNack);
      done->Run();
      return;
  }
  response->set_result(kAck);
  done->Run();
}

void VaultService::CacheChunk(google::protobuf::RpcController*,
                              const maidsafe::CacheChunkRequest *request,
                              maidsafe::CacheChunkResponse *response,
                              google::protobuf::Closure *done) {
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::CacheChunk(%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(),
      request->chunkname(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::CacheChunk(%s), request does not validate.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (vault_chunkstore_->CacheChunk(request->chunkname(),
      request->chunkcontent()) != kSuccess) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::CacheChunk(%s), failed to cache chunk.\n",
           HexSubstr(pmid_).c_str());
#endif
  }

  done->Run();
}

void VaultService::GetSyncData(google::protobuf::RpcController*,
                               const maidsafe::GetSyncDataRequest *request,
                               maidsafe::GetSyncDataResponse *response,
                               google::protobuf::Closure *done) {
  response->set_result(kNack);
  if (!request->IsInitialized()) {
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetSyncData(%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(), "",
      request->pmid())) {
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetSyncData(%s), request does not validate.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (!NodeWithinClosest(request->pmid(), kad::K)) {
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetSyncData(%s), requester (%s) not in local"
           "routing table's closest k nodes.\n", HexSubstr(pmid_).c_str(),
           HexSubstr(request->pmid()).c_str());
#endif
  } else {
    response->set_result(kAck);
    VaultAccountSet *vault_account_set = response->mutable_vault_account_set();
    *vault_account_set = ah_.PutSetToPb();
    ChunkInfoMap *chunk_info_map = response->mutable_chunk_info_map();
    *chunk_info_map = cih_.PutMapToPb();
    done->Run();
  }
}

void VaultService::GetAccount(google::protobuf::RpcController*,
                              const maidsafe::GetAccountRequest *request,
                              maidsafe::GetAccountResponse *response,
                              google::protobuf::Closure *done) {

}

void VaultService::GetChunkInfo(google::protobuf::RpcController*,
                                const maidsafe::GetChunkInfoRequest *request,
                                maidsafe::GetChunkInfoResponse *response,
                                google::protobuf::Closure *done) {

}

void VaultService::VaultStatus(google::protobuf::RpcController*,
                               const maidsafe::VaultStatusRequest *request,
                               maidsafe::VaultStatusResponse *response,
                               google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::VaultStatus (%i)\n", knode_->host_port());
#endif
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::VaultStatus (%s), request isn't initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }
  crypto::Crypto co;
  std::string decrypted_request = co.AsymDecrypt(request->encrypted_request(),
                                  "", pmid_private_, crypto::STRING_STRING);
  maidsafe::VaultCommunication vc;
  if (!vc.ParseFromString(decrypted_request)) {
    response->set_result(kNack);
#ifdef DEBUG
    printf("In VaultService::VaultStatus (%s), request didn't parse as a "
           "VaultCommunication.\n", HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  if (!vault_chunkstore_->is_initialised()) {
    response->set_result(kNack);
#ifdef DEBUG
    printf("In VaultService::VaultStatus (%s), chunkstore isn't initialised.\n",
           HexSubstr(pmid_).c_str());
#endif
    done->Run();
    return;
  }

  vc.set_chunkstore(vault_chunkstore_->ChunkStoreDir());
  vc.set_offered_space(vault_chunkstore_->available_space());
  vc.set_free_space(vault_chunkstore_->FreeSpace());

  std::string serialised_vc;
  vc.SerializeToString(&serialised_vc);
  response->set_encrypted_response(co.AsymEncrypt(serialised_vc, "",
            pmid_public_, crypto::STRING_STRING));
  response->set_result(kAck);
  done->Run();
}

// BP Services
void VaultService::CreateBP(google::protobuf::RpcController*,
                            const maidsafe::CreateBPRequest *request,
                            maidsafe::CreateBPResponse *response,
                            google::protobuf::Closure *done) {
  response->set_pmid_id(pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::CreateBP (%s), request is not initialized.\n",
             HexSubstr(pmid_).c_str());
#endif
    return;
  }

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (!co.AsymCheckSig(request->public_key(), request->signed_public_key(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::CreateBP (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate signed public key.\n");
    }
#endif
    return;
  }

  if (!co.AsymCheckSig(co.Hash(request->public_key() +
      request->signed_public_key() + request->bufferpacket_name(), "",
      crypto::STRING_STRING, false), request->signed_request(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::CreateBP (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate signed request.\n");
    }
#endif
    return;
  }

  if (!StoreChunkLocal(request->bufferpacket_name(), request->data())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::CreateBP (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to store chunk locally.\n");
    }
#endif
    return;
  }

  if (knode_ != NULL) {
    kad::SignedValue sig_value;
    sig_value.set_value(pmid_);
    co.set_hash_algorithm(crypto::SHA_512);
    sig_value.set_value_signature(co.AsymSign(pmid_, "", pmid_private_,
      crypto::STRING_STRING));
    // TTL set to 24 hrs
    std::string request_signature = co.AsymSign(co.Hash(pmid_public_ +
      pmid_public_signature_ + request->bufferpacket_name(), "",
      crypto::STRING_STRING, false), "", pmid_private_, crypto::STRING_STRING);
    kad::SignedRequest sr;
    sr.set_signer_id(pmid_);
    sr.set_public_key(pmid_public_);
    sr.set_signed_public_key(pmid_public_signature_);
    sr.set_signed_request(request_signature);
    knode_->StoreValue(request->bufferpacket_name(), sig_value, sr, 86400,
                       &vsvc_dummy_callback);
  }
  response->set_result(kAck);
  done->Run();
}

void VaultService::ModifyBPInfo(google::protobuf::RpcController*,
                                const maidsafe::ModifyBPInfoRequest *request,
                                maidsafe::ModifyBPInfoResponse *response,
                                google::protobuf::Closure *done) {
  response->set_pmid_id(pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::ModifyBPInfo(%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (!co.AsymCheckSig(request->public_key(), request->signed_public_key(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate signed public key.\n");
    }
#endif
    return;
  }

  if (!co.AsymCheckSig(co.Hash(request->public_key() +
      request->signed_public_key() + request->bufferpacket_name(), "",
      crypto::STRING_STRING, false), request->signed_request(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate signed request.\n");
    }
#endif
    return;
  }

  maidsafe::GenericPacket gp;
  if (!gp.ParseFromString(request->data())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("data sent is not a Generic Packet.\n");
    }
#endif
    return;
  }

  maidsafe::BufferPacketInfo bpi;
  if (!bpi.ParseFromString(gp.data())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("data inside Generic Packet is not BufferPacketInfo.\n");
    }
#endif
    return;
  }

  std::string ser_bp;
  if (!LoadChunkLocal(request->bufferpacket_name(), &ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to load the local chunk where the BP is held.\n");
    }
#endif
    return;
  }

  maidsafe::VaultBufferPacketHandler vbph;
  if (!vbph.ValidateOwnerSignature(request->public_key(), ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to validate the Buffer Packet ownership.\n");
    }
#endif
    return;
  }

  if (!vbph.ChangeOwnerInfo(request->data(), request->public_key(), &ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to update the BufferPacketInfo.\n");
    }
#endif
    return;
  }

  if (!UpdateBPChunkLocal(request->bufferpacket_name(), ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to update the local chunk store.\n");
    }
#endif
    return;
  }

  response->set_result(kAck);
  done->Run();
}

void VaultService::GetBPMessages(google::protobuf::RpcController*,
                                 const maidsafe::GetBPMessagesRequest *request,
                                 maidsafe::GetBPMessagesResponse *response,
                                 google::protobuf::Closure *done) {
  response->set_pmid_id(pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (!co.AsymCheckSig(request->public_key(), request->signed_public_key(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate signed public key.\n");
#endif
    return;
  }

  if (!co.AsymCheckSig(co.Hash(request->public_key() +
      request->signed_public_key() + request->bufferpacket_name(), "",
      crypto::STRING_STRING, false), request->signed_request(),
      request->public_key(), crypto::STRING_STRING)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to validate signed request.\n");
#endif
    return;
  }

  std::string ser_bp;
  if (!LoadChunkLocal(request->bufferpacket_name(), &ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to load the local chunk where the BP is held.\n");
#endif
    return;
  }

  maidsafe::VaultBufferPacketHandler vbph;
  std::vector<std::string> msgs;
  if (!vbph.GetMessages(&ser_bp, &msgs)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to extract the messages.\n");
#endif
    return;
  }
  for (int i = 0; i < static_cast<int>(msgs.size()); ++i)
    response->add_messages(msgs[i]);

  if (!UpdateBPChunkLocal(request->bufferpacket_name(), ser_bp)) {
    response->clear_messages();
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::GetBPMessages (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to update the local chunk store.\n");
#endif
    return;
  }

  response->set_result(kAck);
  done->Run();
}

void VaultService::AddBPMessage(google::protobuf::RpcController*,
                                const maidsafe::AddBPMessageRequest *request,
                                maidsafe::AddBPMessageResponse *response,
                                google::protobuf::Closure *done) {
  response->set_pmid_id(pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::AddBPMessage(%s), request is not initialized.\n",
             HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->signed_public_key(), request->signed_request(),
      request->bufferpacket_name(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::AddBPMessage(%s), request/id doesn't validate.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  std::string ser_bp;
  if (!LoadChunkLocal(request->bufferpacket_name(), &ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::AddBPMessage (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to load the local chunk where the BP is held.\n");
    }
#endif
    return;
  }

  maidsafe::VaultBufferPacketHandler vbph;
  std::string updated_bp;
  if (!vbph.AddMessage(ser_bp, request->data(), request->signed_public_key(),
      &updated_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::AddBPMessage (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to add the message.\n");
    }
#endif
    return;
  }

  if (!UpdateBPChunkLocal(request->bufferpacket_name(), updated_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::AddBPMessage (%s), ", HexSubstr(pmid_).c_str());
      printf("failed to update the local chunk store.\n");
    }
#endif
    return;
  }

  done->Run();
}

void VaultService::ContactInfo(google::protobuf::RpcController*,
                               const maidsafe::ContactInfoRequest* request,
                               maidsafe::ContactInfoResponse* response,
                               google::protobuf::Closure* done) {
  response->set_pmid_id(pmid_);
  response->set_public_key(pmid_public_);
  response->set_public_key_signature(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::ContactInfo (%s), request is not initialized.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(),
      request->bufferpacket_name(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::ContactInfo (%s), request/id does not validate.\n",
           HexSubstr(pmid_).c_str());
#endif
    return;
  }

  std::string ser_bp;
  if (!LoadChunkLocal(request->bufferpacket_name(), &ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::ContactInfo (%s), ", HexSubstr(pmid_).c_str());
    printf("failed to load the local chunk where the BP is held.\n");
#endif
    return;
  }

  maidsafe::EndPoint *ep = response->mutable_ep();
  maidsafe::PersonalDetails *pd = response->mutable_pd();
  boost::uint16_t status;
  maidsafe::VaultBufferPacketHandler vbph;
  if (!vbph.ContactInfo(ser_bp, request->id(), ep, pd, &status)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::ContactInfo (%s), ", HexSubstr(pmid_).c_str());
    printf("failed in the VBPH.\n");
#endif
    return;
  }

  response->set_status(status);
  done->Run();
}

//////// END OF SERVICES ////////

bool VaultService::ValidateSignedSize(const maidsafe::SignedSize &sz) {
  if (!sz.IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::ValidateSignedSize, not initialised.\n");
#endif
    return false;
  }
  if (!ValidateIdentity(sz.pmid(), sz.public_key(),
      sz.public_key_signature())) {
#ifdef DEBUG
    printf("In VaultService::ValidateSignedSize, invalid identity.\n");
#endif
    return false;
  }
  crypto::Crypto co;
  std::string str_size = base::itos_ull(sz.data_size());
  if (!co.AsymCheckSig(str_size, sz.signature(), sz.public_key(),
      crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("In VaultService::ValidateSignedSize, invalid signature.\n");
#endif
    return false;
  }
  return true;
}

bool VaultService::ValidateStoreContract(const maidsafe::StoreContract &sc) {
  if (!sc.IsInitialized() || !sc.inner_contract().IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, not initialised.\n");
#endif
    return false;
  }
  if (!ValidateIdentity(sc.pmid(), sc.public_key(),
      sc.public_key_signature())) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, invalid identity.\n");
#endif
    return false;
  }
  crypto::Crypto co;
  std::string ser_ic = sc.inner_contract().SerializeAsString();
  if (!co.AsymCheckSig(ser_ic, sc.signature(), sc.public_key(),
      crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, invalid signature.\n");
#endif
    return false;
  }
  if (sc.inner_contract().result() != kAck) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, contract rejected.\n");
#endif
    return false;
  }
  if (!ValidateSignedSize(sc.inner_contract().signed_size())) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, invalid signed size.\n");
#endif
    return false;
  }
  if (sc.pmid() == sc.inner_contract().signed_size().pmid()) {
#ifdef DEBUG
    printf("In VaultService::ValidateStoreContract, PMIDs of contract and "
           "signed size don't match (%s vs %s).\n",
           HexSubstr(sc.pmid()).c_str(),
           HexSubstr(sc.inner_contract().signed_size().pmid()).c_str());
#endif
    return false;
  }
  return true;
}

bool VaultService::ValidateAmendRequest(
    const maidsafe::AmendAccountRequest *request,
    boost::uint64_t *account_delta,
    std::string *pmid) {
  *account_delta = 0;
  pmid->clear();
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::ValidateAmendRequest, not initialised.\n");
#endif
    return false;
  }

  if (request->account_pmid() == pmid_) {
#ifdef DEBUG
    printf("In VaultService::ValidateAmendRequest, can't manage own account "
           "locally.\n");
#endif
    return false;
  }

  const maidsafe::SignedSize &sz = request->signed_size();
  if (request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceOffered) {
    if (request->account_pmid() != sz.pmid()) {
#ifdef DEBUG
      printf("In VaultService::ValidateAmendRequest, account owner must be "
             "size signer.\n");
#endif
      return false;
    }
  } else {
    if (!request->has_chunkname()) {
#ifdef DEBUG
      printf("In VaultService::ValidateAmendRequest, no chunk name given.\n");
#endif
      return false;
    }
  }

  if (!ValidateSignedSize(sz)) {
    return false;
  }

  *pmid = request->account_pmid();
  *account_delta = sz.data_size();
  return true;
}

bool VaultService::ValidateSignedRequest(
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &request_signature,
    const std::string &key,
    const std::string &signing_id) {
  if (request_signature == kAnonymousRequestSignature)
    return true;

  maidsafe::MaidsafeValidator msv(pmid_);
  if (!msv.ValidateSignerId(signing_id, public_key, public_key_signature))
    return false;
  if (!msv.ValidateRequest(request_signature, public_key, public_key_signature,
      key))
    return false;
  return true;
}

bool VaultService::ValidateIdentity(const std::string &id,
                                    const std::string &public_key,
                                    const std::string &public_key_signature) {
  maidsafe::MaidsafeValidator msv;
  if (!msv.ValidateSignerId(id, public_key, public_key_signature))
    return false;
  return true;
}

bool VaultService::ValidateSystemPacket(const std::string &ser_content,
                                        const std::string &public_key) {
  maidsafe::GenericPacket gp;
  if (!gp.ParseFromString(ser_content))
    return false;
  crypto::Crypto co;
  return co.AsymCheckSig(gp.data(), gp.signature(), public_key,
    crypto::STRING_STRING);
}

bool VaultService::ValidateDataChunk(const std::string &chunkname,
                                     const std::string &content) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string computed_chunkname = co.Hash(content, "", crypto::STRING_STRING,
                                           false);
  return chunkname == computed_chunkname;
}

int VaultService::Storable(const boost::uint64_t &data_size) {
// TODO(Fraser#5#): 2009-08-04 - Deduct pending store space
  return data_size <= vault_chunkstore_->FreeSpace() && data_size != 0 ? 0 : -1;
}

bool VaultService::HasChunkLocal(const std::string &chunkname) {
  return vault_chunkstore_->Has(chunkname);
}

bool VaultService::StoreChunkLocal(const std::string &chunkname,
                                   const std::string &content) {
  int result = vault_chunkstore_->Store(chunkname, content);
  // If result == kInvalidChunkType, the chunk already exists in the store.
  // Assuming chunk contents don't change, this is an overall success.
  return (result == kSuccess || result == kInvalidChunkType);
}

bool VaultService::UpdateBPChunkLocal(const std::string &bufferpacket_name,
                                      const std::string &content) {
  return vault_chunkstore_->UpdateChunk(bufferpacket_name, content) == kSuccess;
}

bool VaultService::LoadChunkLocal(const std::string &chunkname,
                                  std::string *content) {
  return (vault_chunkstore_->Load(chunkname, content) == kSuccess);
}

bool VaultService::DeleteChunkLocal(const std::string &chunkname) {
  return (vault_chunkstore_->DeleteChunk(chunkname) == kSuccess);
}

boost::uint64_t VaultService::GetChunkSizeLocal(const std::string &chunkname) {
  return vault_chunkstore_->GetChunkSize(chunkname);
}

void VaultService::FindCloseNodesCallback(const std::string &result,
    std::vector<std::string> *close_nodes) {
  close_nodes->clear();
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result))
    return;
  for (int i = 0; i < result_msg.closest_nodes_size(); ++i) {
    close_nodes->push_back(result_msg.closest_nodes(i));
  }
}

void VaultService::AmendRemoteAccount(
    const maidsafe::AmendAccountRequest::Amendment &amendment_type,
    const boost::uint64_t &size,
    const std::string &account_pmid,
    const std::string &chunkname) {
  AmendRemoteAccount(amendment_type, size, account_pmid, chunkname,
      boost::bind(&VaultService::DiscardResult, this, _1));
}

void VaultService::AmendRemoteAccount(
    const maidsafe::AmendAccountRequest::Amendment &amendment_type,
    const boost::uint64_t &size,
    const std::string &account_pmid,
    const std::string &chunkname,
    const VoidFuncOneInt &callback) {
  // Check if we happen to hold the account - if so, modify as required
  int found_local_result = ah_.HaveAccount(account_pmid);
  if (found_local_result != kAccountNotFound) {
    bool increase(false);
    int field(2);
    if (amendment_type == maidsafe::AmendAccountRequest::kSpaceGivenInc ||
        amendment_type == maidsafe::AmendAccountRequest::kSpaceTakenInc)
      increase = true;
    if (amendment_type == maidsafe::AmendAccountRequest::kSpaceTakenDec ||
        amendment_type == maidsafe::AmendAccountRequest::kSpaceTakenInc)
      field = 3;
    // Check that we've got valid amendment type
    if (increase || field != 2 || amendment_type ==
        maidsafe::AmendAccountRequest::kSpaceGivenDec) {
      found_local_result =
          ah_.AmendAccount(account_pmid, field, size, increase);
#ifdef DEBUG
      if (found_local_result != kSuccess) {
        printf("In VaultService::AmendRemoteAccount (%s), failed amending "
               "space offered by %s.\n", HexSubstr(pmid_).c_str(),
               HexSubstr(account_pmid).c_str());
      }
#endif
    }
  }

  crypto::Crypto co;
  maidsafe::AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(amendment_type);
  amend_account_request.set_account_pmid(account_pmid);
  maidsafe::SignedSize *mutable_signed_size =
      amend_account_request.mutable_signed_size();
  mutable_signed_size->set_data_size(size);
  mutable_signed_size->set_pmid(pmid_);
  mutable_signed_size->set_signature(co.AsymSign(base::itos_ull(size), "",
                                     pmid_private_, crypto::STRING_STRING));
  mutable_signed_size->set_public_key(pmid_public_);
  mutable_signed_size->set_public_key_signature(pmid_public_signature_);
  amend_account_request.set_chunkname(chunkname);

  // thread_pool_ handles destruction of task.
  RemoteTask<maidsafe::AmendAccountRequest> *task =
      new RemoteTask<maidsafe::AmendAccountRequest>(amend_account_request,
          found_local_result, callback, vault_service_logic_, transport_id_);
  thread_pool_.start(task);
}

void VaultService::AddToRemoteRefList(const std::string &chunkname,
                                      const maidsafe::StoreContract &contract) {
  // try adding to local ref list (fails if no chunk info or watchers)
  int found_local_result = cih_.AddToReferenceList(chunkname, contract.pmid(),
      contract.inner_contract().signed_size().data_size());
  if (found_local_result == kSuccess) {
    DoneAddToReferenceList(contract, chunkname);
  }

  maidsafe::AddToReferenceListRequest add_to_ref_list_request;
  add_to_ref_list_request.set_chunkname(chunkname);
  maidsafe::StoreContract *sc =
      add_to_ref_list_request.mutable_store_contract();
  *sc = contract;

  // thread_pool_ handles destruction of task.
  RemoteTask<maidsafe::AddToReferenceListRequest> *task =
      new RemoteTask<maidsafe::AddToReferenceListRequest>(
          add_to_ref_list_request, found_local_result,
          boost::bind(&VaultService::DiscardResult, this, _1),
          vault_service_logic_, transport_id_);
  thread_pool_.start(task);
}

void VaultService::RemoteVaultAbleToStore(const boost::uint64_t &size,
                                          const std::string &account_pmid,
                                          const VoidFuncOneInt &callback) {
  boost::uint64_t space_offered(0), space_given(0), space_taken(0);
  int found_local_result = ah_.GetAccountInfo(account_pmid, &space_offered,
                                              &space_given, &space_taken);
  if (found_local_result == kSuccess && space_taken + size > space_offered) {
    found_local_result = kGeneralError;
#ifdef DEBUG
    printf("In VaultService::RemoteVaultAbleToStore (%s), requested space "
           "(%s) not available (> %s).\n",
           HexSubstr(pmid_).c_str(), base::itos_ull(size).c_str(),
           base::itos_ull(space_offered - space_taken).c_str());
#endif
  }

  maidsafe::AccountStatusRequest account_status_request;
  account_status_request.set_account_pmid(account_pmid);
  account_status_request.set_space_requested(size);

  // thread_pool_ handles destruction of task.
  RemoteTask<maidsafe::AccountStatusRequest> *task =
      new RemoteTask<maidsafe::AccountStatusRequest>(account_status_request,
          found_local_result, callback, vault_service_logic_, transport_id_);
  thread_pool_.start(task);
}

int VaultService::AddAccount(const std::string &pmid,
                             const boost::uint64_t &offer) {
  return ah_.AddAccount(pmid, offer);
}

bool VaultService::NodeWithinClosest(const std::string &peer_pmid,
                                     const boost::uint16_t &count) {
  boost::shared_ptr<base::PDRoutingTableHandler> rt_handler =
      (*base::PDRoutingTable::getInstance())
          [boost::lexical_cast<std::string>(knode_->host_port())];
  std::list<base::PDRoutingTableTuple> close_peers;
  if (rt_handler->GetClosestContacts(pmid_, count, &close_peers) != kSuccess) {
#ifdef DEBUG
    printf("In VaultService::NodeWithinClosest(%s), failed to query local"
           "routing table.\n", HexSubstr(pmid_).c_str());
#endif
    return false;
  }
  std::list<base::PDRoutingTableTuple>::iterator peer_list_itr =
      close_peers.begin();
  bool found(false);
  while (peer_list_itr != close_peers.end()) {
    if ((*peer_list_itr).kademlia_id_ == peer_pmid) {
      found = true;
      break;
    }
    ++peer_list_itr;
  }
  return found;
}


RegistrationService::RegistrationService(
    boost::function<void(const maidsafe::VaultConfig&)> notifier)
        : notifier_(notifier),
          status_(maidsafe::NOT_OWNED),
          pending_response_() {}

void RegistrationService::SetLocalVaultOwned(
    google::protobuf::RpcController*,
    const maidsafe::SetLocalVaultOwnedRequest *request,
    maidsafe::SetLocalVaultOwnedResponse *response,
    google::protobuf::Closure *done) {
  if (!request->IsInitialized()) {
    response->set_result(maidsafe::INVALID_OWNREQUEST);
    done->Run();
    return;
  }

  if (status_ == maidsafe::OWNED) {
    response->set_result(maidsafe::VAULT_ALREADY_OWNED);
    done->Run();
    return;
  }

  if (request->space() == 0) {
    response->set_result(maidsafe::NO_SPACE_ALLOCATED);
    done->Run();
    return;
  }

  // checking available space in disk
  boost::filesystem::path vaultdir(request->vault_dir());
  boost::filesystem::space_info info;
  if ("/" != vaultdir.root_directory())
    info = boost::filesystem::space(boost::filesystem::path("/"));
  else
    info = boost::filesystem::space(boost::filesystem::path(vaultdir.root_name()
        + vaultdir.root_directory()));
  if (request->space() > info.available) {
    response->set_result(maidsafe::NOT_ENOUGH_SPACE);
    done->Run();
    return;
  }
  // checking if port is available
  transport::TransportUDT test_tranport;
  if (request->port() == 0 || test_tranport.IsPortAvailable(
      request->port())) {
    response->set_result(maidsafe::OWNED_SUCCESS);
    crypto::Crypto cobj;
    cobj.set_hash_algorithm(crypto::SHA_512);
    std::string pmid_name = cobj.Hash(request->public_key()+
        request->signed_public_key(), "", crypto::STRING_STRING, false);
    response->set_pmid_name(pmid_name);
    pending_response_.callback = done;
    pending_response_.args = response;
    maidsafe::VaultConfig vconfig;
    vconfig.set_pmid_public(request->public_key());
    vconfig.set_pmid_private(request->private_key());
    vconfig.set_signed_pmid_public(request->signed_public_key());
    vconfig.set_vault_dir(request->vault_dir());
    vconfig.set_port(request->port());
    vconfig.set_available_space(request->space());
    notifier_(vconfig);
    return;
  } else {
    response->set_result(maidsafe::INVALID_PORT);
  }
  done->Run();
}

void RegistrationService::LocalVaultOwned(
    google::protobuf::RpcController*,
    const maidsafe::LocalVaultOwnedRequest*,
    maidsafe::LocalVaultOwnedResponse *response,
    google::protobuf::Closure *done) {
  response->set_status(status_);
  done->Run();
}

void RegistrationService::ReplySetLocalVaultOwnedRequest(
    const bool &fail_to_start) {
  if (pending_response_.callback == NULL || pending_response_.args == NULL)
    return;
  if (fail_to_start) {
    pending_response_.args->Clear();
    pending_response_.args->set_result(maidsafe::FAILED_TO_START_VAULT);
  }
  pending_response_.callback->Run();
  pending_response_.callback = NULL;
  pending_response_.args = NULL;
}

}  // namespace maidsafe_vault
