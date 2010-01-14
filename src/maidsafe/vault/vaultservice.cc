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

#include <list>

#include "maidsafe/maidsafe.h"
#include "maidsafe/maidsafevalidator.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
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

void AddToRefListTask::run() {
  int result = vault_service_logic_->AddToRemoteRefList(chunkname_,
                                                        store_contract_);
#ifdef DEBUG
  if (result != kSuccess)
    printf("AddToRemoteRefList returned result %i for chunk (%s).\n",
           result, HexSubstr(chunkname_).c_str());
#endif
}

//  void RemoveFromRefListTask::run() {
//    vault_service_logic_->RemoveFromRefPacket(chunkname_, signed_size_);
//  }

void AmendRemoteAccountTask::run() {
  vault_service_logic_->AmendRemoteAccount(amend_account_request_, callback_);
}

VaultService::VaultService(const std::string &pmid_public,
                           const std::string &pmid_private,
                           const std::string &pmid_public_signature,
                           VaultChunkStore *vault_chunkstore,
                           kad::KNode *knode,
                           PendingOperationsHandler *poh,
                           VaultServiceLogic *vault_service_logic)
    : pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      pmid_public_signature_(pmid_public_signature),
      pmid_(),
      non_hex_pmid_(),
      vault_chunkstore_(vault_chunkstore),
      knode_(knode),
      poh_(poh),
      vault_service_logic_(vault_service_logic),
      prm_(),
      ah_(),
      aah_(&ah_),
      cih_(),
      thread_pool_() {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  pmid_ = co.Hash(pmid_public + pmid_public_signature_, "",
                  crypto::STRING_STRING, true);
  non_hex_pmid_ = base::DecodeFromHex(pmid_);
  thread_pool_.setMaxThreadCount(5);
}

void VaultService::StorePrep(google::protobuf::RpcController*,
                             const maidsafe::StorePrepRequest *request,
                             maidsafe::StorePrepResponse *response,
                             google::protobuf::Closure *done) {
  maidsafe::StoreContract *response_sc = response->mutable_store_contract();
  response_sc->set_pmid(non_hex_pmid_);
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
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("request not initialised.\n");
#endif
    done->Run();
    return;
  }

  std::string str_size_data = base::itos_ull(request_sz.data_size());
  if (!co.AsymCheckSig(str_size_data, request_sz.signature(),
      request_sz.public_key(), crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("failed to validate data size signature.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname() == "" || request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("failed to validate chunkname.\n");
#endif
    done->Run();
    return;
  }
  PrepsReceivedMap::iterator it = prm_.find(request->chunkname());
  if (it != prm_.end()) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("chunkname was in map.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateIdentity(request_sz.pmid(), request_sz.public_key(),
      request_sz.public_key_signature())) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("failed to validate id from request SignedSize.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request_sz.public_key(),
       request_sz.public_key_signature(), request->request_signature(),
       request->chunkname(), request_sz.pmid())) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  // Check we're not being asked to store ourselves as a reference holder for
  // ourself.
  if (request_sz.pmid() == non_hex_pmid_) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), trying to store in ourselves.\n",
           knode_->host_port());
#endif
    done->Run();
    return;
  }

  // TODO(Team#5#): check peer's available space

  boost::uint64_t data_size = request_sz.data_size();
  if (Storable(data_size) != 0) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), no space.\n",
           knode_->host_port());
#endif
    done->Run();
    return;
  }

  std::string peer_pmid(request_sz.pmid());
  std::pair<PrepsReceivedMap::iterator, bool> cp =
      prm_.insert(std::pair<std::string, maidsafe::StoreContract>(
      request->chunkname(), *response_sc));

  if (!cp.second) {
#ifdef DEBUG
    printf("In VaultService::StorePrep (%i), failed to insert prep into map.\n",
           knode_->host_port());
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
  // TODO(Fraser#5#): 2009-12-28 - if this fails more thanm kMinStoreRetries for
  //                               same chunkname & peer, delete from prm_?
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), request is not initialized.\n",
           knode_->host_port());
#endif
    done->Run();
    return;
  }

  PrepsReceivedMap::iterator it = prm_.find(request->chunkname());
  if (it == prm_.end()) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), ", knode_->host_port());
    printf("chunkname wasn't in map - no prep.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  // TODO(Team#5#): Decide on which types of data should come through here
  bool valid_data(false);

  if (!StoreChunkLocal(request->chunkname(), request->data())) {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), ", knode_->host_port());
    printf("failed to store chunk locally.\n");
#endif
    done->Run();
    return;
  }

  // thread_pool_ handles destruction of task.
  // TODO(Fraser#) add ref list task to list
//  AddToRefListTask *task = new AddToRefListTask(request->chunkname(),
//      it->second, vault_service_logic_);
//  thread_pool_.start(task);

  prm_.erase(request->chunkname());
  response->set_result(kAck);
  done->Run();
}

void VaultService::StorePacket(google::protobuf::RpcController*,
                               const maidsafe::StorePacketRequest *request,
                               maidsafe::StorePacketResponse *response,
                               google::protobuf::Closure *done) {
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized() || request->signed_data_size() == 0) {
    response->set_result(kNack);
    done->Run();
    return;
  }

  // Check Type of data
  if (request->data_type() != maidsafe::PDDIR_NOTSIGNED) {
    // Checking request has public key, signed public key and signed
    // request
    if (!request->has_public_key_signature()
        || !request->has_request_signature() || !request->has_public_key()
        || !request->has_key_id()) {
      response->set_result(kNack);
      done->Run();
      return;
    }

    // Checking signature is valid
    if (!ValidateSignedRequest(request->public_key(),
        request->public_key_signature(), request->request_signature(),
        request->packetname(), request->key_id())) {
      response->set_result(kNack);
      done->Run();
      return;
    }

    // Validating data is signed by the same person
    for (int i = 0; i < request->signed_data_size(); ++i) {
      if (!ValidateSystemPacket(request->signed_data(i),
          request->public_key())) {
        response->set_result(kNack);
        done->Run();
        return;
      }
    }

    // Now we can store :)
    int store_result = -1;
    if (vault_chunkstore_->HasPacket(request->packetname())) {
      if (request->append()) {
        // Append Packet
        if (request->signed_data_size() == 1)
          store_result = vault_chunkstore_->AppendToPacket(
                         request->packetname(), request->signed_data(0),
                         request->public_key());
      } else {
        // Overwrite Packet
        std::vector<maidsafe::GenericPacket> values;
        for (int i = 0; i < request->signed_data_size(); ++i)
          values.push_back(request->signed_data(i));
        store_result = vault_chunkstore_->OverwritePacket(
                       request->packetname(), values, request->public_key());
      }
      if (store_result == kSuccess)
        response->set_result(kAck);
      else
        response->set_result(kNack);
      done->Run();
      return;
    }
  }
  // Store Packet
  if (vault_chunkstore_->StorePacket(request->packetname(),
      request->signed_data(0)) == kSuccess)
    response->set_result(kAck);
  else
    response->set_result(kNack);

  // Storing chunk reference
  if (response->result() == kAck && knode_ != NULL) {
    kad::SignedValue sig_value;
    sig_value.set_value(non_hex_pmid_);
    crypto::Crypto co;
    co.set_hash_algorithm(crypto::SHA_512);
    sig_value.set_value_signature(co.AsymSign(non_hex_pmid_, "", pmid_private_,
      crypto::STRING_STRING));
    // TTL set to 24 hrs
    std::string request_signature = co.AsymSign(
        co.Hash(pmid_public_ + pmid_public_signature_ + request->packetname(),
                "", crypto::STRING_STRING, true),
        "",
        pmid_private_,
        crypto::STRING_STRING);
    kad::SignedRequest sr;
    sr.set_signer_id(non_hex_pmid_);
    sr.set_public_key(pmid_public_);
    sr.set_signed_public_key(pmid_public_signature_);
    sr.set_signed_request(request_signature);
    knode_->StoreValue(request->packetname(), sig_value, sr, 86400,
                       &vsvc_dummy_callback);
  }

  done->Run();
}

void VaultService::AddToWatchList(
    google::protobuf::RpcController*,
    const maidsafe::AddToWatchListRequest *request,
    maidsafe::AddToWatchListResponse *response,
    google::protobuf::Closure *done) {

  response->set_pmid(non_hex_pmid_);
  response->set_upload_count(0);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%i), ", knode_->host_port());
    printf("request is not initialized.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%i), ", knode_->host_port());
    printf("failed to validate chunk name.\n");
#endif
    done->Run();
    return;
  }

  const maidsafe::SignedSize &sz = request->signed_size();

  if (!ValidateSignedSize(sz)) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%i), ", knode_->host_port());
    printf("failed to validate signed size.\n");
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
    printf("In VaultService::AddToWatchList (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  int required_references, required_payments;
  if (0 != cih_.PrepareAddToWatchList(request->chunkname(), sz.pmid(),
                                      sz.data_size(), &required_references,
                                      &required_payments)) {
#ifdef DEBUG
    printf("In VaultService::AddToWatchList (%i), ", knode_->host_port());
    printf("failed adding to waiting list.\n");
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
    FinalisePayment(request->chunkname(), sz.pmid(), sz.data_size(),
                    RemoteVaultAbleToStore(sz.data_size(), sz.pmid(),
                                           request->chunkname()));
  }
}

void VaultService::FinalisePayment(const std::string &chunk_name,
                                   const std::string &pmid,
                                   const int &chunk_size,
                                   const bool &can_store) {
  if (!can_store) {
#ifdef DEBUG
    printf("In VaultService::FinalisePayment (%i), ", knode_->host_port());
    printf("failed to obtain storing permission.\n");
#endif
    std::list<std::string> creditors, references;
    cih_.ResetAddToWatchList(chunk_name, pmid, kReasonPaymentFailed, &creditors,
                             &references);
    for (std::list<std::string>::iterator it = creditors.begin();
         it != creditors.end(); it++) {
      // amend account for remaining entry
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         chunk_size, *it, chunk_name);
    }

    for (std::list<std::string>::iterator it = references.begin();
         it != references.end(); it++) {
      // TODO(Steve#) delete remote chunk
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
  }
}

void VaultService::RemoveFromWatchList(
    google::protobuf::RpcController*,
    const maidsafe::RemoveFromWatchListRequest *request,
    maidsafe::RemoveFromWatchListResponse *response,
    google::protobuf::Closure *done) {

  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%i), ", knode_->host_port());
    printf("request is not initialized.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(),
      request->chunkname(), request->pmid())) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  int chunk_size;
  std::list<std::string> creditors, references;
  if (0 != cih_.RemoveFromWatchList(request->chunkname(), request->pmid(),
                                    &chunk_size, &creditors, &references)) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromWatchList (%i), ", knode_->host_port());
    printf("failed to remove from watch list.\n");
#endif
    done->Run();
    return;
  }

  response->set_result(kAck);
  done->Run();

  for (std::list<std::string>::iterator it = creditors.begin();
       it != creditors.end(); it++) {
    // amend account for remaining entry
    AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                       chunk_size, *it, request->chunkname());
  }

  for (std::list<std::string>::iterator it = references.begin();
       it != references.end(); it++) {
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
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);

  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%i), ", knode_->host_port());
    printf("request is not initialized.\n");
#endif
    done->Run();
    return;
  }

  const maidsafe::StoreContract &store_contract = request->store_contract();
  if (!ValidateStoreContract(store_contract)) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%i), ", knode_->host_port());
    printf("failed to validate store contract.\n");
#endif
    done->Run();
    return;
  }

  if (!ValidateSignedRequest(store_contract.public_key(),
      store_contract.public_key_signature(), request->request_signature(),
      request->chunkname(), store_contract.pmid())) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    done->Run();
    return;
  }

  int chunk_size = store_contract.inner_contract().signed_size().data_size();

  if (0 != cih_.AddToReferenceList(request->chunkname(), store_contract.pmid(),
                                   chunk_size)) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%i), ", knode_->host_port());
    printf("failed to add to reference list.\n");
#endif
    done->Run();
    return;
  }

  response->set_result(kAck);
  done->Run();

  kad::SignedValue signed_value;
  signed_value.set_value(store_contract.pmid());
  signed_value.set_value_signature(store_contract.public_key_signature());
  if (!knode_->StoreValueLocal(request->chunkname(),
                               signed_value.SerializeAsString(), 86400)) {
#ifdef DEBUG
    printf("In VaultService::AddToReferenceList (%i), ", knode_->host_port());
    printf("failed to store pmid to local ref packet.\n");
#endif
    done->Run();
    return;
  }

  // amend account for chunk holder (= sender)
  AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceGivenInc,
                     chunk_size, store_contract.pmid(), request->chunkname());

  cih_.SetStoringDone(request->chunkname());
  std::string creditor;
  int refunds;
  if (cih_.TryCommitToWatchList(request->chunkname(), store_contract.pmid(),
                                &creditor, &refunds)) {
    if (refunds > 0) {
      // amend account for watcher, in case he wasn't first after all
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         refunds * chunk_size,
                         store_contract.inner_contract().signed_size().pmid(),
                         request->chunkname());
    }
    if (!creditor.empty()) {
      // amend account for replaced entry
      AmendRemoteAccount(maidsafe::AmendAccountRequest::kSpaceTakenDec,
                         chunk_size, creditor, request->chunkname());
    }
  }
}

void VaultService::RemoveFromReferenceList(
    google::protobuf::RpcController*,
    const maidsafe::RemoveFromReferenceListRequest *request,
    maidsafe::RemoveFromReferenceListResponse *response,
    google::protobuf::Closure *done) {
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);
  // Check request is initialised
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::RemoveFromReferenceList (%i), "
           "request isn't initialized.\n", knode_->host_port());
#endif
    done->Run();
    return;
  }

  // TODO(Team#) implement remove from reference list
  done->Run();
}

void VaultService::AmendAccount(google::protobuf::RpcController*,
                                const maidsafe::AmendAccountRequest *request,
                                maidsafe::AmendAccountResponse *response,
                                google::protobuf::Closure *done) {
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);
  // Validate request and extract data
  boost::uint64_t account_delta;
  std::string pmid;
  if (!ValidateAmendRequest(request, &account_delta, &pmid)) {
#ifdef DEBUG
    printf("In VaultService::AmendAccount (%i), problem with request.\n",
           knode_->host_port());
#endif
    done->Run();
    return;
  }

  if (ah_.HaveAccount(pmid) == kAccountNotFound) {
    if (request->amendment_type() ==
        maidsafe::AmendAccountRequest::kSpaceOffered) {
      if (ah_.AddAccount(pmid, account_delta) == 0) {
        response->set_result(kAck);
      } else {
#ifdef DEBUG
        printf("In VaultService::AmendAccount (%i), failed adding %s's account."
               "\n", knode_->host_port(), HexSubstr(pmid).c_str());
#endif
      }
    }
    done->Run();
    return;
  } else {
    if (request->amendment_type() ==
        maidsafe::AmendAccountRequest::kSpaceOffered) {
      if (ah_.AmendAccount(pmid, 1, account_delta, false) == 0) {
        response->set_result(kAck);
      } else {
#ifdef DEBUG
        printf("In VaultService::AmendAccount (%i), failed amending space"
               " offered by %s.\n", knode_->host_port(),
               HexSubstr(pmid).c_str());
#endif
      }
      done->Run();
      return;
    } else {
      // aah_->ProcessRequest() calls done->Run();
      int result = aah_.ProcessRequest(request, response, done);
      if (result != 0) {
#ifdef DEBUG
        printf("In VaultService::AmendAccount (%i), failed amending account"
               " of %s - error %i\n", knode_->host_port(),
               HexSubstr(pmid).c_str(), result);
#endif
      }
      return;
    }
  }
}

void VaultService::AccountStatus(google::protobuf::RpcController*,
                                 const maidsafe::AccountStatusRequest *request,
                                 maidsafe::AccountStatusResponse *response,
                                 google::protobuf::Closure *done) {
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::AccountStatus (%i), request is not initialized.\n",
           knode_->host_port());
#endif
    done->Run();
    return;
  }

  boost::uint64_t space_offered(0), space_given(0), space_taken(0);
  int n = ah_.GetAccountInfo(request->account_pmid(), &space_offered,
                             &space_given, &space_taken);
  if (n != 0) {
#ifdef DEBUG
    printf("In VaultService::AccountStatus (%i), ", knode_->host_port());
    printf("don't have the account for %s.\n",
           HexSubstr(request->account_pmid()).c_str());
#endif
    done->Run();
    return;
  }

  if (request->has_space_requested()) {
    if (space_taken + request->space_requested() <= space_offered)
      response->set_result(kAck);
    done->Run();
  } else {
    response->set_result(kAck);
    if (!ValidateSignedRequest(request->public_key(),
        request->public_key_signature(), request->request_signature(),
        request->account_pmid() + kAccount, request->account_pmid())) {
  #ifdef DEBUG
      printf("In VaultService::AccountStatus (%i), ", knode_->host_port());
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
  response->set_pmid(non_hex_pmid_);
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
//  printf("In VaultService::GetChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::Get (%i), request isn't initialised.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }
  std::string content;
  if (LoadChunkLocal(request->chunkname(), &content)) {
    response->set_result(kAck);
    response->set_content(content);
  } else {
#ifdef DEBUG
    printf("In VaultService::Get (%i), couldn't find chunk locally.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
  }
  done->Run();
}

void VaultService::GetPacket(google::protobuf::RpcController*,
                             const maidsafe::GetPacketRequest *request,
                             maidsafe::GetPacketResponse *response,
                             google::protobuf::Closure *done) {
  response->Clear();
#ifdef DEBUG
//  if (knode_ != NULL)
//    printf("In VaultService::GetPacket (%i)\n", knode_->host_port());
#endif
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::GetPacket (%i), request isn't initialised.\n",
             knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }

  if (request->has_key_id()) {
    if (!ValidateSignedRequest(request->public_key(),
         request->public_key_signature(), request->request_signature(),
         request->packetname(), request->key_id())) {
      response->set_result(kNack);
      done->Run();
  #ifdef DEBUG
      if (knode_ != NULL) {
        printf("In VaultService::GetPacket (%i), ", knode_->host_port());
        printf("failed to validate signed request.\n");
      }
  #endif
      return;
    }
  }

  if (!LoadPacketLocal(request->packetname(), response)) {
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::GetPacket (%i), couldn't find chunk locally.\n",
             knode_->host_port());
#endif
    response->clear_content();
    response->set_result(kNack);
  }
  done->Run();
}

void VaultService::UpdateChunk(google::protobuf::RpcController*,
                               const maidsafe::UpdateChunkRequest *request,
                               maidsafe::UpdateChunkResponse *response,
                               google::protobuf::Closure *done) {
#ifdef DEBUG
//    printf("Pub key: %s.\n", request->public_key().c_str());
//  printf("In VaultService::UpdateChunk (%i), Data Type: %i\n",
//         knode_->host_port(), request->data_type());
#endif
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
#ifdef DEBUG
    printf("In VaultService::Update (%i), request didn't validate.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }
  bool valid_data = false;
  std::string current_content;
  if (!LoadChunkLocal(request->chunkname(), &current_content)) {
#ifdef DEBUG
    printf("In VaultService::Update (%i), don't have chunk to update.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }

  maidsafe::GenericPacket gp;
  std::string updated_value;
  maidsafe::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
    case maidsafe::SYSTEM_PACKET: if ((ValidateSystemPacket(request->data(),
                                         request->public_key())) &&
                                      (ValidateSystemPacket(current_content,
                                         request->public_key()))) {
                                   updated_value = request->data();
                                   valid_data = true;
                                  }
                                 break;
    case maidsafe::PDDIR_SIGNED: if (ValidateSystemPacket(request->data(),
                                      request->public_key())) {
                                   if (ValidateSystemPacket(current_content,
                                        request->public_key())) {
                                      updated_value = request->data();
                                      valid_data = true;
                                   }
                                 }
                                 break;
    // TODO(David/Fraser#5#): check the validity of a pddir not signed DB
    case maidsafe::PDDIR_NOTSIGNED: if (!gp.ParseFromString(current_content)) {
                                      valid_data = true;
                                      updated_value = request->data();
                                    }
                                    break;
    default: break;  // No specific check for data
  }

  if (valid_data) {
  std::string key = request->chunkname();
    if (!UpdateChunkLocal(key, updated_value)) {
#ifdef DEBUG
      printf("In VaultService::Update (%i), failed local chunk update.\n",
             knode_->host_port());
#endif
      response->set_result(kNack);
      done->Run();
      return;
    }
  } else {
#ifdef DEBUG
    printf("In VaultService::Update (%i), data isn't valid.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }
  response->set_result(kAck);
  done->Run();
  return;
}

void VaultService::DeleteChunk(google::protobuf::RpcController*,
                               const maidsafe::DeleteChunkRequest *request,
                               maidsafe::DeleteChunkResponse *response,
                               google::protobuf::Closure *done) {
#ifdef DEBUG
//  printf("In VaultService::DeleteChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(non_hex_pmid_);
  response->set_result(kNack);
  if (!request->IsInitialized()) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
    printf("request not initialised.\n");
#endif
    done->Run();
    return;
  }

  const maidsafe::SignedSize &sz = request->signed_size();

  if (!ValidateSignedSize(sz)) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
    printf("failed to validate signed size.\n");
#endif
    done->Run();
    return;
  }

  if (request->chunkname().length() != kKeySize) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
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
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
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
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
    printf("invalid chunk size.\n");
#endif
    done->Run();
    return;
  }

  // TODO(Steve#) check request comes from ChunkInfo holder

  if (!DeleteChunkLocal(request->chunkname())) {
#ifdef DEBUG
    printf("In VaultService::DeleteChunk (%i), ", knode_->host_port());
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
  response->set_pmid(non_hex_pmid_);
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
  response->set_pmid(non_hex_pmid_);
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
    printf("In VaultService::VaultStatus (%i), request isn't initialized.\n",
           knode_->host_port());
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
    printf("In VaultService::VaultStatus (%i), request didn't parse as a "
           "VaultCommunication.\n", knode_->host_port());
#endif
    done->Run();
    return;
  }

  if (!vault_chunkstore_->is_initialised()) {
    response->set_result(kNack);
#ifdef DEBUG
    printf("In VaultService::VaultStatus (%i), chunkstore isn't initialised.\n",
           knode_->host_port());
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
  response->set_pmid_id(non_hex_pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::CreateBP (%i), request is not initialized.\n",
             knode_->host_port());
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
      printf("In VaultService::CreateBP (%i), ", knode_->host_port());
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
      printf("In VaultService::CreateBP (%i), ", knode_->host_port());
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
      printf("In VaultService::CreateBP (%i), ", knode_->host_port());
      printf("failed to store chunk locally.\n");
    }
#endif
    return;
  }

  if (knode_ != NULL) {
    kad::SignedValue sig_value;
    sig_value.set_value(non_hex_pmid_);
    co.set_hash_algorithm(crypto::SHA_512);
    sig_value.set_value_signature(co.AsymSign(non_hex_pmid_, "", pmid_private_,
      crypto::STRING_STRING));
    // TTL set to 24 hrs
    std::string request_signature = co.AsymSign(co.Hash(pmid_public_ +
      pmid_public_signature_ + request->bufferpacket_name(), "",
      crypto::STRING_STRING, true), "", pmid_private_, crypto::STRING_STRING);
    kad::SignedRequest sr;
    sr.set_signer_id(non_hex_pmid_);
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
  response->set_pmid_id(non_hex_pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::ModifyBPInfo(%i), request is not initialized.\n",
           knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
      printf("failed to validate the Buffer Packet ownership.\n");
    }
#endif
    return;
  }

  if (!vbph.ChangeOwnerInfo(request->data(), &ser_bp, request->public_key())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
      printf("failed to update the BufferPacketInfo.\n");
    }
#endif
    return;
  }

  if (!UpdateChunkLocal(request->bufferpacket_name(), ser_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::ModifyBPInfo (%i), ", knode_->host_port());
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
  response->set_pmid_id(non_hex_pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::GetBPMessages(%i),request is not initialized.\n",
           knode_->host_port());
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
      printf("In VaultService::GetBPMessages (%i), ", knode_->host_port());
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
      printf("In VaultService::GetBPMessages (%i), ", knode_->host_port());
      printf("failed to validate signed request.\n");
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
      printf("In VaultService::GetBPMessages (%i), ", knode_->host_port());
      printf("failed to load the local chunk where the BP is held.\n");
    }
#endif
    return;
  }

  maidsafe::VaultBufferPacketHandler vbph;
  std::vector<std::string> msgs;
  if (!vbph.GetMessages(&ser_bp, &msgs)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::GetBPMessages (%i), ", knode_->host_port());
      printf("failed to extract the messages.\n");
    }
#endif
    return;
  }
  for (int i = 0; i < static_cast<int>(msgs.size()); i++)
    response->add_messages(msgs[i]);

  if (!UpdateChunkLocal(request->bufferpacket_name(), ser_bp)) {
    response->clear_messages();
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::GetBPMessages (%i), ", knode_->host_port());
      printf("failed to update the local chunk store.\n");
    }
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
  response->set_pmid_id(non_hex_pmid_);
  response->set_public_key(pmid_public_);
  response->set_signed_public_key(pmid_public_signature_);
  response->set_result(kAck);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL)
      printf("In VaultService::AddBPMessage(%i), request is not initialized.\n",
           knode_->host_port());
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
      printf("In VaultService::AddBPMessage (%i), ", knode_->host_port());
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
      printf("In VaultService::AddBPMessage (%i), ", knode_->host_port());
      printf("failed to validate signed request.\n");
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
      printf("In VaultService::AddBPMessage (%i), ", knode_->host_port());
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
      printf("In VaultService::AddBPMessage (%i), ", knode_->host_port());
      printf("failed to add the message.\n");
    }
#endif
    return;
  }

  if (!UpdateChunkLocal(request->bufferpacket_name(), updated_bp)) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    if (knode_ != NULL) {
      printf("In VaultService::AddBPMessage (%i), ", knode_->host_port());
      printf("failed to update the local chunk store.\n");
    }
#endif
    return;
  }

  response->set_result(kAck);
  done->Run();
}

//////// END OF SERVICES ////////

bool VaultService::ValidateSignedSize(const maidsafe::SignedSize &sz) {
  if (!sz.IsInitialized())
    return false;
  if (!ValidateIdentity(sz.pmid(), sz.public_key(), sz.public_key_signature()))
    return false;
  crypto::Crypto co;
  std::string str_size = base::itos_ull(sz.data_size());
  if (!co.AsymCheckSig(str_size, sz.signature(), sz.public_key(),
      crypto::STRING_STRING))
    return false;
  return true;
}

bool VaultService::ValidateStoreContract(const maidsafe::StoreContract &sc) {
  if (!sc.IsInitialized())
    return false;
  if (!ValidateIdentity(sc.pmid(), sc.public_key(), sc.public_key_signature()))
    return false;
  if (!sc.inner_contract().IsInitialized())
    return false;
  crypto::Crypto co;
  std::string ser_ic = sc.inner_contract().SerializeAsString();
  if (!co.AsymCheckSig(ser_ic, sc.signature(), sc.public_key(),
      crypto::STRING_STRING))
    return false;
  if (sc.inner_contract().result() != kAck)
    return false;
  if (!ValidateSignedSize(sc.inner_contract().signed_size()))
    return false;
  if (sc.pmid() == sc.inner_contract().signed_size().pmid())
    return false;
  return true;
}

bool VaultService::ValidateAmendRequest(
    const maidsafe::AmendAccountRequest *request,
    boost::uint64_t *account_delta,
    std::string *pmid) {
  *account_delta = 0;
  pmid->clear();
  if (!request->IsInitialized())
    return false;

  const maidsafe::SignedSize &sz = request->signed_size();
  if (request->amendment_type() ==
      maidsafe::AmendAccountRequest::kSpaceOffered) {
    if (request->account_pmid() != sz.pmid()) {
      return false;
    }
  } else {
    if (!request->has_chunkname()) {
      return false;
    }
  }

  if (!ValidateSignedSize(sz))
    return false;

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

  maidsafe::MaidsafeValidator msv(non_hex_pmid_);
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
  return ValidateSystemPacket(gp, public_key);
}

bool VaultService::ValidateSystemPacket(const maidsafe::GenericPacket &gp,
      const std::string &public_key) {
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

bool VaultService::ModifyBufferPacketInfo(const std::string &new_info,
                                          const std::string &pub_key,
                                          std::string *updated_bp) {
  if (!ValidateSystemPacket(new_info, pub_key)) {
    return false;
  }
  maidsafe::VaultBufferPacketHandler vbph;
  return vbph.ChangeOwnerInfo(new_info, updated_bp, pub_key);
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

bool VaultService::UpdateChunkLocal(const std::string &chunkname,
                                    const std::string &content) {
  return (vault_chunkstore_->UpdateChunk(chunkname, content) == kSuccess);
}

bool VaultService::LoadChunkLocal(const std::string &chunkname,
                                  std::string *content) {
  return (vault_chunkstore_->Load(chunkname, content) == kSuccess);
}

bool VaultService::LoadPacketLocal(const std::string &packetname,
                                   maidsafe::GetPacketResponse *response) {
  response->set_result(kNack);
  std::vector<maidsafe::GenericPacket> gps;
  if (vault_chunkstore_->LoadPacket(packetname, &gps) != kSuccess) {
    response->set_result(kNack);
    return false;
  }
  response->set_result(kAck);
  for (size_t i = 0; i < gps.size(); ++i) {
    maidsafe::GenericPacket *gp = response->add_content();
    *gp = gps.at(i);
  }
  return true;
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
    const Callback &callback) {
  crypto::Crypto co;
  maidsafe::AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(amendment_type);
  amend_account_request.set_account_pmid(account_pmid);
  maidsafe::SignedSize *mutable_signed_size =
      amend_account_request.mutable_signed_size();
  mutable_signed_size->set_data_size(size);
  mutable_signed_size->set_pmid(non_hex_pmid_);
  mutable_signed_size->set_signature(co.AsymSign(base::itos_ull(size), "",
                                     pmid_private_, crypto::STRING_STRING));
  mutable_signed_size->set_public_key(pmid_public_);
  mutable_signed_size->set_public_key_signature(pmid_public_signature_);
  amend_account_request.set_chunkname(chunkname);
  // thread_pool_ handles destruction of task.
  // TODO(Fraser#) add amendment task to list
//  AmendRemoteAccountTask *task = new AmendRemoteAccountTask(
//      amend_account_request, callback, vault_service_logic_);
//  thread_pool_.start(task);
}

int VaultService::RemoteVaultAbleToStore(const boost::uint64_t &size,
                                          const std::string &account_pmid,
                                          const std::string &chunkname) {
  maidsafe::AccountStatusRequest as_req;
  as_req.set_account_pmid(account_pmid);
  as_req.set_space_requested(size);
  return vault_service_logic_->RemoteVaultAbleToStore(as_req);
}

RegistrationService::RegistrationService(
    boost::function< void(const maidsafe::VaultConfig&) > notifier)
        : notifier_(notifier),
          status_(maidsafe::NOT_OWNED),
          pending_response_() {}

void RegistrationService::OwnVault(google::protobuf::RpcController*,
                                   const maidsafe::OwnVaultRequest *request,
                                   maidsafe::OwnVaultResponse *response,
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
  boost::filesystem::path chunkdir(request->chunkstore_dir());
  boost::filesystem::space_info info;
  if ("/" != chunkdir.root_directory())
    info = boost::filesystem::space(boost::filesystem::path("/"));
  else
    info = boost::filesystem::space(boost::filesystem::path(chunkdir.root_name()
        + chunkdir.root_directory()));
  if (request->space() > info.available) {
    response->set_result(maidsafe::NOT_ENOUGH_SPACE);
    done->Run();
    return;
  }
  // Checking if keys sent are a correct RSA key pair
  crypto::Crypto cobj;
  cobj.set_hash_algorithm(crypto::SHA_512);
  if (cobj.AsymCheckSig(request->public_key(), request->signed_public_key(),
      request->public_key(), crypto::STRING_STRING)) {
    std::string signed_key = cobj.AsymSign(request->public_key(), "",
        request->private_key(), crypto::STRING_STRING);
    if (cobj.AsymCheckSig(request->public_key(), signed_key,
        request->public_key(), crypto::STRING_STRING)) {
      // checking if port is available
      transport::Transport test_tranport;
      if (request->port() == 0 || test_tranport.IsPortAvailable(
          request->port())) {
        response->set_result(maidsafe::OWNED_SUCCESS);
        std::string pmid_name = cobj.Hash(request->public_key()+
            request->signed_public_key(), "", crypto::STRING_STRING, false);
        response->set_pmid_name(pmid_name);
        pending_response_.callback = done;
        pending_response_.args = response;
        maidsafe::VaultConfig vconfig;
        vconfig.set_pmid_public(request->public_key());
        vconfig.set_pmid_private(request->private_key());
        vconfig.set_signed_pmid_public(request->signed_public_key());
        vconfig.set_chunkstore_dir(request->chunkstore_dir());
        vconfig.set_port(request->port());
        vconfig.set_available_space(request->space());
        notifier_(vconfig);
        return;
      } else {
        response->set_result(maidsafe::INVALID_PORT);
      }
    } else {
      response->set_result(maidsafe::INVALID_RSA_KEYS);
    }
  } else {
    response->set_result(maidsafe::INVALID_RSA_KEYS);
  }
  done->Run();
}

void RegistrationService::IsVaultOwned(google::protobuf::RpcController*,
                                       const maidsafe::IsOwnedRequest*,
                                       maidsafe::IsOwnedResponse *response,
                                       google::protobuf::Closure *done) {
  response->set_status(status_);
  done->Run();
}

void RegistrationService::ReplyOwnVaultRequest(const bool &fail_to_start) {
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
