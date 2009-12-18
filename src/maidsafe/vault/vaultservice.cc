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

#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
#include "maidsafe/crypto.h"

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

VaultService::VaultService(const std::string &pmid_public,
                           const std::string &pmid_private,
                           const std::string &pmid_public_signature,
                           VaultChunkStore *vault_chunkstore,
                           kad::KNode *knode,
                           PendingOperationsHandler *poh)
    : pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      pmid_public_signature_(pmid_public_signature),
      pmid_(""),
      non_hex_pmid_(""),
      vault_chunkstore_(vault_chunkstore),
      knode_(knode),
      poh_(poh) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  pmid_ = co.Hash(pmid_public + pmid_public_signature_, "",
                  crypto::STRING_STRING, true);
  non_hex_pmid_ = base::DecodeFromHex(pmid_);
}

void VaultService::StorePrep(google::protobuf::RpcController*,
                             const maidsafe::StorePrepRequest* request,
                             maidsafe::StorePrepResponse* response,
                             google::protobuf::Closure* done) {
#ifdef DEBUG
//  printf("In VaultService::StorePrep (%i), Chunk name: %s\n",
//         knode_->host_port(), HexSubstr(request->chunkname()).c_str());
#endif
/*  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunkPrep (%i), request isn't initialized.\n",
           knode_->host_port());
#endif
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunkPrep (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    return;
  }
  // Check we're not being asked to store ourselves as a reference holder for
  // ourself.
  if (request->pmid() == non_hex_pmid_) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("Of all the vaults in all the worlds, you had to try and store a "
           "reference packet here.  Feck off. (%s)\n",
           HexSubstr(non_hex_pmid_).c_str());
#endif
    return;
  }
  boost::uint64_t data_size = request->data_size();
  if (Storable(data_size) != 0) {
#ifdef DEBUG
    printf("In VaultService::StoreChunkPrep (%i), no space.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }
  int n = poh_->AddPendingOperation(request->pmid(), request->chunkname(),
                                    request->data_size(), "", "", 0,
                                    request->public_key(), STORE_ACCEPTED);
  if (n != 0) {
#ifdef DEBUG
    printf("In VaultService::StoreChunkPrep (%i), failed to add pending "
           "operation.\n", knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }
  maidsafe::IOUAuthority iou_authority;
  iou_authority.set_data_size(data_size);
  iou_authority.set_pmid(non_hex_pmid_);
  std::string iou_authority_str;
  iou_authority.SerializeToString(&iou_authority_str);
  response->set_result(kAck);
  response->set_iou_authority(iou_authority_str);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  response->set_signed_iou_authority(co.AsymSign(iou_authority_str, "",
      pmid_private_, crypto::STRING_STRING));
  done->Run();*/
}

void VaultService::StoreChunk(google::protobuf::RpcController*,
                              const maidsafe::StoreChunkRequest* request,
                              maidsafe::StoreChunkResponse* response,
                              google::protobuf::Closure* done) {
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
  response->set_pmid(non_hex_pmid_);/*
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), request is not initialized.\n",
           knode_->host_port());
#endif
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    return;
  }
  bool valid_data = false;
  maidsafe::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
//    case maidsafe::SYSTEM_PACKET:
    case maidsafe::PDDIR_SIGNED: if (ValidateSystemPacket(request->data(),
                                     request->public_key()))
                                   valid_data = true;
                                 break;
//    case maidsafe::BUFFER_PACKET: if (vbph.ValidateOwnerSignature(
//                                      request->public_key(), request->data()))
//                                    valid_data = true;
//                                  break;
    // TODO(David/Fraser#5#): check the validity of a pddir not signed DB
    case maidsafe::PDDIR_NOTSIGNED: valid_data = true;
                                    break;
    case maidsafe::DATA: if (ValidateDataChunk(request->chunkname(),
                             request->data()))
                           valid_data = true;
                         break;
    default: break;  // No specific check for data
  }

  // TODO(Team#5#): check IOU's and signatures before storing the chunk
  // TODO(Team#5#): check available space in the vault's quota
  if (valid_data) {
    int n = poh_->FindOperation(request->pmid(), request->chunkname(),
                                request->data().size(), "", "",
                                STORE_ACCEPTED);
    if (n != 0) {
#ifdef DEBUG
      printf("In VaultService::StoreChunk (%i), not a pending operation.\n",
      knode_->host_port());
#endif
      response->set_result(kNack);
      done->Run();
      return;
    }

    std::string key = request->chunkname();
    if (!StoreChunkLocal(key, request->data())) {
      response->set_result(kNack);
      done->Run();
#ifdef DEBUG
      printf("In VaultService::StoreChunk (%i), ", knode_->host_port());
      printf("failed to store chunk locally.\n");
#endif
      return;
    }
#ifdef DEBUG
//      printf("In VaultService::StoreChunk (%i), stored chunk locally.\n",
//             knode_->host_port());
#endif
    n = poh_->AdvanceStatus(request->pmid(), request->chunkname(),
                                request->data().size(), "", "", "",
                                STORE_DONE);
    if (n != 0) {
#ifdef DEBUG
      printf("In VaultService::StoreChunk (%i), failed to advance to status "
             "STORE_DONE.\n", knode_->host_port());
#endif
      response->set_result(kNack);
      done->Run();
      return;
    }
    response->set_result(kAck);
  } else {
#ifdef DEBUG
    printf("In VaultService::StoreChunk (%i), failed to validate data.\n",
           knode_->host_port());
#endif
    response->set_result(kNack);
  }
#ifdef DEBUG
//  printf("Vault %i stored chunk %s\n", knode_->host_port(),
//         HexSubstr(request->chunkname()).c_str());
#endif
  done->Run();*/
}

void VaultService::StorePacket(google::protobuf::RpcController*,
                               const maidsafe::StorePacketRequest* request,
                               maidsafe::StorePacketResponse* response,
                               google::protobuf::Closure* done) {
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
    knode_->StoreValue(request->packetname(), sig_value, pmid_public_,
                       pmid_public_signature_, request_signature, 86400,
                       &vsvc_dummy_callback);
  }

  done->Run();
}

void VaultService::StoreChunkReference(
    google::protobuf::RpcController*,
    const maidsafe::AddToReferenceListRequest* request,
    maidsafe::AddToReferenceListResponse* response,
    google::protobuf::Closure* done) {
#ifdef DEBUG
//  printf("In VaultService::StoreChunkReference (%i), Chunk name: %s, "
//         "PMID: %s\n", knode_->host_port(),
//         HexSubstr(request->chunkname()).c_str(),
//         base::EncodeToHex(request->pmid()).substr(0, 10).c_str());
#endif
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunkReference (%i), "
           "request isn't initialized.\n", knode_->host_port());
#endif
    return;
  }
/*  if (!ValidateSignedRequest(request->public_key(),
       request->public_key_signature(), request->request_signature(),
       request->chunkname(), request->pmid())) {
    response->set_result(kNack);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunkReference (%i), ", knode_->host_port());
    printf("failed to validate signed request.\n");
#endif
    return;
  }

  if (!request->has_no_iou_rank()) {
    std::string iou;
    boost::uint64_t chunksize;
    int n = poh_->GetSizeAndIOU(request->pmid(), request->chunkname(),
                                &chunksize, &iou);
    if (n != 0) {
  #ifdef DEBUG
      printf("In VaultService::StoreChunkReference (%i), failed to get IOU"
             " for chunk %s saved by vault %s\n", knode_->host_port(),
             HexSubstr(request->chunkname()).c_str(),
             HexSubstr(request->pmid()).c_str());
  #endif
      response->set_result(kNack);
      done->Run();
      return;
    }
    response->set_iou(iou);
    n = poh_->AdvanceStatus(request->pmid(), request->chunkname(), 0, "", "",
                            "", IOU_COLLECTED);
    if (n != 0) {
  #ifdef DEBUG
      printf("In VaultService::StoreChunkReference (%i), failed to advance to "
             "status IOU_COLLECTED.\n", knode_->host_port());
  #endif
      response->set_result(kNack);
      done->Run();
      return;
    }

    std::string ra;
    std::string ra_signature;
    RankAuthorityGenerator(request->chunkname(), chunksize, request->pmid(),
                           &ra, &ra_signature);
    response->set_rank_authority(ra);
    response->set_rank_authority_signature(ra_signature);
  }
  kad::SignedValue signed_value;
  signed_value.set_value(request->pmid());
  signed_value.set_value_signature(request->signed_pmid());
  std::string ser_signed_value;
  bool ser_ok = signed_value.SerializeToString(&ser_signed_value);
  if (!ser_ok ||
      !knode_->StoreValueLocal(request->chunkname(), ser_signed_value, 86400)) {
#ifdef DEBUG
    printf("In VaultService::StoreChunkReference (%i), failed to store pmid to"
           "local ref packet.\n", knode_->host_port());
#endif
    response->set_result(kNack);
    done->Run();
    return;
  }

  response->set_public_key(pmid_public_);
  response->set_public_key_signature(pmid_public_signature_);
  response->set_result(kAck);
  done->Run();*/
}

void VaultService::GetChunk(google::protobuf::RpcController*,
                            const maidsafe::GetChunkRequest* request,
                            maidsafe::GetChunkResponse* response,
                            google::protobuf::Closure* done) {
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
                             const maidsafe::GetPacketRequest* request,
                             maidsafe::GetPacketResponse* response,
                             google::protobuf::Closure* done) {
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

void VaultService::CheckChunk(google::protobuf::RpcController*,
                              const maidsafe::CheckChunkRequest* request,
                              maidsafe::CheckChunkResponse* response,
                              google::protobuf::Closure* done) {
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

void VaultService::UpdateChunk(google::protobuf::RpcController*,
                               const maidsafe::UpdateChunkRequest* request,
                               maidsafe::UpdateChunkResponse* response,
                               google::protobuf::Closure* done) {
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

//  void VaultService::GetMessages(google::protobuf::RpcController*,
//                                const maidsafe::GetBPMessagesRequest* request,
//                                 maidsafe::GetBPMessagesResponse* response,
//                                 google::protobuf::Closure* done) {
//    response->set_pmid(non_hex_pmid_);
//    if (!request->IsInitialized()) {
//      response->set_result(kNack);
//      done->Run();
//      return;
//    }
//    crypto::Crypto co;
//    co.set_symm_algorithm(crypto::AES_256);
//    co.set_hash_algorithm(crypto::SHA_512);
//    if (!co.AsymCheckSig(request->public_key(),
//        request->public_key_signature(), request->public_key(),
//        crypto::STRING_STRING)) {
//      response->set_result(kNack);
//      done->Run();
//      return;
//    }
//    std::string content;
//    if (LoadChunkLocal(request->buffer_packet_name(), &content)) {
//      maidsafe::VaultBufferPacketHandler vbph;
//      if (!vbph.ValidateOwnerSignature(request->public_key(), content)) {
//        response->set_result(kNack);
//        done->Run();
//        return;
//      }
//      std::vector<std::string> msgs;
//      if (!vbph.GetMessages(content, &msgs)) {
//        response->set_result(kNack);
//      } else {
//        for (int i = 0; i < static_cast<int>(msgs.size()); i++)
//          response->add_messages(msgs[i]);
//        response->set_result(kAck);
//      }
//    } else {
//      response->set_result(kNack);
//    }
//    done->Run();
//  }

void VaultService::DeleteChunk(google::protobuf::RpcController*,
                               const maidsafe::DeleteChunkRequest* request,
                               maidsafe::DeleteChunkResponse* response,
                               google::protobuf::Closure* done) {
#ifdef DEBUG
//  printf("In VaultService::DeleteChunk (%i)\n", knode_->host_port());
#endif
  response->set_pmid(non_hex_pmid_);
  if (!request->IsInitialized()) {
    response->set_result(kNack);
    done->Run();
    return;
  }
/*  if (!ValidateSignedRequest(request->public_key(),
      request->public_key_signature(), request->request_signature(),
      request->chunkname(), request->pmid_id())) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  std::string content;
  if (!LoadChunkLocal(request->chunkname(), &content)) {
    response->set_result(kNack);
    done->Run();
    return;
  }
  bool can_delete = false;

  // TODO(david/jose): define how to delete chunk references of signed
  // chunks and then just check the signature and delete it
  maidsafe::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
    case maidsafe::SYSTEM_PACKET: if (ValidateSystemPacket(content,
                                         request->public_key()))
                                    can_delete = true;
                                  break;
    case maidsafe::PDDIR_SIGNED: if (ValidateSystemPacket(content,
                                         request->public_key()))
                                   can_delete = true;
                                 break;
    default: break;
  }
  if (can_delete) {
    if (request->data_type() != maidsafe::BUFFER_PACKET_MESSAGE) {
      if (DeleteChunkLocal(request->chunkname()))
        response->set_result(kAck);
      else
        response->set_result(kNack);
    } else {
      if (UpdateChunkLocal(request->chunkname(), content))
        response->set_result(kAck);
      else
        response->set_result(kNack);
    }
  } else {
    response->set_result(kNack);
  }
  done->Run();*/
}

void VaultService::ValidityCheck(google::protobuf::RpcController*,
                                 const maidsafe::ValidityCheckRequest* request,
                                 maidsafe::ValidityCheckResponse* response,
                                 google::protobuf::Closure* done) {
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
                             const maidsafe::SwapChunkRequest* request,
                             maidsafe::SwapChunkResponse* response,
                             google::protobuf::Closure* done) {
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
      StoreChunkReference(key);
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
                               const maidsafe::VaultStatusRequest* request,
                               maidsafe::VaultStatusResponse* response,
                               google::protobuf::Closure* done) {
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
                            const maidsafe::CreateBPRequest* request,
                            maidsafe::CreateBPResponse* response,
                            google::protobuf::Closure* done) {
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
    knode_->StoreValue(request->bufferpacket_name(), sig_value, pmid_public_,
      pmid_public_signature_, request_signature, 86400,  &vsvc_dummy_callback);
  }
  response->set_result(kAck);
  done->Run();
}

void VaultService::ModifyBPInfo(google::protobuf::RpcController*,
                                const maidsafe::ModifyBPInfoRequest* request,
                                maidsafe::ModifyBPInfoResponse* response,
                                google::protobuf::Closure* done) {
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
                                 const maidsafe::GetBPMessagesRequest* request,
                                 maidsafe::GetBPMessagesResponse* response,
                                 google::protobuf::Closure* done) {
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
                                const maidsafe::AddBPMessageRequest* request,
                                maidsafe::AddBPMessageResponse* response,
                                google::protobuf::Closure* done) {
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

bool VaultService::ValidateSignedRequest(
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &request_signature,
    const std::string &key,
    const std::string &signing_id) {
  if (request_signature == kAnonymousSignedRequest)
    return true;
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  if (signing_id.empty() || signing_id != co.Hash(public_key +
      public_key_signature, "", crypto::STRING_STRING, false)) {
#ifdef DEBUG
    if (signing_id.empty())
      printf("VaultService::ValidateSignedRequest - Empty id\n");
    else
      printf("VaultService::ValidateSignedRequest - Wrong id\n");
    printf("VaultService::ValidateSignedRequest: Didn't validate signing_id %s"
           "\n", HexSubstr(signing_id).c_str());
#endif
    return false;
  }
  if (co.AsymCheckSig(co.Hash(public_key_signature + key +
      non_hex_pmid_, "", crypto::STRING_STRING, false), request_signature,
      public_key, crypto::STRING_STRING))
    return true;
// TODO(Fraser#5#): 2009-08-25 - Remove this second check once all requests are
//                               signed the first way (above).
  return co.AsymCheckSig(co.Hash(public_key + public_key_signature +
    key, "", crypto::STRING_STRING, false), request_signature, public_key,
    crypto::STRING_STRING);
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
  return data_size <= vault_chunkstore_->FreeSpace() ? 0 : -1;
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
                                   maidsafe::GetPacketResponse* response) {
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

void VaultService::StoreChunkReference(const std::string &non_hex_chunkname) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string request_signature = co.AsymSign(co.Hash(pmid_public_ +
      pmid_public_signature_ + non_hex_chunkname, "", crypto::STRING_STRING,
      false), "", pmid_private_, crypto::STRING_STRING);
  kad::ContactInfo ci = knode_->contact_info();
  std::string contact_info;
  ci.SerializeToString(&contact_info);
//  #ifdef DEBUG
//    if (!crypto_.AsymCheckSig(pmid_public_, pmid_public_signature_,
//        pmid_public_, crypto::STRING_STRING))
//      printf("Pa variar, la firma valio vergaaaaaaaa!");
//  #endif
  kad::SignedValue signed_value;
  signed_value.set_value(contact_info);
  signed_value.set_value_signature(co.AsymSign(contact_info, "", pmid_private_,
                                               crypto::STRING_STRING));
  knode_->StoreValue(non_hex_chunkname,
                     signed_value,
                     pmid_public_,
                     pmid_public_signature_,
                     request_signature,
                     86400,
                     &vsvc_dummy_callback);
  return;
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

RegistrationService::RegistrationService(boost::function< void(
      const maidsafe::VaultConfig&) > notifier) : notifier_(notifier),
        status_(maidsafe::NOT_OWNED), pending_response_() {}

void RegistrationService::OwnVault(google::protobuf::RpcController* ,
      const maidsafe::OwnVaultRequest* request,
      maidsafe::OwnVaultResponse* response, google::protobuf::Closure* done) {
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
      const maidsafe::IsOwnedRequest*, maidsafe::IsOwnedResponse* response,
      google::protobuf::Closure* done) {
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
