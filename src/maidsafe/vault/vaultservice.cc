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

#include "maidsafe/vault/vaultservice.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>

#include "maidsafe/maidsafe.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
#include "protobuf/kademlia_service_messages.pb.h"

namespace maidsafe_vault {

void vsvc_dummy_callback(const std::string &) {}

VaultService::VaultService(const std::string &pmid_public,
                           const std::string &pmid_private,
                           const std::string &signed_pmid_public,
                           boost::shared_ptr<ChunkStore>chunkstore,
                           kad::KNode *knode)
    : crypto_(),
      pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      signed_pmid_public_(signed_pmid_public),
      pmid_(""),
      chunkstore_(chunkstore),
      knode_(knode) {
//  printf("In VaultService contructor.\n");
  crypto_.set_symm_algorithm("AES_256");
  crypto_.set_hash_algorithm("SHA512");
  pmid_ = crypto_.Hash(signed_pmid_public_, "", maidsafe_crypto::STRING_STRING,
                       true);
}

void VaultService::StoreChunk(google::protobuf::RpcController*,
                         const maidsafe::StoreRequest* request,
                         maidsafe::StoreResponse* response,
                         google::protobuf::Closure* done) {
//  printf("Chunk name: %s\n", request->chunkname().c_str());
//  printf("Chunk content: %s\n", request->data().c_str());
#ifdef DEBUG
//  printf("In VaultService::StoreChunk, Public Key: %s\n",
//    request->public_key().c_str());
#endif
//  printf("Signed Pub Key: %s\n", request->signed_public_key().c_str());
//  printf("Signed Request: %s\n", request->signed_request().c_str());
//  printf("Data Type: %i\n", request->data_type());
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunk, request is not initialized.\n");
#endif
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
       request->signed_public_key(), request->signed_request(),
       request->chunkname())) {
    response->set_result(kCallbackFailure);
    done->Run();
#ifdef DEBUG
    printf("In VaultService::StoreChunk, failed to validate signed request.\n");
#endif
    return;
  }
  bool valid_data = false;
  packethandler::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
    case maidsafe::SYSTEM_PACKET: if (ValidateSystemPacket(request->data(),
                                      request->public_key()))
                                    valid_data = true;
                                  break;
    case maidsafe::PDDIR_SIGNED: if (ValidateSystemPacket(request->data(),
                                     request->public_key()))
                                   valid_data = true;
                                 break;
    case maidsafe::BUFFER_PACKET: if (vbph.ValidateOwnerSignature(
                                      request->public_key(), request->data()))
                                    valid_data = true;
                                  break;
    // TODO(David/Fraser#5#): check the validity of a pddir not signed DB
    case maidsafe::PDDIR_NOTSIGNED: valid_data = true;
                                    break;
    case maidsafe::DATA: if (ValidateDataChunk(request->chunkname(),
                             request->data()))
                           valid_data = true;
                         break;
    default: break;  // No specific check for data
  }

  // TODO(jose) check IOU's and signatures before storing the chunk
  // TODO(jose) check available space in the vault's quota
  if (valid_data) {
    std::string key = request->chunkname();
    if (!StoreChunkLocal(key, request->data())) {
      response->set_result(kCallbackFailure);
      done->Run();
#ifdef DEBUG
      printf("In VaultService::StoreChunk, failed to store chunk locally.\n");
#endif
      return;
    }
#ifdef DEBUG
      printf("In VaultService::StoreChunk, stored chunk locally.\n");
#endif
    StoreChunkReference(key);
    response->set_result(kCallbackSuccess);
  } else {
#ifdef DEBUG
    printf("In VaultService::StoreChunk, failed to validate data.\n");
#endif
    response->set_result(kCallbackFailure);
  }
#ifdef DEBUG
  printf("In VaultService::StoreChunk, returning result %s\n",
    response->result().c_str());
#endif
  done->Run();
}

void VaultService::Get(google::protobuf::RpcController*,
                       const maidsafe::GetRequest* request,
                       maidsafe::GetResponse* response,
                       google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  std::string content;
  if (LoadChunkLocal(request->chunkname(), &content)) {
    response->set_result(kCallbackSuccess);
    response->set_content(content);
  } else {
    printf("no tiene la mierda\n");
    response->set_result(kCallbackFailure);
  }
  done->Run();
}

void VaultService::CheckChunk(google::protobuf::RpcController*,
                              const maidsafe::CheckChunkRequest* request,
                              maidsafe::CheckChunkResponse* response,
                              google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  if (HasChunkLocal(request->chunkname()))
    response->set_result(kCallbackSuccess);
  else
    response->set_result(kCallbackFailure);
  done->Run();
}

void VaultService::Update(google::protobuf::RpcController*,
                          const maidsafe::UpdateRequest* request,
                          maidsafe::UpdateResponse* response,
                          google::protobuf::Closure* done) {
#ifdef DEBUG
  printf("Pub key: %s.\n", request->public_key().c_str());
#endif
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
       request->signed_public_key(), request->signed_request(),
       request->chunkname())) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  bool valid_data = false;
  std::string current_content;
  if (!LoadChunkLocal(request->chunkname(), &current_content)) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }

  packethandler::GenericPacket gp;
  std::string updated_value;
  packethandler::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
    case maidsafe::SYSTEM_PACKET: if ((ValidateSystemPacket(request->data(),
                                         request->public_key())) &&
                                      (ValidateSystemPacket(current_content,
                                         request->public_key()))) {
                                   updated_value = request->data();
                                   valid_data = true;
                                  }
                                 break;
    case maidsafe::BUFFER_PACKET_MESSAGE: if (vbph.AddMessage(
                                              current_content,
                                              request->data(),
                                              request->signed_public_key(),
                                              &updated_value))
                                            valid_data = true;
                                          break;
    case maidsafe::PDDIR_SIGNED: if (ValidateSystemPacket(request->data(),
                                      request->public_key())) {
                                   if (ValidateSystemPacket(current_content,
                                        request->public_key())) {
                                      updated_value = request->data();
                                      valid_data = true;
                                   } else {
                                      printf("Current data not validated.\n");
                                   }
                                 } else {
                                   printf("New data not validated.\n");
                                 }
                                 break;
    case maidsafe::BUFFER_PACKET_INFO: if (ModifyBufferPacketInfo(
                                             request->data(),
                                             request->public_key(),
                                             &current_content)) {
                                         updated_value = current_content;
                                         valid_data = true;
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
      response->set_result(kCallbackFailure);
      done->Run();
      return;
    }
  } else {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  response->set_result(kCallbackSuccess);
  done->Run();
  return;
}

void VaultService::GetMessages(google::protobuf::RpcController*,
                               const maidsafe::GetMessagesRequest* request,
                               maidsafe::GetMessagesResponse* response,
                               google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  if (!crypto_.AsymCheckSig(request->public_key(), request->signed_public_key(),
      request->public_key(), maidsafe_crypto::STRING_STRING)) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  std::string content;
  if (LoadChunkLocal(request->buffer_packet_name(), &content)) {
    packethandler::VaultBufferPacketHandler vbph;
    if (!vbph.ValidateOwnerSignature(request->public_key(), content)) {
      response->set_result(kCallbackFailure);
      done->Run();
      return;
    }
    std::vector<std::string> msgs;
    if (!vbph.GetMessages(content, &msgs)) {
      response->set_result(kCallbackFailure);
    } else {
      for (int i = 0; i < static_cast<int>(msgs.size()); i++)
        response->add_messages(msgs[i]);
      response->set_result(kCallbackSuccess);
    }
  } else {
    response->set_result(kCallbackFailure);
  }
  done->Run();
}

void VaultService::Delete(google::protobuf::RpcController*,
                          const maidsafe::DeleteRequest* request,
                          maidsafe::DeleteResponse* response,
                          google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  if (!ValidateSignedRequest(request->public_key(),
      request->signed_public_key(), request->signed_request(),
      request->chunkname())) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  std::string content;
  if (!LoadChunkLocal(request->chunkname(), &content)) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  bool can_delete = false;

  // TODO(david/jose): define how to delete chunk references of signed
  // chunks and then just check the signature and delete it
  packethandler::VaultBufferPacketHandler vbph;
  switch (request->data_type()) {
    case maidsafe::SYSTEM_PACKET: if (ValidateSystemPacket(content,
                                         request->public_key()))
                                    can_delete = true;
                                  break;
    case maidsafe::BUFFER_PACKET:
        if (vbph.ValidateOwnerSignature(request->public_key(), content))
          can_delete = true;
        break;
    case maidsafe::BUFFER_PACKET_MESSAGE:
        if (vbph.ValidateOwnerSignature(request->public_key(), content))
          if (vbph.ClearMessages(&content))
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
        response->set_result(kCallbackSuccess);
      else
        response->set_result(kCallbackFailure);
    } else {
      if (UpdateChunkLocal(request->chunkname(), content))
        response->set_result(kCallbackSuccess);
      else
        response->set_result(kCallbackFailure);
    }
  } else {
    response->set_result(kCallbackFailure);
  }
  done->Run();
}

void VaultService::ValidityCheck(google::protobuf::RpcController*,
                                 const maidsafe::ValidityCheckRequest* request,
                                 maidsafe::ValidityCheckResponse* response,
                                 google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  std::string chunk_content;
  if (!LoadChunkLocal(request->chunkname(), &chunk_content)) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  // TODO(Fraser#5#): 2009-03-18 - we should probably do a self-check here and
  //                  return kCallbackFailure if we fail and try and get another
  //                  uncorrupted copy.
  std::string hcontent = crypto_.Hash(chunk_content +
      request->random_data(), "", maidsafe_crypto::STRING_STRING, false);
  response->set_result(kCallbackSuccess);
  response->set_hash_content(hcontent);
  done->Run();
}

void VaultService::SwapChunk(google::protobuf::RpcController*,
                             const maidsafe::SwapChunkRequest* request,
                             maidsafe::SwapChunkResponse* response,
                             google::protobuf::Closure* done) {
  std::string id;
  base::decode_from_hex(pmid_, id);
  response->set_pmid_id(id);
  if (!request->IsInitialized()) {
    response->set_result(kCallbackFailure);
    done->Run();
    return;
  }
  response->set_request_type(request->request_type());
  response->set_chunkname1(request->chunkname1());
  if (request->request_type() == 0) {
    // negotiate, Make request type constant layer
    if (HasChunkLocal(request->chunkname1())) {
      response->set_result(kCallbackFailure);
      done->Run();
      return;
    }
    // Select a local chunk of a similar size +-10%
    // Use random chunk temporarily
    std::string chunkname2;
    std::string chunkcontent2;
    if (!chunkstore_->LoadRandomChunk(&chunkname2, &chunkcontent2)) {
      response->set_result(kCallbackFailure);
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
        response->set_result(kCallbackFailure);
        done->Run();
        return;
      }
      StoreChunkReference(key);
      std::string chunkcontent2;
      if (!LoadChunkLocal(request->chunkname2(), &chunkcontent2)) {
        response->set_result(kCallbackFailure);
        done->Run();
        return;
      }
      response->set_chunkname2(request->chunkname2());
      response->set_chunkcontent2(chunkcontent2);
    }
  } else {
      response->set_result(kCallbackFailure);
      done->Run();
      return;
  }
  response->set_result(kCallbackSuccess);
  done->Run();
}

bool VaultService::ValidateSignedRequest(const std::string &public_key,
                                         const std::string &signed_public_key,
                                         const std::string &signed_request,
                                         const std::string &key) {
  if (crypto_.AsymCheckSig(public_key, signed_public_key, public_key,
                           maidsafe_crypto::STRING_STRING)) {
    std::string encoded_key;
    base::encode_to_hex(key, encoded_key);
    return crypto_.AsymCheckSig(crypto_.Hash(public_key + signed_public_key +
      encoded_key, "", maidsafe_crypto::STRING_STRING, true), signed_request,
      public_key, maidsafe_crypto::STRING_STRING);
  } else {
    printf("Failed to check Signature\n");
    return false;
  }
}

bool VaultService::ValidateSystemPacket(const std::string &ser_content,
                                        const std::string &public_key) {
  packethandler::GenericPacket gp;
  if (!gp.ParseFromString(ser_content))
    return false;
  return crypto_.AsymCheckSig(gp.data(), gp.signature(), public_key,
    maidsafe_crypto::STRING_STRING);
}

bool VaultService::ValidateDataChunk(const std::string &chunkname,
                                     const std::string &content) {
  std::string computed_chunkname = crypto_.Hash(content, "",
    maidsafe_crypto::STRING_STRING, false);
  if (chunkname == computed_chunkname)
    return true;
  else
    return false;
}

bool VaultService::ModifyBufferPacketInfo(const std::string &new_info,
                                          const std::string &pub_key,
                                          std::string *updated_bp) {
  if (!ValidateSystemPacket(new_info, pub_key)) {
    return false;
  }
  packethandler::VaultBufferPacketHandler vbph;
  if (vbph.ChangeOwnerInfo(new_info, updated_bp, pub_key))
    return true;
  else
    return false;
}

bool VaultService::HasChunkLocal(const std::string &chunkname) {
  return chunkstore_->HasChunk(chunkname);
}

bool VaultService::StoreChunkLocal(const std::string &chunkname,
                                   const std::string &content) {
  return chunkstore_->StoreChunk(chunkname, content);
}

bool VaultService::UpdateChunkLocal(const std::string &chunkname,
                                    const std::string &content) {
  return chunkstore_->UpdateChunk(chunkname, content);
}

bool VaultService::LoadChunkLocal(const std::string &chunkname,
                                  std::string *content) {
  return chunkstore_->LoadChunk(chunkname, content);
}

bool VaultService::DeleteChunkLocal(const std::string &chunkname) {
  return chunkstore_->DeleteChunk(chunkname);
}

void VaultService::StoreChunkReference(const std::string &chunk_name) {
  std::string signed_request_ = crypto_.AsymSign(
      crypto_.Hash(pmid_public_ + signed_pmid_public_ + chunk_name,
                   "",
                   maidsafe_crypto::STRING_STRING,
                   true),
      "",
      pmid_private_,
      maidsafe_crypto::STRING_STRING);
  kad::ContactInfo ci = knode_->contact_info();
  std::string contact_info;
  ci.SerializeToString(&contact_info);
#ifdef DEBUG
  if (!crypto_.AsymCheckSig(pmid_public_, signed_pmid_public_, pmid_public_,
      maidsafe_crypto::STRING_STRING))
    printf("Pa variar, la firma valio vergaaaaaaaa!");
#endif
  knode_->StoreValue(chunk_name,
                     contact_info,
                     pmid_public_,
                     signed_pmid_public_,
                     signed_request_,
                     &vsvc_dummy_callback);
  return;
}
}  // namespace maidsafe_vault
