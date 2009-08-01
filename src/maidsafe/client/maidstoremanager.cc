/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manager allowing maidsafe layer to store data to network
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#include "maidsafe/client/maidstoremanager.h"

#include <stdint.h>

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/tokenizer.hpp>
#include <maidsafe/kademlia_service_messages.pb.h>

#include "fs/filesystem.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

MaidsafeStoreManager::MaidsafeStoreManager() : pdclient_(), cry_obj() {
  // If kad config file exists in dir we're in, use that, otherwise get default
  // path to file.
  std::string kadconfig_str("");
  try {
    if (fs::exists(".kadconfig")) {
      kadconfig_str = ".kadconfig";
    } else {
      file_system::FileSystem fsys;
      fs::path kadconfig_path(fsys.ApplicationDataDir(), fs::native);
      kadconfig_path /= ".kadconfig";
      kadconfig_str = kadconfig_path.string();
    }
  }
  catch(const std::exception &ex) {
#ifdef DEBUG
    printf("%s\n", ex.what());
#endif
  }
  printf("kadconfig_path: %s\n", kadconfig_str.c_str());
  pdclient_ = new PDClient(0, kadconfig_str);
  cry_obj.set_symm_algorithm(crypto::AES_256);
  cry_obj.set_hash_algorithm(crypto::SHA_512);
}

void MaidsafeStoreManager::Init(base::callback_func_type cb) {
//  std::vector<kad::Contact> bs_contacts;
//  std::string boostrapping_ip("192.168.1.89");
//  uint16_t boostrapping_port = static_cast<uint16_t>(
//          base::stoi("62001"));
//  kad::Contact c(kad::vault_random_id(),
//                 boostrapping_ip,
//                 boostrapping_port);
//  bs_contacts.push_back(c);
//  GetBootstrappingNodes(&bs_contacts);
  pdclient_->Join("", boost::bind(
    &MaidsafeStoreManager::SimpleResult_Callback,
    this, _1, cb));
}

void MaidsafeStoreManager::Close(base::callback_func_type cb) {
  pdclient_->Leave(boost::bind(&MaidsafeStoreManager::SimpleResult_Callback,
                               this, _1, cb));
  pdclient_->CleanUp();
}

void MaidsafeStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                     base::callback_func_type cb) {
  std::string chunk_name("");
  base::decode_from_hex(hex_chunk_name, &chunk_name);
  pdclient_->GetChunk(chunk_name,
      boost::bind(&MaidsafeStoreManager::LoadChunk_Callback, this, _1, cb));
}

void MaidsafeStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                      const std::string &content,
                                      const std::string &signature,
                                      const std::string &public_key,
                                      const std::string &signed_public_key,
                                      base::callback_func_type cb) {
  std::string chunk_name("");
  base::decode_from_hex(hex_chunk_name, &chunk_name);
  pdclient_->StoreChunk(chunk_name, content, public_key, signed_public_key,
      signature, DATA, boost::bind(&MaidsafeStoreManager::SimpleResult_Callback,
      this, _1, cb));
}

void MaidsafeStoreManager::IsKeyUnique(const std::string &hex_key,
                                       base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  pdclient_->FindValue(key,
      boost::bind(&MaidsafeStoreManager::IsKeyUnique_Callback, this, _1, cb));
}

void MaidsafeStoreManager::DeletePacket(const std::string &hex_key,
                                        const std::string &signature,
                                        const std::string &public_key,
                                        const std::string &signed_public_key,
                                        const value_types &type,
                                        base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  pdclient_->DeleteChunk(key, public_key, signed_public_key, signature, type,
      boost::bind(&MaidsafeStoreManager::DeleteChunk_Callback, this, _1, cb));
}

void MaidsafeStoreManager::StorePacket(const std::string &hex_key,
                                       const std::string &value,
                                       const std::string &signature,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       const value_types &type,
                                       bool update,
                                       base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  if (update)
    pdclient_->UpdateChunk(key, value, public_key, signed_public_key, signature,
        type, boost::bind(&MaidsafeStoreManager::StoreChunk_Callback, this, _1,
        update, cb));
  else
    pdclient_->StoreChunk(key, value, public_key, signed_public_key, signature,
        type, boost::bind(&MaidsafeStoreManager::StoreChunk_Callback, this, _1,
        update, cb));
}

void MaidsafeStoreManager::LoadPacket(const std::string &hex_key,
                                      base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  pdclient_->GetChunk(key,
      boost::bind(&MaidsafeStoreManager::LoadChunk_Callback, this, _1, cb));
}

void MaidsafeStoreManager::GetMessages(const std::string &hex_key,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  pdclient_->GetMessages(key, public_key, signed_public_key, cb);
}

void MaidsafeStoreManager::LoadChunk_Callback(const std::string &result,
                                              base::callback_func_type cb) {
  GetResponse result_msg;
  if (!result_msg.ParseFromString(result)) {
#ifdef DEBUG
    printf("Load chunk callback doesn't parse.\n");
#endif
    result_msg.set_result(kCallbackFailure);
  } else {
    if (result_msg.has_content()) {
      result_msg.clear_result();
      result_msg.set_result(kCallbackSuccess);
    } else {
#ifdef DEBUG
      printf("Load chunk callback came back with no content.\n");
#endif
      result_msg.clear_result();
      result_msg.set_result(kCallbackFailure);
    }
  }
  std::string ser_result;
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::SimpleResult_Callback(const std::string &result,
  base::callback_func_type cb) {
#ifdef DEBUG
  printf("Inside MaidsafeStoreManager::SimpleResult_Callback\n");
#endif
  base::GeneralResponse result_msg;
  if ((!result_msg.ParseFromString(result))||
      (result_msg.result() != kad::kRpcResultSuccess)) {
    result_msg.clear_result();
    result_msg.set_result(kCallbackFailure);
  } else {
    result_msg.clear_result();
    result_msg.set_result(kCallbackSuccess);
  }
  std::string ser_result;
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::IsKeyUnique_Callback(const std::string &result,
  base::callback_func_type cb) {
  kad::FindResponse result_msg;
  base::GeneralResponse local_result;
  std::string ser_result;
  if (!result_msg.ParseFromString(result)) {
    local_result.set_result(kCallbackSuccess);
    local_result.SerializeToString(&ser_result);
    cb(ser_result);
    return;
  }

  if (result_msg.result() == kad::kRpcResultFailure) {
    local_result.set_result(kCallbackSuccess);
    local_result.SerializeToString(&ser_result);
    cb(ser_result);
    return;
  }

  if (result_msg.values_size() == 0) {
    local_result.set_result(kCallbackSuccess);
  } else {
    local_result.set_result(kCallbackFailure);
  }
  local_result.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::GetMsgs_Callback(const std::string &result,
  base::callback_func_type cb) {
  GetMessagesResponse result_msg;
  if ((!result_msg.ParseFromString(result))||
      (result_msg.result() != kad::kRpcResultSuccess)) {
    result_msg.set_result(kCallbackFailure);
  } else {
    result_msg.clear_result();
    result_msg.set_result(kCallbackSuccess);
  }
  std::string ser_result;
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::StoreChunk_Callback(const std::string &result,
  const bool &update, base::callback_func_type cb) {
  std::string ser_result;
  if (update) {
    UpdateResponse result_msg;
    if (!result_msg.ParseFromString(result)) {
      result_msg.set_result(kCallbackFailure);
    } else if (result_msg.result() == kad::kRpcResultSuccess) {
      result_msg.clear_result();
      result_msg.set_result(kCallbackSuccess);
    } else {
      result_msg.clear_result();
      result_msg.set_result(kCallbackFailure);
    }
    result_msg.SerializeToString(&ser_result);
    cb(result);
  } else {
    StoreResponse result_msg;
    if (!result_msg.ParseFromString(result)) {
      result_msg.set_result(kCallbackFailure);
    } else if (result_msg.result() == kad::kRpcResultSuccess) {
      result_msg.clear_result();
      result_msg.set_result(kCallbackSuccess);
    } else {
      result_msg.clear_result();
      result_msg.set_result(kCallbackFailure);
    }
    result_msg.SerializeToString(&ser_result);
    cb(result);
  }
}

void MaidsafeStoreManager::DeleteChunk_Callback(const std::string &result,
  base::callback_func_type cb) {
  DeleteResponse result_msg;
  if (!result_msg.ParseFromString(result)) {
    result_msg.set_result(kCallbackFailure);
  } else {
    if (result_msg.result() == kad::kRpcResultSuccess) {
      result_msg.clear_result();
      result_msg.set_result(kCallbackSuccess);
    } else {
      result_msg.clear_result();
      result_msg.set_result(kCallbackFailure);
    }
  }
  std::string ser_result;
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

}  // namespace maidsafe
