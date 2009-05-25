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

#include "fs/filesystem.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

MaidsafeStoreManager::MaidsafeStoreManager()
    : datastore_dir_(""),
      pdclient_(),
      cry_obj() {
  file_system::FileSystem fsys;
  fs::path datastore_path(fsys.DbDir(), fs::native);
  datastore_dir_ = datastore_path.string();
  // If kad config file exists in dir we're in, use that, otherwise get default
  // path to file.
  std::string kadconfig_str("");
  try {
    if (fs::exists(".kadconfig")) {
      kadconfig_str = ".kadconfig";
    } else {
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
  pdclient_ = new PDClient(datastore_dir_,
                           0,
                           kadconfig_str);
  cry_obj.set_symm_algorithm("AES_256");
  cry_obj.set_hash_algorithm("SHA512");
}

MaidsafeStoreManager::~MaidsafeStoreManager() {
  try {
    fs::remove_all(datastore_dir_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("error: %s\n", e.what());
#endif
  }
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

//  bool MaidsafeStoreManager::GetBootstrappingNodes(
//    // TODO(Richard): we should put this to somewhere else instead here...
//    fs::path config_file(datastore_dir_, fs::native);
//    config_file /= kConfigFileName;
//    if (!fs::exists(config_file)) {
//      // create a default one if the config file doesn't exist
//      try {
//        fs::ofstream fstr;
//        fstr.open(config_file, std::ios_base::binary);
//        const int kBufSize = 200;
//        char buf[kBufSize];
//        snprintf(buf,
//                 kBufSize,
//                 "network:\r\n{\r\nbootstrap_nodes = (%s);\r\n};\r\n",
//                 kOffcialBootStrapNode.c_str());
//        fstr << buf;
//        fstr.close();
//      }
//      catch(const std::exception &ex) {
//  #ifdef DEBUG
//        printf("MaidsafeStoreManager::GetBootstrappingNodes exception ");
//        printf("creating config file: %s\n", ex.what());
//  #endif
//        return false;
//      }
//    }
//    catch(const std::exception &ex) {
// #ifdef DEBUG
//      printf("MaidsafeStoreManager::GetBootstrappingNodes exception ");
//      printf("creating config file: %s\n", ex.what());
// #endif
//      return false;
//    }
//    if (bootstrap_nodes.empty()) {
//  #ifdef DEBUG
//      printf("There are no bootstrapping nodes in the config file.\n");
//  #endif
//      return false;
//    }
//    for (uint32_t i = 0; i < bootstrap_nodes.size(); ++i) {
//      // parse boostrapping node ip:port
//      std::string bootstrap_str = bootstrap_nodes[i];
//      if (bootstrap_str != "") {
//        const int kBootstrapStrSize = bootstrap_str.size();
//        boost::scoped_ptr<char>bootstrap_cstr_(new char[kBootstrapStrSize+1]);
//        for (int i = 0; i <= kBootstrapStrSize; ++i) {
//          bootstrap_cstr_.get()[i] = bootstrap_str.c_str()[i];
//        }
//        std::string boostrapping_ip("");
//        uint16_t boostrapping_port = 0;
//        try {
//          boost::char_separator<char> sep(":");
//          boost::tokenizer<boost::char_separator<char> >
//          tok(bootstrap_str, sep);
//          boost::tokenizer<boost::char_separator<char> >::iterator
//          beg = tok.begin();
//          boostrapping_ip = *beg;
//          ++beg;
//          boostrapping_port = static_cast<uint16_t>(base::stoi(*beg));
//        }
//        catch(const std::exception &e) {
//  #ifdef DEBUG
//          printf("Error with booststrapping node format.\n");
//  #endif
//          break;
//        }
//        if (boostrapping_ip == "" || boostrapping_port == 0) {
//  #ifdef DEBUG
//          printf("Error getting booststrapping node info.\n");
//  #endif
//          break;
//        }
//  #ifdef DEBUG
//        printf("IP: %s, Port: %i\n",
//               boostrapping_ip.c_str(),
//               boostrapping_port);
//  #endif
//        kad::Contact bs_contact(kad::vault_random_id(),
//                                boostrapping_ip,
//                                boostrapping_port);
//        bs_contacts->push_back(bs_contact);
//      }
//    }  // end of parsing
//    if (bs_contacts->empty())
//      return false;
//    return true;
//  }
//  // read the bootstrapping nodes
//  base::ConfigFileHandler cfh(config_file.file_string());
//  std::vector<std::string> bootstrap_nodes;
//  if (cfh.getAttributeList("network.bootstrap_nodes", bootstrap_nodes) != 0) {
// #ifdef DEBUG
//    printf("Failed to read bootstrapping nodes from the config file.\n");
// #endif
//    return false;
//  }
//  if (bootstrap_nodes.empty()) {
// #ifdef DEBUG
//    printf("There are no bootstrapping nodes in the config file.\n");
// #endif
//    return false;
//  }
//  for (uint32_t i = 0; i < bootstrap_nodes.size(); ++i) {
//    // parse boostrapping node ip:port
//    std::string bootstrap_str = bootstrap_nodes[i];
//    if (bootstrap_str != "") {
//      const int kBootstrapStrSize = bootstrap_str.size();
//      boost::scoped_ptr<char> bootstrap_cstr_(new char[kBootstrapStrSize+1]);
//      for (int i = 0; i <= kBootstrapStrSize; ++i) {
//        bootstrap_cstr_.get()[i] = bootstrap_str.c_str()[i];
//      }
//      std::string boostrapping_ip("");
//      uint16_t boostrapping_port = 0;
//      try {
//        boost::char_separator<char> sep(":");
//        boost::tokenizer<boost::char_separator<char> >
//        tok(bootstrap_str, sep);
//        boost::tokenizer<boost::char_separator<char> >::iterator
//        beg = tok.begin();
//        boostrapping_ip = *beg;
//        ++beg;
//        boostrapping_port = static_cast<uint16_t>(base::stoi(*beg));
//      }
//      catch(const std::exception &e) {
// #ifdef DEBUG
//        printf("Error with booststrapping node format.\n");
// #endif
//        break;
//      }
//      if (boostrapping_ip == "" || boostrapping_port == 0) {
// #ifdef DEBUG
//        printf("Error getting booststrapping node info.\n");
// #endif
//        break;
//      }
// #ifdef DEBUG
//     printf("IP: %s, Port: %i\n", boostrapping_ip.c_str(), boostrapping_port);
// #endif
//      kad::Contact bs_contact(kad::vault_random_id(),
//                              boostrapping_ip,
//                              boostrapping_port);
//      bs_contacts->push_back(bs_contact);
//    }
//  }  // end of parsing
//  if (bs_contacts->empty())
//    return false;
//  return true;
// }

void MaidsafeStoreManager::LoadChunk(const std::string &chunk_name,
                                     base::callback_func_type cb) {
  std::string hex_chunk_name;
  base::decode_from_hex(chunk_name, hex_chunk_name);
  pdclient_->GetChunk(hex_chunk_name,
      boost::bind(&MaidsafeStoreManager::LoadChunk_Callback, this, _1, cb));
}

void MaidsafeStoreManager::StoreChunk(const std::string &chunk_name,
                                      const std::string &content,
                                      const std::string &signature,
                                      const std::string &public_key,
                                      const std::string &signed_public_key,
                                      base::callback_func_type cb) {
  std::string hex_chunk_name;
  base::decode_from_hex(chunk_name, hex_chunk_name);
  pdclient_->StoreChunk(hex_chunk_name,
                        content,
                        public_key,
                        signed_public_key,
                        signature,
                        DATA,
                        boost::bind(
                            &MaidsafeStoreManager::SimpleResult_Callback,
                            this,
                            _1,
                            cb));
}

void MaidsafeStoreManager::IsKeyUnique(const std::string &key,
                                       base::callback_func_type cb) {
  std::string hex_key;
  base::decode_from_hex(key, hex_key);
  pdclient_->FindValue(hex_key,
                       boost::bind(&MaidsafeStoreManager::IsKeyUnique_Callback,
                                   this,
                                   _1,
                                   cb));
}

void MaidsafeStoreManager::DeletePacket(const std::string &key,
                                        const std::string &signature,
                                        const std::string &public_key,
                                        const std::string &signed_public_key,
                                        const value_types &type,
                                        base::callback_func_type cb) {
  std::string hex_key;
  base::decode_from_hex(key, hex_key);
  pdclient_->DeleteChunk(hex_key, public_key,
                         signed_public_key, signature,
                         type, boost::bind(
                           &MaidsafeStoreManager::DeleteChunk_Callback,
                           this, _1, cb));
}

void MaidsafeStoreManager::StorePacket(const std::string &key,
                                       const std::string &value,
                                       const std::string &signature,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       const value_types &type,
                                       bool update,
                                       base::callback_func_type cb) {
  std::string hex_key;
  base::decode_from_hex(key, hex_key);
  if (update)
    pdclient_->UpdateChunk(hex_key, value, public_key,
      signed_public_key, signature, type,
      boost::bind(&MaidsafeStoreManager::StoreChunk_Callback, this, _1,
                  update, cb));
  else
    pdclient_->StoreChunk(hex_key, value, public_key,
      signed_public_key, signature, type,
      boost::bind(&MaidsafeStoreManager::StoreChunk_Callback, this, _1,
                  update, cb));
}

void MaidsafeStoreManager::LoadPacket(const std::string &key,
                                      base::callback_func_type cb) {
  std::string hex_key;
  base::decode_from_hex(key, hex_key);
  pdclient_->GetChunk(hex_key,
                      boost::bind(&MaidsafeStoreManager::LoadChunk_Callback,
                                  this,
                                  _1,
                                  cb));
}

void MaidsafeStoreManager::GetMessages(const std::string &key,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       base::callback_func_type cb) {
  std::string hex_key;
  base::decode_from_hex(key, hex_key);
  pdclient_->GetMessages(hex_key, public_key, signed_public_key, cb);
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
