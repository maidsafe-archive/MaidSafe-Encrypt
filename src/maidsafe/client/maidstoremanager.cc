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

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <maidsafe/kademlia_service_messages.pb.h>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/privateshares.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

MaidsafeStoreManager::MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore)
    : channel_manager_(new rpcprotocol::ChannelManager()),
      knode_(new kad::KNode(channel_manager_, kad::CLIENT)),
      client_rpcs_(channel_manager_),
      pdclient_(),
      co_(),
      client_chunkstore_(cstore),
      main_store_thread_(),
      store_thread_running_(false),
      priority_store_queue_(),
      normal_store_queue_(),
      store_thread_pool_(),
      store_thread_running_mutex_(),
      ps_queue_mutex_(),
      ns_queue_mutex_() {
  co_.set_symm_algorithm(crypto::AES_256);
  co_.set_hash_algorithm(crypto::SHA_512);
}

void MaidsafeStoreManager::Init(int port, base::callback_func_type cb) {
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
#ifdef DEBUG
  printf("kadconfig_path: %s\n", kadconfig_str.c_str());
#endif
  channel_manager_->StartTransport(port,
    boost::bind(&kad::KNode::HandleDeadRendezvousServer, knode_.get(), _1));
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Init, before Join.\n");
#endif
  knode_->Join("", kadconfig_str, cb, false);
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Init, after Join.\n");
#endif
  pdclient_ = new PDClient(channel_manager_, knode_, &client_rpcs_);
  StartStoring();
}

void MaidsafeStoreManager::Close(base::callback_func_type cb) {
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, before Leave.\n");
#endif
  // Try to kill the main storing thread;
  StopStoring();
  knode_->Leave();
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, after Leave. Stopping transport\n");
#endif
  channel_manager_->StopTransport();
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, transport stopped.\n");
#endif
  // Try again to kill the main storing thread in case it failed earlier.
  StopStoring();
  base::GeneralResponse result_msg;
  result_msg.set_result(kCallbackSuccess);
  std::string result;
  result_msg.SerializeToString(&result);
  cb(result);
//  knode_.reset();
}

void MaidsafeStoreManager::CleanUpTransport() {
  channel_manager_->CleanUpTransport();
}

void MaidsafeStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                     base::callback_func_type cb) {
  std::string chunk_name("");
  base::decode_from_hex(hex_chunk_name, &chunk_name);
  pdclient_->GetChunk(chunk_name,
      boost::bind(&MaidsafeStoreManager::LoadChunk_Callback, this, _1, cb));
}

void MaidsafeStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                      const DirType dir_type,
                                      const std::string &msid) {
#ifdef DEBUG
  std::string hex(hex_chunk_name.substr(0, 10) + "...");
  printf("In MaidsafeStoreManager::StoreChunk (%i), chunk_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  std::string chunk_name("");
  base::decode_from_hex(hex_chunk_name, &chunk_name);
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  if (chunk_type < 0) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::StoreChunk (%i), didn't find chunk %s\n",
           knode_->host_port(), hex.c_str());
#endif
    return;
  }
  if (chunk_type == (kHashable | kOutgoing) ||
      chunk_type == (kNonHashable | kOutgoing))
    AddToNormalStoreQueue(StoreTuple(chunk_name, dir_type, msid));
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
                                        const ValueType &type,
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
                                       const ValueType &type,
                                       bool update,
                                       base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  if (update)
    pdclient_->UpdateChunk(key, value, public_key, signed_public_key, signature,
        type, boost::bind(&MaidsafeStoreManager::StoreChunk_Callback, this, _1,
        update, cb));
  else
    StoreChunk(hex_key, value, public_key, signed_public_key, signature, cb);
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
      (result_msg.result() != kCallbackSuccess)) {
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
      (result_msg.result() != kCallbackSuccess)) {
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
    } else if (result_msg.result() == kCallbackSuccess) {
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
      result_msg.set_result(kNack);
    } else if (result_msg.result() == kAck) {
      result_msg.clear_result();
      result_msg.set_result(kAck);
    } else {
      result_msg.clear_result();
      result_msg.set_result(kNack);
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
    if (result_msg.result() == kCallbackSuccess) {
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

void MaidsafeStoreManager::StartStoring() {
  {
    boost::mutex::scoped_lock lock(store_thread_running_mutex_);
    if (store_thread_running_)
      return;
    store_thread_running_ = true;
  }
  main_store_thread_ = boost::thread(&MaidsafeStoreManager::StoreThread, this);
}

void MaidsafeStoreManager::StopStoring() {
  {
    boost::mutex::scoped_lock lock(store_thread_running_mutex_);
    if (!store_thread_running_)
      return;
    store_thread_running_ = false;
  }
  printf("Trying to join store thread.\n");
  try {
    store_thread_running_ = !main_store_thread_.timed_join(
        boost::posix_time::seconds(8));
  }
  catch(const std::exception &e) {
    store_thread_running_ = true;
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
  }
}

bool MaidsafeStoreManager::StoreThreadRunning() {
  bool result;
  {
    boost::mutex::scoped_lock lock(store_thread_running_mutex_);
    result = store_thread_running_;
  }
  return result;
}

void MaidsafeStoreManager::StoreThreadStopping() {
  boost::mutex::scoped_lock lock(store_thread_running_mutex_);
  store_thread_running_ = false;
}

void MaidsafeStoreManager::StoreThread() {
  boost::this_thread::at_thread_exit(boost::bind(
      &MaidsafeStoreManager::StoreThreadStopping, this));
  while (StoreThreadRunning()) {
    if (store_thread_pool_.size() < kMaxStoreThreads) {
      boost::mutex::scoped_lock lock_ps(ps_queue_mutex_);
      if (!priority_store_queue_.empty()) {
        StoreTuple store_tuple = priority_store_queue_.front();
        priority_store_queue_.pop();
        boost::shared_ptr<boost::thread> thr(new boost::thread(
            &MaidsafeStoreManager::SendChunk, this, store_tuple));
        store_thread_pool_.AddThread(thr);
      }
    }
    // Leave room for a further priority store thread
    if (store_thread_pool_.size() < kMaxStoreThreads - 1) {
      boost::mutex::scoped_lock lock_ns(ns_queue_mutex_);
      if (!normal_store_queue_.empty()) {
        StoreTuple store_tuple = normal_store_queue_.front();
        normal_store_queue_.pop();
        boost::shared_ptr<boost::thread> thr(new boost::thread(
            &MaidsafeStoreManager::SendChunk, this, store_tuple));
        store_thread_pool_.AddThread(thr);
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

void MaidsafeStoreManager::GetSignedPubKeyAndRequest(
    const std::string &non_hex_name,
    const DirType dir_type,
    const std::string &msid,
    std::string *pubkey,
    std::string *signed_pubkey,
    std::string *signed_request) {
  SessionSingleton *ss_ = SessionSingleton::getInstance();
  switch (dir_type) {
    case PRIVATE_SHARE: {
#ifdef DEBUG
//      printf("Getting signed request for PRIVATE_SHARE.\n\n");
#endif
      std::string prikey("");
      if (0 != ss_->GetShareKeys(msid, pubkey, &prikey)) {
        *pubkey = "";
        *signed_pubkey = "";
        *signed_request = "";
        return;
      }
      *signed_pubkey = co_.AsymSign(*pubkey, "", prikey, crypto::STRING_STRING);
      *signed_request = co_.AsymSign(co_.Hash(
          *pubkey + *signed_pubkey + non_hex_name, "", crypto::STRING_STRING,
          true), "", prikey, crypto::STRING_STRING);
      }
      break;
    case PUBLIC_SHARE:
#ifdef DEBUG
//      printf("Getting signed request for PUBLIC_SHARE.\n\n");
#endif
      *pubkey = ss_->PublicKey(MPID);
      *signed_pubkey = co_.AsymSign(*pubkey, "", ss_->PrivateKey(MPID),
          crypto::STRING_STRING);
      *signed_request = co_.AsymSign(co_.Hash(
          *pubkey + *signed_pubkey + non_hex_name, "", crypto::STRING_STRING,
          true), "", ss_->PrivateKey(MPID), crypto::STRING_STRING);
      break;
    case ANONYMOUS:
#ifdef DEBUG
//      printf("Getting signed request for ANONYMOUS.\n\n");
#endif
      *pubkey = " ";
      *signed_pubkey = " ";
      *signed_request = kAnonymousSignedRequest;
      break;
    default:
#ifdef DEBUG
//      printf("Getting signed request for default.\n\n");
#endif
      *pubkey = ss_->PublicKey(PMID);
      *signed_pubkey = co_.AsymSign(*pubkey, "", ss_->PrivateKey(PMID),
          crypto::STRING_STRING);
      *signed_request = co_.AsymSign(co_.Hash(
          *pubkey+*signed_pubkey+non_hex_name, "", crypto::STRING_STRING, true),
          "", ss_->PrivateKey(PMID), crypto::STRING_STRING);
      break;
  }
}

void MaidsafeStoreManager::AddToPriorityStoreQueue(
    const StoreTuple &store_tuple) {
  boost::mutex::scoped_lock lock(ps_queue_mutex_);
  priority_store_queue_.push(store_tuple);
}

void MaidsafeStoreManager::AddToNormalStoreQueue(
    const StoreTuple &store_tuple) {
  boost::mutex::scoped_lock lock(ns_queue_mutex_);
  normal_store_queue_.push(store_tuple);
}

void MaidsafeStoreManager::SendChunk(const StoreTuple &store_tuple) {
#ifdef DEBUG
  printf("In MaidsafeStoreManager::SendChunk\n");
#endif
  boost::this_thread::at_thread_exit(boost::bind(&ThreadPool::DeleteThread,
      &store_thread_pool_, boost::this_thread::get_id()));
  std::string chunk_name(""), msid(""), chunk_content("");
  std::string public_key(""), signed_public_key(""), signed_request("");
  DirType dir_type;
  if (PrepareToStore(store_tuple, &chunk_name, &dir_type, &msid, &chunk_content,
      &public_key, &signed_public_key, &signed_request) != 0)
    return;

  CallbackObj cbo;
  pdclient_->StoreChunk(chunk_name, chunk_content, public_key,
      signed_public_key, signed_request, DATA,
      boost::bind(&CallbackObj::CallbackFunc, &cbo, _1));
  int count(0);
  while (count < 6000 && !cbo.called()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    count += 10;
  }
  if (cbo.result() == "")
    printf("MaidsafeStoreManager::SendChunk failed.\n");
}

int MaidsafeStoreManager::PrepareToStore(const StoreTuple &store_tuple,
                                         std::string *chunk_name,
                                         DirType *dir_type,
                                         std::string *msid,
                                         std::string *chunk_content,
                                         std::string *public_key,
                                         std::string *signed_public_key,
                                         std::string *signed_request) {
  *chunk_name = store_tuple.get<0>();
  *dir_type = store_tuple.get<1>();
  *msid = store_tuple.get<2>();
  ChunkType chunk_type = client_chunkstore_->chunk_type(*chunk_name);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(*chunk_name, chunk_type,
                                                       false));
  if (chunk_path == fs::path(""))
    return -1;
  try {
    uint64_t size = fs::file_size(chunk_path);
    boost::scoped_ptr<char> temp(new char[static_cast<unsigned int>(size)]);
    fs::ifstream fstr;
    fstr.open(chunk_path, std::ios_base::binary);
    fstr.read(temp.get(), static_cast<std::streamsize>(size));
    fstr.close();
    *chunk_content = std::string(static_cast<const char*>(temp.get()),
                                 static_cast<boost::uint64_t>(size));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return -2;
  }
  GetSignedPubKeyAndRequest(*chunk_name, *dir_type, *msid, public_key,
                            signed_public_key, signed_request);
  return (*public_key == "" || *signed_public_key == "" ||
      *signed_request == "") ? -3 : 0;
}

}  // namespace maidsafe
