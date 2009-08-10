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
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

MaidsafeStoreManager::MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore)
    : channel_manager_(new rpcprotocol::ChannelManager()),
      knode_(new kad::KNode(channel_manager_, kad::CLIENT)),
      client_rpcs_(channel_manager_),
      pdclient_(),
      ss_(SessionSingleton::getInstance()),
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
  CallbackObj kad_cb_obj;
  knode_->Join("", kadconfig_str, boost::bind(&CallbackObj::CallbackFunc,
      &kad_cb_obj, _1), false);
  kad_cb_obj.WaitForCallback(60000);
  base::GeneralResponse kad_response;
  GenericResponse maid_response;
  std::string kad_result = kad_cb_obj.result();
  std::string maid_result;
  if (!kad_response.ParseFromString(kad_result) ||
      kad_response.result() != kad::kRpcResultSuccess) {
    maid_response.set_result(kNack);
    maid_response.SerializeToString(&maid_result);
    cb(maid_result);
    return;
  } else {
    maid_response.set_result(kAck);
    maid_response.SerializeToString(&maid_result);
    cb(maid_result);
  }
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
  GenericResponse result_msg;
  result_msg.set_result(kAck);
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
    result_msg.set_result(kNack);
  } else {
    if (result_msg.has_content()) {
      result_msg.clear_result();
      result_msg.set_result(kAck);
    } else {
#ifdef DEBUG
      printf("Load chunk callback came back with no content.\n");
#endif
      result_msg.clear_result();
      result_msg.set_result(kNack);
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
  GenericResponse result_msg;
  if ((!result_msg.ParseFromString(result))||
      (result_msg.result() != kAck)) {
    result_msg.clear_result();
    result_msg.set_result(kNack);
  } else {
    result_msg.clear_result();
    result_msg.set_result(kAck);
  }
  std::string ser_result;
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::IsKeyUnique_Callback(const std::string &result,
  base::callback_func_type cb) {
  kad::FindResponse result_msg;
  GenericResponse local_result;
  std::string ser_result;
  if (!result_msg.ParseFromString(result)) {
    local_result.set_result(kAck);
    local_result.SerializeToString(&ser_result);
    cb(ser_result);
    return;
  }

  if (result_msg.result() == kad::kRpcResultSuccess) {
    local_result.set_result(kAck);
    local_result.SerializeToString(&ser_result);
    cb(ser_result);
    return;
  }

  if (result_msg.values_size() == 0) {
    local_result.set_result(kAck);
  } else {
    local_result.set_result(kNack);
  }
  local_result.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::GetMsgs_Callback(const std::string &result,
  base::callback_func_type cb) {
  GetMessagesResponse result_msg;
  if ((!result_msg.ParseFromString(result))||
      (result_msg.result() != kAck)) {
    result_msg.set_result(kNack);
  } else {
    result_msg.clear_result();
    result_msg.set_result(kAck);
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
    result_msg.set_result(kNack);
  } else {
    if (result_msg.result() == kAck) {
      result_msg.clear_result();
      result_msg.set_result(kAck);
    } else {
      result_msg.clear_result();
      result_msg.set_result(kNack);
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

void MaidsafeStoreManager::SendChunk(StoreTuple store_tuple) {
#ifdef DEBUG
  printf("In MaidsafeStoreManager::SendChunk\n");
#endif
  boost::this_thread::at_thread_exit(boost::bind(&ThreadPool::DeleteThread,
      &store_thread_pool_, boost::this_thread::get_id()));
  int duplicate_count = 0;
  float largest_rtt = -1;  // set to -1 so that first store is to furthest peer
  std::vector<kad::Contact> exclude;
  StorePrepRequest store_prep_request;
  StoreRequest store_request;
  if (GetStoreRequests(store_tuple, &store_prep_request, &store_request) != 0)
    return;
  boost::uint64_t data_size = store_prep_request.data_size();
  while (duplicate_count < kMinChunkCopies) {
    printf("dup count: %i\tmin copies: %i\n", duplicate_count, kMinChunkCopies);
    kad::Contact peer;
    bool local;
    printf("largest: %f\t", largest_rtt);
    float ideal_rtt = largest_rtt * (1 - (duplicate_count/kMinChunkCopies));
    printf("ideal: %f\n", ideal_rtt);
    if (GetStorePeer(ideal_rtt, exclude, &peer, &local) != 0)
      break;  // try another peer
    else
      exclude.push_back(peer);  // whether we succeed in storing or not, we'll
                                // not be trying this peer again
    if (!duplicate_count)
//      largest_rtt = peer.rtt();
// TODO(Fraser#5#): 2009-08-09 - get rtt properly
      largest_rtt = 1.0;
//    StorePrepRequest store_prep_request = store_prep_req;
    if (SendPrep(peer, local, &store_prep_request) != 0)
      break;  // try another peer
    int failed_attempt_count = 0;
    while (failed_attempt_count < kMaxChunkStoreTries) {
//      StoreRequest store_request = store_req;
      if (SendContent(peer, local, data_size, &store_request) == 0) {
        printf("In MSM::SendChunk - success storing.\n");
        break;  // succeeded in storing to this peer
      } else {
        ++failed_attempt_count;
        printf("In MSM::SendChunk - failed storing.\n");
      }
    }
    printf("Fails: %i\tMax Tries: %i\n", failed_attempt_count,
           kMaxChunkStoreTries);
    if (failed_attempt_count < kMaxChunkStoreTries)
      ++duplicate_count;
    if (!duplicate_count)  // if this is failed 1st duplicate, reset largest rtt
      largest_rtt = -1;
  }
}

int MaidsafeStoreManager::GetStoreRequests(const StoreTuple &store_tuple,
                                           StorePrepRequest *store_prep_request,
                                           StoreRequest *store_request) {
  std::string chunk_name = store_tuple.get<0>();
  DirType dir_type = store_tuple.get<1>();
  ValueType data_type = DATA;
  if (dir_type == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  std::string msid = store_tuple.get<2>();
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                       false));
  if (chunk_path == fs::path(""))
    return -1;
  std::string chunk_content("");
  uint64_t chunk_size(0);
  try {
    chunk_size = fs::file_size(chunk_path);
    boost::scoped_ptr<char>
        temp(new char[static_cast<unsigned int>(chunk_size)]);
    fs::ifstream fstr;
    fstr.open(chunk_path, std::ios_base::binary);
    fstr.read(temp.get(), static_cast<std::streamsize>(chunk_size));
    fstr.close();
    chunk_content = std::string(static_cast<const char*>(temp.get()),
                                static_cast<boost::uint64_t>(chunk_size));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return -2;
  }
  std::string public_key(""), signed_public_key(""), signed_request("");
  GetSignedPubKeyAndRequest(chunk_name, dir_type, msid, &public_key,
                            &signed_public_key, &signed_request);
  if (public_key == "" || signed_public_key == "" || signed_request == "")
    return -3;
  std::string pmid = ss_->Id(PMID);
  store_prep_request->set_chunkname(chunk_name);
  store_prep_request->set_data_size(chunk_size);
  store_prep_request->set_pmid(pmid);
  store_prep_request->set_public_key(public_key);
  store_prep_request->set_signed_public_key(signed_public_key);
  store_prep_request->set_signed_request(signed_request);
  store_request->set_chunkname(chunk_name);
  store_request->set_data(chunk_content);
  store_request->set_pmid(pmid);
  store_request->set_public_key(public_key);
  store_request->set_signed_public_key(signed_public_key);
  store_request->set_signed_request(signed_request);
  store_request->set_data_type(data_type);
  return 0;
}

void MaidsafeStoreManager::GetSignedPubKeyAndRequest(
    const std::string &non_hex_name,
    const DirType dir_type,
    const std::string &msid,
    std::string *pubkey,
    std::string *signed_pubkey,
    std::string *signed_request) {
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

int MaidsafeStoreManager::GetStorePeer(const float &,
                                       const std::vector<kad::Contact> &exclude,
                                       kad::Contact *new_peer,
                                       bool *local) {
// TODO(Fraser#5#): 2009-08-08 - complete this so that rtt & rank is considered.
  std::vector<kad::Contact> result;
  knode_->GetRandomContacts(1, exclude, &result);
  if (result.size() == static_cast<unsigned int>(0))
    return -1;
  *new_peer = result.at(0);
  *local = (knode_->CheckContactLocalAddress(new_peer->node_id(),
      new_peer->local_ip(), new_peer->local_port(), new_peer->host_ip()) ==
      kad::LOCAL);
  return 0;
}

int MaidsafeStoreManager::SendPrep(const kad::Contact &peer,
                                   bool local,
                                   StorePrepRequest *store_prep_request) {
  const boost::shared_ptr<StorePrepResponse>
      store_prep_response(new StorePrepResponse());
  bool store_prep_response_returned(false);
  boost::mutex mutex;
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendPrepCallback, &store_prep_response_returned,
      &mutex);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  client_rpcs_.StorePrep(peer, local, store_prep_request,
      store_prep_response.get(), controller, callback);
  int count(0), timeout(10000);
  while (count < timeout) {
    {
      boost::mutex::scoped_lock lock(mutex);
      if (store_prep_response_returned)
        break;
    }
    count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  return (store_prep_response->pmid_id() == peer.node_id() &&
          store_prep_response->result() == kAck) ? 0 : -1;
}

void MaidsafeStoreManager::SendPrepCallback(bool *send_prep_returned,
                                            boost::mutex *mutex) {
#ifdef DEBUG
  printf("In MaidsafeStoreManager::SendPrepCallback.\n");
#endif
  boost::mutex::scoped_lock lock(*mutex);
  *send_prep_returned = true;
}

int MaidsafeStoreManager::SendContent(const kad::Contact &peer,
                                      bool local,
                                      boost::uint64_t &data_size,
                                      StoreRequest *store_request) {
  const boost::shared_ptr<StoreResponse>store_response(new StoreResponse());
  bool store_response_returned(false);
  boost::mutex mutex;
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendContentCallback, &store_response_returned,
      &mutex);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  client_rpcs_.Store(peer, local, store_request, store_response.get(),
      controller, callback);
  int count(0), timeout(data_size * 100);  // timeout if speed < 10 bytes / sec
  while (count < timeout) {
    {
      boost::mutex::scoped_lock lock(mutex);
      if (store_response_returned)
        break;
    }
    count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
// TODO(Fraser#5#): 2009-08-09 - cancel rpc if timed out
  if (store_response->pmid_id() == peer.node_id())
    printf("In MSM::SendContent, ids are OK.\n");
  else
    printf("In MSM::SendContent, ids are not OK.\n");
  if (store_response->result() == kAck)
    printf("In MSM::SendContent, result kAck.\n");
  else
    printf("In MSM::SendContent, result not kAck.\n");
  return (store_response->pmid_id() == peer.node_id() &&
          store_response->result() == kAck) ? 0 : -1;
}

void MaidsafeStoreManager::SendContentCallback(bool *send_content_returned,
                                               boost::mutex *mutex) {
#ifdef DEBUG
  printf("In MaidsafeStoreManager::SendContentCallback.\n");
#endif
  boost::mutex::scoped_lock lock(*mutex);
  *send_content_returned = true;
}
}  // namespace maidsafe
