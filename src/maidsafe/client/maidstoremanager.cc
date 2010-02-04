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
#include <boost/utility.hpp>
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/transporthandler-api.h>
#include <map>

#include "fs/filesystem.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

// TODO(Fraser#5#): 2009-12-17 - Reconsider use of ValueType when sending
//                               chunks/packets for storing.  If client chooses
//                               type, there's little incentive to not set all
//                               chunks as Anon to avoiding paying for them.

namespace fs = boost::filesystem;

namespace maidsafe {

void AddToWatchListTask::run() {
  printf("AddToWatchListTask start %s\n",
         HexSubstr(store_data_.non_hex_key).c_str());
  msm_->AddToWatchList(store_data_);
}

void SendChunkCopyTask::run() {
  printf("SendChunkCopyTask - chunk %s ENQUEUEDISED\n",
         HexSubstr(store_data_.non_hex_key).c_str());
  msm_->SendChunkPrep(store_data_);
  printf("SendChunkCopyTask end %s\n",
         HexSubstr(store_data_.non_hex_key).c_str());
}

void StorePacketTask::run() {
  msm_->SendPacketPrep(store_data_);
}

void DeleteChunkTask::run() {
  printf("DeleteChunkTask - chunk %s ENQUEUEDISED\n",
         HexSubstr(store_data_.non_hex_key).c_str());
  msm_->RemoveFromWatchList(store_data_);
  printf("DeleteChunkTask end %s\n",
         HexSubstr(store_data_.non_hex_key).c_str());
}

void DeletePacketTask::run() {
  msm_->DeletePacketFromNet(delete_data_);
}

void AmendAccountTask::run() {
  msm_->AmendAccount(space_offered_);
}

MaidsafeStoreManager::MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore)
    : udt_transport_(),
      transport_handler_(),
      channel_manager_(&transport_handler_),
      knode_(new kad::KNode(&channel_manager_, &transport_handler_, kad::CLIENT,
             "", "", false, false)),
      client_rpcs_(new ClientRpcs(&transport_handler_, &channel_manager_)),
      ss_(SessionSingleton::getInstance()),
      tasks_handler_(),
      client_chunkstore_(cstore),
      chunk_thread_pool_(),
      packet_thread_pool_(),
      kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore),
      store_packet_mutex_(),
      get_chunk_conditional_(),
      bprpcs_(new BufferPacketRpcsImpl(&transport_handler_, &channel_manager_)),
      cbph_(bprpcs_, knode_) {
  boost::int16_t trans_id;
  transport_handler_.Register(&udt_transport_, &trans_id);
  knode_->SetTransID(trans_id);
  knode_->SetAlternativeStore(client_chunkstore_.get());
}

void MaidsafeStoreManager::Init(int port, base::callback_func_type cb) {
  // If kad config file exists in dir we're in, use that, otherwise get default
  // path to file.
  bool success(true);
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
    success = false;
  }
#ifdef DEBUG
//  printf("kadconfig_path: %s\n", kadconfig_str.c_str());
#endif
  if (success)
    success = channel_manager_.RegisterNotifiersToTransport();
  if (success)
    success = transport_handler_.RegisterOnServerDown(boost::bind(
        &kad::KNode::HandleDeadRendezvousServer, knode_.get(), _1));
  if (success)
    success = (transport_handler_.Start(port, udt_transport_.GetID()) == 0);
  if (success)
    success = (channel_manager_.Start() == 0);
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Init, before Join.\n");
#endif
  CallbackObj kad_cb_obj;
  if (success) {
    knode_->Join(kadconfig_str, boost::bind(&CallbackObj::CallbackFunc,
        &kad_cb_obj, _1));
    kad_cb_obj.WaitForCallback();
  }
  base::GeneralResponse kad_response;
  GenericResponse maid_response;
  std::string kad_result = kad_cb_obj.result();
  std::string maid_result;
  if (!success || !kad_response.ParseFromString(kad_result) ||
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
  chunk_thread_pool_.setMaxThreadCount(kChunkMaxThreadCount);
  packet_thread_pool_.setMaxThreadCount(kPacketMaxThreadCount);
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Init, after Join.\n");
#endif
}

void MaidsafeStoreManager::Close(base::callback_func_type cb, bool) {
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, before Leave.\n");
#endif
//  if (cancel_pending_ops)
//    store_thread_pool_.clear();
  chunk_thread_pool_.waitForDone();
  printf("\tIn MaidsafeStoreManager::Close, chunk_thread_pool_ done.\n");
//  if (cancel_pending_ops)
//    packet_thread_pool_.clear();
  packet_thread_pool_.waitForDone();
  printf("\tIn MaidsafeStoreManager::Close, packet_thread_pool_ done.\n");
  knode_->Leave();
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, after Leave. "
//         "Stopping transport.\n");
#endif
  transport_handler_.StopAll();
  channel_manager_.Stop();
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, transport stopped.\n");
#endif
  // Try again to kill the main storing thread in case it failed earlier.
  GenericResponse result_msg;
  result_msg.set_result(kAck);
  std::string result;
  result_msg.SerializeToString(&result);
  cb(result);
//  knode_.reset();
}

void MaidsafeStoreManager::CleanUpTransport() {
  transport::TransportUDT::CleanUp();
}

void MaidsafeStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                      DirType dir_type,
                                      const std::string &msid) {
#ifdef DEBUG
  std::string hex(hex_chunk_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::StoreChunk (%i), chunk_name = %s\n",
//         knode_->host_port(), hex.c_str());
#endif
  std::string chunk_name = base::DecodeFromHex(hex_chunk_name);
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                       false));
  if (chunk_type < 0 || chunk_path == fs::path("")) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::StoreChunk (%i), didn't find chunk %s\n",
           knode_->host_port(), hex.c_str());
#endif
    return;
  }
  boost::uint64_t chunk_size(0);
  try {
    chunk_size = fs::file_size(chunk_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MaidsafeStoreManager::StoreChunk (%i) - path: %s - %s\n",
           knode_->host_port(), chunk_path.string().c_str(), e.what());
#endif
    return;
  }
  // TODO(Fraser#5#): 2010-01-29 - Check we've got enough space in our account
  //                               to allow storing.
  if (chunk_type & kOutgoing) {
    std::string key_id, public_key, public_key_signature, private_key;
    GetChunkSignatureKeys(dir_type, msid, &key_id, &public_key,
        &public_key_signature, &private_key);
    // Task is added needing kMinChunkCopies to succeed.  This figure is amended
    // after AddToWatchList method ascertains actual number of uploads needed.
    tasks_handler_.AddTask(chunk_name, kStoreChunk, chunk_size, kMinChunkCopies,
                           kMaxStoreFailures);
    // chunk_thread_pool_ handles destruction of add_to_watch_list_task.
    AddToWatchListTask *add_to_watch_list_task = new AddToWatchListTask(
        StoreData(chunk_name, chunk_size, chunk_type, dir_type, msid, key_id,
        public_key, public_key_signature, private_key), this);
    chunk_thread_pool_.start(add_to_watch_list_task);
  }
}

void MaidsafeStoreManager::StorePacket(const std::string &hex_packet_name,
                                       const std::string &value,
                                       PacketType system_packet_type,
                                       DirType dir_type,
                                       const std::string &msid,
                                       IfPacketExists if_packet_exists,
                                       const VoidFuncOneInt &cb) {
  ReturnCode prep = kSuccess;
  if (hex_packet_name.length() != 2 * kKeySize) {
    prep = kIncorrectKeySize;
  }
  if (prep == kSuccess) {
    std::string packet_name = base::DecodeFromHex(hex_packet_name);
    std::string key_id, public_key, public_key_signature, private_key;
    GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
        &public_key, &public_key_signature, &private_key);
    switch (system_packet_type) {
      case MID:
      case SMID:
      case MSID:
      case TMID:
      case MPID:
      case PMID:
      case MAID:
      case ANMID:
      case ANSMID:
      case ANTMID:
      case ANMPID: {
        boost::shared_ptr<StoreData> store_data(new StoreData(packet_name,
            value, system_packet_type, dir_type, msid, key_id, public_key,
            public_key_signature, private_key, if_packet_exists, cb));
        // packet_thread_pool_ handles destruction of store_packet_task.
        StorePacketTask *store_packet_task =
            new StorePacketTask(store_data, this);
        packet_thread_pool_.start(store_packet_task);
        return;
      }
      case PD_DIR:
//        StorePdDirToVaults(hex_packet_name, value, dir_type, msid);
        return;
      default:
        prep = kPacketUnknownType;
    }
  }
  if (prep != kSuccess)
    cb(prep);
}

int MaidsafeStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                    std::string *data) {
#ifdef DEBUG
  std::string hex(hex_chunk_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::LoadChunk (%i), chunk_name = %s\n",
//         knode_->host_port(), hex.c_str());
#endif
  data->clear();
  std::string chunk_name = base::DecodeFromHex(hex_chunk_name);
  if (client_chunkstore_->Load(chunk_name, data) == kSuccess) {
#ifdef DEBUG
    printf("(%i) Found chunk %s in local chunkstore.\n",
           knode_->host_port(), hex.c_str());
#endif
    return kSuccess;
  }
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  // If the maidsafe value is cached, this blocking Kad call to FindValue may
  // yield serialised contact details for a cache copy holder.  Otherwise it
  // should yield the reference holders.
  for (int attempt = 0; attempt < kMaxChunkLoadRetries; ++attempt) {
    int find_result = (FindValue(chunk_name, false, &cache_holder,
                                 &chunk_holders_ids, &needs_cache_copy_id));
    if ((find_result != kSuccess) && (attempt == kMaxChunkLoadRetries - 1)) {
#ifdef DEBUG
      printf("In MaidsafeStoreManager::LoadChunk (%i), failed in FindValue.\n",
             knode_->host_port());
#endif
      return kLoadChunkFindValueFailure;
    } else {
#ifdef DEBUG
        printf("In MaidsafeStoreManager::LoadChunk (%i), FindValue yielded %i:"
               "\nCache holder: %s\tno of chunk holders: %i\n\n",
               knode_->host_port(), find_result,
               HexSubstr(cache_holder.node_id()).c_str(),
               chunk_holders_ids.size());
#endif
      if (find_result == kSuccess)
        break;
    }
  }
  if (cache_holder.has_node_id()) {  // We got a cached copy holder's details
// TODO(Fraser#5#): 2009-08-21 - We should maybe try again - we may get a
//                               different chunkholder next time?
    boost::shared_ptr<ChunkHolder> chunk_holder(new ChunkHolder(cache_holder));
    chunk_holder->local = AddressIsLocal(cache_holder);
    boost::mutex mutex;
    int get_result = GetChunk(chunk_name, chunk_holder, data, &mutex);
// TODO(Fraser#5#): 2009-08-31 - Store cache copy to needs_cache_copy_id
    // if (!data->empty() && !needs_cache_copy_id.empty())
    //   CacheChunk(*data, needs_cache_copy_id);
    return get_result;
  } else {
    int result = FindAndLoadChunk(chunk_name, chunk_holders_ids, true, data);
#ifdef DEBUG
    printf("In MaidsafeStoreManager::LoadChunk (%i), FindAndLoadChunk: %d.\n",
           knode_->host_port(), result);
#endif
    if (result == kSuccess) {
// TODO(Fraser#5#): 2009-08-31 - Store cache copy to needs_cache_copy_id
    // if (!needs_cache_copy_id.empty())
    //   CacheChunk(*data, needs_cache_copy_id);
    }
    return result;
  }
}

int MaidsafeStoreManager::LoadPacket(const std::string &hex_packet_name,
                                     std::string *result) {
  result->clear();
  std::vector<std::string> results;
  int retrn = LoadPacket(hex_packet_name, &results);
  if (retrn != kSuccess)
    return retrn;
  *result = results.front();
  return kSuccess;
}

int MaidsafeStoreManager::LoadPacket(const std::string &hex_packet_name,
                                     std::vector<std::string> *results) {
  results->clear();
#ifdef DEBUG
  std::string hex(hex_packet_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::LoadPacket (%i), packet_name = %s\n",
//         knode_->host_port(), hex.c_str());
#endif
  if (hex_packet_name.length() != 2 * kKeySize)
    return kIncorrectKeySize;

  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  kad::ContactInfo cache_holder;
  std::string needs_cache_copy_id;
  for (int attempt = 0; attempt < kMaxChunkLoadRetries; ++attempt) {
    cache_holder.Clear();
    results->clear();
    int res = FindValue(packet_name, false, &cache_holder, results,
        &needs_cache_copy_id);
    if (res != kSuccess || results->empty() || cache_holder.has_node_id()) {
      if (attempt == kMaxChunkLoadRetries - 1) {
#ifdef DEBUG
        printf("In MaidsafeStoreManager::LoadPacket (%i), failed FindValue\n",
               knode_->host_port());
#endif
        results->clear();
        return kFindValueFailure;
      } else {
        continue;
      }
    } else {
      return kSuccess;
    }
  }
  return kFindValueFailure;
}

bool MaidsafeStoreManager::KeyUnique(const std::string &hex_key,
                                     bool check_local) {
#ifdef DEBUG
//  std::string hex(hex_key.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::KeyUnique (%i), packet_name = %s\n",
//         knode_->host_port(), hex.c_str());
#endif
  std::string non_hex_key = base::DecodeFromHex(hex_key);
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  if (FindValue(non_hex_key, check_local, &cache_holder, &chunk_holders_ids,
      &needs_cache_copy_id) != kSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::KeyUnique (%i), FindValue - no key.\n",
           knode_->host_port());
#endif
    return true;
  }
  return false;
}

int MaidsafeStoreManager::DeleteChunk(const std::string &hex_chunk_name,
                                      const boost::uint64_t &chunk_size,
                                      DirType dir_type,
                                      const std::string &msid) {
#ifdef DEBUG
  std::string hex(hex_chunk_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::DeleteChunk (%i), chunk_name = %s\n",
//         knode_->host_port(), hex.c_str());
#endif
  std::string chunk_name = base::DecodeFromHex(hex_chunk_name);
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
    fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                         false));
  boost::uint64_t size(chunk_size);
  if (size < 2) {
    if (chunk_type < 0 || chunk_path == fs::path("")) {
#ifdef DEBUG
      printf("In MSM::DeleteChunk (%i), didn't find chunk %s in local "
             "chunkstore - can't delete without valid size.\n",
             knode_->host_port(), hex.c_str());
#endif
      return kDeleteSizeError;
    }
    try {
      size = fs::file_size(chunk_path);
    }
    catch(const std::exception &e) {
  #ifdef DEBUG
      printf("In MSM::DeleteChunk (%i), didn't find chunk %s in local "
             "chunkstore - can't delete without valid size.\n%s\n",
             knode_->host_port(), hex.c_str(), e.what());
  #endif
      return kDeleteSizeError;
    }
  }
  ChunkType new_type(chunk_type);
  if (chunk_type >= 0) {
    // Move chunk to TempCache.
    if (chunk_type & kNormal)
      new_type = chunk_type ^ (kNormal | kTempCache);
    else if (chunk_type & kOutgoing)
      new_type = chunk_type ^ (kOutgoing | kTempCache);
    else if (chunk_type & kCache)
      new_type = chunk_type ^ (kCache | kTempCache);
    if (!new_type < 0 &&
        client_chunkstore_->ChangeChunkType(chunk_name, new_type) != kSuccess) {
  #ifdef DEBUG
      printf("In MSM::DeleteChunk, failed to change chunk type.\n");
  #endif
    }
  }
  std::string key_id, public_key, public_key_signature, private_key;
  GetChunkSignatureKeys(dir_type, msid, &key_id, &public_key,
      &public_key_signature, &private_key);
  tasks_handler_.AddTask(chunk_name, kDeleteChunk, size, 1, 1);
  // chunk_thread_pool_ handles destruction of store_chunk_task.
  DeleteChunkTask *delete_chunk_task = new DeleteChunkTask(StoreData(
      chunk_name, size, new_type, dir_type, msid, key_id, public_key,
      public_key_signature, private_key), this);
  chunk_thread_pool_.start(delete_chunk_task);
  return kSuccess;
}

void MaidsafeStoreManager::DeletePacket(const std::string &hex_packet_name,
                                        const std::string &value,
                                        PacketType system_packet_type,
                                        DirType dir_type,
                                        const std::string &msid,
                                        const VoidFuncOneInt &cb) {
  if (value.empty()) {
    DeletePacket(hex_packet_name, system_packet_type, dir_type, msid, cb);
  } else {
    std::vector<std::string> values;
    values.push_back(value);
    DeletePacket(hex_packet_name, values, system_packet_type, dir_type, msid,
                 cb);
  }
}

void MaidsafeStoreManager::DeletePacket(const std::string &hex_packet_name,
                                        PacketType system_packet_type,
                                        DirType dir_type,
                                        const std::string &msid,
                                        const VoidFuncOneInt &cb) {
  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  kad::ContactInfo cache_holder;
  std::vector<std::string> values;
  std::string needs_cache_copy_id;
  int res = FindValue(packet_name, false, &cache_holder, &values,
                      &needs_cache_copy_id);
  if (res == kFindNodesFailure) {  // packet doesn't exist on net
    cb(kSuccess);
    return;
  } else if (res != kSuccess || !values.size()) {
    cb(kDeletePacketFindValueFailure);
    return;
  } else {
    DeletePacket(hex_packet_name, values, system_packet_type, dir_type, msid,
                 cb);
  }
}

void MaidsafeStoreManager::DeletePacket(const std::string &hex_packet_name,
                                        const std::vector<std::string> values,
                                        PacketType system_packet_type,
                                        DirType dir_type,
                                        const std::string &msid,
                                        const VoidFuncOneInt &cb) {
  ReturnCode prep = kSuccess;
  if (hex_packet_name.length() != 2 * kKeySize) {
    prep = kIncorrectKeySize;
  }
  if (prep == kSuccess) {
    std::string packet_name = base::DecodeFromHex(hex_packet_name);
    std::string key_id, public_key, public_key_signature, private_key;
    GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
        &public_key, &public_key_signature, &private_key);
    switch (system_packet_type) {
      case MID:
      case SMID:
      case MSID:
      case TMID:
      case MPID:
      case PMID:
      case MAID:
      case ANMID:
      case ANSMID:
      case ANTMID:
      case ANMPID: {
        boost::shared_ptr<DeletePacketData> delete_data(new DeletePacketData(
            packet_name, values, system_packet_type, dir_type, msid, key_id,
            public_key, public_key_signature, private_key, cb));
        // packet_thread_pool_ handles destruction of delete_packet_task.
        DeletePacketTask *delete_packet_task =
            new DeletePacketTask(delete_data, this);
        packet_thread_pool_.start(delete_packet_task);
        return;
      }
      case PD_DIR:
//        StorePdDirToVaults(hex_packet_name, value, dir_type, msid);
        return;
      default:
        prep = kPacketUnknownType;
    }
  }
  if (prep != kSuccess)
    cb(prep);
}

int MaidsafeStoreManager::CreateAccount(const boost::uint64_t &space_offered) {
  return SetSpaceOffered(space_offered);
}

int MaidsafeStoreManager::SetSpaceOffered(const boost::uint64_t &space) {
  // packet_thread_pool_ handles destruction of amend_account_task.
  AmendAccountTask *amend_account_task = new AmendAccountTask(space, this);
  packet_thread_pool_.start(amend_account_task);
  return kSuccess;
}

int MaidsafeStoreManager::GetAccountDetails(boost::uint64_t *space_offered,
                                            boost::uint64_t *space_given,
                                            boost::uint64_t *space_taken) {
  *space_offered = 0;
  *space_given = 0;
  *space_taken = 0;
  // Set the account name
  std::string non_hex_pmid = base::DecodeFromHex(ss_->Id(PMID));
  std::string pmid_pub = ss_->PublicKey(PMID);
  std::string pmid_pub_sig = ss_->SignedPublicKey(PMID);
  std::string pmid_pri = ss_->PrivateKey(PMID);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name = co.Hash(non_hex_pmid + kAccount, "",
      crypto::STRING_STRING, false);
  // Find the account holders
  std::vector<kad::Contact> account_holders;
  if (FindKNodes(account_name, &account_holders) != kSuccess)
    return kFindAccountHoldersError;
  // Create the request
  boost::shared_ptr<boost::condition_variable>
      cond_var(new boost::condition_variable);
  GenericConditionData cond_data(cond_var);
  AccountStatusRequest account_status_request;
  account_status_request.set_account_pmid(non_hex_pmid);
  account_status_request.set_public_key(pmid_pub);
  account_status_request.set_public_key_signature(pmid_pub_sig);
  std::vector<AccountStatusRequest> account_status_requests;
  std::vector<AccountStatusResponse> account_status_responses;
  for (boost::uint16_t i = 0; i < account_holders.size(); ++i) {
    std::string request_signature = co.AsymSign(co.Hash(
        pmid_pub_sig + account_name + account_holders.at(i).node_id(), "",
        crypto::STRING_STRING, false), "", pmid_pri, crypto::STRING_STRING);
    account_status_request.set_request_signature(request_signature);
    AccountStatusResponse account_status_response;
    account_status_requests.push_back(account_status_request);
    account_status_responses.push_back(account_status_response);
  }
  // Send the requests
  boost::uint16_t rpcs_sent_count(account_status_responses.size());
  for (boost::uint16_t i = 0; i < rpcs_sent_count; ++i) {
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(&google::protobuf::DoNothing);
    rpcprotocol::Controller controller;
    client_rpcs_->AccountStatus(account_holders.at(i),
        AddressIsLocal(account_holders.at(i)), udt_transport_.GetID(),
        &account_status_requests.at(i), &account_status_responses.at(i),
        &controller, callback);
  }
  boost::uint16_t successful_count(0);
  boost::uint16_t failed_count(0);
  // Once we've got enough successful replies, cancel the remaining RPCs (they
  // should still succeed, we just won't handle the reply)
//  while (successful_count < kKadStoreThreshold_ &&
//         failed_count < kad::K - kKadStoreThreshold_ + 1 &&
//         successful_count + failed_count < ref_holders.size()) {
// TODO(Fraser#5#): 2009-10-13 - Preceding lines cause segfault on Unix due to
// callbacks trying to lock destructed mutex - figure out why.
  int timeout = 10000;  // milliseconds
  int timeout_count = 0;
  while ((successful_count + failed_count < rpcs_sent_count) &&
         (timeout_count < timeout)) {
    successful_count = 0;
    failed_count = 0;
    for (boost::uint16_t i = 0; i < rpcs_sent_count; ++i) {
      boost::mutex::scoped_lock lock(cond_data.cond_mutex);
      if (account_status_responses.at(i).IsInitialized()) {
        if (account_status_responses.at(i).result() == kAck) {
          ++successful_count;
          // If we've now got enough successes, populate account data
          if (successful_count == kKadStoreThreshold_) {
            if (account_status_responses.at(i).has_space_offered() &&
                account_status_responses.at(i).space_given() &&
                account_status_responses.at(i).space_taken()) {
              *space_offered = account_status_responses.at(i).space_offered();
              *space_given = account_status_responses.at(i).space_given();
              *space_taken = account_status_responses.at(i).space_taken();
            } else {  // Account data wasn't set correctly in response
              account_status_responses.at(i).set_result(kNack);
              --successful_count;
              ++failed_count;
            }
          }
        } else {
          ++failed_count;
        }
      } else {
        break;
      }
    }
    timeout_count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    if (timeout_count >= timeout)
      printf("\n\n\n\n\n\n\nAccount Status TIMED OUT\n\n\n\n\n\n\n\n");
  }
//  if (successful_count < kKadStoreThreshold_) {
//    retry?
// Cancel outstanding RPCs
// TODO(Fraser#5#): 2009-10-13 - Once preceding todo is resolved, reinstate
// following code.  Bool store_iou_response_returned needs replaced with
// three state flag, kPending, kReturned, kDone or similar.
//  for (boost::uint16_t j = 0; j < results.size(); ++j) {
//    if (!results.at(j)->store_iou_response_returned)
//      channel_manager_.
//          DeletePendingRequest(results.at(j)->controller->req_id());
//  }
  return kSuccess;
}

void MaidsafeStoreManager::GetChunkSignatureKeys(DirType dir_type,
                                                 const std::string &msid,
                                                 std::string *key_id,
                                                 std::string *public_key,
                                                 std::string *public_key_sig,
                                                 std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (dir_type) {
    case PRIVATE_SHARE:
      if (kSuccess == ss->GetShareKeys(msid, public_key, private_key)) {
        *key_id = msid;
        *public_key_sig =
            co.AsymSign(*public_key, "", *private_key, crypto::STRING_STRING);
      } else {
        key_id->clear();
        public_key->clear();
        public_key_sig->clear();
        private_key->clear();
      }
      break;
    case PUBLIC_SHARE:
      *key_id = ss->Id(MPID);
      *public_key = ss->PublicKey(MPID);
      *public_key_sig = ss->SignedPublicKey(MPID);
      *private_key = ss->PrivateKey(MPID);
      break;
    case ANONYMOUS:
      *key_id = " ";
      *public_key = " ";
      *public_key_sig = " ";
      *private_key = "";
      break;
    case PRIVATE:
    default:
      *key_id = ss->Id(PMID);
      *public_key = ss->PublicKey(PMID);
      *public_key_sig = ss->SignedPublicKey(PMID);
      *private_key = ss->PrivateKey(PMID);
      break;
  }
}

void MaidsafeStoreManager::GetPacketSignatureKeys(PacketType packet_type,
                                                  DirType dir_type,
                                                  const std::string &msid,
                                                  std::string *key_id,
                                                  std::string *public_key,
                                                  std::string *public_key_sig,
                                                  std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (packet_type) {
    case MID:
    case ANMID:
      *key_id = ss->Id(ANMID);
      *public_key = ss->PublicKey(ANMID);
      *public_key_sig = ss->SignedPublicKey(ANMID);
      *private_key = ss->PrivateKey(ANMID);
      break;
    case SMID:
    case ANSMID:
      *key_id = ss->Id(ANSMID);
      *public_key = ss->PublicKey(ANSMID);
      *public_key_sig = ss->SignedPublicKey(ANSMID);
      *private_key = ss->PrivateKey(ANSMID);
      break;
    case TMID:
    case ANTMID:
      *key_id = ss->Id(ANTMID);
      *public_key = ss->PublicKey(ANTMID);
      *public_key_sig = ss->SignedPublicKey(ANTMID);
      *private_key = ss->PrivateKey(ANTMID);
      break;
    case MPID:
    case ANMPID:
      *key_id = ss->Id(ANMPID);
      *public_key = ss->PublicKey(ANMPID);
      *public_key_sig = ss->SignedPublicKey(ANMPID);
      *private_key = ss->PrivateKey(ANMPID);
      break;
      // TODO(Fraser#5#): 2010-01-29 - Uncomment below once auth.cc fixed (MAID
      //                               should be signed by ANMAID, not self)
//    case MAID:
//    case ANMAID:
//      *key_id = ss->Id(ANMAID);
//      *public_key = ss->PublicKey(ANMAID);
//      *public_key_sig = ss->SignedPublicKey(ANMAID);
//      *private_key = ss->PrivateKey(ANMAID);
//      break;
//    case PMID:
//      *key_id = ss->Id(MAID);
//      *public_key = ss->PublicKey(MAID);
//      *public_key_sig = ss->SignedPublicKey(MAID);
//      *private_key = ss->PrivateKey(MAID);
//      break;
    case PMID:
    case MAID:
      *key_id = ss->Id(MAID);
      *public_key = ss->PublicKey(MAID);
      *public_key_sig = ss->SignedPublicKey(MAID);
      *private_key = ss->PrivateKey(MAID);
      break;
    case MSID:
    case PD_DIR:
      GetChunkSignatureKeys(dir_type, msid, key_id, public_key, public_key_sig,
                            private_key);
      break;
    case BUFFER:
    case BUFFER_INFO:
    case BUFFER_MESSAGE:
      *key_id = ss->Id(MPID);
      *public_key = ss->PublicKey(MPID);
      *public_key_sig = ss->SignedPublicKey(MPID);
      *private_key = ss->PrivateKey(MPID);
      break;
    default:
      break;
  }
}

int MaidsafeStoreManager::CreateBP() {
  BPInputParameters bi_input_params = {ss_->Id(MPID), ss_->PublicKey(MPID),
                                       ss_->PrivateKey(MPID)};
  bool called_back(false);
  boost::condition_variable cond_var;
  boost::mutex mutex;
  ReturnCode result;
  BPCallbackObj bp_callback_obj(&called_back, &cond_var, &mutex, &result);
  cbph_.CreateBufferPacket(bi_input_params, boost::bind(
      &BPCallbackObj::BPOperationCallback, &bp_callback_obj, _1),
      udt_transport_.GetID());
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!called_back)
      cond_var.wait(lock);
  }
  return result;
}

int MaidsafeStoreManager::LoadBPMessages(
    std::list<ValidatedBufferPacketMessage> *messages) {
  BPInputParameters bi_input_params = {ss_->Id(MPID), ss_->PublicKey(MPID),
                                       ss_->PrivateKey(MPID)};
  bool called_back(false);
  boost::condition_variable cond_var;
  boost::mutex mutex;
  ReturnCode result;
//  std::list<ValidatedBufferPacketMessage> received_messages;
  BPCallbackObj bp_callback_obj(&called_back, &cond_var, &mutex, &result,
                                messages);
  cbph_.GetMessages(bi_input_params, boost::bind(
      &BPCallbackObj::BPGetMessagesCallback, &bp_callback_obj, _1, _2),
      udt_transport_.GetID());
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!called_back)
      cond_var.wait(lock);
  }

//  crypto::Crypto crypto_obj_;
//  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
//  crypto_obj_.set_symm_algorithm(crypto::AES_256);
//  while (!received_messages.empty()) {
//    ValidatedBufferPacketMessage valid_message = received_messages.front();
//    std::string aes_key = crypto_obj_.AsymDecrypt(valid_message.index(), "",
//        ss_->PrivateKey(MPID), crypto::STRING_STRING);
//    valid_message.set_message(crypto_obj_.SymmDecrypt(valid_message.message(),
//        "", crypto::STRING_STRING, aes_key));
//    messages->push_back(valid_message);
//    received_messages.pop_front();
//  }
  return result;
}

int MaidsafeStoreManager::ModifyBPInfo(const std::string &info) {
  BPInputParameters bi_input_params = {ss_->Id(MPID), ss_->PublicKey(MPID),
                                       ss_->PrivateKey(MPID)};
  bool called_back(false);
  boost::condition_variable cond_var;
  boost::mutex mutex;
  ReturnCode result;
  BPCallbackObj bp_callback_obj(&called_back, &cond_var, &mutex, &result);
  std::vector<std::string> users;
  BufferPacketInfo buffer_packet_info;
  if (!buffer_packet_info.ParseFromString(info)) {
    printf("MaidsafeStoreManager::ModifyBPInfo - Wrong BPI\n");
    return kBPInfoParseError;
  }
  for (int i = 0; i < buffer_packet_info.users_size(); ++i)
    users.push_back(buffer_packet_info.users(i));
  cbph_.ModifyOwnerInfo(bi_input_params, ss_->ConnectionStatus(), users,
      boost::bind(&BPCallbackObj::BPOperationCallback, &bp_callback_obj, _1),
      udt_transport_.GetID());
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!called_back)
      cond_var.wait(lock);
  }
  return result;
}

int MaidsafeStoreManager::AddBPMessage(
    const std::vector<std::string> &receivers,
    const std::string &message,
    const MessageType &type) {
  BPInputParameters bi_input_params = {ss_->Id(MPID), ss_->PublicKey(MPID),
                                       ss_->PrivateKey(MPID)};
  bool called_back(false);
  boost::condition_variable cond_var;
  boost::mutex mutex;
  std::vector <ReturnCode> results;
  std::vector <BPCallbackObj> bp_callback_objs;
  // Set up callback objects and results
  for (size_t i = 0; i < receivers.size(); ++i) {
    ReturnCode result(kBPError);
    results.push_back(result);
    BPCallbackObj bp_callback_obj(&called_back, &cond_var, &mutex,
        &results.at(i));
    bp_callback_objs.push_back(bp_callback_obj);
  }
  // Add the message to each receiver's bp
  for (size_t i = 0; i < receivers.size(); ++i) {
    cbph_.AddMessage(bi_input_params, ss_->PublicUsername(),
        ss_->GetContactPublicKey(receivers.at(i)),
        receivers.at(i), message, type, boost::bind(
        &BPCallbackObj::BPOperationCallback, &bp_callback_objs.at(i), _1),
        udt_transport_.GetID());
  }
  // Wait for all to call back
  size_t returned_count(0);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!called_back && returned_count < receivers.size())
      cond_var.wait(lock);
    called_back = false;
    ++returned_count;
  }
  // Assess results and return
  ReturnCode result(kSuccess);
  for (size_t i = 0; i < receivers.size(); ++i) {
    if (results.at(i) != kSuccess) {
#ifdef DEBUG
      printf("In MSM::AddBPMessage, failed to AddMessage - result %u is %i\n",
             i, results.at(i));
#endif
      result = results.at(i);
      break;
    }
  }
  return result;
}

void MaidsafeStoreManager::AddToWatchList(const StoreData &store_data) {
  // TODO(Fraser#5#): 2009-12-21 - Consider repeating this until success or
  //                               some max. no. of failures.
  StoreTask task;
  // Assess whether to start the subtask or not
  TaskStatus status = AssessTaskStatus(store_data.non_hex_key, kStoreChunk,
                                       &task);
  if (status == kCompleted) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList (chunk %s): Task already completed.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return;
  }
  if (status == kCancelled) {
    if (task.active_subtask_count_ == 0) {
#ifdef DEBUG
      printf("In MSM::AddToWatchList (chunk %s): Task cancelled.\n",
             HexSubstr(store_data.non_hex_key).c_str());
#endif
      tasks_handler_.DeleteTask(store_data.non_hex_key, kStoreChunk,
                                kStoreCancelledOrDone);
    }
    return;
  }
  // Find the Chunk Info holders
  boost::shared_ptr<WatchListOpData> data(new WatchListOpData(store_data));
  int result = FindKNodes(store_data.non_hex_key, &data->contacts);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList, Kad lookup failed -- error %i\n", result);
#endif
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kStoreChunk,
                              kStoreChunkFindNodesFailure);
    return;
  }
  if (data->contacts.size() < kKadStoreThreshold_) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList, Kad lookup failed to find %u nodes; "
           "found %u nodes.\n", kKadStoreThreshold_, data->contacts.size());
#endif
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kStoreChunk,
                              kStoreChunkFindNodesFailure);
    return;
  }

  // Set up holders for forthcoming RPCs
  std::vector<AddToWatchListRequest> add_to_watch_list_requests;
  if (GetAddToWatchListRequests(store_data, data->contacts,
      &add_to_watch_list_requests) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList, failed to generate requests.\n");
#endif
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kStoreChunk,
                              kStoreChunkError);
    return;
  }
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    WatchListOpData::AddToWatchDataHolder holder(
        data->contacts.at(i).node_id());
    data->add_to_watchlist_data_holders.push_back(holder);
  }

  // Send RPCs
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::AddToWatchListCallback, j, data);
    client_rpcs_->AddToWatchList(data->contacts.at(j),
        AddressIsLocal(data->contacts.at(j)), udt_transport_.GetID(),
        &add_to_watch_list_requests.at(j),
        &data->add_to_watchlist_data_holders.at(j).response,
        data->add_to_watchlist_data_holders.at(j).controller.get(), callback);
  }
}

void MaidsafeStoreManager::AddToWatchListCallback(
    boost::uint16_t index,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->consensus_upload_copies >= 0)
    // Consensus has already been achieved and acted upon
    return;
  ++data->returned_count;
  WatchListOpData::AddToWatchDataHolder &holder =
      data->add_to_watchlist_data_holders.at(index);
  bool success(true);
  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListCallback, response %u is uninitialised.\n",
           index);
#endif
    success = false;
  }
  if (success && holder.response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListCallback, response %u has result %i.\n",
           index, holder.response.result());
#endif
    success = false;
  }
  if (success && holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListCallback, response %u from %s has pmid %s.\n",
           index, HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    success = false;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  }
  if (success && holder.response.upload_count() > kMinChunkCopies) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListCallback, response %u from %s has "
           "upload_count of %u.\n", index, HexSubstr(holder.node_id).c_str(),
           holder.response.upload_count());
#endif
    success = false;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  }

  if (success)
    data->required_upload_copies.insert(holder.response.upload_count());
  int result = AssessUploadCounts(data);
  if (result == kSuccess) {
    if (data->consensus_upload_copies > 0) {
      tasks_handler_.SetSuccessesRequired(data->store_data.non_hex_key,
          kStoreChunk, data->consensus_upload_copies);
      for (int i = 0; i < data->consensus_upload_copies; ++i) {
        // chunk_thread_pool_ handles destruction of send_chunk_copy_task.
        SendChunkCopyTask *send_chunk_copy_task =
            new SendChunkCopyTask(data->store_data, this);
        chunk_thread_pool_.start(send_chunk_copy_task);
      }
    } else {
      tasks_handler_.DeleteTask(data->store_data.non_hex_key, kStoreChunk,
                                kSuccess);
    }
  } else if (result == kUploadCopiesFailedConsensus) {
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kStoreChunk,
                              kUploadCopiesFailedConsensus);
  }
}

int MaidsafeStoreManager::AssessUploadCounts(
    boost::shared_ptr<WatchListOpData> data) {
  int discrete_opinions(0);
  size_t max_count(0);
  std::multiset<int>::iterator it;
  // data->mutex should already be locked, but just in case...
  boost::mutex::scoped_try_lock lock(data->mutex);
if (data->returned_count < kKadStoreThreshold_)
    return kUploadCopiesPendingConsensus;
  // Get most common upload_copies figure
  std::multiset<int> copy_required_upload_copies(data->required_upload_copies);
  while (!copy_required_upload_copies.empty()) {
    int current_copies = *(copy_required_upload_copies.begin());
    size_t current_count = copy_required_upload_copies.erase(current_copies);
    if (current_count > max_count) {
      max_count = current_count;
      data->consensus_upload_copies = current_copies;
    }
    ++discrete_opinions;
  }
  if (discrete_opinions == 1 && max_count >= kKadStoreThreshold_)
    return kSuccess;

  // If more than two discrete opinions, return error and set copies to zero.
  if (discrete_opinions > 2) {
    data->consensus_upload_copies = 0;
    return kUploadCopiesFailedConsensus;
  }
  // If no more results due, try to get consensus.
  if (data->returned_count >= data->add_to_watchlist_data_holders.size()) {
    if (discrete_opinions == 2) {
      it = data->required_upload_copies.end();
      --it;
      int max_copies(*it);
      it = data->required_upload_copies.begin();
      int min_copies(*it);
      // If max_copies is the most common figure, go with this.  Otherwise...
      if (data->consensus_upload_copies != max_copies) {
        if (data->store_data.size > kMaxSmallChunkSize && min_copies > 0)
          data->consensus_upload_copies = min_copies;
        else
          data->consensus_upload_copies = max_copies;
      }
    } else if (discrete_opinions == 0) {
      data->consensus_upload_copies = 0;
      return kUploadCopiesFailedConsensus;
    }
  } else {
      data->consensus_upload_copies = -1;
      return kUploadCopiesPendingConsensus;
  }
  // If not enough for consensus, return error and set copies to -1.
  if (static_cast<int>(data->required_upload_copies.count(
      data->consensus_upload_copies)) <= kad::K - kKadStoreThreshold_) {
    data->consensus_upload_copies = 0;
    return kUploadCopiesFailedConsensus;
  }
  return kSuccess;
}

TaskStatus MaidsafeStoreManager::AssessTaskStatus(const std::string &data_name,
                                                  StoreTaskType task_type,
                                                  StoreTask *task) {
  if (!tasks_handler_.Task(data_name, task_type, task))
    return kCompleted;
  // Check if there's a conflicting task and if there is, cancel the older one.
  StoreTaskType conflicting_type;
  bool potential_conflict(false);
  StoreTask conflicting_task;
  if (task_type == kStoreChunk) {
    conflicting_type = kDeleteChunk;
    potential_conflict = true;
  } else if (task_type == kDeleteChunk) {
    conflicting_type = kStoreChunk;
    potential_conflict = true;
  }
  if (potential_conflict) {
    if (tasks_handler_.Task(data_name, conflicting_type, &conflicting_task)) {
      if (conflicting_task.timestamp_ < task->timestamp_) {
        tasks_handler_.CancelTask(conflicting_task.data_name_,
                                  conflicting_type);
      } else {
        tasks_handler_.CancelTask(task->data_name_, task_type);
        return kCancelled;
      }
    }
  }
  if (task->cancelled_)
    return kCancelled;
  if (task->started_)
    return kStarted;
  else
    return kPending;
}

bool MaidsafeStoreManager::WaitForOnline(const std::string &data_name,
                                         const StoreTaskType &task_type) {
  while (ss_->ConnectionStatus() != 0) {  // offline
    // Check whether task has been finished or cancelled
    StoreTask task;
    if (!tasks_handler_.Task(data_name, task_type, &task))
      return false;
    if (task.cancelled_) {
      int overall_result = tasks_handler_.StopSubTask(data_name, task_type,
                                                      false);
#ifdef DEBUG
      printf("In MSM::WaitForOnline (data %s): Task cancelled.\n",
             HexSubstr(data_name).c_str());
#endif
      if (overall_result == kStoreTaskFinishedPass ||
          overall_result == kStoreTaskFinishedFail) {
        tasks_handler_.DeleteTask(data_name, task_type, kTaskCancelledOffline);
      }
      return false;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  return true;
}

bool MaidsafeStoreManager::AssessTaskAndOnlineStatus(
    const std::string &data_name,
    const StoreTaskType &task_type) {
  StoreTask task;
  int status = AssessTaskStatus(data_name, task_type, &task);
  if (status == kCompleted) {
#ifdef DEBUG
    printf("In MSM::AssessTaskAndOnlineStatus (data_name %s): Task already "
           "completed.\n", HexSubstr(data_name).c_str());
#endif
    return false;
  }
  if (status == kCancelled) {
#ifdef DEBUG
    printf("In MSM::AssessTaskAndOnlineStatus (data_name %s): Task "
           "cancelled.\n", HexSubstr(data_name).c_str());
#endif
    if (task.active_subtask_count_ <= 1) {
      tasks_handler_.DeleteTask(data_name, task_type, kTaskCancelledOffline);
    } else {
      tasks_handler_.StopSubTask(data_name, task_type, false);
    }
    return false;
  }
  return WaitForOnline(data_name, task_type);
}

int MaidsafeStoreManager::GetStoreRequests(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  StoreData &store_data = send_chunk_data->store_data;
  StorePrepRequest &store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest &store_chunk_request = send_chunk_data->store_chunk_request;
  store_prep_request.Clear();
  store_chunk_request.Clear();
  ValueType data_type = DATA;
  if (store_data.dir_type == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  ChunkType chunk_type = store_data.chunk_type;
  fs::path chunk_path(client_chunkstore_->GetChunkPath(store_data.non_hex_key,
                                                       chunk_type, false));
  if (chunk_path == fs::path(""))
    return kChunkNotInChunkstore;
  boost::uint64_t chunk_size = store_data.size;
  std::string chunk_content("");
  try {
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
    printf("MaidsafeStoreManager::GetStoreRequests - path: %s - %s\n",
           chunk_path.string().c_str(), e.what());
#endif
    return kStoreManagerException;
  }
  std::string request_signature("");
  GetRequestSignature(store_data, send_chunk_data->peer.node_id(),
                      &request_signature);
  if (request_signature.empty())
    return kGetRequestSigError;
  std::string non_hex_pmid = base::DecodeFromHex(ss_->Id(PMID));
  store_prep_request.set_chunkname(store_data.non_hex_key);
  SignedSize *mutable_signed_size = store_prep_request.mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_size);
  mutable_signed_size->set_pmid(non_hex_pmid);
  if (store_data.dir_type == ANONYMOUS) {
    mutable_signed_size->set_signature(request_signature);
    mutable_signed_size->set_public_key(" ");
    mutable_signed_size->set_public_key_signature(" ");
    store_prep_request.set_request_signature(request_signature);
  } else {
    crypto::Crypto co;
    co.set_symm_algorithm(crypto::AES_256);
    mutable_signed_size->set_signature(co.AsymSign(base::itos_ull(chunk_size),
        "", store_data.private_key, crypto::STRING_STRING));
    mutable_signed_size->set_public_key(store_data.public_key);
    mutable_signed_size->set_public_key_signature(
        store_data.public_key_signature);
    store_prep_request.set_request_signature(request_signature);
  }
  store_chunk_request.set_chunkname(store_data.non_hex_key);
  store_chunk_request.set_data(chunk_content);
  store_chunk_request.set_pmid(non_hex_pmid);
  store_chunk_request.set_public_key(store_data.public_key);
  store_chunk_request.set_public_key_signature(store_data.public_key_signature);
  store_chunk_request.set_request_signature(request_signature);
  store_chunk_request.set_data_type(data_type);
  return kSuccess;
}

int MaidsafeStoreManager::GetAddToWatchListRequests(
    const StoreData &store_data,
    const std::vector<kad::Contact> &recipients,
    std::vector<AddToWatchListRequest> *add_to_watch_list_requests) {
  add_to_watch_list_requests->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  AddToWatchListRequest request;
  request.set_chunkname(store_data.non_hex_key);
  SignedSize *mutable_signed_size = request.mutable_signed_size();
  mutable_signed_size->set_data_size(store_data.size);
  mutable_signed_size->set_signature(co.AsymSign(
      base::itos_ull(store_data.size), "", store_data.private_key,
      crypto::STRING_STRING));
  mutable_signed_size->set_pmid(store_data.key_id);
  mutable_signed_size->set_public_key(store_data.public_key);
  mutable_signed_size->set_public_key_signature(
      store_data.public_key_signature);
  for (size_t i = 0; i < recipients.size(); ++i) {
    std::string signature;
    GetRequestSignature(store_data.non_hex_key, store_data.dir_type,
        recipients.at(i).node_id(), store_data.public_key,
        store_data.public_key_signature, store_data.private_key, &signature);
    if (signature.empty()) {
      add_to_watch_list_requests->clear();
      return kGetRequestSigError;
    }
    request.set_request_signature(signature);
    add_to_watch_list_requests->push_back(request);
  }
  return kSuccess;
}

int MaidsafeStoreManager::GetRemoveFromWatchListRequests(
    const StoreData &store_data,
    const std::vector<kad::Contact> &recipients,
    std::vector<RemoveFromWatchListRequest> *remove_from_watch_list_requests) {
  remove_from_watch_list_requests->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  RemoveFromWatchListRequest request;
  request.set_chunkname(store_data.non_hex_key);
  request.set_pmid(store_data.key_id);
  request.set_public_key(store_data.public_key);
  request.set_public_key_signature(store_data.public_key_signature);
  for (size_t i = 0; i < recipients.size(); ++i) {
    std::string signature;
    GetRequestSignature(store_data.non_hex_key, store_data.dir_type,
        recipients.at(i).node_id(), store_data.public_key,
        store_data.public_key_signature, store_data.private_key, &signature);
    if (signature.empty()) {
      remove_from_watch_list_requests->clear();
      return kGetRequestSigError;
    }
    request.set_request_signature(signature);
    remove_from_watch_list_requests->push_back(request);
  }
  return kSuccess;
}

void MaidsafeStoreManager::GetRequestSignature(
    const std::string &non_hex_name,
    const DirType dir_type,
    const std::string &recipient_id,
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &private_key,
    std::string *request_signature) {
  request_signature->clear();
  if (dir_type == ANONYMOUS) {
    *request_signature = kAnonymousRequestSignature;
  } else if (public_key.empty() ||
             public_key_signature.empty() ||
             private_key.empty()) {
    return;
  } else {
    crypto::Crypto co;
    co.set_symm_algorithm(crypto::AES_256);
    co.set_hash_algorithm(crypto::SHA_512);
    *request_signature = co.AsymSign(co.Hash(
        public_key_signature + non_hex_name + recipient_id, "",
        crypto::STRING_STRING, false), "", private_key, crypto::STRING_STRING);
  }
}

void MaidsafeStoreManager::GetRequestSignature(const StoreData &store_data,
                                               const std::string &recipient_id,
                                               std::string *request_signature) {
  GetRequestSignature(store_data.non_hex_key, store_data.dir_type,
      recipient_id, store_data.public_key, store_data.public_key_signature,
      store_data.private_key, request_signature);
}

int MaidsafeStoreManager::GetStorePeer(const float &,
                                       const std::vector<kad::Contact> &exclude,
                                       kad::Contact *new_peer,
                                       bool *local) {
// TODO(Fraser#5#): 2009-08-08 - Complete this so that rtt & rank is considered.
  std::vector<kad::Contact> result;
  knode_->GetRandomContacts(1, exclude, &result);
  if (result.size() == static_cast<unsigned int>(0))
    return kGetStorePeerError;
  *new_peer = result.at(0);
  *local = AddressIsLocal(*new_peer);
  return kSuccess;
}

int MaidsafeStoreManager::SendChunkPrep(const StoreData &store_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendChunkPrep\n");
#endif
  StoreTask task;
  // Assess whether to start the subtask or not
  TaskStatus status = AssessTaskStatus(store_data.non_hex_key, kStoreChunk,
      &task);
  if (status == kCompleted) {
#ifdef DEBUG
    printf("In MSM::SendChunkPrep (chunk %s): Task already completed.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return kStoreCancelledOrDone;
  }
  if (status == kCancelled) {
    if (task.active_subtask_count_ == 0) {
#ifdef DEBUG
      printf("In MSM::SendChunkPrep (chunk %s): Task cancelled.\n",
             HexSubstr(store_data.non_hex_key).c_str());
#endif
      tasks_handler_.DeleteTask(store_data.non_hex_key, kStoreChunk,
                                kStoreCancelledOrDone);
    }
    return kStoreCancelledOrDone;
  }
//  // Establish if this is the first SendChunkPrep for the overall task
//  bool first(task.success_count_ == 0);
//  // Get peer
// TODO(Fraser#5#): 2009-08-14 - Uncomment lines below
//  if (first) {  // set largest_rtt from first peer
//    base::PDRoutingTableHandler rt_handler;
//    base::PDRoutingTableTuple peer_details;
//    if (rt_handler.GetTupleInfo(peer.node_id(), &peer_details) != kSuccess) {
//      set largest rtt via tasks_handler_.SetRtt
//      largest_rtt = 1.0f;
//    } else {
//      set largest rtt via tasks_handler_.SetRtt
//      largest_rtt = peer_details.rtt();
//    }
//  } else {
//    float ideal_rtt = task.largest_rtt * (1 -
//        (static_cast<float>(task.success_count_)/task.successes_required_));
//  }
  float ideal_rtt = 1.0f;
  kad::Contact peer;
  bool local(false);
  int peer_result = GetStorePeer(ideal_rtt, task.exclude_peers_, &peer, &local);
  // Start subtask
  if (tasks_handler_.StartSubTask(store_data.non_hex_key, kStoreChunk, peer) !=
      kSuccess)
    return kSendChunkFailure;
  // If GetStorePeer failed, stop subtask to record failure
  if (peer_result != kSuccess) {
    tasks_handler_.StopSubTask(store_data.non_hex_key, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunkPrep (chunk %s): Error getting store peer.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return kGetStorePeerError;
  }
  // Form store requests
  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data, peer, local));
  int result = GetStoreRequests(send_chunk_data);
  if (result != kSuccess) {
    tasks_handler_.StopSubTask(store_data.non_hex_key, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunkPrep (chunk %s): Error getting store requests.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return result;
  }
  // Check we're online and parent task has not been completed or cancelled
  if (!WaitForOnline(store_data.non_hex_key, kStoreChunk)) {
#ifdef DEBUG
    printf("In MSM::SendChunkPrep (chunk %s): Offline before sending prep.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return kTaskCancelledOffline;
  }
  // Send prep
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendPrepCallback, send_chunk_data);
  client_rpcs_->StorePrep(peer,
                          local,
                          udt_transport_.GetID(),
                          &send_chunk_data->store_prep_request,
                          &send_chunk_data->store_prep_response,
                          send_chunk_data->controller.get(),
                          callback);
  return kSuccess;
}

void MaidsafeStoreManager::SendPrepCallback(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPrepCallback.\n");
#endif
  ++send_chunk_data->attempt;
  int result = ValidatePrepResponse(send_chunk_data->peer.node_id(),
      send_chunk_data->store_prep_request.signed_size(),
      &send_chunk_data->store_prep_response);
  if (result == kSuccess) {
    SendChunkContent(send_chunk_data);
  } else if (send_chunk_data->attempt < kMaxChunkStoreTries) {
    // Check the task hasn't been completed or cancelled and that we're online
    if (!AssessTaskAndOnlineStatus(send_chunk_data->store_data.non_hex_key,
        kStoreChunk)) {
#ifdef DEBUG
      printf("In MSM::SendChunkPrep (chunk %s): Task cancelled/completed.\n",
             HexSubstr(send_chunk_data->store_data.non_hex_key).c_str());
#endif
      return;
    }
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::SendPrepCallback, send_chunk_data);
    send_chunk_data->store_prep_response.Clear();
    client_rpcs_->StorePrep(send_chunk_data->peer,
                            send_chunk_data->local,
                            udt_transport_.GetID(),
                            &send_chunk_data->store_prep_request,
                            &send_chunk_data->store_prep_response,
                            send_chunk_data->controller.get(),
                            callback);
  } else {
    int overall_result = tasks_handler_.StopSubTask(
        send_chunk_data->store_data.non_hex_key, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendPrepCallback (chunk %s): Error sending prep.\n",
           HexSubstr(send_chunk_data->store_data.non_hex_key).c_str());
#endif
    if (overall_result == kStoreTaskFinishedPass ||
        overall_result == kStoreTaskFinishedFail) {
      tasks_handler_.DeleteTask(send_chunk_data->store_data.non_hex_key,
                                kStoreChunk, kSendPrepFailure);
    }
    return;
  }
}

int MaidsafeStoreManager::ValidatePrepResponse(
    const std::string &peer_node_id,
    const SignedSize &request_signed_size,
    StorePrepResponse *const store_prep_response) {
  // Check response is initialised and from correct peer
  if (!store_prep_response->IsInitialized())
    return kSendPrepResponseUninitialised;
  StoreContract store_contract = store_prep_response->store_contract();
  if (!store_contract.IsInitialized())
    return kSendPrepResponseUninitialised;
  StoreContract::InnerContract inner_contract = store_contract.inner_contract();
  if (!inner_contract.IsInitialized())
    return kSendPrepResponseUninitialised;
  if (store_contract.pmid() != peer_node_id)
    return kSendPrepPeerError;
  // Check original SignedSize is unaltered
  std::string ser_req_signed_size, ser_resp_signed_size;
  request_signed_size.SerializeToString(&ser_req_signed_size);
  inner_contract.signed_size().SerializeToString(&ser_resp_signed_size);
  if (ser_req_signed_size != ser_resp_signed_size)
    return kSendPrepSignedSizeAltered;
  // Check response is kAck & peer PMID validates
  if (inner_contract.result() != kAck)
    return kSendPrepFailure;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (store_contract.pmid() != co.Hash(store_contract.public_key() +
      store_contract.public_key_signature(), "", crypto::STRING_STRING, false))
    return kSendPrepInvalidId;
  // Check peer correctly signed StoreContract and InnerContract
  std::string ser_store_contract, ser_inner_contract;
  store_contract.SerializeToString(&ser_store_contract);
  inner_contract.SerializeToString(&ser_inner_contract);
  if (!co.AsymCheckSig(ser_store_contract,
                       store_prep_response->response_signature(),
                       store_contract.public_key(),
                       crypto::STRING_STRING))
    return kSendPrepInvalidResponseSignature;
  if (!co.AsymCheckSig(ser_inner_contract, store_contract.signature(),
                       store_contract.public_key(), crypto::STRING_STRING))
    return kSendPrepInvalidContractSignature;
  return kSuccess;
}

int MaidsafeStoreManager::SendChunkContent(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  // Check the task hasn't been completed or cancelled and that we're online
  if (!AssessTaskAndOnlineStatus(send_chunk_data->store_data.non_hex_key,
      kStoreChunk)) {
#ifdef DEBUG
      printf("In MSM::SendChunkContent (chunk %s): Task cancelled/completed.\n",
             HexSubstr(send_chunk_data->store_data.non_hex_key).c_str());
#endif
    return kStoreCancelledOrDone;
  }
  // Send chunk content
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendContentCallback, send_chunk_data);
  client_rpcs_->StoreChunk(send_chunk_data->peer,
                           send_chunk_data->local,
                           udt_transport_.GetID(),
                           &send_chunk_data->store_chunk_request,
                           &send_chunk_data->store_chunk_response,
                           send_chunk_data->controller.get(),
                           callback);
  return kSuccess;
}

void MaidsafeStoreManager::SendContentCallback(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  ++send_chunk_data->attempt;
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendContentCallback.\n");
#endif
  StoreChunkResponse &response = send_chunk_data->store_chunk_response;
  int result(kSuccess);
  if (!response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::SendContentCallback, resp from pmid %s uninitialised.\n",
           HexSubstr(send_chunk_data->peer.node_id()).c_str());
#endif
    result = kSendContentFailure;
  }
  if (result == kSuccess &&
      response.pmid() != send_chunk_data->peer.node_id()) {
#ifdef DEBUG
    printf("In MSM::SendContentCallback, ids are not OK: response pmid: %s pee"
           "r node ID: %s\n", HexSubstr(response.pmid()).c_str(),
           HexSubstr(send_chunk_data->peer.node_id()).c_str());
#endif
    result = kSendContentFailure;
  }
  if (result == kSuccess && response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::SendContentCallback, resp from pmid %s returned %u\n",
           HexSubstr(send_chunk_data->peer.node_id()).c_str(),
           response.result());
#endif
    result = kSendContentFailure;
  }
  if (result == kSuccess) {
#ifdef DEBUG
//    printf("In MSM::SendContentCallback, succeeded.\n");
#endif
    std::string &chunkname = send_chunk_data->store_data.non_hex_key;
    // Stop subtask - record success
    int overall_result =
        tasks_handler_.StopSubTask(chunkname, kStoreChunk, true);
#ifdef DEBUG
    StoreTask task;
    AssessTaskStatus(send_chunk_data->store_data.non_hex_key, kStoreChunk,
                     &task);
    printf("Chunkname: %s  Dup count: %i\n\n", HexSubstr(chunkname).c_str(),
           task.success_count_ + 1);
#endif
    if (overall_result == kStoreTaskFinishedPass ||
        overall_result == kStoreTaskFinishedFail) {
      tasks_handler_.DeleteTask(chunkname, kStoreChunk, kSuccess);
    }
    // TODO(Fraser#5#): 2009-08-14 - Check later that there are enough vaults
    // listed in ref & watch lists to ensure upload ultimately successful.

    // Move chunk from Outgoing to Normal.  If this operation fails, still
    // return kSuccess as this is non-critical.
    ChunkType chunk_type = client_chunkstore_->chunk_type(chunkname);
    ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
    if (client_chunkstore_->ChangeChunkType(chunkname, new_type) != kSuccess) {
#ifdef DEBUG
      printf("In MSM::SendContentCallback, failed to change chunk type.\n");
#endif
    }
  } else if (send_chunk_data->attempt < kMaxChunkStoreTries) {  // Retry
    // Check the task hasn't been completed or cancelled and that we're online
    if (!AssessTaskAndOnlineStatus(send_chunk_data->store_data.non_hex_key,
        kStoreChunk)) {
#ifdef DEBUG
        printf("In MSM::SendContentCallback (chunk %s): Task cancelled/done\n",
               HexSubstr(send_chunk_data->store_data.non_hex_key).c_str());
#endif
      return;
    }
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::SendContentCallback, send_chunk_data);
    send_chunk_data->store_chunk_response.Clear();
    client_rpcs_->StoreChunk(send_chunk_data->peer,
                             send_chunk_data->local,
                             udt_transport_.GetID(),
                             &send_chunk_data->store_chunk_request,
                             &send_chunk_data->store_chunk_response,
                             send_chunk_data->controller.get(),
                             callback);
  } else {  // Fail
    int overall_result = tasks_handler_.StopSubTask(
        send_chunk_data->store_data.non_hex_key, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendPrepCallback (chunk %s): Error sending content.\n",
           HexSubstr(send_chunk_data->store_data.non_hex_key).c_str());
#endif
    if (overall_result == kStoreTaskFinishedPass ||
        overall_result == kStoreTaskFinishedFail) {
      tasks_handler_.DeleteTask(send_chunk_data->store_data.non_hex_key,
                                kStoreChunk, kSendContentFailure);
    }
  }
}

void MaidsafeStoreManager::RemoveFromWatchList(const StoreData &store_data) {
  // TODO(Fraser#5#): 2009-12-21 - Consider repeating this until success or
  //                               some max. no. of failures.
  StoreTask task;
  // Assess whether to start the subtask or not
  TaskStatus status = AssessTaskStatus(store_data.non_hex_key, kDeleteChunk,
                                       &task);
  if (status == kCompleted) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList (chunk %s): Task already completed.\n",
           HexSubstr(store_data.non_hex_key).c_str());
#endif
    return;
  }
  if (status == kCancelled) {
    if (task.active_subtask_count_ == 0) {
#ifdef DEBUG
      printf("In MSM::RemoveFromWatchList (chunk %s): Task cancelled.\n",
             HexSubstr(store_data.non_hex_key).c_str());
#endif
      tasks_handler_.DeleteTask(store_data.non_hex_key, kDeleteChunk,
                                kDeleteCancelledOrDone);
    }
    return;
  }
  // Find the Chunk Info holders
  boost::shared_ptr<WatchListOpData> data(new WatchListOpData(store_data));
  int result = FindKNodes(store_data.non_hex_key, &data->contacts);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList, Kad lookup failed -- error %i\n",
           result);
#endif
    tasks_handler_.DeleteTask(store_data.non_hex_key, kDeleteChunk,
                              kDeleteChunkFindNodesFailure);
    return;
  }
  if (data->contacts.size() < kKadStoreThreshold_) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList, Kad lookup failed to find %u nodes; "
           "found %u nodes.\n", kKadStoreThreshold_, data->contacts.size());
#endif
    tasks_handler_.DeleteTask(store_data.non_hex_key, kDeleteChunk,
                              kDeleteChunkFindNodesFailure);
    return;
  }

  // Set up holders for forthcoming RPCs
  std::vector<RemoveFromWatchListRequest> remove_from_watch_list_requests;
  if (GetRemoveFromWatchListRequests(store_data, data->contacts,
      &remove_from_watch_list_requests) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList, failed to generate requests.\n");
#endif
    tasks_handler_.DeleteTask(store_data.non_hex_key, kDeleteChunk,
                              kDeleteChunkError);
    return;
  }
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    WatchListOpData::RemoveFromWatchDataHolder holder(
        data->contacts.at(i).node_id());
    data->remove_from_watchlist_data_holders.push_back(holder);
  }

  // Send RPCs
  for (boost::uint16_t j = 0; j < data->contacts.size(); ++j) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::RemoveFromWatchListCallback, j, data);
    client_rpcs_->RemoveFromWatchList(data->contacts.at(j),
        AddressIsLocal(data->contacts.at(j)), udt_transport_.GetID(),
        &remove_from_watch_list_requests.at(j),
        &data->remove_from_watchlist_data_holders.at(j).response,
        data->remove_from_watchlist_data_holders.at(j).controller.get(),
        callback);
  }
}

void MaidsafeStoreManager::RemoveFromWatchListCallback(
    boost::uint16_t index,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->successful_delete_count >= kKadStoreThreshold_)
    // Success has already been achieved and acted upon
    return;
  ++data->returned_count;
  WatchListOpData::RemoveFromWatchDataHolder &holder =
      data->remove_from_watchlist_data_holders.at(index);
  bool success(true);
  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListCallback, response %u uninitialised.\n",
           index);
#endif
    success = false;
  }
  if (success && holder.response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListCallback, response %u has result %i.\n",
           index, holder.response.result());
#endif
    success = false;
  }
  if (success && holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListCallback, response %u from %s has "
           "pmid %s.\n", index, HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    success = false;
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  }

  if (success)
    ++data->successful_delete_count;

  // Overall success
  if (data->successful_delete_count >= kKadStoreThreshold_) {
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kDeleteChunk,
                              kSuccess);
    return;
  }
  // Overall failure
  if (data->returned_count >= data->contacts.size())
    tasks_handler_.DeleteTask(data->store_data.non_hex_key, kDeleteChunk,
                              kDeleteChunkFailure);
}

int MaidsafeStoreManager::FindKNodes(const std::string &kad_key,
                                     std::vector<kad::Contact> *contacts) {
  CallbackObj kad_cb_obj;
  knode_->FindCloseNodes(kad_key, boost::bind(&CallbackObj::CallbackFunc,
      &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
  if (kad_cb_obj.result().empty()) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, fail - timeout.\n");
#endif
    return kFindNodesError;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, can't parse result.\n");
#endif
    return kFindNodesParseError;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, Kademlia operation failed.\n");
#endif
    return kFindNodesFailure;
  }
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::FindKNodes, succeeded.\n");
#endif
  return kSuccess;
}

int MaidsafeStoreManager::FindValue(const std::string &kad_key,
                                    bool check_local,
                                    kad::ContactInfo *cache_holder,
                                    std::vector<std::string> *values,
                                    std::string *needs_cache_copy_id) {
  cache_holder->Clear();
  values->clear();
  needs_cache_copy_id->clear();
  CallbackObj kad_cb_obj;
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::FindValue, before.\n");
#endif
  knode_->FindValue(kad_key, check_local,
      boost::bind(&CallbackObj::CallbackFunc, &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::FindValue, after.\n");
#endif
  if (kad_cb_obj.result().empty()) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, fail - timeout.\n");
#endif
    return kFindValueError;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, can't parse result.\n");
#endif
    return kFindValueParseError;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, Kademlia operation "
           "failed to find the value for key %s.\n",
           HexSubstr(kad_key).c_str());
    printf("Found %i nodes\n", find_response.closest_nodes_size());
    printf("Found %i values\n", find_response.values_size());
//    printf("Found alt val holder: %i\n",
//           find_response.has_alternative_value_holder());
#endif
    return kFindValueFailure;
  }
  if (find_response.has_needs_cache_copy())
    *needs_cache_copy_id = find_response.needs_cache_copy();
  // If the response has an alternative_value, then the value is the ID of a
  // peer which has a cached copy of the chunk.
  if (find_response.has_alternative_value_holder()) {
    *cache_holder = find_response.alternative_value_holder();
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, node %s has cached the "
           "value.\n", cache_holder->node_id().substr(0, 20).c_str());
#endif
    return kSuccess;
  }
  for (int i = find_response.values_size(); i > 0; --i) {
    values->push_back(find_response.values(i - 1));
  }
#ifdef DEBUG
  printf("In MaidsafeStoreManager::FindValue, %i values have returned.\n",
         values->size());
#endif
  return (values->size() > 0) ? kSuccess : kFindValueFailure;
}

void MaidsafeStoreManager::FindAvailableChunkHolders(
    const std::string &chunk_name,
    const std::vector<std::string> &chunk_holders_ids,
    boost::shared_ptr<GenericConditionData> cond_data,
    std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
    int *available_chunk_holder_index,
    bool *stop_sending,
    int *check_chunk_rpc_count) {
  chunk_holders->clear();
  *check_chunk_rpc_count = 0;
  // Find chunk holders' contact details
  for (size_t h = 0; h < chunk_holders_ids.size(); ++h) {
    knode_->FindCloseNodes(chunk_holders_ids[h],
        boost::bind(&MaidsafeStoreManager::GetHolderContactCallback, this,
        chunk_holders_ids[h], _1, chunk_holders, cond_data));
  }
  // For each, if we have their contact details, check they still have the chunk
  for (size_t i = 0; i < chunk_holders_ids.size(); ++i) {
    // End now if calling function is satisfied that no more CheckChunk RPCs
    // need sent.
    if (*stop_sending)
      break;
    boost::mutex::scoped_lock lock(cond_data->cond_mutex);
    while (i >= chunk_holders->size()) {
//     printf("MaidsafeStoreManager::FindAvailableChunkHolders locked %u\n", i);
      cond_data->cond_variable->wait(lock);
//   printf("MaidsafeStoreManager::FindAvailableChunkHolders unlocked %u\n", i);
    }
    chunk_holders->at(i)->index = i;
    if (*stop_sending)
      break;
    if (chunk_holders->at(i)->status != kFailedHolder) {
      kad::Contact new_peer = chunk_holders->at(i)->chunk_holder_contact;
      chunk_holders->at(i)->local = AddressIsLocal(new_peer);
      CheckChunkRequest check_chunk_request;
      check_chunk_request.set_chunkname(chunk_name);
      chunk_holders->at(i)->mutex = &cond_data->cond_mutex;
      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      chunk_holders->at(i)->controller = controller;
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::HasChunkCallback, chunk_holders->at(i),
          available_chunk_holder_index);
      client_rpcs_->CheckChunk(chunk_holders->at(i)->chunk_holder_contact,
          chunk_holders->at(i)->local, udt_transport_.GetID(),
          &check_chunk_request, &chunk_holders->at(i)->check_chunk_response,
          controller.get(), callback);
      ++(*check_chunk_rpc_count);
    }
  }
//  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
}

bool MaidsafeStoreManager::AddressIsLocal(const kad::Contact &peer) {
  return knode_->CheckContactLocalAddress(peer.node_id(), peer.local_ip(),
      peer.local_port(), peer.host_ip()) == kad::LOCAL;
}

bool MaidsafeStoreManager::AddressIsLocal(const kad::ContactInfo &peer) {
  return knode_->CheckContactLocalAddress(peer.node_id(), peer.local_ip(),
      peer.local_port(), peer.ip()) == kad::LOCAL;
}

void MaidsafeStoreManager::GetHolderContactCallback(
    const std::string &chunk_holder_id,
    const std::string &result,
    std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
    boost::shared_ptr<GenericConditionData> cond_data) {
  boost::shared_ptr<ChunkHolder>
      failed_chunkholder(new ChunkHolder(kad::Contact(chunk_holder_id, "", 0)));
  failed_chunkholder->status = kFailedHolder;
  if (result.empty()) {
#ifdef DEBUG
    printf("In MSM::GetHolderContactCallback, fail - timeout.\n");
#endif
//    printf("MaidsafeStoreManager::GetHolderContactCallback 1 locked\n");
    boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
    chunk_holders->push_back(failed_chunkholder);
    cond_data->cond_variable->notify_all();
//    printf("MaidsafeStoreManager::GetHolderContactCallback 1 unlocked\n");
    return;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(result)) {
#ifdef DEBUG
    printf("In MSM::GetHolderContactCallback, can't parse result.\n");
#endif
//    printf("MaidsafeStoreManager::GetHolderContactCallback 2 locked\n");
    boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
    chunk_holders->push_back(failed_chunkholder);
    cond_data->cond_variable->notify_all();
//    printf("MaidsafeStoreManager::GetHolderContactCallback 2 unlocked\n");
    return;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::GetHolderContactCallback, Kad operation failed.\n");
#endif
//    printf("MaidsafeStoreManager::GetHolderContactCallback 3 locked\n");
    boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
    chunk_holders->push_back(failed_chunkholder);
    cond_data->cond_variable->notify_all();
//    printf("MaidsafeStoreManager::GetHolderContactCallback 3 unlocked\n");
    return;
  }
  // If we have the desired node's details, return them, otherwise push back a
  // contact with no IP/port.
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    if (contact.node_id() == chunk_holder_id) {
      boost::shared_ptr<ChunkHolder> chunkholder(new ChunkHolder(contact));
      chunkholder->status = kContactable;
//      printf("MaidsafeStoreManager::GetHolderContactCallback 4 locked\n");
      boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
      chunk_holders->push_back(chunkholder);
      cond_data->cond_variable->notify_all();
//      printf("MaidsafeStoreManager::GetHolderContactCallback 4 unlocked\n");
      return;
    }
  }
#ifdef DEBUG
  printf("In MSM::GetHolderContactCallback, didn't get node's details.\n");
#endif
//  printf("MaidsafeStoreManager::GetHolderContactCallback 5 locked\n");
  boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
  chunk_holders->push_back(failed_chunkholder);
  cond_data->cond_variable->notify_all();
//  printf("MaidsafeStoreManager::GetHolderContactCallback 5 unlocked\n");
  return;
}

void MaidsafeStoreManager::HasChunkCallback(
    boost::shared_ptr<ChunkHolder> chunk_holder,
    int *available_chunk_holder_index) {
  boost::lock_guard<boost::mutex> lock(*(chunk_holder->mutex));
  if (chunk_holder->check_chunk_response.result() == kNack) {
#ifdef DEBUG
//      printf("In MSM::HasChunkCallback (%d), %d doesn't have the chunk.\n",
//             knode_->host_port(),
//             chunk_holder->chunk_holder_contact.host_port());
#endif
    chunk_holder->status = kFailedHolder;
    // If available_chunk_holder_index is < 0, decrement it to indicate
    // another unsuccessful CheckChunk RPC.
    if (*available_chunk_holder_index < 0)
      --(*available_chunk_holder_index);
  } else if (chunk_holder->chunk_holder_contact.node_id() !=
             chunk_holder->check_chunk_response.pmid()) {
#ifdef DEBUG
    printf("In MSM, response from HasChunk came back from wrong node (%d).\n",
           knode_->host_port());
#endif
    chunk_holder->status = kFailedHolder;
    // If available_chunk_holder_index is < 0, decrement it to indicate
    // another unsuccessful CheckChunk RPC.
    if (*available_chunk_holder_index < 0)
      --(*available_chunk_holder_index);
  } else {
    chunk_holder->status = kHasChunk;
    // If available_chunk_holder_index is < 0, this is the first successful
    // response to the round of CheckChunk RPCs.
    if (*available_chunk_holder_index < 0)
      *available_chunk_holder_index = chunk_holder->index;
  }
  get_chunk_conditional_.notify_all();
}

int MaidsafeStoreManager::FindAndLoadChunk(
    const std::string &chunk_name,
    const std::vector<std::string> &chunk_holders_ids,
    bool load_data,
    std::string *data) {
  boost::shared_ptr<boost::condition_variable>
      cond_variable(new boost::condition_variable);
  boost::shared_ptr<GenericConditionData>
      cond_data(new GenericConditionData(cond_variable));
  boost::mutex get_mutex;
  std::vector< boost::shared_ptr<ChunkHolder> > chunk_holders;
  int available_chunk_holder_index(-1);
  int holder_count(0);
  bool stop_sending(false);
  int check_chunk_rpc_count(0);
  // If we need to load the data, iterate through all holders until the data has
  // been loaded, otherwise we can return after only one holder has confirmed
  // they have the data.
  if (load_data) {
    // Chunk holders responding to CheckChunk RPCs (from
    // FindAvailableChunkHolders below) amend available_chunk_holder_index.  If
    // they don't have the chunk, they decrement it by 1.  If they do, and
    // available_chunk_holder_index < 0, they set it to their own index in the
    // vector chunk_holders.  If they do have the chunk, and
    // available_chunk_holder_index >= 0, then they don't adjust it (as they're
    // not the first node to reply positively).
    int first_respondent_index(-1);
    int index(-1);
    while (data->empty()) {
      {
        boost::mutex::scoped_lock lock(get_mutex);
        // This function reads the chunk ref packet to get the IDs of holders &
        // querys them via CheckChunk RPCs, but doesn't wait for the responses.
        FindAvailableChunkHolders(chunk_name, chunk_holders_ids, cond_data,
                                  &chunk_holders,
                                  &available_chunk_holder_index,
                                  &stop_sending, &check_chunk_rpc_count);
        holder_count = static_cast<int>(chunk_holders_ids.size());
        // Wait until we get a positive response to one of the CheckChunk RPCs
        // or until they have all failed.
#ifdef DEBUG
        printf("available_chunk_holder_index: %i\n",
               available_chunk_holder_index);
        printf("holder_count: %i\n", holder_count);
#endif
        while ((available_chunk_holder_index < 0) &&
            (available_chunk_holder_index != (-1 - holder_count))) {
          get_chunk_conditional_.wait(lock);
#ifdef DEBUG
          printf("available_chunk_holder_index: %i\n",
                 available_chunk_holder_index);
#endif
        }
        index = available_chunk_holder_index;
      }
      // If none of the chunk holders have the chunk, fail.
      if (index == -1 - holder_count) {
#ifdef DEBUG
        printf("None of the holders actually are.\n");
#endif
        break;
      }
      // Set the first_repondent_index if this is the first iteration
      bool available_holder(false);
      if (index != first_respondent_index) {
        available_holder = true;
        first_respondent_index = index;
        {
          boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
          chunk_holders.at(index)->status = kAwaitingChunk;
        }
        GetChunk(chunk_name, chunk_holders.at(index), data, &get_mutex);
      } else {  // Iterate through chunk_holders to get another non-failed one.
        for (size_t k = 0; k < chunk_holders.size(); ++k) {
          if (chunk_holders.at(k)->status == kHasChunk) {
            available_holder = true;
            {
              boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
              chunk_holders.at(k)->status = kAwaitingChunk;
            }
            GetChunk(chunk_name, chunk_holders.at(k), data, &get_mutex);
            break;
          }
        }
      }
      // If we've tried all possible chunkholders, fail.
      if (!available_holder)
        break;
    }
  } else {  // Don't need to load the actual data
    boost::mutex::scoped_lock lock(get_mutex);
    // This function reads the chunk ref packet to get the IDs of holders &
    // querys them via CheckChunk RPCs, but doesn't wait for the responses.
    FindAvailableChunkHolders(chunk_name, chunk_holders_ids, cond_data,
                              &chunk_holders, &available_chunk_holder_index,
                              &stop_sending, &check_chunk_rpc_count);
    holder_count = static_cast<int>(chunk_holders_ids.size());
    // Wait until we get a positive response to one of the CheckChunk RPCs or
    // until they have all failed.
    while ((available_chunk_holder_index < 0) &&
           (available_chunk_holder_index != (-1 - holder_count)))
      get_chunk_conditional_.wait(lock);
  }
  // Stop FindAvailableChunkHolders from sending further RPCs
  stop_sending = true;
  // Cancel outstanding RPCs
  {
    boost::mutex::scoped_lock loch(cond_data->cond_mutex);
    for (int m = 0; m < holder_count; ++m) {
      if (chunk_holders.at(m)->status == kContactable) {
        if (chunk_holders.at(m)->controller.get() != NULL) {
          channel_manager_.DeletePendingRequest(chunk_holders.at(m)->
              controller->req_id());
        }
      }
    }
  }
  if (load_data)
    return data->empty() ? kLoadedChunkEmpty : kSuccess;

//  while (!find_holders_finshed) {
//    printf("FindAvailableChunkHolders still hasn't finished\n");
//    boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
//  }
  return (available_chunk_holder_index < 0) ? kLoadChunkFailure : kSuccess;
}

int MaidsafeStoreManager::GetChunk(const std::string &chunk_name,
                                   boost::shared_ptr<ChunkHolder> chunk_holder,
                                   std::string *data,
                                   boost::mutex *get_mutex) {
  GetChunkRequest get_chunk_request;
  get_chunk_request.set_chunkname(chunk_name);
  GetChunkResponse get_chunk_response;
  bool get_chunk_done(false);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::GetChunkCallback, get_mutex, &get_chunk_done);
  rpcprotocol::Controller controller;
  client_rpcs_->GetChunk(chunk_holder->chunk_holder_contact,
      chunk_holder->local, udt_transport_.GetID(), &get_chunk_request,
      &get_chunk_response, &controller, callback);
  {
    boost::mutex::scoped_lock lock(*get_mutex);
    while (!get_chunk_done) {
      get_chunk_conditional_.wait(lock);
    }
  }
  if (get_chunk_response.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from GetChunk came back failed (%d).\n",
           knode_->host_port());
#endif
    {  // NOLINT (Fraser)
      boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
      chunk_holder->status = kFailedHolder;
    }
    return kGetChunkFailure;
  }
  if (chunk_holder->chunk_holder_contact.node_id() !=
      get_chunk_response.pmid()) {
#ifdef DEBUG
    printf("In MSM, response from GetChunk came back from wrong node (%d).\n",
           knode_->host_port());
#endif
    {  // NOLINT (Fraser)
      boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
      chunk_holder->status = kFailedHolder;
    }
    return kGetChunkFailure;
  }
  *data = get_chunk_response.content();
  {  // NOLINT (Fraser)
    boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
    chunk_holder->status = kDone;
  }
  return kSuccess;
}

void MaidsafeStoreManager::GetChunkCallback(boost::mutex *mutex,
                                            bool *get_chunk_done) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::GetChunkCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(*mutex);
  *get_chunk_done = true;
  get_chunk_conditional_.notify_all();
}

/*
int MaidsafeStoreManager::StorePdDirToVaults(const std::string &hex_packet_name,
                                             const std::string &value,
                                             DirType dir_type,
                                             const std::string &msid) {
#ifdef DEBUG
//  std::string hex(hex_chunk_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::StorePacketToVaults (%i), packet name = "
//         "%s\n", knode_->host_port(), hex.c_str());
#endif
  if (ss_->ConnectionStatus() == 1)
    return kNotConnected;
//  std::string packet_name = base::DecodeFromHex(hex_packet_name);
//  std::string key_id, public_key, public_key_signature, private_key;
//  GetPacketSignatureKeys(PD_DIR, dir_type, msid, &key_id,
//      &public_key, &public_key_signature, &private_key);
//  AddStorePacketTask(StoreData(packet_name, value, PD_DIR, dir_type, msid,
// key_id, public_key, public_key_signature, private_key, true), true, NULL,
//      NULL);
//  return kSuccess;
}
*/

void MaidsafeStoreManager::FindCloseNodes(
    const std::vector<std::string> &packet_holder_ids,
    std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
    boost::shared_ptr<GenericConditionData> find_cond_data) {
  packet_holders->clear();
  // Find packet holders' contact details
  for (size_t h = 0; h < packet_holder_ids.size(); ++h) {
    knode_->FindCloseNodes(packet_holder_ids.at(h),
        boost::bind(&MaidsafeStoreManager::GetHolderContactCallback, this,
        packet_holder_ids.at(h), _1, packet_holders, find_cond_data));
  }
}

void MaidsafeStoreManager::SendPacketPrep(
    boost::shared_ptr<StoreData> store_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPacketPrep\n");
#endif
  ReturnCode to_return = kUndefined;
  kad::ContactInfo cache_holder;
  std::vector<std::string> values;
  std::string needs_cache_copy_id;
  int find_result = (FindValue(store_data->non_hex_key, true, &cache_holder,
                               &values, &needs_cache_copy_id));
  if (cache_holder.has_node_id())
    to_return = kSendPacketCached;
  bool exists = (find_result == kSuccess && values.size());
  // If FindValue failed to complete the kad function then return.
  if (to_return == kUndefined && !exists && find_result != kFindValueFailure) {
#ifdef DEBUG
    printf("In MSM::SendPacketPrep (%i), failed in FindValue.\n",
           knode_->host_port());
#endif
    to_return = kSendPacketFindValueFailure;
  }
  if (to_return == kUndefined) {
    if (exists) {
      switch (store_data->if_packet_exists) {
        case kDoNothingReturnFailure:
          to_return = kSendPacketAlreadyExists;
          break;
        case kDoNothingReturnSuccess:
          to_return = kSuccess;
          break;
        case kOverwrite:
          OverwritePacket(store_data, values);
          break;
        case kAppend:
          SendPacket(store_data);
          break;
        default:
          to_return = kSendPacketUnknownExistsType;
          break;
      }
    } else {
      SendPacket(store_data);
    }
  }
  if (to_return != kUndefined) {
#ifdef DEBUG
    printf("In MSM::SendPacketPrep, fail: %i.\n", to_return);
#endif
    store_data->callback(to_return);
  }
}

void MaidsafeStoreManager::SendPacket(boost::shared_ptr<StoreData> store_data) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  kad::SignedValue signed_value;
  signed_value.set_value(store_data->value);
  signed_value.set_value_signature(co.AsymSign(store_data->value, "",
      store_data->private_key, crypto::STRING_STRING));
  std::string signed_request = co.AsymSign(co.Hash(store_data->public_key +
      store_data->public_key_signature + store_data->non_hex_key, "",
      crypto::STRING_STRING, true), "", store_data->private_key,
      crypto::STRING_STRING);
  kad::SignedRequest sr;
  sr.set_signer_id(store_data->key_id);
  sr.set_public_key(store_data->public_key);
  sr.set_signed_public_key(store_data->public_key_signature);
  sr.set_signed_request(signed_request);
  base::callback_func_type cb = boost::bind(
      &MaidsafeStoreManager::SendPacketCallback, this, _1, store_data);
  knode_->StoreValue(store_data->non_hex_key, signed_value, sr, 31556926, cb);
}

void MaidsafeStoreManager::SendPacketCallback(
    const std::string &ser_kad_store_result,
    boost::shared_ptr<StoreData> store_data) {
  if (ser_kad_store_result.empty()) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback, fail - timeout.\n");
#endif
    store_data->callback(kSendPacketError);
    return;
  }
  kad::StoreResponse store_response;
  if (!store_response.ParseFromString(ser_kad_store_result)) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback, can't parse result.\n");
#endif
    store_data->callback(kSendPacketParseError);
    return;
  }
  if (store_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback, Kademlia operation failed.\n");
#endif
    store_data->callback(kSendPacketFailure);
    return;
  }
  store_data->callback(kSuccess);
}

void MaidsafeStoreManager::OverwritePacket(
    boost::shared_ptr<StoreData> store_data,
    const std::vector<std::string> &values) {
  boost::shared_ptr<DeletePacketData> delete_data(new DeletePacketData(
      store_data, values, boost::bind(
      &MaidsafeStoreManager::OverwritePacketStageTwo, this, store_data, _1)));
  DeletePacketFromNet(delete_data);
}

void MaidsafeStoreManager::OverwritePacketStageTwo(
    boost::shared_ptr<StoreData> store_data,
    const ReturnCode &delete_result) {
  if (delete_result == kSuccess)
    SendPacket(store_data);
  else
    store_data->callback(delete_result);
}

void MaidsafeStoreManager::DeletePacketFromNet(
    boost::shared_ptr<DeletePacketData> delete_data) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  base::callback_func_type cb = boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, this, _1, delete_data);
  boost::mutex::scoped_lock lock(delete_data->mutex);
  for (size_t i = 0; i < delete_data->values.size(); ++i) {
    kad::SignedValue signed_value;
    signed_value.set_value(delete_data->values.at(i));
    signed_value.set_value_signature(co.AsymSign(delete_data->values.at(i), "",
        delete_data->private_key, crypto::STRING_STRING));
    std::string signed_request = co.AsymSign(co.Hash(delete_data->public_key +
        delete_data->public_key_signature + delete_data->non_hex_packet_name,
        "", crypto::STRING_STRING, true), "", delete_data->private_key,
        crypto::STRING_STRING);
    kad::SignedRequest sr;
    sr.set_signer_id(delete_data->key_id);
    sr.set_public_key(delete_data->public_key);
    sr.set_signed_public_key(delete_data->public_key_signature);
    sr.set_signed_request(signed_request);
    knode_->DeleteValue(delete_data->non_hex_packet_name, signed_value, sr, cb);
  }
}

void MaidsafeStoreManager::DeletePacketCallback(
    const std::string &ser_kad_delete_result,
    boost::shared_ptr<DeletePacketData> delete_data) {
  if (delete_data->called_back)
    return;
  if (ser_kad_delete_result.empty()) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback, fail - timeout.\n");
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketError);
    delete_data->called_back = true;
    return;
  }
  kad::DeleteResponse delete_response;
  if (!delete_response.ParseFromString(ser_kad_delete_result)) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback, can't parse result.\n");
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketParseError);
    delete_data->called_back = true;
    return;
  }
  if (delete_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback, Kademlia operation failed.\n");
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketFailure);
    delete_data->called_back = true;
    return;
  }
  boost::mutex::scoped_lock lock(delete_data->mutex);
  ++delete_data->returned_count;
  if (delete_data->returned_count >= delete_data->values.size()) {
    delete_data->callback(kSuccess);
    delete_data->called_back = true;
  }
}

void MaidsafeStoreManager::PollVaultInfo(base::callback_func_type cb) {
  VaultCommunication vc;
  vc.set_chunkstore("YES");
  vc.set_offered_space(0);
  vc.set_free_space(0);
  vc.set_ip("YES");
  vc.set_port(0);
  vc.set_timestamp(base::get_epoch_time());
  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  crypto::Crypto co;
  std::string enc_ser_vc = co.AsymEncrypt(ser_vc, "", ss_->PublicKey(PMID),
                           crypto::STRING_STRING);
  VaultStatusResponse vault_status_response;
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<MaidsafeStoreManager,
      const VaultStatusResponse*, base::callback_func_type>
      (this, &MaidsafeStoreManager::PollVaultInfoCallback,
      &vault_status_response, cb);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  rpcprotocol::Channel *channel = new rpcprotocol::Channel(
      &channel_manager_, &transport_handler_, udt_transport_.GetID(),
      ss_->VaultIP(), ss_->VaultPort(), "", 0, "", 0);
  client_rpcs_->PollVaultInfo(enc_ser_vc, &vault_status_response, controller,
      channel, done);
}

void MaidsafeStoreManager::PollVaultInfoCallback(
    const VaultStatusResponse *response,
    base::callback_func_type cb) {
  std::string result;
  if (!response->IsInitialized()) {
    cb("FAIL");
    return;
  }
  if (response->result() != kAck) {
    cb("FAIL");
    return;
  }

  crypto::Crypto co;
  std::string unenc = co.AsymDecrypt(response->encrypted_response(), "",
                      ss_->PrivateKey(PMID), crypto::STRING_STRING);

  VaultCommunication vc;
  if (!vc.ParseFromString(unenc)) {
    cb("FAIL");
    return;
  }

  if (vc.chunkstore().empty() && vc.offered_space() == 0 &&
      vc.free_space() == 0 && vc.ip().empty() && vc.port() == 0) {
    cb("FAIL");
    return;
  }

  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  cb(ser_vc);
}

void MaidsafeStoreManager::VaultContactInfo(base::callback_func_type cb) {
  knode_->FindNode(ss_->Id(PMID), cb, false);
}

void MaidsafeStoreManager::SetLocalVaultOwned(
    const std::string &priv_key,
    const std::string &pub_key,
    const std::string &signed_pub_key,
    const boost::uint32_t &port,
    const std::string &chunkstore_dir,
    const boost::uint64_t &space,
    const SetLocalVaultOwnedFunctor &functor) {
  boost::shared_ptr<SetLocalVaultOwnedCallbackArgs>
      cb_args(new SetLocalVaultOwnedCallbackArgs(functor));
  // 20 seconds, since the rpc is replied after the vault has
  // started successfully
  cb_args->ctrl->set_timeout(20);
  SetLocalVaultOwnedRequest request;
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_pub_key);
  request.set_port(port);
  request.set_chunkstore_dir(chunkstore_dir);
  request.set_space(space);
  rpcprotocol::Channel channel(&channel_manager_, &transport_handler_,
                               udt_transport_.GetID(), "127.0.0.1", kLocalPort,
                               "", 0, "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SetLocalVaultOwnedCallback, cb_args);
  client_rpcs_->SetLocalVaultOwned(&request, cb_args->response, cb_args->ctrl,
      &channel, done);
}

void MaidsafeStoreManager::SetLocalVaultOwnedCallback(
    boost::shared_ptr<SetLocalVaultOwnedCallbackArgs> callback_args) {
  if (callback_args->ctrl->Failed() ||
      !callback_args->response->IsInitialized()) {
    if (callback_args->ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args->cb(VAULT_IS_DOWN, "");
    else
      callback_args->cb(INVALID_OWNREQUEST, "");
    return;
  }
  std::string pmid_name;
  if (callback_args->response->has_pmid_name())
    pmid_name = callback_args->response->pmid_name();
  OwnLocalVaultResult result = callback_args->response->result();
  callback_args->cb(result, pmid_name);
}

void MaidsafeStoreManager::LocalVaultOwned(
    const LocalVaultOwnedFunctor &functor) {
  boost::shared_ptr<LocalVaultOwnedCallbackArgs>
      cb_args(new LocalVaultOwnedCallbackArgs(functor));
  rpcprotocol::Channel channel(&channel_manager_, &transport_handler_,
                               udt_transport_.GetID(), "127.0.0.1", kLocalPort,
                               "", 0, "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::LocalVaultOwnedCallback, cb_args);
  client_rpcs_->LocalVaultOwned(cb_args->response, cb_args->ctrl, &channel,
      done);
}

void MaidsafeStoreManager::LocalVaultOwnedCallback(
    boost::shared_ptr<LocalVaultOwnedCallbackArgs> callback_args) {
  if (callback_args->ctrl->Failed() ||
      !callback_args->response->IsInitialized()) {
    if (callback_args->ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args->cb(DOWN);
    else
      callback_args->cb(ISOWNRPC_CANCELLED);
    return;
  }
  VaultStatus result = callback_args->response->status();
  callback_args->cb(result);
}

bool MaidsafeStoreManager::NotDoneWithUploading() {
  printf("MaidsafeStoreManager::NotDoneWithUploading %d -- %d -- %u\n",
         chunk_thread_pool_.activeThreadCount(),
         packet_thread_pool_.activeThreadCount(),
         tasks_handler_.TasksCount());
  if (chunk_thread_pool_.activeThreadCount() == 0 &&
      packet_thread_pool_.activeThreadCount() == 0) {
    return false;
  } else {
    return true;
  }
}

void MaidsafeStoreManager::AmendAccount(const boost::uint64_t &space_offered) {
  // TODO(Fraser#5#): 2009-12-21 - Consider repeating this until success or
  //                               some max. no. of failures.
  // Set the account name
  std::string non_hex_pmid = base::DecodeFromHex(ss_->Id(PMID));
  std::string pmid_pub = ss_->PublicKey(PMID);
  std::string pmid_pub_sig = ss_->SignedPublicKey(PMID);
  std::string pmid_pri = ss_->PrivateKey(PMID);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name = co.Hash(non_hex_pmid + kAccount, "",
      crypto::STRING_STRING, false);
  // Find the account holders
  std::vector<kad::Contact> account_holders;
  if (FindKNodes(account_name, &account_holders) != kSuccess)
    return;
  // Create the request
  boost::shared_ptr<boost::condition_variable>
      cond_var(new boost::condition_variable);
  GenericConditionData cond_data(cond_var);
  AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(AmendAccountRequest::kSpaceOffered);
  SignedSize *mutable_signed_size = amend_account_request.mutable_signed_size();
  mutable_signed_size->set_data_size(space_offered);
  mutable_signed_size->set_pmid(non_hex_pmid);
  mutable_signed_size->set_signature(co.AsymSign(base::itos_ull(space_offered),
      "", pmid_pri, crypto::STRING_STRING));
  mutable_signed_size->set_public_key(pmid_pub);
  mutable_signed_size->set_public_key_signature(pmid_pub_sig);
  amend_account_request.set_account_pmid(non_hex_pmid);
  std::vector<AmendAccountResponse> amend_account_responses;
  for (boost::uint16_t i = 0; i < account_holders.size(); ++i) {
    AmendAccountResponse amend_account_response;
    amend_account_responses.push_back(amend_account_response);
  }
  // Send the requests
  boost::uint16_t rpcs_sent_count(amend_account_responses.size());
  for (boost::uint16_t i = 0; i < rpcs_sent_count; ++i) {
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(&google::protobuf::DoNothing);
    rpcprotocol::Controller controller;
    client_rpcs_->AmendAccount(account_holders.at(i),
        AddressIsLocal(account_holders.at(i)), udt_transport_.GetID(),
        &amend_account_request, &amend_account_responses.at(i), &controller,
        callback);
  }
  boost::uint16_t successful_count(0);
  boost::uint16_t failed_count(0);
  // Once we've got enough successful replies, cancel the remaining RPCs (they
  // should still succeed, we just won't handle the reply)
//  while (successful_count < kKadStoreThreshold_ &&
//         failed_count < kad::K - kKadStoreThreshold_ + 1 &&
//         successful_count + failed_count < ref_holders.size()) {
// TODO(Fraser#5#): 2009-10-13 - Preceding lines cause segfault on Unix due to
// callbacks trying to lock destructed mutex - figure out why.
  int timeout = 10000;  // milliseconds
  int timeout_count = 0;
  while ((successful_count + failed_count < rpcs_sent_count) &&
         (timeout_count < timeout)) {
    successful_count = 0;
    failed_count = 0;
    for (boost::uint16_t i = 0; i < rpcs_sent_count; ++i) {
      boost::mutex::scoped_lock lock(cond_data.cond_mutex);
      if (amend_account_responses.at(i).IsInitialized()) {
        if (amend_account_responses.at(i).result() == kAck) {
          ++successful_count;
        } else {
          ++failed_count;
        }
      } else {
        break;
      }
    }
    timeout_count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    if (timeout_count >= timeout)
      printf("\n\n\n\n\n\n\nAmend Account TIMED OUT\n\n\n\n\n\n\n\n");
  }
//  if (successful_count < kKadStoreThreshold_)
//    retry?
// Cancel outstanding RPCs
// TODO(Fraser#5#): 2009-10-13 - Once preceding todo is resolved, reinstate
// following code.  Bool store_iou_response_returned needs replaced with
// three state flag, kPending, kReturned, kDone or similar.
//  for (boost::uint16_t j = 0; j < results.size(); ++j) {
//    if (!results.at(j)->store_iou_response_returned)
//      channel_manager_.
//          DeletePendingRequest(results.at(j)->controller->req_id());
//  }
}

}  // namespace maidsafe
