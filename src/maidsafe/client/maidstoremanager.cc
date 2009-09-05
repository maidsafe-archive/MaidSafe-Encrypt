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
      knode_(new kad::KNode(channel_manager_, kad::CLIENT, "", "", false,
          false)),
      client_rpcs_(channel_manager_),
      pdclient_(NULL),
      ss_(SessionSingleton::getInstance()),
      client_chunkstore_(cstore),
      store_thread_pool_(kMaxStoreThreads),
      kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore),
      store_packet_mutex_(),
      store_packet_conditional_(),
      send_iou_done_conditional_(),
      send_prep_done_conditional_() {
  knode_->SetAlternativeStore(client_chunkstore_.get());
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
  knode_->Join(kadconfig_str, boost::bind(&CallbackObj::CallbackFunc,
      &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
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
}

void MaidsafeStoreManager::Close(base::callback_func_type cb,
                                 bool cancel_pending_ops) {
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, before Leave.\n");
#endif
  if (cancel_pending_ops)
    store_thread_pool_.clear();
//  store_thread_pool_.wait();
  knode_->Leave();
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, after Leave. Stopping transport\n");
#endif
  channel_manager_->StopTransport();
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, transport stopped.\n");
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
  channel_manager_->CleanUpTransport();
}

int MaidsafeStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                    std::string *data) {
#ifdef DEBUG
  std::string hex(hex_chunk_name.substr(0, 10) + "...");
  printf("In MaidsafeStoreManager::LoadChunk (%i), chunk_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  *data = "";
  std::string chunk_name("");
  base::decode_from_hex(hex_chunk_name, &chunk_name);
  if (client_chunkstore_->Load(chunk_name, data) == 0)
    return 0;
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  // If the maidsafe value is cached, this blocking Kad call to FindValue may
  // yield serialised contact details for a cache copy holder.  Otherwise it
  // should yield the reference holders.
  if (FindValue(chunk_name, false, &cache_holder, &chunk_holders_ids,
      &needs_cache_copy_id) != 0) {
#ifdef DEBUG
  printf("In MaidsafeStoreManager::LoadChunk (%i), failed in FindValue.\n",
         knode_->host_port());
#endif
    return -1;
  }
  if (cache_holder.has_node_id()) {  // We got a cached copy holder's details
// TODO(Fraser#5#): 2009-08-21 - We should maybe try again - we may get a
//                               different chunkholder next time?
    boost::shared_ptr<ChunkHolder> chunk_holder(new ChunkHolder(cache_holder));
    chunk_holder->local = (knode_->CheckContactLocalAddress(
        cache_holder.node_id(), cache_holder.local_ip(),
        cache_holder.local_port(), cache_holder.ip())
        == kad::LOCAL);
    GetChunk(chunk_holder, data);
// TODO(Fraser#5#): 2009-08-31 - Store cache copy to needs_cache_copy_id
    // if (!data->empty() && !needs_cache_copy_id.empty())
    //   CacheChunk(*data, needs_cache_copy_id);
    return 0;
  } else {
    int result = FindAndLoadChunk(chunk_name, chunk_holders_ids, true, data);
    if (result == 0) {
// TODO(Fraser#5#): 2009-08-31 - Store cache copy to needs_cache_copy_id
    // if (!needs_cache_copy_id.empty())
    //   CacheChunk(*data, needs_cache_copy_id);
    }
    return result;
  }
}

void MaidsafeStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                      DirType dir_type,
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
  if (chunk_type & kOutgoing && ss_->ConnectionStatus() != 1)
    AddNormalStoreTask(StoreTask(chunk_name, dir_type, msid), kStoreSuccess);
}

int MaidsafeStoreManager::StorePacket(
    const std::string &hex_packet_name,
    const std::string &value,
    packethandler::SystemPackets system_packet_type,
    DirType dir_type,
    const std::string &msid) {
#ifdef DEBUG
  std::string hex(hex_packet_name.substr(0, 10) + "...");
  printf("In MaidsafeStoreManager::StorePacket (%i), packet_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  std::string packet_name("");
  base::decode_from_hex(hex_packet_name, &packet_name);
  int return_value(1);
  AddPriorityStoreTask(StoreTask(packet_name, value, system_packet_type,
                                 dir_type, msid), kAppend, &return_value);
  boost::mutex::scoped_lock lock(store_packet_mutex_);
  while (return_value > 0) {
    store_packet_conditional_.wait(lock);
  }
  return return_value;
}

bool MaidsafeStoreManager::KeyUnique(const std::string &hex_key,
                                     bool check_local) {
#ifdef DEBUG
  std::string hex(hex_key.substr(0, 10) + "...");
  printf("In MaidsafeStoreManager::KeyUnique (%i), packet_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  std::string non_hex_key;
  base::decode_from_hex(hex_key, &non_hex_key);
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  return (FindValue(non_hex_key, check_local, &cache_holder, &chunk_holders_ids,
          &needs_cache_copy_id) != 0);
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

void MaidsafeStoreManager::LoadPacket(const std::string &hex_key,
                                      base::callback_func_type cb) {
  std::string data, ser_result;
  GetResponse result_msg;
  if (LoadChunk(hex_key, &data) != 0) {
    result_msg.set_result(kNack);
  } else {
    result_msg.set_result(kAck);
    result_msg.set_content(data);
  }
  result_msg.SerializeToString(&ser_result);
  cb(ser_result);
}

void MaidsafeStoreManager::GetMessages(const std::string &hex_key,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  pdclient_->GetMessages(key, public_key, signed_public_key, cb);
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





void MaidsafeStoreManager::GetChunkSignatureKeys(DirType dir_type,
                                                 const std::string &msid,
                                                 std::string *public_key,
                                                 std::string *public_key_sig,
                                                 std::string *private_key) {
  *public_key = "";
  *public_key_sig = "";
  *private_key = "";
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (dir_type) {
    case PRIVATE_SHARE:
      if (0 == ss->GetShareKeys(msid, public_key, private_key)) {
        *public_key_sig =
            co.AsymSign(*public_key, "", *private_key, crypto::STRING_STRING);
      } else {
        *public_key = "";
        *public_key_sig = "";
        *private_key = "";
      }
      break;
    case PUBLIC_SHARE:
      *public_key = ss->PublicKey(MPID);
      *public_key_sig = ss->SignedPublicKey(MPID);
      *private_key = ss->PrivateKey(MPID);
      break;
    case ANONYMOUS:
      *public_key = " ";
      *public_key_sig = " ";
      *private_key = "";
      break;
    case PRIVATE:
    default:
      *public_key = ss->PublicKey(PMID);
      *public_key_sig = ss->SignedPublicKey(PMID);
      *private_key = ss->PrivateKey(PMID);
      break;
  }
}

void MaidsafeStoreManager::GetPacketSignatureKeys(
    packethandler::SystemPackets packet_type,
    DirType dir_type,
    const std::string &msid,
    std::string *public_key,
    std::string *public_key_sig,
    std::string *private_key) {
  *public_key = "";
  *public_key_sig = "";
  *private_key = "";
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (packet_type) {
    case packethandler::MID:
    case packethandler::ANMID:
      *public_key = ss->PublicKey(ANMID);
      *public_key_sig = ss->SignedPublicKey(ANMID);
      *private_key = ss->PrivateKey(ANMID);
      break;
    case packethandler::SMID:
    case packethandler::ANSMID:
      *public_key = ss->PublicKey(ANSMID);
      *public_key_sig = ss->SignedPublicKey(ANSMID);
      *private_key = ss->PrivateKey(ANSMID);
      break;
    case packethandler::TMID:
    case packethandler::ANTMID:
      *public_key = ss->PublicKey(ANTMID);
      *public_key_sig = ss->SignedPublicKey(ANTMID);
      *private_key = ss->PrivateKey(ANTMID);
      break;
    case packethandler::MPID:
    case packethandler::ANMPID:
      *public_key = ss->PublicKey(ANMPID);
      *public_key_sig = ss->SignedPublicKey(ANMPID);
      *private_key = ss->PrivateKey(ANMPID);
      break;
    case packethandler::PMID:
    case packethandler::MAID:
      *public_key = ss->PublicKey(MAID);
      *public_key_sig = ss->SignedPublicKey(MAID);
      *private_key = ss->PrivateKey(MAID);
      break;
    case packethandler::MSID:
    case packethandler::PD_DIR:
      GetChunkSignatureKeys(dir_type, msid, public_key, public_key_sig,
                            private_key);
      break;
    case packethandler::BUFFER:
    case packethandler::BUFFER_INFO:
    case packethandler::BUFFER_MESSAGE:
      *public_key = ss->PublicKey(MPID);
      *public_key_sig = ss->SignedPublicKey(MPID);
      *private_key = ss->PrivateKey(MPID);
      break;
    default:
      break;
  }
}

void MaidsafeStoreManager::AddPriorityStoreTask(const StoreTask &store_task,
                                                IfExists if_exists,
                                                int *return_value) {
  store_thread_pool_.schedule(boost::threadpool::prio_task_func(10, boost::bind(
      &MaidsafeStoreManager::PreSendAnalysis, this, store_task, if_exists,
      return_value)));
  size_t pool_size = store_thread_pool_.size();
  if (pool_size < kMaxPriorityStoreThreads + kMaxStoreThreads)
    store_thread_pool_.size_controller().resize(pool_size + 1);
}

void MaidsafeStoreManager::AddNormalStoreTask(const StoreTask &store_task,
                                              IfExists if_exists) {
  int *p_int = NULL;
  store_thread_pool_.schedule(boost::threadpool::prio_task_func(5, boost::bind(
      &MaidsafeStoreManager::PreSendAnalysis, this, store_task, if_exists,
      p_int)));
  if (store_thread_pool_.size() > kMaxStoreThreads)
    store_thread_pool_.size_controller().resize(kMaxStoreThreads);
  delete p_int;
}

void MaidsafeStoreManager::PreSendAnalysis(const StoreTask &store_task,
                                           IfExists if_exists,
                                           int *return_value) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::PreSendAnalysis\n");
#endif
  // Find out if the chunk already exists on the network.
  std::string chunk_name = store_task.non_hex_key_;
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  // If the maidsafe value is cached, this blocking Kad call to FindValue may
  // yield serialised contact details for a cache copy holder.  Otherwise it
  // should yield the reference holders.  If it yields the reference holders,
  // check that at least one currently has the chunk.
  int find_result = FindValue(chunk_name, false, &cache_holder,
      &chunk_holders_ids, &needs_cache_copy_id);
  bool exists = (find_result == 0);
  // If FindValue failed to complete the kad function then return.
  if (!exists && find_result != -3) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::PreSendAnalysis (%i), failed in "
           "FindValue.\n", knode_->host_port());
#endif
    SetStoreReturnValue(-1, return_value);
    return;
  }
  bool data_cached = (cache_holder.has_node_id());
  std::string data;
  if (exists && !data_cached) {
    exists =
        (FindAndLoadChunk(chunk_name, chunk_holders_ids, false, &data) == 0);
  }
  // If the chunk does already exist on the network, determine what to do.
  if (exists) {
    switch (if_exists) {
      case kStoreFailure:
        SetStoreReturnValue(-2, return_value);
        return;
      case kStoreSuccess:
        SetStoreReturnValue(0, return_value);
        return;
      case kAppend:
        if (data_cached) {
#ifdef DEBUG
          printf("In MaidsafeStoreManager::PreSendAnalysis (%i), can't append"
                 " to a cached value.\n", knode_->host_port());
#endif
          SetStoreReturnValue(-3, return_value);
        } else {
          int res = UpdateChunkCopies(store_task, chunk_holders_ids);
          SetStoreReturnValue(res, return_value);
        }
        return;
      default:
#ifdef DEBUG
        printf("In MaidsafeStoreManager::PreSendAnalysis (%i), invalid "
               "IfExists setting.\n", knode_->host_port());
#endif
        SetStoreReturnValue(-4, return_value);
        return;
    }
  } else {  // If the data doesn't already exist on the network, store it.
    int res(-1);
    if (return_value == NULL)
      res = SendChunk(store_task, kMinChunkCopies);
    else
      res = SendPacket(store_task, kMinChunkCopies);
    SetStoreReturnValue(res, return_value);
  }
}

int MaidsafeStoreManager::SendChunk(const StoreTask &store_task, int copies) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendChunk\n");
#endif
  if (copies <= 0)
    return -1;
  int duplicate_count = 0;
  float largest_rtt = -1;  // set to -1 so that first store is to furthest peer
  std::vector<kad::Contact> exclude;
  base::PDRoutingTableHandler rt_handler;
// TODO(Fraser#5#): 2009-08-10 - Account for online status in while loop also
  while (duplicate_count < copies) {
    StorePrepRequest store_prep_request;
    StorePrepResponse store_prep_response;
    StoreRequest store_request;
    IOUDoneRequest iou_done_request;
    kad::Contact peer;
    bool local;
    float ideal_rtt = largest_rtt * (1 - (duplicate_count/copies));
    if (GetStorePeer(ideal_rtt, exclude, &peer, &local) != 0)
      break;  // try another peer
    else
      exclude.push_back(peer);  // whether we succeed in storing or not, we'll
                                // not be trying this peer again
#ifdef DEBUG
//    std::string hex_name, hex_id;
//    base::encode_to_hex(store_task.non_hex_key_, &hex_name);
//    base::encode_to_hex(peer.node_id(), &hex_id);
//    printf("Chunkname: %s... Peer PMID: %s... Dup count: %i  Exclude "
//           "peer size: %i\n\n\n", hex_name.substr(0,10).c_str(),
//           hex_id.substr(0,10).c_str(), duplicate_count, exclude.size());
#endif
    if (duplicate_count == 0) {  // set largest_rtt from first peer
// TODO(Fraser#5#): 2009-08-14 - Uncomment lines below
//      base::PDRoutingTableTuple peer_details;
//      if (rt_handler.GetTupleInfo(peer.node_id(), &peer_details) != 0)
//        break;
//      largest_rtt = peer_details.rtt();
      largest_rtt = 1.0f;
    }
    if (GetStoreRequests(store_task, peer.node_id(), &store_prep_request,
        &store_request, &iou_done_request) != 0)
      return -2;
    if (SendPrep(peer, local, &store_prep_request, &store_prep_response) != 0)
      break;  // try another peer
    int failed_attempt_count = 0;
    while (failed_attempt_count < kMaxChunkStoreTries) {
      if (SendContent(peer, local, true, &store_request) == 0) {
        break;  // succeeded in storing to this peer
      } else {
        ++failed_attempt_count;
      }
    }
    if (failed_attempt_count >= kMaxChunkStoreTries) {
      if (!duplicate_count)  // if this is failed 1st copy, reset largest rtt
        largest_rtt = -1;
      continue;
    }
// TODO(Fraser#5#): 2009-08-13 - Do we want to get the ref holders again if the
//                               previous store was relatively fast?
    if (StoreIOUs(store_task, store_prep_request.data_size(),
        store_prep_response) != 0) {
      if (!duplicate_count)  // if this is failed 1st copy, reset largest rtt
        largest_rtt = -1;
      continue;
    }
    if (SendIOUDone(peer, local, &iou_done_request) == 0) {
      ++duplicate_count;
    } else {
      if (!duplicate_count)  // if this is failed 1st copy, reset largest rtt
        largest_rtt = -1;
    }
  }
// TODO(Fraser#5#): 2009-08-14 - Check later that there are enough vaults
// listed in ref packet to ensure upload ultimately successful.
  return 0;
}

int MaidsafeStoreManager::GetStoreRequests(const StoreTask &store_task,
                                           const std::string &recipient_id,
                                           StorePrepRequest *store_prep_request,
                                           StoreRequest *store_request,
                                           IOUDoneRequest *iou_done_request) {
  ValueType data_type = DATA;
  if (store_task.dir_type_ == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  ChunkType chunk_type =
      client_chunkstore_->chunk_type(store_task.non_hex_key_);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(store_task.non_hex_key_,
                                                       chunk_type, false));
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
  std::string request_signature("");
  GetRequestSignature(store_task, recipient_id, &request_signature);
  if (request_signature == "")
    return -3;
  std::string pmid = ss_->Id(PMID);
  std::string non_hex_pmid;
  base::decode_from_hex(pmid, &non_hex_pmid);
  store_prep_request->set_chunkname(store_task.non_hex_key_);
  store_prep_request->set_data_size(chunk_size);
  store_prep_request->set_pmid(non_hex_pmid);
  store_prep_request->set_public_key(store_task.public_key_);
  store_prep_request->set_signed_public_key(store_task.public_key_signature_);
  store_prep_request->set_signed_request(request_signature);
  store_request->set_chunkname(store_task.non_hex_key_);
  store_request->set_data(chunk_content);
  store_request->set_pmid(non_hex_pmid);
  store_request->set_public_key(store_task.public_key_);
  store_request->set_signed_public_key(store_task.public_key_signature_);
  store_request->set_signed_request(request_signature);
  store_request->set_data_type(data_type);
  iou_done_request->set_chunkname(store_task.non_hex_key_);
  iou_done_request->set_public_key(store_task.public_key_);
  iou_done_request->set_signed_public_key(store_task.public_key_signature_);
  iou_done_request->set_signed_request(request_signature);
  return 0;
}

void MaidsafeStoreManager::GetRequestSignature(
    const std::string &non_hex_name,
    const DirType dir_type,
    const std::string &recipient_id,
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &private_key,
    std::string *request_signature) {
  *request_signature = "";
  if (public_key == "" || public_key_signature == "" || private_key == "")
    return;
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  if (dir_type == ANONYMOUS) {
    *request_signature = kAnonymousSignedRequest;
  } else {
    *request_signature = co.AsymSign(co.Hash(
        public_key_signature + non_hex_name + recipient_id, "",
        crypto::STRING_STRING, false), "", private_key, crypto::STRING_STRING);
  }
}

void MaidsafeStoreManager::GetRequestSignature(const StoreTask &store_task,
                                               const std::string &recipient_id,
                                               std::string *request_signature) {
  GetRequestSignature(store_task.non_hex_key_, store_task.dir_type_,
      recipient_id, store_task.public_key_, store_task.public_key_signature_,
      store_task.private_key_, request_signature);
}

int MaidsafeStoreManager::GetStorePeer(const float &,
                                       const std::vector<kad::Contact> &exclude,
                                       kad::Contact *new_peer,
                                       bool *local) {
// TODO(Fraser#5#): 2009-08-08 - Complete this so that rtt & rank is considered.
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
                                   StorePrepRequest *store_prep_request,
                                   StorePrepResponse *store_prep_response) {
  boost::mutex mutex;
  bool send_prep_done(false);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendPrepCallback, &mutex, &send_prep_done);
  rpcprotocol::Controller controller;
  client_rpcs_.StorePrep(peer, local, store_prep_request,
      store_prep_response, &controller, callback);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!send_prep_done) {
      send_prep_done_conditional_.wait(lock);
    }
  }
  return (store_prep_response->pmid_id() == peer.node_id() &&
          store_prep_response->result() == kAck) ? 0 : -1;
}

void MaidsafeStoreManager::SendPrepCallback(boost::mutex *mutex,
                                            bool *send_prep_done) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPrepCallback.\n");
#endif
  {  // NOLINT(Fraser)
    boost::mutex::scoped_lock lock(*mutex);
    *send_prep_done = true;
  }
  send_prep_done_conditional_.notify_all();
}

int MaidsafeStoreManager::SendContent(const kad::Contact &peer,
                                      bool local,
                                      bool is_chunk,
                                      StoreRequest *store_request) {
  const boost::shared_ptr<StoreResponse>store_response(new StoreResponse());
  boost::mutex mutex;
  boost::condition_variable cond;
  boost::mutex::scoped_lock lock(mutex);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendContentCallback, &cond);
  rpcprotocol::Controller controller;
  if (is_chunk) {
    client_rpcs_.StoreChunk(peer, local, store_request, store_response.get(),
        &controller, callback);
  } else {
    client_rpcs_.StorePacket(peer, local, store_request, store_response.get(),
        &controller, callback);
  }
  cond.wait(lock);
  if (store_response->pmid_id() != peer.node_id()) {
#ifdef DEBUG
    printf("In MSM::SendContent, ids are not OK.\n");
#endif
    return -1;
  }
  if (store_response->result() != kAck) {
#ifdef DEBUG
    printf("In MSM::SendContent, result not kAck.\n");
#endif
    return -1;
  }
#ifdef DEBUG
//  printf("In MSM::SendContent, succeeded.\n");
#endif
  if (is_chunk) {
    // Move chunk from Outgoing to Normal.  If this operation fails, still
    // return 0 as this is non-critical.
    ChunkType chunk_type =
        client_chunkstore_->chunk_type(store_request->chunkname());
    ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
    if (client_chunkstore_->ChangeChunkType(store_request->chunkname(),
                                            new_type) != 0) {
  #ifdef DEBUG
      printf("In MSM::SendContent, failed to change chunk type.\n");
  #endif
    }
  }
  return 0;
}

void MaidsafeStoreManager::SendContentCallback(
    boost::condition_variable *cond) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendContentCallback.\n");
#endif
  cond->notify_one();
}

int MaidsafeStoreManager::StoreIOUs(
    const StoreTask &store_task,
    const boost::uint64_t &chunk_size,
    const StorePrepResponse &store_prep_response) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  // Make up the IOU
  IOU iou;
  iou.set_serialised_iou_authority(store_prep_response.iou_authority());
  iou.set_signed_iou_authority(store_prep_response.signed_iou_authority());
  iou.set_signature(co.AsymSign(iou.signed_iou_authority(), "",
                                ss_->PrivateKey(PMID), crypto::STRING_STRING));
  std::string serialised_iou;
  if (!iou.SerializeToString(&serialised_iou))
    return -1;
  // Find the chunk reference holders
  std::vector<kad::Contact> ref_holders;
  if (FindKNodes(store_task.non_hex_key_, &ref_holders) != 0) {
    return -1;
  }
  std::string own_pmid = ss_->Id(PMID);
  std::string own_non_hex_pmid;
  base::decode_from_hex(own_pmid, &own_non_hex_pmid);
  StoreIOURequest store_iou_request;
  store_iou_request.set_chunkname(store_task.non_hex_key_);
  store_iou_request.set_data_size(chunk_size);
  store_iou_request.set_collector_pmid(store_prep_response.pmid_id());
  store_iou_request.set_iou(serialised_iou);
  store_iou_request.set_own_pmid(own_non_hex_pmid);
  store_iou_request.set_public_key(store_task.public_key_);
  store_iou_request.set_signed_public_key(store_task.public_key_signature_);
  int successful_count(0);
  std::vector< boost::shared_ptr<StoreIouResultHolder> > results;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    boost::shared_ptr<StoreIouResultHolder>
        store_iou_result_holder(new StoreIouResultHolder);
    results.push_back(store_iou_result_holder);
  }
  boost::mutex store_iou_mutex;
  // Send out the store IOU RPCs
  std::set<std::string> ref_holder_ids;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    std::string request_signature("");
    GetRequestSignature(store_task, ref_holders.at(i).node_id(),
                        &request_signature);
    store_iou_request.set_signed_request(request_signature);
    SendIouToRefHolder(ref_holders.at(i), store_iou_request, &store_iou_mutex,
                       results.at(i));
    ref_holder_ids.insert(ref_holders.at(i).node_id());
  }
  // Once we've got enough successful replies, cancel the remaining store IOU
  // RPCs (they should still succeed, we just won't handle the reply)
  while (successful_count < kKadStoreThreshold_) {
    for (boost::uint16_t i = 0; i < results.size(); ++i) {
      boost::mutex::scoped_lock loch(store_iou_mutex);
      if (results.at(i)->store_iou_response_returned) {
        int n = HandleStoreIOUResponse(results.at(i), &ref_holder_ids);
        if (n == 0)
          ++successful_count;
        results.at(i)->store_iou_response_returned = false;
        break;
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  if (successful_count < kKadStoreThreshold_)
    return -1;  // We've not received enough successful responses
  // Cancel outstanding RPCs
  for (boost::uint16_t j = 0; j < results.size(); ++j) {
    if (!results.at(j)->store_iou_response_returned)
      channel_manager_->
          DeletePendingRequest(results.at(j)->controller->req_id());
  }
  return 0;
}

int MaidsafeStoreManager::FindKNodes(const std::string &kad_key,
                                     std::vector<kad::Contact> *contacts) {
  CallbackObj kad_cb_obj;
  knode_->FindCloseNodes(kad_key, boost::bind(&CallbackObj::CallbackFunc,
      &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
  if (kad_cb_obj.result() == "") {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, fail - timeout.\n");
#endif
    return -1;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, can't parse result.\n");
#endif
    return -2;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindKNodes, Kademlia operation failed.\n");
#endif
    return -3;
  }
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::FindKNodes, succeeded.\n");
#endif
  return 0;
}

int MaidsafeStoreManager::FindValue(
    const std::string &kad_key,
    bool check_local,
    kad::ContactInfo *cache_holder,
    std::vector<std::string> *chunk_holders_ids,
    std::string *needs_cache_copy_id) {
  cache_holder->Clear();
  chunk_holders_ids->clear();
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
  if (kad_cb_obj.result() == "") {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, fail - timeout.\n");
#endif
    return -1;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, can't parse result.\n");
#endif
    return -2;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, Kademlia operation failed to "
           "find the value.\n");
#endif
    return -3;
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
    return 0;
  }
  for (int i = find_response.values_size(); i >= 1; --i) {
    chunk_holders_ids->push_back(find_response.values(i - 1));
  }
#ifdef DEBUG
    printf("In MaidsafeStoreManager::FindValue, %lu values have returned.\n",
           chunk_holders_ids->size());
#endif
  return (chunk_holders_ids->size()) ? 0 : -4;
}

void MaidsafeStoreManager::FindAvailableChunkHolders(
    const std::string &chunk_name,
    const std::vector<std::string> &chunk_holders_ids,
    boost::mutex *find_mutex,
    boost::condition_variable *has_conditional,
    std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders) {
  boost::condition_variable find_conditional;
  boost::mutex::scoped_lock lock(*find_mutex);
  // Find chunk holders' contact details
  for (size_t i = 0; i < chunk_holders_ids.size(); ++i) {
    knode_->FindCloseNodes(chunk_holders_ids[i],
        boost::bind(&MaidsafeStoreManager::GetChunkHolderContactCallback,
        this, chunk_holders_ids[i], _1, chunk_holders, find_mutex,
        &find_conditional));
  }
  for (size_t i = 0; i < chunk_holders_ids.size(); ++i) {
    find_conditional.wait(lock);
    if (chunk_holders->at(i)->status != kFailedHolder) {
      kad::Contact new_peer = chunk_holders->at(i)->chunk_holder_contact;
      chunk_holders->at(i)->local = (knode_->CheckContactLocalAddress(
          new_peer.node_id(), new_peer.local_ip(), new_peer.local_port(),
          new_peer.host_ip()) == kad::LOCAL);
      CheckChunkRequest check_chunk_request;
      check_chunk_request.set_chunkname(chunk_name);
      chunk_holders->at(i)->find_mutex = find_mutex;
      chunk_holders->at(i)->has_conditional = has_conditional;
      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::HasChunkCallback, chunk_holders->at(i),
          controller);
      client_rpcs_.CheckChunk(chunk_holders->at(i)->chunk_holder_contact,
          chunk_holders->at(i)->local, &check_chunk_request,
          &chunk_holders->at(i)->check_chunk_response, controller.get(),
          callback);
      chunk_holders->at(i)->rpc_id = controller->req_id();
    }
  }
}

void MaidsafeStoreManager::GetChunkHolderContactCallback(
    const std::string &chunk_holder_id,
    const std::string &result,
    std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
    boost::mutex *find_mutex,
    boost::condition_variable *find_conditional) {
  boost::shared_ptr<ChunkHolder>
      failed_chunkholder(new ChunkHolder(kad::Contact(chunk_holder_id, "", 0)));
  failed_chunkholder->status = kFailedHolder;
  if (result == "") {
#ifdef DEBUG
    printf("In MSM::GetChunkHolderContactCallback, fail - timeout.\n");
#endif
    {  // NOLINT (Fraser)
      boost::lock_guard<boost::mutex> lock(*find_mutex);
      chunk_holders->push_back(failed_chunkholder);
    }
    find_conditional->notify_one();
    return;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(result)) {
#ifdef DEBUG
    printf("In MSM::GetChunkHolderContactCallback, can't parse result.\n");
#endif
    {  // NOLINT (Fraser)
      boost::lock_guard<boost::mutex> lock(*find_mutex);
      chunk_holders->push_back(failed_chunkholder);
    }
    find_conditional->notify_one();
    return;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::GetChunkHolderContactCallback, Kad operation failed.\n");
#endif
    {  // NOLINT (Fraser)
      boost::lock_guard<boost::mutex> lock(*find_mutex);
      chunk_holders->push_back(failed_chunkholder);
    }
    find_conditional->notify_one();
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
      {
        boost::lock_guard<boost::mutex> lock(*find_mutex);
        chunk_holders->push_back(chunkholder);
      }
      find_conditional->notify_one();
      return;
    }
  }
#ifdef DEBUG
  printf("In MSM::GetChunkHolderContactCallback, didn't get node's details.\n");
#endif
  {  // NOLINT (Fraser)
    boost::lock_guard<boost::mutex> lock(*find_mutex);
    chunk_holders->push_back(failed_chunkholder);
  }
  find_conditional->notify_one();
}

void MaidsafeStoreManager::HasChunkCallback(
    boost::shared_ptr<ChunkHolder> chunk_holder,
    boost::shared_ptr<rpcprotocol::Controller>) {
  boost::lock_guard<boost::mutex> lock(*(chunk_holder->find_mutex));
  if (chunk_holder->check_chunk_response.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from HasChunk came back failed (%d).\n",
           knode_->host_port());
#endif
    chunk_holder->status = kFailedHolder;
    chunk_holder->has_conditional->notify_one();
    return;
  }
  if (chunk_holder->chunk_holder_contact.node_id() !=
      chunk_holder->check_chunk_response.pmid_id()) {
#ifdef DEBUG
    printf("In MSM, response from HasChunk came back from wrong node (%d).\n",
           knode_->host_port());
#endif
    chunk_holder->status = kFailedHolder;
    chunk_holder->has_conditional->notify_one();
    return;
  }
  chunk_holder->status = kHasChunk;
  chunk_holder->has_conditional->notify_one();
}

int MaidsafeStoreManager::FindAndLoadChunk(
    const std::string &chunk_name,
    const std::vector<std::string> &chunk_holders_ids,
    bool load_data,
    std::string *data) {
  boost::mutex find_mutex;
  boost::condition_variable has_conditional;
  std::vector< boost::shared_ptr<ChunkHolder> > chunk_holders;
  FindAvailableChunkHolders(chunk_name, chunk_holders_ids, &find_mutex,
                            &has_conditional, &chunk_holders);
  bool available_chunk_holders(true);
  boost::mutex::scoped_lock lock(find_mutex);
  // If we need to load the data, iterate through all holders until the data has
  // been loaded, otherwise we can return after only one holder has confirmed
  // they have the data.
  if (load_data) {
    while (data->empty() && available_chunk_holders) {
      available_chunk_holders = false;
      has_conditional.wait(lock);
      for (size_t j = 0; j < chunk_holders.size(); ++j) {
        if (chunk_holders.at(j)->status == kHasChunk) {
          chunk_holders.at(j)->status = kAwaitingChunk;
          GetChunk(chunk_holders.at(j), data);
          available_chunk_holders = true;
          break;
        }
      }
    }
  } else {
    while (available_chunk_holders) {
      available_chunk_holders = false;
      has_conditional.wait(lock);
      for (size_t j = 0; j < chunk_holders.size(); ++j) {
        if (chunk_holders.at(j)->status == kHasChunk) {
          available_chunk_holders = true;
          break;
        }
      }
    }
  }
  // Cancel outstanding RPCs
  for (size_t m = 0; m < chunk_holders.size(); ++m) {
    if (chunk_holders.at(m)->status == kContactable)
      channel_manager_->DeletePendingRequest(chunk_holders.at(m)->rpc_id);
  }
  if (load_data) {
    return data->empty() ? -1 : 0;
  } else {
    return (available_chunk_holders) ? 0 : -1;
  }
}

void MaidsafeStoreManager::GetChunk(boost::shared_ptr<ChunkHolder> chunk_holder,
                                    std::string *data) {
  GetRequest get_request;
  GetResponse get_response;
  boost::mutex mutex;
  boost::condition_variable cond;
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::GetChunkCallback, &cond);
  rpcprotocol::Controller controller;
  client_rpcs_.Get(chunk_holder->chunk_holder_contact, chunk_holder->local,
      &get_request, &get_response, &controller, callback);
  boost::mutex::scoped_lock lock(mutex);
  cond.wait(lock);
  if (get_response.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from GetChunk came back failed (%d).\n",
           knode_->host_port());
#endif
    chunk_holder->status = kFailedHolder;
    return;
  }
  if (chunk_holder->chunk_holder_contact.node_id() != get_response.pmid_id()) {
#ifdef DEBUG
    printf("In MSM, response from GetChunk came back from wrong node (%d).\n",
           knode_->host_port());
#endif
    chunk_holder->status = kFailedHolder;
    return;
  }
  *data = get_response.content();
  chunk_holder->status = kDone;
}

void MaidsafeStoreManager::GetChunkCallback(boost::condition_variable *cond) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::GetChunkCallback.\n");
#endif
  cond->notify_one();
}

int MaidsafeStoreManager::SendIouToRefHolder(
    const kad::Contact &ref_holder,
    StoreIOURequest store_iou_request,
    boost::mutex *store_iou_mutex,
    boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder) {
  bool local = (knode_->CheckContactLocalAddress(ref_holder.node_id(),
      ref_holder.local_ip(), ref_holder.local_port(), ref_holder.host_ip())
      == kad::LOCAL);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendIouToRefHolderCallback,
      &store_iou_result_holder->store_iou_response_returned, store_iou_mutex);
  client_rpcs_.StoreIOU(ref_holder, local, &store_iou_request,
      &store_iou_result_holder->store_iou_response,
      store_iou_result_holder->controller.get(), callback);
  return 0;
}

void MaidsafeStoreManager::SendIouToRefHolderCallback(
    bool *store_iou_response_returned,
    boost::mutex *store_iou_mutex) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendIouToRefHolderCallback.\n");
#endif
  boost::mutex::scoped_lock loch(*store_iou_mutex);
  *store_iou_response_returned = true;
}

int MaidsafeStoreManager::HandleStoreIOUResponse(
    const boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder,
    std::set<std::string> *ref_holder_ids) {
  maidsafe::StoreIOUResponse sir =
      store_iou_result_holder->store_iou_response;
  if (sir.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from rpc id %d came back failed (%d).\n",
           store_iou_result_holder->controller->req_id(), knode_->host_port());
#endif
    return -1;
  }
  if (ref_holder_ids->find(sir.pmid_id()) == ref_holder_ids->end()) {
#ifdef DEBUG
    printf("In MSM, response on rpc id %d has fake identity (%d).\n",
           store_iou_result_holder->controller->req_id(), knode_->host_port());
#endif
    return -1;
  }
  return 0;
}

int MaidsafeStoreManager::SendIOUDone(const kad::Contact &peer,
                                      bool local,
                                      IOUDoneRequest *iou_done_request) {
  IOUDoneResponse iou_done_response;
  boost::mutex mutex;
  bool iou_done(false);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::IOUDoneCallback, &mutex, &iou_done);
  rpcprotocol::Controller controller;
  client_rpcs_.IOUDone(peer, local, iou_done_request, &iou_done_response,
      &controller, callback);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!iou_done) {
      send_iou_done_conditional_.wait(lock);
    }
  }
  return (iou_done_response.pmid_id() == peer.node_id() &&
          iou_done_response.result() == kAck) ? 0 : -1;
}

void MaidsafeStoreManager::IOUDoneCallback(boost::mutex *mutex,
                                           bool *iou_done) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::IOUDoneCallback.\n");
#endif
  {  // NOLINT (Fraser)
    boost::mutex::scoped_lock lock(*mutex);
    *iou_done = true;
  }
  send_iou_done_conditional_.notify_all();
}

int MaidsafeStoreManager::SendPacket(const StoreTask &store_task, int copies) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPacket\n");
#endif
  if (copies <= 0)
    return -1;
  int duplicate_count = 0;
  float largest_rtt = -1;  // set to -1 so that first store is to furthest peer
  std::vector<kad::Contact> exclude;
  base::PDRoutingTableHandler rt_handler;
// TODO(Fraser#5#): 2009-08-24 - Account for online status in while loop also
  while (duplicate_count < copies) {
    StoreRequest store_request;
    StoreResponse store_response;
    kad::Contact peer;
    bool local;
    float ideal_rtt = largest_rtt * (1 - (duplicate_count/copies));
    if (GetStorePeer(ideal_rtt, exclude, &peer, &local) != 0)
      break;  // try another peer
    else
      exclude.push_back(peer);  // whether we succeed in storing or not, we'll
                                // not be trying this peer again
#ifdef DEBUG
//    std::string hex_name, hex_id;
//    base::encode_to_hex(store_task.non_hex_key_, &hex_name);
//    base::encode_to_hex(peer.node_id(), &hex_id);
//    printf("Packetname: %s... Peer PMID: %s... Dup count: %i  Exclude "
//           "peer size: %i\n\n\n", hex_name.substr(0,10).c_str(),
//           hex_id.substr(0,10).c_str(), duplicate_count, exclude.size());
#endif
    if (duplicate_count == 0) {  // set largest_rtt from first peer
// TODO(Fraser#5#): 2009-08-14 - Uncomment lines below
//      base::PDRoutingTableTuple peer_details;
//      if (rt_handler.GetTupleInfo(peer.node_id(), &peer_details) != 0)
//        break;
//      largest_rtt = peer_details.rtt();
      largest_rtt = 1.0f;
    }
    if (GetStorePacketRequest(store_task, peer.node_id(), &store_request) != 0)
      return -2;
    int failed_attempt_count = 0;
    while (failed_attempt_count < kMaxChunkStoreTries) {
      if (SendContent(peer, local, false, &store_request) == 0) {
        break;  // succeeded in storing to this peer
      } else {
        ++failed_attempt_count;
      }
    }
    if (failed_attempt_count >= kMaxChunkStoreTries) {
      if (!duplicate_count)  // if this is failed 1st copy, reset largest rtt
        largest_rtt = -1;
      continue;
    }
  }
// TODO(Fraser#5#): 2009-08-14 - Check later that there are enough vaults
// listed in ref packet to ensure upload ultimately successful.
  return 0;
}

int MaidsafeStoreManager::GetStorePacketRequest(const StoreTask &store_task,
                                                const std::string &recipient_id,
                                                StoreRequest *store_request) {
  ValueType data_type = SYSTEM_PACKET;
  if (store_task.dir_type_ == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  std::string request_signature("");
  GetRequestSignature(store_task, recipient_id, &request_signature);
  if (request_signature == "")
    return -1;
  store_request->set_chunkname(store_task.non_hex_key_);
  store_request->set_data(store_task.value_);
  store_request->set_public_key(store_task.public_key_);
  store_request->set_signed_public_key(store_task.public_key_signature_);
  store_request->set_signed_request(request_signature);
  store_request->set_data_type(data_type);
  return 0;
}

void MaidsafeStoreManager::SendPacketCallback(boost::condition_variable *cond) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPacketCallback.\n");
#endif
  cond->notify_one();
}

int MaidsafeStoreManager::UpdateChunkCopies(
    const StoreTask &store_task,
    const std::vector<std::string> &chunk_holders_ids) {
  std::string msid = store_task.msid_;
  boost::mutex find_mutex;
  boost::condition_variable has_conditional;
  boost::condition_variable update_conditional;
  std::vector< boost::shared_ptr<ChunkHolder> > chunk_holders;
  FindAvailableChunkHolders(store_task.non_hex_key_, chunk_holders_ids,
                            &find_mutex, &has_conditional, &chunk_holders);
  bool uncontacted_chunk_holders(true);
  boost::mutex::scoped_lock lock(find_mutex);
  // Iterate through all holders until the data has been updated.
  std::vector<UpdateResponse> update_responses;
  while (uncontacted_chunk_holders) {
    uncontacted_chunk_holders = false;
    has_conditional.wait(lock);
    for (size_t i = 0; i < chunk_holders.size(); ++i) {
      if (chunk_holders.at(i)->status == kHasChunk) {
        chunk_holders.at(i)->status = kUpdatingChunk;
        update_responses.push_back(UpdateResponse());
        UpdateChunk(chunk_holders.at(i), store_task, &update_responses.back(),
                    &update_conditional);
        uncontacted_chunk_holders = true;
        break;
      }
    }
  }
  // Wait for all responses.
  for (size_t j = 0; j < update_responses.size(); ++j) {
    update_conditional.wait(lock);
// TODO(Fraser#5#): 2009-08-22 - If a listed chunk holder doesn't reply, we
//                               should send an update chunk message to his
//                               buffer packet.  Also need to decide how to
//                               handle mixed results ie some fails but not all.
  }
  return update_responses.empty() ? -1 : 0;
}

void MaidsafeStoreManager::UpdateChunk(
    const boost::shared_ptr<ChunkHolder> chunk_holder,
    const StoreTask &store_task,
    UpdateResponse *update_resonse,
    boost::condition_variable *update_conditional) {
  UpdateRequest update_request;
  std::string request_signature("");
  GetRequestSignature(store_task, chunk_holder->chunk_holder_contact.node_id(),
                      &request_signature);
  if (request_signature == "")
    return;
  std::string pmid = ss_->Id(PMID);
  std::string non_hex_pmid;
  base::decode_from_hex(pmid, &non_hex_pmid);
  ValueType data_type = DATA;
  if (store_task.dir_type_ == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  update_request.set_chunkname(store_task.non_hex_key_);
  update_request.set_data(store_task.value_);
  update_request.set_public_key(store_task.public_key_);
  update_request.set_signed_public_key(store_task.public_key_signature_);
  update_request.set_signed_request(request_signature);
  update_request.set_data_type(data_type);
  boost::shared_ptr<rpcprotocol::Controller>
      controller(new rpcprotocol::Controller);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::UpdateChunkCallback, update_conditional,
      controller);
  client_rpcs_.Update(chunk_holder->chunk_holder_contact, chunk_holder->local,
      &update_request, update_resonse, controller.get(), callback);
}

void MaidsafeStoreManager::UpdateChunkCallback(
    boost::condition_variable *cond,
    boost::shared_ptr<rpcprotocol::Controller>) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::UpdateChunkCallback.\n");
#endif
  cond->notify_one();
}

void MaidsafeStoreManager::SetStoreReturnValue(int value, int *return_value) {
  if (return_value != NULL) {
    {
      boost::lock_guard<boost::mutex> lock(store_packet_mutex_);
      *return_value = value;
    }
    store_packet_conditional_.notify_all();
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
      channel_manager_.get(), ss_->VaultIP(), ss_->VaultPort(), "", 0);
  client_rpcs_.PollVaultInfo(enc_ser_vc,
                             &vault_status_response,
                             controller,
                             channel,
                             done);
}

void MaidsafeStoreManager::PollVaultInfoCallback(
    const VaultStatusResponse *response, base::callback_func_type cb) {
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

  if (vc.chunkstore() == "" && vc.offered_space() == 0 &&
      vc.free_space() == 0 && vc.ip() == "" && vc.port() == 0) {
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

void MaidsafeStoreManager::OwnLocalVault(const std::string &priv_key,
    const std::string &pub_key, const std::string &signed_pub_key,
    const boost::uint32_t &port, const std::string &chunkstore_dir,
    const boost::uint64_t &space,
    boost::function<void(const OwnVaultResult&, const std::string&)> cb) {
  if (pdclient_ == NULL)
    return;
  pdclient_->OwnLocalVault(priv_key, pub_key, signed_pub_key, port,
      chunkstore_dir, space, cb);
}

void MaidsafeStoreManager::LocalVaultStatus(
    boost::function<void(const VaultStatus&)> cb) {
  if (pdclient_ == NULL)
    return;
  pdclient_->IsLocalVaultOwned(cb);
}

}  // namespace maidsafe
