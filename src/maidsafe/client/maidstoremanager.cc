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
      client_chunkstore_(cstore),
      store_thread_pool_(kMaxStoreThreads),
      kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore) {}

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
}

void MaidsafeStoreManager::Close(base::callback_func_type cb,
                                 bool cancel_pending_ops) {
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Close, before Leave.\n");
#endif
  if (cancel_pending_ops)
    store_thread_pool_.clear();
  store_thread_pool_.wait();
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
  if (chunk_type & kOutgoing)
    AddNormalStoreTask(StoreTuple(chunk_name, dir_type, msid));
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





void MaidsafeStoreManager::AddPriorityStoreTask(const StoreTuple &store_tuple) {
  store_thread_pool_.schedule(boost::threadpool::prio_task_func(10, boost::bind(
      &MaidsafeStoreManager::SendChunk, this, store_tuple)));
  size_t pool_size = store_thread_pool_.size();
  if (pool_size < kMaxPriorityStoreThreads + kMaxStoreThreads)
    store_thread_pool_.size_controller().resize(pool_size + 1);
}

void MaidsafeStoreManager::AddNormalStoreTask(const StoreTuple &store_tuple) {
  store_thread_pool_.schedule(boost::threadpool::prio_task_func(5, boost::bind(
      &MaidsafeStoreManager::SendChunk, this, store_tuple)));
  if (store_thread_pool_.size() > kMaxStoreThreads)
    store_thread_pool_.size_controller().resize(kMaxStoreThreads);
}

void MaidsafeStoreManager::SendChunk(StoreTuple store_tuple) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendChunk\n");
#endif
  int duplicate_count = 0;
  float largest_rtt = -1;  // set to -1 so that first store is to furthest peer
  std::vector<kad::Contact> exclude;
  base::PDRoutingTableHandler rt_handler;
// TODO(Fraser#5#): 2009-08-10 - Account for online status in while loop also
  while (duplicate_count < kMinChunkCopies) {
    StorePrepRequest store_prep_request;
    StorePrepResponse store_prep_response;
    StoreRequest store_request;
    IOUDoneRequest iou_done_request;
    kad::Contact peer;
    bool local;
    float ideal_rtt = largest_rtt * (1 - (duplicate_count/kMinChunkCopies));
    if (GetStorePeer(ideal_rtt, exclude, &peer, &local) != 0)
      break;  // try another peer
    else
      exclude.push_back(peer);  // whether we succeed in storing or not, we'll
                                // not be trying this peer again
#ifdef DEBUG
//    std::string hex_name, hex_id;
//    base::encode_to_hex(store_tuple.get<0>(), &hex_name);
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
    if (GetStoreRequests(store_tuple, peer.node_id(), &store_prep_request,
        &store_request, &iou_done_request) != 0)
      return;
    if (SendPrep(peer, local, &store_prep_request, &store_prep_response) != 0)
      break;  // try another peer
    int failed_attempt_count = 0;
    while (failed_attempt_count < kMaxChunkStoreTries) {
      if (SendContent(peer, local, &store_request) == 0) {
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
    if (StoreIOUs(store_prep_request.chunkname(),
        store_prep_request.data_size(), store_prep_response) != 0) {
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
}

int MaidsafeStoreManager::GetStoreRequests(const StoreTuple &store_tuple,
                                           const std::string &recipient_id,
                                           StorePrepRequest *store_prep_request,
                                           StoreRequest *store_request,
                                           IOUDoneRequest *iou_done_request) {
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
  GetSignedPubKeyAndRequest(chunk_name, dir_type, msid, recipient_id,
                            &public_key, &signed_public_key, &signed_request);
  if (public_key == "" || signed_public_key == "" || signed_request == "")
    return -3;
  std::string pmid = ss_->Id(PMID);
  std::string non_hex_pmid;
  base::decode_from_hex(pmid, &non_hex_pmid);
  store_prep_request->set_chunkname(chunk_name);
  store_prep_request->set_data_size(chunk_size);
  store_prep_request->set_pmid(non_hex_pmid);
  store_prep_request->set_public_key(public_key);
  store_prep_request->set_signed_public_key(signed_public_key);
  store_prep_request->set_signed_request(signed_request);
  store_request->set_chunkname(chunk_name);
  store_request->set_data(chunk_content);
  store_request->set_pmid(non_hex_pmid);
  store_request->set_public_key(public_key);
  store_request->set_signed_public_key(signed_public_key);
  store_request->set_signed_request(signed_request);
  store_request->set_data_type(data_type);
  iou_done_request->set_chunkname(chunk_name);
  iou_done_request->set_public_key(public_key);
  iou_done_request->set_signed_public_key(signed_public_key);
  iou_done_request->set_signed_request(signed_request);
  return 0;
}

void MaidsafeStoreManager::GetSignedPubKeyAndRequest(
    const std::string &non_hex_name,
    const DirType dir_type,
    const std::string &msid,
    const std::string &recipient_id,
    std::string *pubkey,
    std::string *signed_pubkey,
    std::string *signed_request) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
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
      *signed_pubkey = co.AsymSign(*pubkey, "", prikey, crypto::STRING_STRING);
      *signed_request = co.AsymSign(co.Hash(
          *signed_pubkey + non_hex_name + recipient_id, "",
          crypto::STRING_STRING, false), "", prikey, crypto::STRING_STRING);
      }
      break;
    case PUBLIC_SHARE:
#ifdef DEBUG
//      printf("Getting signed request for PUBLIC_SHARE.\n\n");
#endif
      *pubkey = ss_->PublicKey(MPID);
      *signed_pubkey = ss_->SignedPublicKey(MPID);
      *signed_request = co.AsymSign(co.Hash(
          *signed_pubkey + non_hex_name + recipient_id, "",
          crypto::STRING_STRING, false), "", ss_->PrivateKey(MPID),
          crypto::STRING_STRING);
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
      *signed_pubkey = ss_->SignedPublicKey(PMID);
      *signed_request = co.AsymSign(co.Hash(
          *signed_pubkey + non_hex_name + recipient_id, "",
          crypto::STRING_STRING, false), "", ss_->PrivateKey(PMID),
          crypto::STRING_STRING);
      break;
  }
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
  bool store_prep_response_returned(false);
  boost::mutex mutex;
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendPrepCallback, &store_prep_response_returned,
      &mutex);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  client_rpcs_.StorePrep(peer, local, store_prep_request,
      store_prep_response, controller, callback);
// TODO(Fraser#5#): 2009-08-12 - Make timeout a maidsafe constant
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
//  printf("In MaidsafeStoreManager::SendPrepCallback.\n");
#endif
  boost::mutex::scoped_lock lock(*mutex);
  *send_prep_returned = true;
}

int MaidsafeStoreManager::SendContent(const kad::Contact &peer,
                                      bool local,
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
  while (true) {
    {
      boost::mutex::scoped_lock lock(mutex);
      if (store_response_returned)
        break;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
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
  // Move chunk from Outgoing to Normal.  If this operation fails, still return
  // 0 as this is non-critical.
  ChunkType chunk_type =
      client_chunkstore_->chunk_type(store_request->chunkname());
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(store_request->chunkname(),
                                          new_type) != 0) {
#ifdef DEBUG
    printf("In MSM::SendContent, failed to change chunk type.\n");
#endif
  }
  return 0;
}

void MaidsafeStoreManager::SendContentCallback(bool *send_content_returned,
                                               boost::mutex *mutex) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendContentCallback.\n");
#endif
  boost::mutex::scoped_lock lock(*mutex);
  *send_content_returned = true;
}

int MaidsafeStoreManager::StoreIOUs(
    const std::string &non_hex_chunk_name,
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
  if (FindKNodes(non_hex_chunk_name, &ref_holders) != 0) {
    return -1;
  }
  std::string own_pmid = ss_->Id(PMID);
  std::string own_non_hex_pmid;
  base::decode_from_hex(own_pmid, &own_non_hex_pmid);
  StoreIOURequest store_iou_request;
  store_iou_request.set_chunkname(non_hex_chunk_name);
  store_iou_request.set_data_size(chunk_size);
  store_iou_request.set_collector_pmid(store_prep_response.pmid_id());
  store_iou_request.set_iou(serialised_iou);
  store_iou_request.set_own_pmid(own_non_hex_pmid);
  int successful_count(0);
  std::vector<StoreIouResultHolder> results;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    StoreIouResultHolder store_iou_result_holder;
    results.push_back(store_iou_result_holder);
  }
  boost::mutex store_iou_mutex;
  // Send out the store IOU RPCs
  std::set<std::string> ref_holder_ids;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    SendIouToRefHolder(ref_holders.at(i), store_iou_request, &store_iou_mutex,
                       &results.at(i));
    ref_holder_ids.insert(ref_holders.at(i).node_id());
  }
  // Once we've got enough successful replies, cancel the remaining store IOU
  // RPCs (they should still succeed, we just won't handle the reply)
  while (successful_count < kKadStoreThreshold_) {
    for (boost::uint16_t i = 0; i < results.size(); ++i) {
      boost::mutex::scoped_lock loch(store_iou_mutex);
      if (results.at(i).store_iou_response_returned_) {
        int n = HandleStoreIOUResponse(results.at(i), &ref_holder_ids);
        if (n == 0)
          ++successful_count;
        results.at(i).store_iou_response_returned_ = false;
        break;
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  if (successful_count < kKadStoreThreshold_)
    return -1;  // We've not received enough successful responses
  for (boost::uint16_t j = 0; j < results.size(); ++j)
    channel_manager_->DeletePendingRequest(results.at(j).rpc_id_);
  return 0;
}

int MaidsafeStoreManager::FindKNodes(const std::string &kad_key,
                                     std::vector<kad::Contact> *contacts) {
  CallbackObj kad_cb_obj;
  knode_->FindCloseNodes(kad_key, boost::bind(&CallbackObj::CallbackFunc,
      &kad_cb_obj, _1));
// TODO(Fraser#5#): 2009-08-12 - Make timeout a maidsafe constant
  kad_cb_obj.WaitForCallback(30000);
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

int MaidsafeStoreManager::SendIouToRefHolder(
    const kad::Contact &ref_holder,
    StoreIOURequest store_iou_request,
    boost::mutex *store_iou_mutex,
    StoreIouResultHolder *store_iou_result_holder) {
  std::string public_key(""), signed_public_key(""), signed_request("");
  GetSignedPubKeyAndRequest(store_iou_request.chunkname(), PRIVATE, "",
      ref_holder.node_id(), &public_key, &signed_public_key,
      &signed_request);
  store_iou_request.set_public_key(public_key);
  store_iou_request.set_signed_public_key(signed_public_key);
  store_iou_request.set_signed_request(signed_request);
  bool local = (knode_->CheckContactLocalAddress(ref_holder.node_id(),
      ref_holder.local_ip(), ref_holder.local_port(), ref_holder.host_ip())
      == kad::LOCAL);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendIouToRefHolderCallback,
      &store_iou_result_holder->store_iou_response_returned_, store_iou_mutex);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  client_rpcs_.StoreIOU(ref_holder, local, &store_iou_request,
      &store_iou_result_holder->store_iou_response_, controller, callback);
  store_iou_result_holder->rpc_id_ = controller->req_id();
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
    const StoreIouResultHolder &store_iou_result_holder,
    std::set<std::string> *ref_holder_ids) {
  maidsafe::StoreIOUResponse sir =
      store_iou_result_holder.store_iou_response_;
  if (sir.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from rpc id %d came back failed (%d).\n",
           store_iou_result_holder.rpc_id_, knode_->host_port());
#endif
    return -1;
  }
  if (ref_holder_ids->find(sir.pmid_id()) == ref_holder_ids->end()) {
#ifdef DEBUG
    printf("In MSM, response on rpc id %d has fake identity (%d).\n",
           store_iou_result_holder.rpc_id_, knode_->host_port());
#endif
    return -1;
  }
  return 0;
}

int MaidsafeStoreManager::SendIOUDone(const kad::Contact &peer,
                                      bool local,
                                      IOUDoneRequest *iou_done_request) {
  IOUDoneResponse iou_done_response;
  bool iou_done_returned(false);
  boost::mutex mutex;
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::IOUDoneCallback, &iou_done_returned,
      &mutex);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  client_rpcs_.IOUDone(peer, local, iou_done_request, &iou_done_response,
      controller, callback);
// TODO(Fraser#5#): 2009-08-12 - Make timeout a maidsafe constant
  int count(0), timeout(120000);
  while (count < timeout) {
    {
      boost::mutex::scoped_lock lock(mutex);
      if (iou_done_returned)
        break;
    }
    count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  return (iou_done_response.pmid_id() == peer.node_id() &&
          iou_done_response.result() == kAck) ? 0 : -1;
}

void MaidsafeStoreManager::IOUDoneCallback(bool *iou_done_returned,
                                           boost::mutex *mutex) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::IOUDoneCallback.\n");
#endif
  boost::mutex::scoped_lock lock(*mutex);
  *iou_done_returned = true;
}

}  // namespace maidsafe
