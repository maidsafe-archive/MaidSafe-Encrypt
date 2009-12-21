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
#include <maidsafe/transport-api.h>
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

void StoreChunkTask::run() {
  printf("StoreChunkTask - chunk %s ENQUEUEDISED\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
  msm_->PrepareToSendChunk(store_data_, if_exists_);
  printf("StoreChunkTask end %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
}

void SendChunkCopyTask::run() {
  printf("SendChunkCopyTask - chunk %s ENQUEUEDISED\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
  msm_->SendChunk(store_data_);
  printf("SendChunkCopyTask end %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
}

void StorePacketToVaultsTask::run() {
  printf("StorePacketToVaultsTask start %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
  int ret = msm_->SendPacketToVaults(store_data_);
  // If we're not waiting for results, the ret val and cond data will be NULL
  if (return_value_ != NULL && generic_cond_data_ != NULL) {
    boost::mutex::scoped_lock loch(generic_cond_data_->cond_mutex);
    generic_cond_data_->cond_flag = true;
    *return_value_ = ret;
    generic_cond_data_->cond_variable->notify_all();
  }
  printf("StorePacketToVaultsTask end %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
}

void StorePacketToKadTask::run() {
  printf("StorePacketToVaultsTask start %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
  msm_->SendPacketToKad(store_data_, return_value_, generic_cond_data_);
  boost::mutex::scoped_lock loch(generic_cond_data_->cond_mutex);
  generic_cond_data_->cond_flag = true;
  generic_cond_data_->cond_variable->notify_all();
  if (return_value_ != NULL)
    printf("StorePacketToKadTask end %s -- result: %i\n",
           HexSubstr(store_data_.non_hex_key_).c_str(), *return_value_);
  else
    printf("StorePacketToKadTask end %s\n",
           HexSubstr(store_data_.non_hex_key_).c_str());
}

void AddToWatchListTask::run() {
  printf("AddToWatchListTask start %s\n",
         HexSubstr(store_data_.non_hex_key_).c_str());
  msm_->AddToWatchList(store_data_, store_prep_response_);
}

MaidsafeStoreManager::MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore)
    : transport_(),
      channel_manager_(&transport_),
      knode_(new kad::KNode(&channel_manager_, &transport_, kad::CLIENT, "", "",
          false, false)),
      client_rpcs_(new ClientRpcs(&transport_, &channel_manager_)),
      pdclient_(NULL),
      ss_(SessionSingleton::getInstance()),
      tasks_handler_(),
      client_chunkstore_(cstore),
      chunk_thread_pool_(),
      packet_thread_pool_(),
      kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore),
      store_packet_mutex_(),
      get_chunk_conditional_(),
      mock_rpcs_(false),
      bprpcs_(new BufferPacketRpcsImpl(&transport_, &channel_manager_)),
      cbph_(bprpcs_, knode_) {
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
    success = transport_.RegisterOnServerDown(boost::bind(
        &kad::KNode::HandleDeadRendezvousServer, knode_.get(), _1));
  if (success)
    success = (transport_.Start(port) == 0);
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
  chunk_thread_pool_.setMaxThreadCount(20);
  packet_thread_pool_.setMaxThreadCount(10);
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Init, after Join.\n");
#endif
  pdclient_ = new PDClient(&transport_, &channel_manager_, knode_,
      client_rpcs_);
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
  transport_.Stop();
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
  transport::CleanUp();
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
  if (chunk_type & kOutgoing) {
    std::string key_id, public_key, public_key_signature, private_key;
    GetChunkSignatureKeys(dir_type, msid, &key_id, &public_key,
        &public_key_signature, &private_key);
    AddStoreChunkTask(StoreData(chunk_name, chunk_size, chunk_type, dir_type,
        msid, key_id, public_key, public_key_signature, private_key),
        kStoreSuccess);
  }
}

int MaidsafeStoreManager::StorePacket(const std::string &hex_packet_name,
                                      const std::string &value,
                                      PacketType system_packet_type,
                                      DirType dir_type,
                                      const std::string &msid) {
  if (hex_packet_name.length() != 2 * kKeySize) {
    return kIncorrectKeySize;
  }

  switch (system_packet_type) {
    case MID:
    case SMID:
    case MSID:
      return StorePacketToVaults(hex_packet_name, value, system_packet_type,
                                 dir_type, msid, false);  // Overwrite
    case PD_DIR:
      return StorePdDirToVaults(hex_packet_name, value, dir_type, msid);
    case TMID:
    case MPID:
    case PMID:
    case MAID:
    case ANMID:
    case ANSMID:
    case ANTMID:
    case ANMPID:
      return StorePacketToKad(hex_packet_name, value, system_packet_type,
                              dir_type, msid);
    default:
      return kPacketUnknownType;
  }
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
    int result = FindAndLoadChunk(chunk_name, chunk_holders_ids, true, "", "",
                                  data);
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
  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  kad::ContactInfo cache_holder;
  std::string needs_cache_copy_id;
  // If this blocking Kad call to FindValue yields multiple values, they are
  // packet holder IDs.  If there is just one, it should be the actual value.
  for (int attempt = 0; attempt < kMaxChunkLoadRetries; ++attempt) {
    int res = FindValue(packet_name, false, &cache_holder, results,
        &needs_cache_copy_id);
    if (res != kSuccess || results->empty()) {
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
      break;
    }
  }
  // If only one value returned, it should be the packet value
  if (results->size() == 1) {
    return kSuccess;
  } else if (results->size() > 1) {
    std::vector<std::string> packet_holder_ids(*results);
    return LoadPacketFromVaults(packet_name, packet_holder_ids, results);
  } else {
    return kFindValueFailure;
  }
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

int MaidsafeStoreManager::DeletePacket(const std::string &hex_key,
                                       const std::string &signature,
                                       const std::string &public_key,
                                       const std::string &signed_public_key,
                                       const ValueType &type,
                                       base::callback_func_type cb) {
/*  std::string key = base::DecodeFromHex(hex_key);
  pdclient_->DeleteChunk(key, public_key, signed_public_key, signature, type,
      boost::bind(&MaidsafeStoreManager::DeleteChunk_Callback, this, _1, cb));*/
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

// Buffer packet
int MaidsafeStoreManager::CreateBP() {
  BPInputParameters bi_input_params = {ss_->Id(MPID), ss_->PublicKey(MPID),
                                       ss_->PrivateKey(MPID)};
  bool called_back(false);
  boost::condition_variable cond_var;
  boost::mutex mutex;
  ReturnCode result;
  BPCallbackObj bp_callback_obj(&called_back, &cond_var, &mutex, &result);
  cbph_.CreateBufferPacket(bi_input_params, boost::bind(
      &BPCallbackObj::BPOperationCallback, &bp_callback_obj, _1));
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
      &BPCallbackObj::BPGetMessagesCallback, &bp_callback_obj, _1, _2));
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
      boost::bind(&BPCallbackObj::BPOperationCallback, &bp_callback_obj, _1));
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
    cbph_.AddMessage(bi_input_params, ss_->GetContactPublicKey(receivers.at(i)),
        receivers.at(i), message, type, boost::bind(
        &BPCallbackObj::BPOperationCallback, &bp_callback_objs.at(i), _1));
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
      printf("In MSM::AddBPMessage, failed to AddMessage - result %u is %i\n",
             i, results.at(i));
      result = results.at(i);
      break;
    }
  }
  return result;
}

void MaidsafeStoreManager::AddStorePacketTask(
    const StoreData &store_data,
    bool is_mutable,
    int *return_value,
    GenericConditionData *generic_cond_data) {
  if (is_mutable) {
    // packet_thread_pool_ handles destruction of store_packet_task.
    StorePacketToVaultsTask *store_packet_task = new StorePacketToVaultsTask(
        store_data, this, return_value, generic_cond_data);
    packet_thread_pool_.start(store_packet_task);
  } else {
    // packet_thread_pool_ handles destruction of store_packet_task.
    StorePacketToKadTask *store_packet_task = new StorePacketToKadTask(
        store_data, this, return_value, generic_cond_data);
    packet_thread_pool_.start(store_packet_task);
  }
}

void MaidsafeStoreManager::AddStoreChunkTask(const StoreData &store_data,
                                             IfExists if_exists) {
  tasks_handler_.AddTask(store_data.non_hex_key_, kStoreChunk, store_data.size_,
                         kMinChunkCopies, kMaxStoreFailures);
  // chunk_thread_pool_ handles destruction of store_chunk_task.
  StoreChunkTask *store_chunk_task = new StoreChunkTask(store_data, if_exists,
                                                        this);
  chunk_thread_pool_.start(store_chunk_task);
}

void MaidsafeStoreManager::AddSendChunkCopyTask(const StoreData &store_data) {
  // chunk_thread_pool_ handles destruction of store_chunk_task.
  SendChunkCopyTask *send_chunk_copy_task = new SendChunkCopyTask(store_data,
                                                                  this);
  chunk_thread_pool_.start(send_chunk_copy_task);
}

void MaidsafeStoreManager::PrepareToSendChunk(const StoreData &store_data,
                                              IfExists if_exists) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::PrepareToSendChunk\n");
#endif
  // Find out if the chunk already exists on the network.
  std::string chunk_name = store_data.non_hex_key_;
  kad::ContactInfo cache_holder;
  std::vector<std::string> chunk_holders_ids;
  std::string needs_cache_copy_id;
  // If the maidsafe value is cached, this blocking Kad call to FindValue may
  // yield serialised contact details for a cache copy holder.  Otherwise it
  // should yield the reference holders.  If it yields the reference holders,
  // check that at least one currently has the chunk.
  int find_result = FindValue(chunk_name, false, &cache_holder,
      &chunk_holders_ids, &needs_cache_copy_id);
  bool exists = (find_result == kSuccess);
  // If FindValue failed to complete the kad function then return.
  if (!exists && find_result != kFindValueFailure) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::PrepareToSendChunk (%i), failed in "
           "FindValue.\n", knode_->host_port());
#endif
//    SetStoreReturnValue(kPreSendFindValueFailure, return_value);
    return;
  }
  bool data_cached = (cache_holder.has_node_id());
  std::string data;
  if (exists && !data_cached) {
    exists = (FindAndLoadChunk(chunk_name, chunk_holders_ids, false, "", "",
                               &data) == kSuccess);
  }
  // If the chunk does already exist on the network, determine what to do.
  if (exists) {
    switch (if_exists) {
      case kStoreFailure:
//        SetStoreReturnValue(kPreSendChunkAlreadyExists, return_value);
        return;
      case kStoreSuccess:
        // TODO(Fraser#5#): 2009-12-21 - Add ourselves to the watchlist
//        SetStoreReturnValue(kSuccess, return_value);
        return;
      case kOverwrite:
        if (data_cached) {
#ifdef DEBUG
          printf("In MaidsafeStoreManager::PrepareToSendChunk (%i), can't "
                 "overwrite a cached value.\n", knode_->host_port());
#endif
//          SetStoreReturnValue(kPreSendOverwriteCached, return_value);
        } else {
          UpdateChunkCopies(store_data, chunk_holders_ids);
//          SetStoreReturnValue(static_cast<ReturnCode>(res), return_value);
        }
        return;
      default:
#ifdef DEBUG
        printf("In MaidsafeStoreManager::PrepareToSendChunk (%i), invalid "
               "IfExists setting.\n", knode_->host_port());
#endif
//        SetStoreReturnValue(kStoreManagerError, return_value);
        return;
    }
  } else {  // If the data doesn't already exist on the network, store it.
    for (int i = 0; i < kMinChunkCopies; ++i) {
      SendChunk(store_data);
    }
//    else
//      res = SendPacket(store_data, kMinChunkCopies);
  }
}

TaskStatus MaidsafeStoreManager::AssessStoreTaskStatus(
    const StoreData &store_data,
    StoreTask *task) {
  if (!tasks_handler_.Task(store_data.non_hex_key_, kStoreChunk, task))
    return kCompleted;
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
    if (!tasks_handler_.Task(data_name, task_type, &task) || task.cancelled_)
      return false;
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  return true;
}

int MaidsafeStoreManager::SendChunk(const StoreData &store_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendChunk\n");
#endif
  StoreTask task;
  // Assess whether to start the subtask or not
  TaskStatus status = AssessStoreTaskStatus(store_data, &task);
  if (status == kCompleted || status == kCancelled) {
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Task already completed.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return kStoreAlreadyCompleted;
  }
  // Establish if this is the first SendChunk for the overall task
  bool first(task.success_count_ == 0);
  // Get peer
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
  if (tasks_handler_.StartSubTask(store_data.non_hex_key_, kStoreChunk, peer) !=
      kSuccess)
    return kSendChunkFailure;
  // If GetStorePeer failed, stop subtask to record failure
  if (peer_result != kSuccess) {
    tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Error getting store peer.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return kGetStorePeerError;
  }
  // Form store requests
  StorePrepRequest store_prep_request;
  StorePrepResponse store_prep_response;
  StoreChunkRequest store_chunk_request;
  int result = GetStoreRequests(store_data, peer.node_id(), &store_prep_request,
                                &store_chunk_request);
  if (result != kSuccess) {
    tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Error getting store requests.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return result;
  }
  // Check we're online
  if (!WaitForOnline(store_data.non_hex_key_, kStoreChunk)) {
    tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Offline before sending prep.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return kTaskCancelledOffline;
  }
  // Send prep
  boost::shared_ptr<boost::condition_variable>
      cond_variable(new boost::condition_variable);
  result = SendPrep(peer, local, cond_variable, &store_prep_request,
      &store_prep_response);
  if (result != kSuccess) {
    tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Error sending prep.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return result;
  }
  // Check task hasn't already been finished
  status = AssessStoreTaskStatus(store_data, &task);
  if (status == kCompleted || status == kCancelled) {
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Task already completed.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return kStoreAlreadyCompleted;
  }
  // Send chunk content
  int failed_attempt_count = 0;
  while (failed_attempt_count < kMaxChunkStoreTries) {
    // Check we're online
    if (!WaitForOnline(store_data.non_hex_key_, kStoreChunk)) {
      tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
  #ifdef DEBUG
      printf("In MSM::SendChunk (chunk %s): Offline before sending content.\n",
             HexSubstr(store_data.non_hex_key_).c_str());
  #endif
      return kTaskCancelledOffline;
    }
    result = SendContent(peer, local, cond_variable, &store_chunk_request);
    if (result == kSuccess) {
      break;  // succeeded in storing to this peer
    } else {
      ++failed_attempt_count;
    }
  }
  if (failed_attempt_count >= kMaxChunkStoreTries) {
    if (first) {  // if this is failed 1st copy, reset largest rtt
//      set largest rtt via tasks_handler_.SetRtt
//      largest_rtt = -1.0f;
    }
    tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, false);
#ifdef DEBUG
    printf("In MSM::SendChunk (chunk %s): Error sending content.\n",
           HexSubstr(store_data.non_hex_key_).c_str());
#endif
    return result;
  }
  // Add ourself to the Watch List if this is the first chunk copy
  if (first) {
    // chunk_thread_pool_ handles destruction of store_chunk_task.
    AddToWatchListTask *add_to_watch_list_task =
        new AddToWatchListTask(store_data, store_prep_response, this);
    chunk_thread_pool_.start(add_to_watch_list_task);
  }
  // Stop subtask - record success
  tasks_handler_.StopSubTask(store_data.non_hex_key_, kStoreChunk, true);
#ifdef DEBUG
  printf("Chunkname: %s  Dup count: %i\n\n",
         HexSubstr(store_data.non_hex_key_).c_str(), task.success_count_ + 1);
#endif
// TODO(Fraser#5#): 2009-08-14 - Check later that there are enough vaults
// listed in ref & watch lists to ensure upload ultimately successful.
  return kSuccess;
}

int MaidsafeStoreManager::GetStoreRequests(
    const StoreData &store_data,
    const std::string &recipient_id,
    StorePrepRequest *store_prep_request,
    StoreChunkRequest *store_chunk_request) {
  store_prep_request->Clear();
  store_chunk_request->Clear();
  ValueType data_type = DATA;
  if (store_data.dir_type_ == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  ChunkType chunk_type = store_data.chunk_type_;
  fs::path chunk_path(client_chunkstore_->GetChunkPath(store_data.non_hex_key_,
                                                       chunk_type, false));
  if (chunk_path == fs::path(""))
    return kChunkNotInChunkstore;
  boost::uint64_t chunk_size = store_data.size_;
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
  GetRequestSignature(store_data, recipient_id, &request_signature);
  if (request_signature == "")
    return kGetRequestSigError;
  std::string non_hex_pmid = base::DecodeFromHex(ss_->Id(PMID));
  store_prep_request->set_chunkname(store_data.non_hex_key_);
  SignedSize *mutable_signed_size = store_prep_request->mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_size);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  mutable_signed_size->set_signature(co.AsymSign(base::itos_ull(chunk_size), "",
      store_data.private_key_, crypto::STRING_STRING));
  mutable_signed_size->set_pmid(non_hex_pmid);
  mutable_signed_size->set_public_key(store_data.public_key_);
  mutable_signed_size->set_public_key_signature(
      store_data.public_key_signature_);
  store_prep_request->set_request_signature(request_signature);
  store_chunk_request->set_chunkname(store_data.non_hex_key_);
  store_chunk_request->set_data(chunk_content);
  store_chunk_request->set_pmid(non_hex_pmid);
  store_chunk_request->set_public_key(store_data.public_key_);
  store_chunk_request->set_public_key_signature(
      store_data.public_key_signature_);
  store_chunk_request->set_request_signature(request_signature);
  store_chunk_request->set_data_type(data_type);
  return kSuccess;
}

int MaidsafeStoreManager::GetWatchListRequest(
    const StoreData &store_data,
    const StorePrepResponse &store_prep_response,
    const std::string &recipient_id,
    AddToWatchListRequest *add_to_watch_list_request) {
  add_to_watch_list_request->Clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string watch_list_name = co.Hash(store_data.key_id_ + "WATCHLIST", "",
      crypto::STRING_STRING, false);
  std::string request_signature("");
  GetRequestSignature(watch_list_name, store_data.dir_type_,
      recipient_id, store_data.public_key_, store_data.public_key_signature_,
      store_data.private_key_, &request_signature);
  if (request_signature == "")
    return kGetRequestSigError;
  add_to_watch_list_request->set_watch_list_name(watch_list_name);
  if (store_prep_response.has_store_contract()) {
    StoreContract *mutable_store_contract =
        add_to_watch_list_request->mutable_store_contract();
    *mutable_store_contract = store_prep_response.store_contract();
  } else {
    SignedSize *mutable_signed_size =
        add_to_watch_list_request->mutable_signed_size();
    mutable_signed_size->set_data_size(store_data.size_);
    mutable_signed_size->set_signature(co.AsymSign(
        base::itos_ull(store_data.size_), "", store_data.private_key_,
        crypto::STRING_STRING));
    mutable_signed_size->set_pmid(store_data.key_id_);
    mutable_signed_size->set_public_key(store_data.public_key_);
    mutable_signed_size->set_public_key_signature(
        store_data.public_key_signature_);
  }
  add_to_watch_list_request->set_request_signature(request_signature);
  return kSuccess;
}

int MaidsafeStoreManager::GetStorePacketRequest(
    const StoreData &store_data,
    const std::string &recipient_id,
    const std::vector<std::string> &values,
    StorePacketRequest *store_packet_request) {
  store_packet_request->Clear();
  ValueType data_type = SYSTEM_PACKET;
  if (store_data.system_packet_type_ == PD_DIR) {
    if (store_data.dir_type_ == ANONYMOUS) {
      data_type = PDDIR_NOTSIGNED;
    } else {
      data_type = PDDIR_SIGNED;
    }
  }
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  // If values vector is not empty, we are sending entire set of values for a
  // key (e.g. in case of failed existing holder), so set append to false and
  // disregard single store_data.value_.  Otherwise use store_data.value_ and
  // store_data.append_.
  if (values.empty()) {
    GenericPacket *generic_packet = store_packet_request->add_signed_data();
    generic_packet->set_data(store_data.value_);
    generic_packet->set_signature(co.AsymSign(store_data.value_, "",
        store_data.private_key_, crypto::STRING_STRING));
    store_packet_request->set_append(store_data.append_);
  } else {
    for (size_t i = 0; i < values.size(); ++i) {
      GenericPacket *generic_packet = store_packet_request->add_signed_data();
      generic_packet->set_data(values.at(i));
      generic_packet->set_signature(co.AsymSign(values.at(i), "",
          store_data.private_key_, crypto::STRING_STRING));
    }
    store_packet_request->set_append(false);
  }
  store_packet_request->set_packetname(store_data.non_hex_key_);
  store_packet_request->set_key_id(base::DecodeFromHex(store_data.key_id_));
  store_packet_request->set_public_key(store_data.public_key_);
  store_packet_request->set_public_key_signature(
      store_data.public_key_signature_);
  std::string request_signature("");
  GetRequestSignature(store_data, recipient_id, &request_signature);
  if (request_signature == "")
    return kGetRequestSigError;
  store_packet_request->set_request_signature(request_signature);
  store_packet_request->set_data_type(data_type);
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
  *request_signature = "";
  if (dir_type == ANONYMOUS) {
    *request_signature = kAnonymousSignedRequest;
  } else if (public_key == "" ||
             public_key_signature == "" ||
             private_key == "") {
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
  GetRequestSignature(store_data.non_hex_key_, store_data.dir_type_,
      recipient_id, store_data.public_key_, store_data.public_key_signature_,
      store_data.private_key_, request_signature);
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

int MaidsafeStoreManager::SendPrep(
    const kad::Contact &peer,
    bool local,
    boost::shared_ptr<boost::condition_variable> cond_variable,
    StorePrepRequest *store_prep_request,
    StorePrepResponse *store_prep_response) {
  GenericConditionData send_prep_cond_data(cond_variable);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendPrepCallback, &send_prep_cond_data);
  rpcprotocol::Controller controller;
  client_rpcs_->StorePrep(peer, local, store_prep_request,
      store_prep_response, &controller, callback);
  {
    boost::mutex::scoped_lock lock(send_prep_cond_data.cond_mutex);
    while (!send_prep_cond_data.cond_flag) {
      send_prep_cond_data.cond_variable->wait(lock);
    }
    send_prep_cond_data.cond_flag = false;
  }
  // TODO(Fraser#5#): 2009-12-18 - Validate contract in store_prep_response
  return (store_prep_response->store_contract().pmid() == peer.node_id() &&
          store_prep_response->store_contract().inner_contract().result() ==
          kAck) ? kSuccess : kSendPrepFailure;
}

void MaidsafeStoreManager::SendPrepCallback(
    GenericConditionData *send_prep_cond_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPrepCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(send_prep_cond_data->cond_mutex);
  send_prep_cond_data->cond_flag = true;
  send_prep_cond_data->cond_variable->notify_all();
}

int MaidsafeStoreManager::SendContent(
    const kad::Contact &peer,
    bool local,
    boost::shared_ptr<boost::condition_variable> cond_variable,
    StoreChunkRequest *store_chunk_request) {
  const boost::shared_ptr<StoreChunkResponse>
      store_chunk_response(new StoreChunkResponse());
  GenericConditionData send_cond_data(cond_variable);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendContentCallback, &send_cond_data);
  rpcprotocol::Controller controller;
  client_rpcs_->StoreChunk(peer, local, store_chunk_request,
                           store_chunk_response.get(), &controller, callback);
  {
    boost::mutex::scoped_lock lock(send_cond_data.cond_mutex);
    while (!send_cond_data.cond_flag) {
      send_cond_data.cond_variable->wait(lock);
    }
    send_cond_data.cond_flag = false;
  }
  if (store_chunk_response->pmid() != peer.node_id()) {
#ifdef DEBUG
    printf("In MSM::SendContent, ids are not OK: response pmid: %s peer "
           "node ID: %s\n", HexSubstr(store_chunk_response->pmid()).c_str(),
           HexSubstr(peer.node_id()).c_str());
#endif
    return kSendContentFailure;
  }
  if (store_chunk_response->result() != kAck) {
#ifdef DEBUG
    printf("In MSM::SendContent, result not kAck.\n");
#endif
    return kSendContentFailure;
  }
#ifdef DEBUG
//  printf("In MSM::SendContent, succeeded.\n");
#endif
  // Move chunk from Outgoing to Normal.  If this operation fails, still
  // return kSuccess as this is non-critical.
  ChunkType chunk_type =
      client_chunkstore_->chunk_type(store_chunk_request->chunkname());
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(store_chunk_request->chunkname(),
                                          new_type) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::SendContent, failed to change chunk type.\n");
#endif
  }
  return kSuccess;
}

void MaidsafeStoreManager::SendContentCallback(
    GenericConditionData *send_cond_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendContentCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(send_cond_data->cond_mutex);
  send_cond_data->cond_flag = true;
  send_cond_data->cond_variable->notify_all();
}

void MaidsafeStoreManager::AddToWatchList(
    const StoreData &store_data,
    const StorePrepResponse &store_prep_response) {
  // TODO(Fraser#5#): 2009-12-21 - Consider repeating this until success or
  //                               some max. no. of failures.
  // Set the Watch List name
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string watch_list_name = co.Hash(store_data.key_id_ + "WATCHLIST", "",
      crypto::STRING_STRING, false);
  // Find the Watch List Holders
  std::vector<kad::Contact> watch_list_holders;
  if (FindKNodes(watch_list_name, &watch_list_holders) != kSuccess)
    return;
  // Send the requests
  boost::mutex mutex;
  std::vector<AddToWatchListRequest> add_to_watch_list_requests;
  std::vector<AddToWatchListResponse> add_to_watch_list_responses;
  for (boost::uint16_t i = 0; i < watch_list_holders.size(); ++i) {
    AddToWatchListRequest add_to_watch_list_request;
    if (GetWatchListRequest(store_data, store_prep_response,
        watch_list_holders.at(i).node_id(), &add_to_watch_list_request) !=
        kSuccess)
      continue;
    add_to_watch_list_requests.push_back(add_to_watch_list_request);
    AddToWatchListResponse add_to_watch_list_response;
    add_to_watch_list_responses.push_back(add_to_watch_list_response);
  }
  boost::uint16_t rpcs_sent_count(add_to_watch_list_requests.size());
  for (boost::uint16_t i = 0; i < rpcs_sent_count; ++i) {
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(&google::protobuf::DoNothing);
    rpcprotocol::Controller controller;
    client_rpcs_->AddToWatchList(watch_list_holders.at(i),
        AddressIsLocal(watch_list_holders.at(i)),
        &add_to_watch_list_requests.at(i), &add_to_watch_list_responses.at(i),
        &controller, callback);
  }
  boost::uint16_t successful_count(0);
  boost::uint16_t failed_count(0);
  // Once we've got enough successful replies, cancel the remaining store IOU
  // RPCs (they should still succeed, we just won't handle the reply)
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
      boost::mutex::scoped_lock lock(mutex);
      if (add_to_watch_list_responses.at(i).IsInitialized()) {
        if (add_to_watch_list_responses.at(i).result() == kAck) {
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
      printf("\n\n\n\n\n\n\nAdd to Watch List TIMED OUT\n\n\n\n\n\n\n\n");
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
    chunk_holders_ids->push_back(find_response.values(i - 1));
  }
#ifdef DEBUG
  printf("In MaidsafeStoreManager::FindValue, %i values have returned.\n",
         chunk_holders_ids->size());
#endif
  return (chunk_holders_ids->size() > 0) ? kSuccess : kFindValueFailure;
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
          chunk_holders->at(i)->local, &check_chunk_request,
          &chunk_holders->at(i)->check_chunk_response, controller.get(),
          callback);
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
  if (result == "") {
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
    const std::string &public_key,
    const std::string &signed_public_key,
    std::string *data) {
  bool get_messages = (public_key != "") && (signed_public_key != "");
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
  if (load_data || get_messages) {
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
        if (get_messages)
          GetMessages(chunk_name, chunk_holders.at(index), public_key,
                      signed_public_key, data, &get_mutex);
        else
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
          channel_manager_.CancelPendingRequest(
              chunk_holders.at(m)->controller->req_id());
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
      chunk_holder->local, &get_chunk_request, &get_chunk_response, &controller,
      callback);
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

void MaidsafeStoreManager::GetMessages(
    const std::string &buffer_packet_name,
    boost::shared_ptr<ChunkHolder> chunk_holder,
    const std::string &public_key,
    const std::string &signed_public_key,
    std::string *serialised_get_messages_response,
    boost::mutex *get_mutex) {
// TODO(Fraser#5#): 2009-11-07 - Remove this method
  GetBPMessagesRequest get_messages_request;
  get_messages_request.set_bufferpacket_name(buffer_packet_name);
  get_messages_request.set_public_key(public_key);
  get_messages_request.set_signed_public_key(signed_public_key);
  GetBPMessagesResponse get_messages_response;
  bool get_messages_done(false);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::GetChunkCallback, get_mutex, &get_messages_done);
  rpcprotocol::Controller controller;
  bprpcs_->GetBPMessages(chunk_holder->chunk_holder_contact,
      chunk_holder->local, &get_messages_request, &get_messages_response,
      &controller, callback);
  {
    boost::mutex::scoped_lock lock(*get_mutex);
    while (!get_messages_done) {
      get_chunk_conditional_.wait(lock);
    }
  }
  if (get_messages_response.result() == kNack) {
#ifdef DEBUG
    printf("In MSM, response from GetMessages came back failed (%d).\n",
           knode_->host_port());
#endif
    {  // NOLINT (Fraser)
      boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
      chunk_holder->status = kFailedHolder;
    }
    return;
  }
  if (chunk_holder->chunk_holder_contact.node_id() !=
      get_messages_response.pmid_id()) {
#ifdef DEBUG
    printf("In MSM, response from GetMessages came back from wrong node (%d)\n",
           knode_->host_port());
#endif
    {  // NOLINT (Fraser)
      boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
      chunk_holder->status = kFailedHolder;
    }
    return;
  }
  get_messages_response.SerializeToString(serialised_get_messages_response);
  {
    boost::mutex::scoped_lock lock(*(chunk_holder->mutex));
    chunk_holder->status = kDone;
  }
  return;
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

/*int MaidsafeStoreManager::SendIouToRefHolder(
    const kad::Contact &ref_holder,
    StoreIOURequest store_iou_request,
    boost::mutex *store_iou_mutex,
    boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder) {
  bool local = AddressIsLocal(ref_holder);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SendIouToRefHolderCallback,
      &store_iou_result_holder->store_iou_response_returned, store_iou_mutex);
  client_rpcs_->StoreIOU(ref_holder, local, &store_iou_request,
      &store_iou_result_holder->store_iou_response,
      store_iou_result_holder->controller.get(), callback);
#ifdef DEBUG
//  printf("Ref Holder Vault (%i) req to store iou for vault id %s...\n",
//      ref_holder.host_port(),
//      HexSubstr(store_iou_request.collector_pmid()).c_str());
#endif
  return kSuccess;
}

void MaidsafeStoreManager::SendIouToRefHolderCallback(
    bool *store_iou_response_returned,
    boost::mutex *store_iou_mutex) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendIouToRefHolderCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(*store_iou_mutex);
  *store_iou_response_returned = true;
}

int MaidsafeStoreManager::HandleStoreIOUResponse(
    const boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder,
    std::set<std::string> *ref_holder_ids) {
  maidsafe::StoreIOUResponse sir =
      store_iou_result_holder->store_iou_response;
  if (sir.result() != kAck) {
#ifdef DEBUG
    if (!mock_rpcs_) {
      printf("In MSM, response from rpc id %d came back failed (%d).\n",
             store_iou_result_holder->controller->req_id(),
             knode_->host_port());
    }
#endif
    return kStoreIOUFailure;
  }
  if (ref_holder_ids->find(sir.pmid()) == ref_holder_ids->end()) {
#ifdef DEBUG
    if (!mock_rpcs_) {
      printf("In MSM, response on rpc id %d has fake identity (%d).\n",
             store_iou_result_holder->controller->req_id(),
             knode_->host_port());
    }
#endif
    return kStoreIOUFailure;
  }
  return kSuccess;
}

int MaidsafeStoreManager::SendIOUDone(
    const kad::Contact &peer,
    bool local,
    boost::shared_ptr<boost::condition_variable> cond_variable,
    IOUDoneRequest *iou_done_request) {
  IOUDoneResponse iou_done_response;
  GenericConditionData iou_done_cond_data(cond_variable);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::IOUDoneCallback, &iou_done_cond_data);
  rpcprotocol::Controller controller;
  client_rpcs_->IOUDone(peer, local, iou_done_request, &iou_done_response,
      &controller, callback);
  {
    boost::mutex::scoped_lock lock(iou_done_cond_data.cond_mutex);
    while (!iou_done_cond_data.cond_flag) {
      iou_done_cond_data.cond_variable->wait(lock);
    }
    iou_done_cond_data.cond_flag = false;
  }
  return (iou_done_response.pmid() == peer.node_id() &&
          iou_done_response.result() == kAck) ? kSuccess : kSendIOUDoneFailure;
}

void MaidsafeStoreManager::IOUDoneCallback(
    GenericConditionData *iou_done_cond_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::IOUDoneCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(iou_done_cond_data->cond_mutex);
  iou_done_cond_data->cond_flag = true;
  iou_done_cond_data->cond_variable->notify_all();
}
*/
int MaidsafeStoreManager::StorePacketToVaults(
    const std::string &hex_packet_name,
    const std::string &value,
    PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid,
    bool append) {
#ifdef DEBUG
//  std::string hex(hex_chunk_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::StorePacketToVaults (%i), packet name = "
//         "%s\n", knode_->host_port(), hex.c_str());
#endif
  if (ss_->ConnectionStatus() == 1)
    return kNotConnected;
  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  int return_value(99999);
  boost::shared_ptr<boost::condition_variable>
      cv(new boost::condition_variable);
  GenericConditionData generic_cond_data(cv);
  std::string key_id, public_key, public_key_signature, private_key;
  GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  AddStorePacketTask(StoreData(packet_name, value, system_packet_type,
      dir_type, msid, key_id, public_key, public_key_signature, private_key,
      append), true, &return_value, &generic_cond_data);
  {
    boost::mutex::scoped_lock lock(generic_cond_data.cond_mutex);
    while (!generic_cond_data.cond_flag) {
      generic_cond_data.cond_variable->wait(lock);
#ifdef DEBUG
      printf("In MaidsafeStoreManager::StorePacketToVaults (%i), return"
             "_value %d\n", knode_->host_port(), return_value);
#endif
    }
  }
  return return_value;
}

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
  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  GetPacketSignatureKeys(PD_DIR, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  AddStorePacketTask(StoreData(packet_name, value, PD_DIR, dir_type, msid,
      key_id, public_key, public_key_signature, private_key, true), true, NULL,
      NULL);
  return kSuccess;
}

int MaidsafeStoreManager::StorePacketToKad(
    const std::string &hex_packet_name,
    const std::string &value,
    PacketType system_packet_type,
    DirType dir_type,
    const std::string &msid) {
#ifdef DEBUG
//  std::string hex(hex_packet_name.substr(0, 10) + "...");
//  printf("In MaidsafeStoreManager::StorePacketToKad (%i), packet name = "
//         "%s\n", knode_->host_port(), hex.c_str());
#endif
  std::string packet_name = base::DecodeFromHex(hex_packet_name);
  int return_value(1);
  boost::shared_ptr<boost::condition_variable>
      cv(new boost::condition_variable);
  GenericConditionData generic_cond_data(cv);
  std::string key_id, public_key, public_key_signature, private_key;
  GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  AddStorePacketTask(StoreData(packet_name, value, system_packet_type, dir_type,
      msid, key_id, public_key, public_key_signature, private_key, true),
      false, &return_value, &generic_cond_data);
  {
    boost::mutex::scoped_lock lock(generic_cond_data.cond_mutex);
    while (!generic_cond_data.cond_flag) {
      generic_cond_data.cond_variable->wait(lock);
#ifdef DEBUG
      printf("In MaidsafeStoreManager::StorePacketToKad (%i), return"
             "_value %d\n", knode_->host_port(), return_value);
#endif
    }
  }
  return return_value;
}

int MaidsafeStoreManager::SendPacketToVaults(const StoreData &store_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPacketToVaults\n");
#endif
  // Find out if the packet already exists on the network.
  std::string packet_name = store_data.non_hex_key_;
  kad::ContactInfo cache_holder;
  std::vector<std::string> packet_holders_ids;
  std::string needs_cache_copy_id;
  // The value shouldn't be cached, but this blocking Kad call to FindValue may
  // yield serialised contact details for a cache copy holder.  Otherwise it
  // should yield the reference holders.
  int find_result = FindValue(packet_name, false, &cache_holder,
      &packet_holders_ids, &needs_cache_copy_id);
  bool exists = (find_result == kSuccess);
  // If FindValue failed to complete the kad function then return.
  if (!exists && find_result != kFindValueFailure) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::SendPacketToVaults (%i), failed in "
           "FindValue.\n", knode_->host_port());
#endif
    return kSendPacketFindValueFailure;
  }
  if (cache_holder.has_node_id())
    return kSendPacketCached;
  boost::shared_ptr<boost::condition_variable>
      find_cond_variable(new boost::condition_variable);
  boost::shared_ptr<boost::condition_variable>
      store_cond_variable(new boost::condition_variable);
  boost::shared_ptr<GenericConditionData>
      find_cond_data(new GenericConditionData(find_cond_variable));
  GenericConditionData store_cond_data(store_cond_variable);
  std::vector< boost::shared_ptr<ChunkHolder> > packet_holders;
  std::vector< boost::shared_ptr<ChunkHolder> > failed_packet_holders;
  std::vector< boost::shared_ptr<StorePacketResponse> > store_packet_responses;
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  // Update copies currently available, otherwise store new copies until
  // kMinChunkCopies have been stored.
  FindCloseNodes(packet_holders_ids, &packet_holders, find_cond_data);
  // For each, if we have their contact details, send StorePacket.
  int sent_rpc_count(0);
  int returned_rpc_count(0);
  std::vector<std::string> packet_values;
  std::vector<kad::Contact> exclude;
  for (size_t i = 0; i < packet_holders_ids.size(); ++i) {
    boost::mutex::scoped_lock lock(find_cond_data->cond_mutex);
    // Wait until we've got details for current packet holder.
    while (i >= packet_holders.size()) {
      find_cond_data->cond_variable->wait(lock);
    }
    packet_holders.at(i)->index = i;
    // If we got the details, send StorePacket RPC.
    if (packet_holders.at(i)->status != kFailedHolder) {
      kad::Contact new_peer = packet_holders.at(i)->chunk_holder_contact;
      packet_holders.at(i)->local = AddressIsLocal(new_peer);
      packet_holders.at(i)->mutex = &store_cond_data.cond_mutex;
      exclude.push_back(new_peer);  // whether we succeed in storing or not,
                                    // we'll not be trying this peer again.
      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      packet_holders.at(i)->controller = controller;
      StorePacketRequest store_packet_request;
      if (GetStorePacketRequest(store_data, new_peer.node_id(), packet_values,
          &store_packet_request) != kSuccess) {
        packet_holders.at(i)->status = kFailedHolder;
        continue;
      }
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::StorePacketCallback, &store_cond_data,
          &returned_rpc_count);
      client_rpcs_->StorePacket(packet_holders.at(i)->chunk_holder_contact,
          packet_holders.at(i)->local, &store_packet_request,
          &packet_holders.at(i)->store_packet_response, controller.get(),
          callback);
      ++sent_rpc_count;
    }
  }
  // Wait for all RPCs to return.
  {
    boost::mutex::scoped_lock lock(store_cond_data.cond_mutex);
    while (returned_rpc_count < sent_rpc_count) {
      store_cond_variable->wait(lock);
    }
  }
  // Check returns for success.
  std::string common_checksum;
  int checksum_result = AssessPacketStoreResults(&packet_holders,
      &failed_packet_holders, &common_checksum);
  if (checksum_result == kCommonChecksumUndecided) {
    // TODO(Fraser#5#): 2009-10-27 - Handle failure better - try and establish
    // if any vault has correct checksum and repopulate to others, or postpone
    // and retry later hoping for another packet holder to come back online?
    return kCommonChecksumUndecided;
  }
  // Count how many good copies we have.
  int duplicate_count(0);
  std::vector< boost::shared_ptr<ChunkHolder> >::iterator it =
      packet_holders.begin();
  while (it != packet_holders.end()) {
    if ((*it)->status == kFailedChecksum) {
      // TODO(Fraser#5#): 2009-10-27 - change subsequent lines to:-
      // 1 - Read entire packet from successful holder to packet_values
      // 2 - Store all values to failed holder with append == false
      // 3 - If it fails, amend status to kFailedHolder
      failed_packet_holders.push_back(*it);
      it = packet_holders.erase(it);
    } else {
      ++duplicate_count;
      ++it;
    }
  }
  boost::shared_ptr<boost::condition_variable>
      fresh_cond_variable(new boost::condition_variable);
  while (duplicate_count < kMinChunkCopies) {
    // Store copies until we have at least kMinChunkCopies
    sent_rpc_count = 0;
    returned_rpc_count = 0;
    float largest_rtt = -1.0f;  // set to -1.0 so first store is to furthst peer
    base::PDRoutingTableHandler rt_handler;
    GenericConditionData fresh_store_cond_data(fresh_cond_variable);
  // TODO(Fraser#5#): 2009-08-10 - Account for online status in while loop also
    while (sent_rpc_count < kMinChunkCopies - duplicate_count) {
      kad::Contact peer;
      bool local(false);
      float ideal_rtt = largest_rtt * (1 - (static_cast<float>(
          duplicate_count) / (kMinChunkCopies - duplicate_count)));
      if (GetStorePeer(ideal_rtt, exclude, &peer, &local) != kSuccess)
        continue;  // try another peer
      else
        exclude.push_back(peer);  // whether we succeed in storing or not, we'll
                                  // not be trying this peer again
      if (duplicate_count == 0) {  // set largest_rtt from first peer
  // TODO(Fraser#5#): 2009-08-14 - Uncomment lines below
  //      base::PDRoutingTableTuple peer_details;
  //      if (rt_handler.GetTupleInfo(peer.node_id(), &peer_details) != 0)
  //        break;
  //      largest_rtt = peer_details.rtt();
        largest_rtt = 1.0f;
      }
      StorePacketRequest store_packet_request;
      if (GetStorePacketRequest(store_data, peer.node_id(), packet_values,
          &store_packet_request) != kSuccess) {
        continue;
      }
      boost::shared_ptr<ChunkHolder> packet_holder(new ChunkHolder(peer));
      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      packet_holder->controller = controller;
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::StorePacketCallback, &fresh_store_cond_data,
          &returned_rpc_count);
      client_rpcs_->StorePacket(peer, local, &store_packet_request,
          &packet_holder->store_packet_response, controller.get(), callback);
      packet_holders.push_back(packet_holder);
      ++sent_rpc_count;
    }
    // Wait for all RPCs to return.
    {
      boost::mutex::scoped_lock lock(fresh_store_cond_data.cond_mutex);
      while (returned_rpc_count < sent_rpc_count) {
        fresh_cond_variable->wait(lock);
      }
    }
    // Check returns for success.
    std::string common_checksum;
    int checksum_result = AssessPacketStoreResults(&packet_holders,
        &failed_packet_holders, &common_checksum);
    if (checksum_result == kCommonChecksumUndecided) {
      // TODO(Fraser#5#): 2009-10-27 - Handle failure better - try and establish
      // if any vault has correct checksum and repopulate to others, or postpone
      // and retry later hoping for another packet holder to come back online?
      return kCommonChecksumUndecided;
    }
    // Count how many good copies we have.
    duplicate_count = 0;
    std::vector< boost::shared_ptr<ChunkHolder> >::iterator it =
        packet_holders.begin();
    while (it != packet_holders.end()) {
      if ((*it)->status == kFailedChecksum) {
        // TODO(Fraser#5#): 2009-10-27 - change subsequent lines to:-
        // 1 - Read entire packet from successful holder to packet_values
        // 2 - Store all values to failed holder with append == false
        // 3 - If it fails, amend status to kFailedHolder
        failed_packet_holders.push_back(*it);
        it = packet_holders.erase(it);
      } else {
        ++duplicate_count;
        ++it;
      }
    }
  }
  // TODO(Fraser#5#): 2009-10-27 - finally, spawn new thread which sends delete
  // packet rpc to all chunkholders with status kFailedHolder.

  return kSuccess;
}

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

void MaidsafeStoreManager::StorePacketCallback(
    GenericConditionData *store_cond_data,
    int *returned_rpc_count) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::StorePacketCallback.\n");
#endif
  boost::lock_guard<boost::mutex> lock(store_cond_data->cond_mutex);
  store_cond_data->cond_flag = true;
  ++(*returned_rpc_count);
  store_cond_data->cond_variable->notify_all();
}

int MaidsafeStoreManager::AssessPacketStoreResults(
    std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
    std::vector< boost::shared_ptr<ChunkHolder> > *failed_packet_holders,
    std::string *common_checksum) {
  common_checksum->clear();
  failed_packet_holders->clear();
  if (packet_holders->size() == size_t(0))
    return kSuccess;
  // Make a map of <checksum, vector index>
  std::multimap<std::string, int> check;
  for (size_t i = 0; i < packet_holders->size(); ++i) {
    if (packet_holders->at(i)->status == kDone) {  // has already been assessed
      check.insert(std::pair<std::string, int>(
          packet_holders->at(i)->store_packet_response.checksum(), i));
    } else if (packet_holders->at(i)->store_packet_response.result() == kAck &&
               packet_holders->at(i)->store_packet_response.pmid() ==
               packet_holders->at(i)->chunk_holder_contact.node_id()) {
      packet_holders->at(i)->status = kDone;
      check.insert(std::pair<std::string, int>(
          packet_holders->at(i)->store_packet_response.checksum(), i));
    } else {
      packet_holders->at(i)->status = kFailedHolder;
    }
  }
  size_t common_checksum_count(0);
  bool tie(true);
  std::multimap<std::string, int>::iterator map_iter;
  // Iterate through checksums to establish most common string
  for (map_iter = check.begin(); map_iter != check.end(); ++map_iter) {
    if (check.count((*map_iter).first) > common_checksum_count) {
      *common_checksum = (*map_iter).first;
      common_checksum_count = check.count((*map_iter).first);
      tie = false;
      if (common_checksum_count > (packet_holders->size() / 2))
        break;
    } else if (check.count((*map_iter).first) == common_checksum_count) {
      common_checksum->clear();
      tie = true;
    }
  }
  // If we cannot establish a common checksum, return error.
  if (tie) {
    std::vector< boost::shared_ptr<ChunkHolder> >::iterator it =
        packet_holders->begin();
    while (it != packet_holders->end()) {
      (*it)->status = kFailedChecksum;
      failed_packet_holders->push_back(*it);
      it = packet_holders->erase(it);
    }
    return kCommonChecksumUndecided;
  }
  // If all holders have the same checksum, return success.
  if (common_checksum_count == packet_holders->size())
    return kSuccess;
  // Change status of holders who returned kAck, but didn't yield correct
  // checksum to kFailedChecksum
  for (size_t i = 0; i < packet_holders->size(); ++i) {
    if (packet_holders->at(i)->store_packet_response.result() == kAck &&
        packet_holders->at(i)->store_packet_response.checksum() !=
        *common_checksum) {
      packet_holders->at(i)->status = kFailedChecksum;
    }
  }
  // Move failed holders to failed_packet_holders vector.
  std::vector< boost::shared_ptr<ChunkHolder> >::iterator it =
      packet_holders->begin();
  while (it != packet_holders->end()) {
    if ((*it)->status == kFailedHolder || (*it)->status == kFailedChecksum) {
      failed_packet_holders->push_back(*it);
      it = packet_holders->erase(it);
    } else {
      ++it;
    }
  }
  return kCommonChecksumMajority;
}

int MaidsafeStoreManager::SendPacketContent(const kad::Contact &, bool,
      boost::shared_ptr<boost::condition_variable>, StorePacketRequest *) {
  return kSuccess;
}

void MaidsafeStoreManager::SendPacketToKad(
    const StoreData &store_data,
    int *return_value,
    GenericConditionData *generic_cond_data) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::SendPacket\n");
#endif
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  kad::SignedValue signed_value;
  signed_value.set_value(store_data.value_);
  signed_value.set_value_signature(co.AsymSign(store_data.value_, "",
      store_data.private_key_, crypto::STRING_STRING));
  std::string signed_request = co.AsymSign(co.Hash(store_data.public_key_ +
      store_data.public_key_signature_ + store_data.non_hex_key_, "",
      crypto::STRING_STRING, true), "", store_data.private_key_,
      crypto::STRING_STRING);
  CallbackObj kad_cb_obj;
  kad::SignedRequest sr;
  sr.set_signer_id(store_data.key_id_);
  sr.set_public_key(store_data.public_key_);
  sr.set_signed_public_key(store_data.public_key_signature_);
  sr.set_signed_request(signed_request);
  knode_->StoreValue(store_data.non_hex_key_, signed_value, sr, 3600*24*365,
                     boost::bind(&CallbackObj::CallbackFunc, &kad_cb_obj, _1));
  kad_cb_obj.WaitForCallback();
  if (kad_cb_obj.result() == "") {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::SendPacket, fail - timeout.\n");
#endif
    boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
    *return_value = kSendPacketError;
//      generic_cond_data->cond_flag = true;
    generic_cond_data->cond_variable->notify_all();
    return;
  }
  kad::StoreResponse store_response;
  if (!store_response.ParseFromString(kad_cb_obj.result())) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::SendPacket, can't parse result.\n");
#endif
    boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
    *return_value = kSendPacketParseError;
//      generic_cond_data->cond_flag = true;
    generic_cond_data->cond_variable->notify_all();
    return;
  }
  if (store_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MaidsafeStoreManager::SendPacket, Kademlia operation failed.\n");
#endif
    boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
    *return_value = kSendPacketFailure;
//      generic_cond_data->cond_flag = true;
    generic_cond_data->cond_variable->notify_all();
    return;
  }
  boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
  *return_value = kSuccess;
//    generic_cond_data->cond_flag = true;
  generic_cond_data->cond_variable->notify_all();
}

int MaidsafeStoreManager::UpdateChunkCopies(
    const StoreData &store_data,
    const std::vector<std::string> &chunk_holders_ids) {
  std::string msid = store_data.msid_;
  boost::shared_ptr<boost::condition_variable>
      has_conditional(new boost::condition_variable);
  boost::condition_variable update_conditional;
  boost::shared_ptr<GenericConditionData>
      cond_data(new GenericConditionData(has_conditional));
  std::vector< boost::shared_ptr<ChunkHolder> > chunk_holders;
  int available_chunk_holder_index;
  bool stop_sending(false);
  int check_chunk_rpc_count(0);
  FindAvailableChunkHolders(store_data.non_hex_key_, chunk_holders_ids,
                            cond_data, &chunk_holders,
                            &available_chunk_holder_index, &stop_sending,
                            &check_chunk_rpc_count);
  bool uncontacted_chunk_holders(true);
  boost::mutex::scoped_lock lock(cond_data->cond_mutex);
  // Iterate through all holders until the data has been updated.
  std::vector<UpdateChunkResponse> update_chunk_responses;
  while (uncontacted_chunk_holders) {
    uncontacted_chunk_holders = false;
    has_conditional->wait(lock);
    for (size_t i = 0; i < chunk_holders.size(); ++i) {
      if (chunk_holders.at(i)->status == kHasChunk) {
        chunk_holders.at(i)->status = kUpdatingChunk;
        update_chunk_responses.push_back(UpdateChunkResponse());
        UpdateChunk(chunk_holders.at(i), store_data,
                    &update_chunk_responses.back(), &update_conditional);
        uncontacted_chunk_holders = true;
        break;
      }
    }
  }
  // Wait for all responses.
  for (size_t j = 0; j < update_chunk_responses.size(); ++j) {
    update_conditional.wait(lock);
// TODO(Fraser#5#): 2009-08-22 - If a listed chunk holder doesn't reply, we
//                               should send an update chunk message to his
//                               buffer packet.  Also need to decide how to
//                               handle mixed results ie some fails but not all.
  }
  return update_chunk_responses.empty() ? kUpdateChunksFailure : kSuccess;
}

void MaidsafeStoreManager::UpdateChunk(
    const boost::shared_ptr<ChunkHolder> chunk_holder,
    const StoreData &store_data,
    UpdateChunkResponse *update_chunk_resonse,
    boost::condition_variable *update_conditional) {
  UpdateChunkRequest update_chunk_request;
  std::string request_signature("");
  GetRequestSignature(store_data, chunk_holder->chunk_holder_contact.node_id(),
                      &request_signature);
  if (request_signature == "")
    return;
  ValueType data_type = DATA;
  if (store_data.dir_type_ == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  update_chunk_request.set_chunkname(store_data.non_hex_key_);
  update_chunk_request.set_data(store_data.value_);
  update_chunk_request.set_public_key(store_data.public_key_);
  update_chunk_request.set_public_key_signature(
      store_data.public_key_signature_);
  update_chunk_request.set_request_signature(request_signature);
  update_chunk_request.set_data_type(data_type);
  boost::shared_ptr<rpcprotocol::Controller>
      controller(new rpcprotocol::Controller);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::UpdateChunkCallback, update_conditional,
      controller);
  client_rpcs_->UpdateChunk(chunk_holder->chunk_holder_contact,
      chunk_holder->local, &update_chunk_request, update_chunk_resonse,
      controller.get(), callback);
}

void MaidsafeStoreManager::UpdateChunkCallback(
    boost::condition_variable *cond,
    boost::shared_ptr<rpcprotocol::Controller>) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::UpdateChunkCallback.\n");
#endif
  cond->notify_one();
}

int MaidsafeStoreManager::LoadPacketFromVaults(
    const std::string &packet_name,
    const std::vector<std::string> &packet_holder_ids,
    std::vector<std::string> *result) {
  result->clear();
  std::vector< boost::shared_ptr<ChunkHolder> > packet_holders;
  boost::shared_ptr<boost::condition_variable>
      find_cond_var(new boost::condition_variable);
  boost::shared_ptr<GenericConditionData>
      find_cond_data(new GenericConditionData(find_cond_var));
  boost::shared_ptr<boost::condition_variable>
      load_cond_var(new boost::condition_variable);
  GenericConditionData load_cond_data(load_cond_var);
  // Find packet holders' contact details
  FindCloseNodes(packet_holder_ids, &packet_holders, find_cond_data);
//  printf("FindCloseNodes result: %u - %u\n", packet_holder_ids.size(),
//         packet_holders.size());
  // For each, if we have their contact details, retrieve the packet
  std::vector<GetPacketResponse> get_packet_responses;
  for (size_t i = 0; i < packet_holder_ids.size(); ++i) {
    GetPacketResponse get_packet_response;
    get_packet_responses.push_back(get_packet_response);
  }
  int success_index(-1);
  size_t returned_rpc_count(0);
  for (size_t i = 0; i < packet_holder_ids.size(); ++i) {
    boost::mutex::scoped_lock lock(find_cond_data->cond_mutex);
    while (i >= packet_holders.size()) {
      find_cond_data->cond_variable->wait(lock);
    }
    packet_holders.at(i)->index = i;
    if (packet_holders.at(i)->status != kFailedHolder && success_index < 0) {
//      printf("status != kFailedHolder\n");
      kad::Contact new_peer = packet_holders.at(i)->chunk_holder_contact;
      packet_holders.at(i)->local = AddressIsLocal(new_peer);
      GetPacketRequest get_packet_request;
      get_packet_request.set_packetname(packet_name);
      packet_holders.at(i)->mutex = &load_cond_data.cond_mutex;
      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      packet_holders.at(i)->controller = controller;
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::GetPacketCallback, &load_cond_data,
          &returned_rpc_count);
      client_rpcs_->GetPacket(packet_holders.at(i)->chunk_holder_contact,
          packet_holders.at(i)->local, &get_packet_request,
          &get_packet_responses.at(i), controller.get(), callback);
      for (size_t n = 0; n < i; ++n) {
        boost::mutex::scoped_lock loch(load_cond_data.cond_mutex);
        if (get_packet_responses.at(n).result() == kAck &&
            packet_holders.at(n)->chunk_holder_contact.node_id() ==
            get_packet_responses.at(n).pmid()) {
          success_index = n;
          break;
        }
      }
    }
  }
  for (size_t i = 0; ((i < get_packet_responses.size()) && (success_index < 0));
       ++i) {
//    printf("Checking the RPC results: %u\n", i);
    boost::mutex::scoped_lock loch(load_cond_data.cond_mutex);
    if (returned_rpc_count < get_packet_responses.size()) {
      load_cond_data.cond_variable->wait(loch);
    }
    if (get_packet_responses.at(i).result() == kAck &&
        packet_holders.at(i)->chunk_holder_contact.node_id() ==
        get_packet_responses.at(i).pmid()) {
      success_index = i;
      break;
    }
  }
#ifdef DEBUG
  if (mock_rpcs_) {
    printf("Would have returned by now; sleeping until mock RPCs call back.\n");
    boost::this_thread::sleep(boost::posix_time::seconds(15));
  } else {
//    printf("Deleting the potential RPCs. %u\n", get_packet_responses.size());
    for (size_t i = 0; i < packet_holders.size(); ++i) {
      if (packet_holders.at(i)->controller)
        channel_manager_.CancelPendingRequest(packet_holders.at(i)->
                                              controller->req_id());
    }
  }
#else
  for (size_t i = 0; i < packet_holders.size(); ++i) {
    if (packet_holders.at(i)->controller)
      channel_manager_.
          CancelPendingRequest(packet_holders.at(i)->controller->req_id());
  }
#endif
  result->clear();
  if (success_index < 0)
    return kLoadPacketFailure;
  for (int i = 0; i < get_packet_responses.at(success_index).content_size();
      ++i) {
    result->push_back(
        get_packet_responses.at(success_index).content(i).data());
  }
  return kSuccess;
}

void MaidsafeStoreManager::GetPacketCallback(GenericConditionData *cond_data,
                                             size_t *returned_rpc_count) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::GetPacketCallback.\n");
#endif
  boost::mutex::scoped_lock lock(cond_data->cond_mutex);
  ++(*returned_rpc_count);
  cond_data->cond_variable->notify_all();
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
      &channel_manager_, &transport_, ss_->VaultIP(), ss_->VaultPort(), "", 0,
      "", 0);
  client_rpcs_->PollVaultInfo(enc_ser_vc, &vault_status_response, controller,
      channel, done);
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

void MaidsafeStoreManager::OwnLocalVault(
    const std::string &priv_key,
    const std::string &pub_key,
    const std::string &signed_pub_key,
    const boost::uint32_t &port,
    const std::string &chunkstore_dir,
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

}  // namespace maidsafe
