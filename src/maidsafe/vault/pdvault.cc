/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class containing vault logic
* Version:      1.0
* Created:      2009-02-21-23.55.54
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

#include "maidsafe/vault/pdvault.h"

#include <boost/thread/thread.hpp>
#include <boost/thread/xtime.hpp>
#include <google/protobuf/descriptor.h>

#include "maidsafe/maidsafe-dht.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/kademlia_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

void pdv_dummy_callback(const std::string&) {}

PDVault::PDVault(const std::string &pmid_public,
                 const std::string &pmid_private,
                 const std::string &signed_pmid_public,
                 const std::string &chunkstore_dir,
                 const std::string &datastore_dir,
                 const boost::uint16_t &port,
                 const std::string &kad_config_file)
    : port_(port),
      mutex0_(),
      mutex1_(),
      channel_manager_(),
      knode_(new kad::KNode(datastore_dir,
                            channel_manager_,
                            kad::VAULT)),
      vault_rpcs_(channel_manager_),
      chunkstore_(new ChunkStore(chunkstore_dir)),
      vault_service_(),
      kad_joined_(false),
      kad_joined_calledback_(false),
      kad_left_calledback_(false),
      vault_started_(false),
      pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      signed_pmid_public_(signed_pmid_public),
      pmid_(""),
      co(),
      svc_channel_(),
      kad_config_file_(kad_config_file) {
  co.set_symm_algorithm("AES_256");
  co.set_hash_algorithm("SHA512");
  pmid_ = co.Hash(signed_pmid_public_, "", crypto::STRING_STRING, true);
}

PDVault::~PDVault() {
  printf("In PDVault destructor, before Stop().\n");
  int result = Stop();
  printf("In PDVault destructor, Stop() returned %i.\n", result);
#ifdef DEBUG
  if (vault_started_)
    printf("Vault didn't stop correctly.");
#endif
}


void PDVault::Start(const bool &port_forwarded) {
  if (vault_started_)
    return;
  channel_manager_->StartTransport(port_,
      boost::bind(&kad::KNode::HandleDeadRendezvousServer,
                  knode_.get(),
                  _1,
                  _2,
                  _3));
  kad_joined_calledback_ = false;
  RegisterMaidService();
  knode_->Join(pmid_,
               kad_config_file_,
               boost::bind(&PDVault::KadJoinedCallback, this, _1),
               port_forwarded);
  // Hash check all current chunks in chunkstore
  std::list<std::string> failed_keys;
  if (0 != chunkstore_->HashCheckAllChunks(true, &failed_keys)) {
    return;
  }
//  const int kTimeout_(300);
//  int count_(0);
  bool finished_bootstrap = false;
  while (!finished_bootstrap) {
    {
      boost::mutex::scoped_lock guard(mutex0_);
      if (kad_joined_calledback_) {  // || count_ >= kTimeout_) {
        finished_bootstrap = true;
      }
    }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    // ++count_;
  }
  vault_started_ = kad_joined_;
}

void PDVault::KadJoinedCallback(const std::string &result) {
  base::GeneralResponse result_;
  if (!result_.ParseFromString(result)) {
    kad_joined_ = false;
  } else if (result_.result() != kRpcResultSuccess) {
    UnRegisterMaidService();
    kad_joined_ = false;
  } else {
    kad_joined_ = true;
  }
  kad_joined_calledback_ = true;
}

int PDVault::Stop() {
  if (!vault_started_) {
    printf("In PDVault::Stop(), already stopped.\n");
    return -1;
  }
  UnRegisterMaidService();
  knode_->Leave();
  kad_joined_ = knode_->is_joined();
  vault_started_ = kad_joined_;
  channel_manager_->StopTransport();
  return 0;
}

void PDVault::SyncVault(base::callback_func_type cb) {
  // Process of updating vault:
  // 1. Get the list of all chunk names
  // 2. Do validity check for each chunk with an arbitrary alive partner.
  // 3. If chunk content is stale, synchronize chunk content with the partner.
  // otherwise, do the next vadility check.
  boost::shared_ptr<SyncVaultData> data(new struct SyncVaultData());
  chunkstore_->GetAllChunks(&data->chunk_names);
  if (!data->chunk_names.empty()) {
    printf("Synchronizing vault (One * represents one chunk):\n");
    data->num_chunks = data->chunk_names.size();
    data->cb = cb;
    int parallel_size;
    if (static_cast<int>(data->chunk_names.size()) > kad::kAlpha)
      parallel_size = kad::kAlpha;
    else
      parallel_size = static_cast<int>(data->chunk_names.size());
    for (int i = 0; i < parallel_size; ++i) {
      IterativeSyncVault(data);
    }
  } else {  // no chunks on this vault node
    maidsafe::UpdateResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kRpcResultSuccess);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
}

void PDVault::IterativeSyncVault(boost::shared_ptr<SyncVaultData> data) {
  if (data->is_callbacked) return;
  if (data->chunk_names.empty() && data->active_updating == 0) {
    // no more chunks need to be updated, job done!
    printf("\nVault synchronized!\n");
    maidsafe::UpdateResponse local_result;
    std::string local_result_str("");
    if (static_cast<float>(data->num_updated_chunks) >=
        kMinSuccessfulPecentageOfUpdating*(data->num_chunks))
      local_result.set_result(kRpcResultSuccess);
    else
      local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  } else if (!data->chunk_names.empty()) {
    printf("*");
    std::string chunk_name = data->chunk_names.front();
    data->chunk_names.pop_front();
    ++data->active_updating;
    // Look up the chunk references
    knode_->FindValue(chunk_name,
                     boost::bind(&PDVault::SyncVault_FindAlivePartner,
                                 this,
                                 _1,
                                 data,
                                 chunk_name));
  }
}

void PDVault::SyncVault_FindAlivePartner(
    const std::string& result,
    boost::shared_ptr<SyncVaultData> data,
    std::string chunk_name) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
//    TRI_LOG_STR("No chunk reference found.");
    // TODO(Haiyang): shall we remove the chunk?!
    --data->active_updating;
    IterativeSyncVault(data);
    return;
  }
  // Get an arbitrary alive chunk holder by using simple ping operation
  boost::shared_ptr<GetAlivePartner>
      partner_data(new GetAlivePartner(
          static_cast<int>(result_msg.values_size()), chunk_name));
  partner_data->data = data;
  bool correct_info = false;
  for (int i = 0; i < result_msg.values_size(); ++i) {
    std::string contact_info = result_msg.values(i);
    kad::Contact remote;
    if (remote.ParseFromString(contact_info) &&
        remote.node_id() != knode_->node_id()) {
      correct_info = true;
      knode_->Ping(remote,
                  boost::bind(&PDVault::SyncVault_FindAlivePartner_Callback,
                              this,
                              _1,
                              partner_data,
                              remote));
    } else {
      --partner_data->number_partners;
    }
  }
  // chunk reference infomation corrupt? impossible? hacker did that? Oh, no
  if (!correct_info) {
//    TRI_LOG_STR("No valid chunk references found for chunk: ");
    // TODO(Haiyang): shall we remove the chunk?!
    --data->active_updating;
    IterativeSyncVault(data);
  }
}

void PDVault::SyncVault_FindAlivePartner_Callback(
    const std::string& result,
    boost::shared_ptr<GetAlivePartner> partner_data,
    kad::Contact remote) {
  if (partner_data->is_found) return;
  ++partner_data->contacted_partners;
  kad::PingResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kRpcResultFailure ||
      !result_msg.has_echo() ||
      result_msg.echo() != "pong") {
    if (partner_data->contacted_partners == partner_data->number_partners &&
        !partner_data->is_found) {
//      TRI_LOG_STR("No alive partners found.");
      // TODO(Haiyang): shall we remove the chunk?!
      --partner_data->data->active_updating;
      IterativeSyncVault(partner_data->data);
    }
  } else {
    // we found an alive partner, validate chunk with it
    partner_data->is_found = true;
    ValidityCheck(partner_data->chunk_name,
                  "",
                  remote,
                  0,
                  boost::bind(&PDVault::IterativeSyncVault_SyncChunk,
                              this,
                              _1,
                              partner_data->data,
                              partner_data->chunk_name,
                              remote));
  }
}

void PDVault::ValidityCheck(const std::string &chunk_name,
                            const std::string &random_data,
                            const kad::Contact &remote,
                            int attempt,
                            base::callback_func_type cb) {
  if (attempt > kValidityCheckRetry) {
    base::GeneralResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  std::string random_data_("");
  // TODO(Fraser#5#): 2009-03-18 - make limits for data maidsafe constants
  if (random_data == "" ||
      random_data.size() < 512 ||
      random_data.size() > 1023)
    // generate random string of random length between 512 & 1023 bits inclusive
    random_data_ =
        base::RandomString((base::random_32bit_uinteger() % 512) + 512);
  else
    random_data_ = random_data;
  boost::shared_ptr<ValidityCheckArgs> validity_check_args_(
      new ValidityCheckArgs(chunk_name, random_data_, remote, cb));
  boost::shared_ptr<maidsafe::ValidityCheckResponse>
      validity_check_response_(new maidsafe::ValidityCheckResponse());
  google::protobuf::Closure* callback =
      google::protobuf::NewCallback(this,
                                    &PDVault::ValidityCheckCallback,
                                    validity_check_response_,
                                    validity_check_args_);
  kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(validity_check_args_->
                                           chunk_holder_.node_id(),
                                       validity_check_args_->
                                           chunk_holder_.local_ip(),
                                       validity_check_args_->
                                           chunk_holder_.local_port(),
                                       validity_check_args_->
                                           chunk_holder_.host_ip());
  bool local = false;
  std::string ip = validity_check_args_->chunk_holder_.host_ip();
  uint16_t port = static_cast<uint16_t>(
                      validity_check_args_->chunk_holder_.host_port());
  if (conn_type == kad::LOCAL) {
    ip = validity_check_args_->chunk_holder_.local_ip();
    port = validity_check_args_->chunk_holder_.local_port();
    local = true;
    validity_check_args_->retry_remote = true;
  }
  vault_rpcs_.ValidityCheck(validity_check_args_->chunk_name_,
                            validity_check_args_->random_data_,
                            ip,
                            port,
                            validity_check_response_.get(),
                            callback,
                            local);
}

void PDVault::ValidityCheckCallback(
    boost::shared_ptr<maidsafe::ValidityCheckResponse> validity_check_response,
    boost::shared_ptr<ValidityCheckArgs> validity_check_args) {
  // TODO(Fraser#5#): 2009-03-18 -handle timeout: call ValdtyChck with ++attempt

  if (!validity_check_response->IsInitialized())
    return;
  if (!validity_check_response->has_pmid_id() &&
      validity_check_response->pmid_id() !=
          validity_check_args->chunk_holder_.node_id()) {
    if (validity_check_args->retry_remote) {
      validity_check_args->retry_remote = false;
      boost::shared_ptr<maidsafe::ValidityCheckResponse>
          resp(new maidsafe::ValidityCheckResponse());
      google::protobuf::Closure* done = google::protobuf::NewCallback(this,
                                          &PDVault::ValidityCheckCallback,
                                          resp,
                                          validity_check_args);
      vault_rpcs_.ValidityCheck(validity_check_args->chunk_name_,
                                validity_check_args->random_data_,
                                validity_check_args->chunk_holder_.host_ip(),
                                validity_check_args->chunk_holder_.host_port(),
                                resp.get(),
                                done,
                                false);
      return;
    }
  }
  if (validity_check_response->result() == kRpcResultFailure ||
      !validity_check_response->has_hash_content()) {
    // TODO(Fraser#5#): 2009-03-18 - We should probably self-check our chunk
    //                  (hash contents == name) then if OK try validity check
    //                  with another chunk holder.
    return;
  }
  std::string remote_hash_content_(validity_check_response->hash_content());
  std::string local_content_("");
  chunkstore_->LoadChunk(validity_check_args->chunk_name_, &local_content_);
  std::string local_hash_content_(co.Hash(local_content_ +
      validity_check_args->random_data_, "", crypto::STRING_STRING, true));
  if (local_hash_content_ != remote_hash_content_) {
    // TODO(Fraser#5#): 2009-03-18 - if check fails do we retry once, or try
    //                  with another chunk holder (if available) and/or alert
    //                  the current holder that he has a dirty chunk?
  }
}

void PDVault::IterativeSyncVault_SyncChunk(
    const std::string& result,
    boost::shared_ptr<SyncVaultData> data,
    std::string chunk_name,
    kad::Contact remote) {
  maidsafe::ValidityCheckResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kRpcResultFailure) {
    // chunk content is stale, synchronize the chunk
    boost::shared_ptr<SynchArgs>
        synch_args_(new SynchArgs(chunk_name, remote, data));
    boost::shared_ptr<maidsafe::GetResponse>
        get_chunk_response_(new maidsafe::GetResponse());
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(this,
                                      &PDVault::IterativeSyncVault_UpdateChunk,
                                      get_chunk_response_,
                                      synch_args_);
    kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(synch_args_->chunk_holder_.node_id(),
                                       synch_args_->chunk_holder_.local_ip(),
                                       synch_args_->chunk_holder_.local_port(),
                                       synch_args_->chunk_holder_.host_ip());
    bool local = false;
    std::string ip = synch_args_->chunk_holder_.host_ip();
    uint16_t port =
        static_cast<uint16_t>(synch_args_->chunk_holder_.host_port());
    if (conn_type == kad::LOCAL) {
      ip = synch_args_->chunk_holder_.local_ip();
      port = synch_args_->chunk_holder_.local_port();
      local = true;
    }
    vault_rpcs_.Get(synch_args_->chunk_name_,
                    ip,
                    port,
                    get_chunk_response_.get(),
                    callback,
                    local);
  } else {
    // chunk is consistent with the partner, move on to the next updating
    --data->active_updating;
    ++data->num_updated_chunks;
    IterativeSyncVault(data);
  }
}

void PDVault::IterativeSyncVault_UpdateChunk(
    boost::shared_ptr<maidsafe::GetResponse> get_chunk_response_,
    boost::shared_ptr<SynchArgs> synch_args_) {
  maidsafe::GetResponse result_msg;
  if (!get_chunk_response_->IsInitialized() ||
      get_chunk_response_->result() == kRpcResultFailure) {
//    TRI_LOG_STR("Failed to synchronize the chunk.");
    // TODO(Haiyang): chunk deleted? shall we remove the chunk?!
  } else {
    chunkstore_->UpdateChunk(synch_args_->chunk_name_,
                            get_chunk_response_->content());
  }
  --synch_args_->data_->active_updating;
  ++synch_args_->data_->num_updated_chunks;
  IterativeSyncVault(synch_args_->data_);
}

void PDVault::RepublishChunkRef(base::callback_func_type cb) {
  boost::shared_ptr<RepublishChunkRefData>
    data(new struct RepublishChunkRefData());
  chunkstore_->GetAllChunks(&data->chunk_names);
  if (!data->chunk_names.empty()) {
    printf("Republishing chunk references (One * represents one chunk):\n");
    data->num_chunks = data->chunk_names.size();
    data->cb = cb;
    IterativePublishChunkRef(data);
  } else {  // no chunks on this vault node
    base::GeneralResponse local_result;
    std::string local_result_str;
    local_result.set_result(kRpcResultSuccess);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
}

void PDVault::IterativePublishChunkRef(
    boost::shared_ptr<RepublishChunkRefData> data) {
  if (data->is_callbacked) return;
  if (data->chunk_names.empty()) {
    // no more chunks need to be republished, job done!
    base::GeneralResponse local_result;
    std::string local_result_str;
    printf("\nVault republished!\n");
    if (static_cast<float>(data->num_republished_chunks) >=
        kMinSuccessfulPecentageOfUpdating*(data->num_chunks))
      local_result.set_result(kRpcResultSuccess);
    else
      local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  } else {
    printf("*");
    std::string chunk_name = data->chunk_names.front();
    data->chunk_names.pop_front();
    std::string signed_request_ = co.AsymSign(
        co.Hash(pmid_public_ + signed_pmid_public_ + chunk_name,
                "",
                crypto::STRING_STRING,
                true),
        "",
        pmid_private_,
        crypto::STRING_STRING);
    knode_->StoreValue(chunk_name,
                       pmid_,
                       pmid_public_,
                       signed_pmid_public_,
                       signed_request_,
                       boost::bind(&PDVault::IterativePublishChunkRef_Next,
                                   this,
                                   _1,
                                   data));
  }
}

void PDVault::IterativePublishChunkRef_Next(
    const std::string& result,
    boost::shared_ptr<RepublishChunkRefData> data) {
  kad::StoreResponse result_msg;
  if (result_msg.ParseFromString(result))
    if (result_msg.result() == kRpcResultSuccess)
      ++data->num_republished_chunks;
  IterativePublishChunkRef(data);
}

void PDVault::GetChunk(const std::string &chunk_name,
                       base::callback_func_type cb) {
  // preparing the shared pointer with data for the LoadChunk operation
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  FindChunkRef(data);
}

void PDVault::FindChunkRef(boost::shared_ptr<struct LoadChunkData> data) {
  knode_->FindValue(
      data->chunk_name,
      boost::bind(&PDVault::FindChunkRefCallback, this, _1, data));
}

void PDVault::FindChunkRefCallback(
    const std::string &result,
    boost::shared_ptr<struct LoadChunkData> data) {
  if (data->is_callbacked || !knode_->is_joined()) {
    // callback can only be called once
    return;
  }
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
    return;
  }
  data->number_holders = result_msg.values_size();
  bool correct_info(false);
  for (int i = 0; i < result_msg.values_size(); ++i) {
    std::string contact_info = result_msg.values(i);
    kad::Contact remote;
    if (remote.ParseFromString(contact_info)) {
      data->chunk_holders.push_back(remote);
      correct_info = true;
      boost::shared_ptr<GetArgs> get_args_(new GetArgs(remote, data));
      CheckChunk(get_args_);
    } else {
      --data->number_holders;
    }
  }
  if (!correct_info) {
    // could not get contact info from the values retrieved
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}


void PDVault::CheckChunk(boost::shared_ptr<GetArgs> get_args) {
  boost::shared_ptr<maidsafe::CheckChunkResponse>
      check_chunk_response_(new maidsafe::CheckChunkResponse());
  google::protobuf::Closure* callback =
      google::protobuf::NewCallback(this,
                                    &PDVault::CheckChunkCallback,
                                    check_chunk_response_,
                                    get_args);
  kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                       get_args->chunk_holder_.local_ip(),
                                       get_args->chunk_holder_.local_port(),
                                       get_args->chunk_holder_.host_ip());
  bool local = false;
  std::string ip = get_args->chunk_holder_.host_ip();
  uint16_t port = static_cast<uint16_t>(get_args->chunk_holder_.host_port());
  if (conn_type == kad::LOCAL) {
    ip = get_args->chunk_holder_.local_ip();
    port = get_args->chunk_holder_.local_port();
    local = true;
    get_args->retry_remote = true;
  }
  vault_rpcs_.CheckChunk(get_args->data_->chunk_name,
                         ip,
                         port,
                         check_chunk_response_.get(),
                         callback,
                         local);
}

void PDVault::CheckChunkCallback(
    boost::shared_ptr<maidsafe::CheckChunkResponse> check_chunk_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked ||
      !knode_->is_joined()) {
    // callback can only be called once
    return;
  }
  if (check_chunk_response->IsInitialized() &&
      check_chunk_response->has_pmid_id() &&
      check_chunk_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::CheckChunkResponse>
          resp(new maidsafe::CheckChunkResponse());
      google::protobuf::Closure* done =
          google::protobuf::NewCallback(this,
                                        &PDVault::CheckChunkCallback,
                                        resp,
                                        get_args);
      vault_rpcs_.CheckChunk(get_args->data_->chunk_name,
                             get_args->chunk_holder_.host_ip(),
                             get_args->chunk_holder_.host_port(),
                             resp.get(),
                             done,
                             false);
      return;
    }
  }
  if (!check_chunk_response->IsInitialized() ||
      check_chunk_response->result() == kRpcResultFailure) {
    ++get_args->data_->failed_holders;
    if (get_args->data_->failed_holders >=
        get_args->data_->number_holders) {
      // the chunk references did not respond to the check
      maidsafe::GetResponse local_result;
      std::string local_result_str("");
      local_result.set_result(kRpcResultFailure);
      local_result.SerializeToString(&local_result_str);
      get_args->data_->cb(local_result_str);
      get_args->data_->is_callbacked = true;
    }
  } else {
    // only send one contact the get chunk request
    if (!get_args->data_->is_active) {
      get_args->data_->is_active = true;
      // if we're trying to get messages (a buffer packet)
      kad::connect_to_node conn_type =
        knode_->CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                         get_args->chunk_holder_.local_ip(),
                                         get_args->chunk_holder_.local_port(),
                                         get_args->chunk_holder_.host_ip());
      bool local = false;
      std::string ip = get_args->chunk_holder_.host_ip();
      uint16_t port = static_cast<uint16_t>(
                          get_args->chunk_holder_.host_port());
      if (conn_type == kad::LOCAL) {
        ip = get_args->chunk_holder_.local_ip();
        port = get_args->chunk_holder_.local_port();
        local = true;
      }
      if (get_args->data_->get_msgs) {
          boost::shared_ptr<maidsafe::GetMessagesResponse>
              get_messages_response_(new maidsafe::GetMessagesResponse());
        google::protobuf::Closure* callback =
            google::protobuf::NewCallback(this,
                                          &PDVault::GetMessagesCallback,
                                          get_messages_response_,
                                          get_args);
        vault_rpcs_.GetMessages(get_args->data_->chunk_name,
                                get_args->data_->pub_key,
                                get_args->data_->sig_pub_key,
                                ip,
                                port,
                                get_messages_response_.get(),
                                callback,
                                local);
      } else {
       boost::shared_ptr<maidsafe::GetResponse>
          get_response_(new maidsafe::GetResponse());
       google::protobuf::Closure* callback =
            google::protobuf::NewCallback(this,
                                          &PDVault::GetChunkCallback,
                                          get_response_,
                                          get_args);
        vault_rpcs_.Get(get_args->data_->chunk_name,
                        ip,
                        port,
                        get_response_.get(),
                        callback,
                        local);
      }
    }
  }
}

void PDVault::GetMessages(const std::string &chunk_name,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb) {
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  data->get_msgs = true;
  data->pub_key = public_key;
  data->sig_pub_key = signed_public_key;
  FindChunkRef(data);
}

void PDVault::GetMessagesCallback(
    boost::shared_ptr<maidsafe::GetMessagesResponse> get_messages_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked)
    return;
  if (get_messages_response->IsInitialized() &&
      get_messages_response->has_pmid_id() &&
      get_messages_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::GetMessagesResponse>
          resp(new maidsafe::GetMessagesResponse());
      google::protobuf::Closure* done =
          google::protobuf::NewCallback(this,
                                        &PDVault::GetMessagesCallback,
                                        resp,
                                        get_args);
      vault_rpcs_.GetMessages(get_args->data_->chunk_name,
                              get_args->data_->pub_key,
                              get_args->data_->sig_pub_key,
                              get_args->chunk_holder_.host_ip(),
                              get_args->chunk_holder_.host_port(),
                              resp.get(),
                              done,
                              false);
      return;
    }
  }
  if (!get_messages_response->IsInitialized() ||
      get_messages_response->result() == kRpcResultFailure) {
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    get_args->data_->is_callbacked = true;
    get_args->data_->cb(get_messages_response->result());
  }
}

void PDVault::GetChunkCallback(
    boost::shared_ptr<maidsafe::GetResponse> get_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked)
    return;
  if (get_response->IsInitialized() &&
      get_response->has_pmid_id() &&
      get_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::GetResponse>
          resp(new maidsafe::GetResponse());
      google::protobuf::Closure* done =
          google::protobuf::NewCallback(this,
                                        &PDVault::GetChunkCallback,
                                        resp,
                                        get_args);
      vault_rpcs_.Get(get_args->data_->chunk_name,
                      get_args->chunk_holder_.host_ip(),
                      get_args->chunk_holder_.host_port(),
                      resp.get(),
                      done,
                      false);
      return;
    }
  }
  if (!get_response->IsInitialized() ||
      get_response->result() == kRpcResultFailure) {
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    std::string result_str_("");
    get_response->SerializeToString(&result_str_);
    get_args->data_->is_callbacked = true;
// TODO(Fraser#5#): 2009-04-08 - Should save chunk to chunkstore now and this
//                  vault to chunk ref
    get_args->data_->cb(result_str_);
  }
}

void PDVault::RetryGetChunk(boost::shared_ptr<struct LoadChunkData> data) {
  if (data->is_callbacked || !knode_->is_joined()) {
    // callback can only be called once
    return;
  }
  bool send_request = false;
  if (data->retry < kMaxChunkLoadRetries) {
    ++data->retry;
    data->number_holders = data->chunk_holders.size() -
      data->failed_chunk_holders.size();
    data->failed_holders = 0;
    data->is_active = false;
    for (int i = 0; i < static_cast<int>(data->chunk_holders.size()); ++i) {
      kad::Contact remote = data->chunk_holders[i];
      bool send = true;
      for (int j = 0; j < static_cast<int>(data->failed_chunk_holders.size())
            && send; ++j)
        if (remote == data->failed_chunk_holders[j])
          send = false;
      if (send) {
        boost::shared_ptr<GetArgs> get_args_(new GetArgs(remote, data));
        CheckChunk(get_args_);
        send_request = true;
      }
    }
  }
  if (!send_request) {
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}

void PDVault::SwapChunk(const std::string &chunk_name,
    const std::string &remote_ip,
    const uint16_t &remote_port,
    base::callback_func_type cb) {
  boost::shared_ptr<SwapChunkArgs> swap_chunk_args(
      new SwapChunkArgs(chunk_name, remote_ip, remote_port, cb));
  boost::shared_ptr<maidsafe::SwapChunkResponse>
      swap_chunk_response(new maidsafe::SwapChunkResponse());
  google::protobuf::Closure* callback =
      google::protobuf::NewCallback(this,
                                    &PDVault::SwapChunkSendChunk,
                                    swap_chunk_response,
                                    swap_chunk_args);
  std::string chunkcontent1;
  if (!chunkstore_->LoadChunk(swap_chunk_args->chunkname_, &chunkcontent1)) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
  vault_rpcs_.SwapChunk(0,
                        chunk_name,
                        "",
                        chunkcontent1.size(),
                        remote_ip,
                        remote_port,
                        swap_chunk_response.get(),
                        callback,
                        false);
}

void PDVault::SwapChunkSendChunk(
    boost::shared_ptr<maidsafe::SwapChunkResponse> swap_chunk_response,
    boost::shared_ptr<SwapChunkArgs> swap_chunk_args) {
  if (!swap_chunk_response->IsInitialized()
      ||(swap_chunk_response->result() == kRpcResultFailure)) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
    return;
  }
  std::string chunkcontent1;
  if (!chunkstore_->LoadChunk(swap_chunk_args->chunkname_, &chunkcontent1)) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
  }
  google::protobuf::Closure* callback =
      google::protobuf::NewCallback(this,
                                    &PDVault::SwapChunkAcceptChunk,
                                    swap_chunk_response,
                                    swap_chunk_args);
  vault_rpcs_.SwapChunk(1,
                        swap_chunk_args->chunkname_,
                        chunkcontent1,
                        chunkcontent1.size(),
                        swap_chunk_args->remote_ip_,
                        swap_chunk_args->remote_port_,
                        swap_chunk_response.get(),
                        callback,
                        false);
}

void PDVault::SwapChunkAcceptChunk(
    boost::shared_ptr<maidsafe::SwapChunkResponse> swap_chunk_response,
    boost::shared_ptr<SwapChunkArgs> swap_chunk_args) {
  if (!swap_chunk_response->IsInitialized()
      || (swap_chunk_response->result() == kRpcResultFailure
      || (swap_chunk_response->request_type() != 1)
      || (!swap_chunk_response->has_chunkname2())
      || (!swap_chunk_response->has_chunkcontent2()))) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kRpcResultFailure);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
    return;
  }
  // Accept the swapped chunk
  std::string chunk_name_ = swap_chunk_response->chunkname2();
  chunkstore_->StoreChunk(chunk_name_,
                          swap_chunk_response->chunkcontent2());
  // Store chunk reference
  std::string signed_request = co.AsymSign(
      co.Hash(pmid_public_ + signed_pmid_public_ + chunk_name_,
              "",
              crypto::STRING_STRING,
              true),
      "",
      pmid_private_,
      crypto::STRING_STRING);
  knode_->StoreValue(swap_chunk_args->chunkname_,
                    pmid_,
                    pmid_public_,
                    signed_pmid_public_,
                    signed_request,
                    &pdv_dummy_callback);
  maidsafe::SwapChunkResponse local_result;
  std::string local_result_str("");
  local_result.set_request_type(1);
  local_result.set_result(kRpcResultSuccess);
  local_result.SerializeToString(&local_result_str);
  swap_chunk_args->cb_(local_result_str);
}

void PDVault::RegisterMaidService() {
  vault_service_ = boost::shared_ptr<VaultService>(
    new VaultService(pmid_public_,
                     pmid_private_,
                     signed_pmid_public_,
                     chunkstore_,
                     knode_));
  svc_channel_ = boost::shared_ptr<rpcprotocol::Channel>(
      new rpcprotocol::Channel(channel_manager_.get()));
  svc_channel_->SetService(vault_service_.get());
  channel_manager_->RegisterChannel(
    vault_service_->GetDescriptor()->name(), svc_channel_.get());
}

void PDVault::UnRegisterMaidService() {
  channel_manager_->UnRegisterChannel(
    vault_service_->GetDescriptor()->name());
  svc_channel_.reset();
  vault_service_.reset();
}

const std::string PDVault::node_id() {
  std::string hex_id("");
  base::encode_to_hex(knode_->node_id(), hex_id);
  return hex_id;
}
}  // namespace maidsafe_vault
