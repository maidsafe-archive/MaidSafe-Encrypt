/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose, Fraser
 */

#include "maidsafe/client/pdclient.h"

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/maidsafe-dht.h>

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe {

inline void dummy_callback(const std::string&) {}

void PDClient::CheckChunk(boost::shared_ptr<GetArgs> get_args) {
  const boost::shared_ptr<CheckChunkResponse>
      check_chunk_response(new CheckChunkResponse());
  google::protobuf::Closure* callback =
      google::protobuf::NewCallback(this,
                                    &PDClient::CheckChunkCallback,
                                    check_chunk_response,
                                    get_args);
#ifdef DEBUG
  printf("\tIn PDClient::CheckChunk, before CheckContactLocalAddress.\n");
#endif
  kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                       get_args->chunk_holder_.local_ip(),
                                       get_args->chunk_holder_.local_port(),
                                       get_args->chunk_holder_.host_ip());
#ifdef DEBUG
  printf("\tIn PDClient::CheckChunk, after CheckContactLocalAddress.\n");
#endif
  std::string ip = get_args->chunk_holder_.host_ip();
  uint16_t port = static_cast<uint16_t>(
                     get_args->chunk_holder_.host_port());
  if (conn_type == kad::LOCAL) {
    ip = get_args->chunk_holder_.local_ip();
    port = get_args->chunk_holder_.local_port();
    get_args->retry_remote = true;
  }
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//  client_rpcs_->CheckChunk(get_args->data_->chunk_name,
//                           ip,
//                           port,
//                           get_args->chunk_holder_.rendezvous_ip(),
//                           get_args->chunk_holder_.rendezvous_port(),
//                           check_chunk_response.get(),
//                           controller,
//                           callback);
}

void PDClient::CheckChunkCallback(
    const boost::shared_ptr<CheckChunkResponse> check_chunk_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked ||
      !knode_->is_joined()) {
#ifdef DEBUG
    if (get_args->data_->is_callbacked)
      printf("Data has already been called back.\n");
    if (!knode_->is_joined())
      printf("Not joined to network.\n");
#endif
    // callback can only be called once
    return;
  }
  if (check_chunk_response->IsInitialized() &&
      check_chunk_response->has_pmid_id() &&
      check_chunk_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
#ifdef DEBUG
      printf("\tIn PDClient::CheckChunkCallback, before UpdatePDRTContac...\n");
#endif
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
#ifdef DEBUG
      printf("\tIn PDClient::CheckChunkCallback, after UpdatePDRTContact...\n");
#endif
      boost::shared_ptr<CheckChunkResponse>
          check_chunk_response(new CheckChunkResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                        &PDClient::CheckChunkCallback,
                                        check_chunk_response,
                                        get_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//      client_rpcs_->CheckChunk(get_args->data_->chunk_name,
//                               get_args->chunk_holder_.host_ip(),
//                               get_args->chunk_holder_.host_port(),
//                               get_args->chunk_holder_.rendezvous_ip(),
//                               get_args->chunk_holder_.rendezvous_port(),
//                               check_chunk_response.get(),
//                               controller,
//                               callback);
      return;
    }
  }
  if (!check_chunk_response->IsInitialized() ||
      check_chunk_response->result() == kNack) {
#ifdef DEBUG
    printf("Doesn't have the chunk.\n");
#endif
    ++get_args->data_->failed_holders;
    if (get_args->data_->failed_holders >=
        get_args->data_->number_holders) {
      // the chunk references did not respond to the check
      GetResponse local_result;
      std::string local_result_str("");
      local_result.set_result(kNack);
      local_result.SerializeToString(&local_result_str);
#ifdef DEBUG
      printf("check chunkcallback --- callback\n");
#endif
      get_args->data_->cb(local_result_str);
      get_args->data_->is_callbacked = true;
    }
  } else {
    // only send one contact the get chunk request
    if (!get_args->data_->is_active) {
      get_args->data_->is_active = true;
#ifdef DEBUG
      printf("\tIn PDClient::CheckChunkCallback, before CheckContactLoca...\n");
#endif
      kad::connect_to_node conn_type =
        knode_->CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                         get_args->chunk_holder_.local_ip(),
                                         get_args->chunk_holder_.local_port(),
                                         get_args->chunk_holder_.host_ip());
#ifdef DEBUG
      printf("\tIn PDClient::CheckChunkCallback, after CheckContactLocal...\n");
#endif
      std::string ip = get_args->chunk_holder_.host_ip();
      uint16_t port = static_cast<uint16_t>(
                         get_args->chunk_holder_.host_port());
      if (conn_type == kad::LOCAL) {
        ip = get_args->chunk_holder_.local_ip();
        port = get_args->chunk_holder_.local_port();
        get_args->retry_remote = true;
      }
      // if we're trying to get messages (a buffer packet)
      if (get_args->data_->get_msgs) {
        const boost::shared_ptr<GetMessagesResponse>
            get_messages_response(new GetMessagesResponse());
        google::protobuf::Closure* callback =
            google::protobuf::NewCallback(this,
                                          &PDClient::GetMessagesCallback,
                                          get_messages_response,
                                          get_args);
        rpcprotocol::Controller *controller = new rpcprotocol::Controller;
        client_rpcs_->GetMessages(get_args->data_->chunk_name,
                                  get_args->data_->pub_key,
                                  get_args->data_->sig_pub_key,
                                  ip,
                                  port,
                                  get_args->chunk_holder_.rendezvous_ip(),
                                  get_args->chunk_holder_.rendezvous_port(),
                                  get_messages_response.get(),
                                  controller,
                                  callback);
      } else {
       const boost::shared_ptr<GetResponse> get_response(new GetResponse());
       google::protobuf::Closure* callback =
            google::protobuf::NewCallback(this,
                                          &PDClient::GetChunkCallback,
                                          get_response,
                                          get_args);
        rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//        client_rpcs_->Get(get_args->data_->chunk_name,
//                          ip,
//                          port,
//                          get_args->chunk_holder_.rendezvous_ip(),
//                          get_args->chunk_holder_.rendezvous_port(),
//                          get_response.get(),
//                          controller,
//                          callback);
      }
    }
  }
}

void PDClient::GetMessages(const std::string &chunk_name,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb) {
//  boost::recursive_mutex::scoped_lock guard(*recursive_mutex_);
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  data->get_msgs = true;
  data->pub_key = public_key;
  data->sig_pub_key = signed_public_key;
  FindChunkRef(data);
}

void PDClient::GetChunk(const std::string &chunk_name,
                        base::callback_func_type cb) {
  // preparing the shared pointer with data for the LoadChunk operation
  // boost::recursive_mutex::scoped_lock guard(*recursive_mutex_);
#ifdef DEBUG
  std::string hex;
  base::encode_to_hex(chunk_name, &hex);
  hex = hex.substr(0, 10) + "...";
  printf("In PDClient::GetChunk (%i), chunk_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  FindChunkRef(data);
}

void PDClient::GetMessagesCallback(
    const boost::shared_ptr<GetMessagesResponse> get_messages_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked)
    return;
  if (get_messages_response->IsInitialized() &&
      get_messages_response->has_pmid_id() &&
      get_messages_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
#ifdef DEBUG
      printf("\tIn PDClient::GetMessagesCallback, before UpdatePDRTConta...\n");
#endif
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
#ifdef DEBUG
      printf("\tIn PDClient::GetMessagesCallback, after UpdatePDRTContac...\n");
#endif
      boost::shared_ptr<GetMessagesResponse>
          get_messages_response(new GetMessagesResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                        &PDClient::GetMessagesCallback,
                                        get_messages_response,
                                        get_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
      client_rpcs_->GetMessages(get_args->data_->chunk_name,
                                get_args->data_->pub_key,
                                get_args->data_->sig_pub_key,
                                get_args->chunk_holder_.host_ip(),
                                get_args->chunk_holder_.host_port(),
                                get_args->chunk_holder_.rendezvous_ip(),
                                get_args->chunk_holder_.rendezvous_port(),
                                get_messages_response.get(),
                                controller,
                                callback);
      return;
    }
  }
  if (!get_messages_response->IsInitialized() ||
      get_messages_response->result() == kNack) {
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    get_args->data_->is_callbacked = true;
    std::string result;
    get_messages_response->SerializeToString(&result);
    get_args->data_->cb(result);
  }
}

void PDClient::GetChunkCallback(
    const boost::shared_ptr<GetResponse> get_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (get_args->data_->is_callbacked)
    return;
  if (get_response->IsInitialized() &&
      get_response->has_pmid_id() &&
      get_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote) {
      get_args->retry_remote = false;
#ifdef DEBUG
      printf("\tIn PDClient::GetChunkCallback, before UpdatePDRTContactT...\n");
#endif
      knode_->UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
#ifdef DEBUG
      printf("\tIn PDClient::GetChunkCallback, after UpdatePDRTContactTo...\n");
#endif
      boost::shared_ptr<GetResponse> get_response(new GetResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                        &PDClient::GetChunkCallback,
                                        get_response,
                                        get_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//      client_rpcs_->Get(get_args->data_->chunk_name,
//                        get_args->chunk_holder_.host_ip(),
//                        get_args->chunk_holder_.host_port(),
//                        get_args->chunk_holder_.rendezvous_ip(),
//                        get_args->chunk_holder_.rendezvous_port(),
//                        get_response.get(),
//                        controller,
//                        callback);
      return;
    }
  }
  if (!get_response->IsInitialized() ||
      get_response->result() == kNack ||
      !get_response->has_content()) {
#ifdef DEBUG
    if (!get_response->IsInitialized())
      printf("Response in GetChunkCallback isn't initialised.\n");
    else if (get_response->result() == kNack)
      printf("GetChunkCallback response came back failed.\n");
    else
      printf("Response has no chunk content.\n");
#endif
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    get_args->data_->is_callbacked = true;
    std::string result;
    get_response->SerializeToString(&result);
    get_args->data_->cb(result);
  }
}

void PDClient::RetryGetChunk(boost::shared_ptr<LoadChunkData> data) {
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
    GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
#ifdef DEBUG
    printf("In PDClient::RetryGetChunk, returning kNack.\n");
#endif
    data->cb(local_result_str);
  }
}

void PDClient::FindChunkRef(boost::shared_ptr<LoadChunkData> data) {
#ifdef DEBUG
  printf("\tIn PDClient::FindChunkRef, before FindValue.\n");
#endif
  knode_->FindValue(
      data->chunk_name,
      boost::bind(&PDClient::FindChunkRefCallback, this, _1, data));
#ifdef DEBUG
  printf("\tIn PDClient::FindChunkRef, after FindValue.\n");
#endif
}

void PDClient::FindChunkRefCallback(const std::string &result,
                                    boost::shared_ptr<LoadChunkData> data) {
  if (data->is_callbacked || !knode_->is_joined()) {
#ifdef DEBUG
    if (data->is_callbacked)
      printf("Data is callbacked\n");
    else if (!knode_->is_joined())
      printf("Knode not joined\n");
    // callback can only be called once
#endif
    return;
  }
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
#ifdef DEBUG
    if (!result_msg.ParseFromString(result)) {
      printf("not initialized\n");
    } else if (result_msg.result() == kad::kRpcResultFailure) {
      printf("result = kNack\n");
    } else {
      printf("result_msg.values_size() == 0\n");
    }
    printf("chunk references not found\n");
#endif
    GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
    return;
  }
  data->number_holders = result_msg.values_size();
  bool correct_info(false);
#ifdef DEBUG
  printf("No. de values %d.\n", result_msg.values_size());
#endif
  for (int i = 0; i < result_msg.values_size(); ++i) {
    kad::SignedValue signed_value;
    if (signed_value.ParseFromString(result_msg.values(i))) {
      std::string contact_info = signed_value.value();
      kad::Contact remote;
      if (remote.ParseFromString(contact_info)) {
        data->chunk_holders.push_back(remote);
        correct_info = true;
        boost::shared_ptr<GetArgs> get_args_(new GetArgs(remote, data));
        CheckChunk(get_args_);
      } else {
        --data->number_holders;
      }
    } else {
      --data->number_holders;
    }
  }
  if (!correct_info) {
#ifdef DEBUG
    printf("Could not get contact info from the values retrieved.\n");
#endif
    GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}

void PDClient::GetRandomContacts(
    const int &count,
    const std::vector<kad::Contact> &exclude_contacts,
    std::vector<kad::Contact> *contacts) {
#ifdef DEBUG
  printf("\tIn PDClient::GetRandomContacts, before GetRandomContacts.\n");
#endif
  knode_->GetRandomContacts(count, exclude_contacts, contacts);
#ifdef DEBUG
  printf("\tIn PDClient::GetRandomContacts, after GetRandomContacts.\n");
#endif
}

void PDClient::UpdateChunk(const std::string &chunk_name,
                           const std::string &content,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const std::string &signed_request,
                           const maidsafe::ValueType &data_type,
                           base::callback_func_type cb) {
//  boost::recursive_mutex::scoped_lock guard(*recursive_mutex_);
#ifdef DEBUG
  std::string hex;
  base::encode_to_hex(chunk_name, &hex);
  hex = hex.substr(0, 10) + "...";
  printf("In PDClient::UpdateChunk (%i), chunk_name = %s\n",
         knode_->host_port(), hex.c_str());
#endif
  // Look up the chunk references
  knode_->FindValue(chunk_name,
                    boost::bind(&PDClient::IterativeCheckAlive,
                                this,
                                _1,
                                chunk_name,
                                content,
                                public_key,
                                signed_public_key,
                                signed_request,
                                data_type,
                                cb));
#ifdef DEBUG
  printf("\tIn PDClient::UpdateChunk, after FindValue.\n");
#endif
}

void PDClient::IterativeCheckAlive(const std::string &result,
                                   std::string chunk_name,
                                   std::string content,
                                   std::string public_key,
                                   std::string signed_public_key,
                                   std::string signed_request,
                                   maidsafe::ValueType data_type,
                                   base::callback_func_type cb) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      result_msg.values_size() == 0) {
#ifdef DEBUG
    printf("No chunk reference found.\n");
#endif
    // no chunk references were found
    UpdateResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  // Get the alive chunk holders by using simple ping operation
  boost::shared_ptr<UpdateChunkData>
      data(new UpdateChunkData(chunk_name,
                               content,
                               cb,
                               public_key,
                               signed_public_key,
                               signed_request,
                               data_type));
  bool correct_info(false);
  for (int i = 0; i < result_msg.values_size(); ++i) {
    kad::SignedValue signed_value;
    if (signed_value.ParseFromString(result_msg.values(i))) {
      std::string contact_info = signed_value.value();
      kad::Contact remote;
      if (remote.ParseFromString(contact_info)) {
        data->chunk_holders.push_back(remote);
        correct_info = true;
#ifdef DEBUG
        printf("\tIn PDClient::IterativeCheckAlive, before Ping.\n");
#endif
        knode_->Ping(remote, boost::bind(&PDClient::IterativeCheckAliveCallback,
                                        this,
                                        _1,
                                        1,
                                        remote,
                                        data));
#ifdef DEBUG
        printf("\tIn PDClient::IterativeCheckAlive, after Ping.\n");
#endif
      }
    }
  }
  if (!correct_info) {
#ifdef DEBUG
    printf("No valid chunk reference found.\n");
#endif
    UpdateResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}

void PDClient::IterativeCheckAliveCallback(
    const std::string &result,
    int retry,
    kad::Contact remote,
    boost::shared_ptr<UpdateChunkData> data) {
  if (data->is_callbacked) {
    return;
  }
  kad::PingResponse result_msg;
  if ((!result_msg.ParseFromString(result)) ||
      (result_msg.result() == kad::kRpcResultFailure)) {
    // we assume the node to be dead if it fails to respond to kMaxPingRetries
    // consecutive pings
    if (retry > kMaxPingRetries) {
      // dead node
      ++data->contacted_holders;
      IterativeUpdateChunk(data);
    } else {  // ping again
#ifdef DEBUG
      printf("\tIn PDClient::IterativeCheckAliveCallback, before Ping.\n");
#endif
      knode_->Ping(remote, boost::bind(&PDClient::IterativeCheckAliveCallback,
                                      this,
                                      _1,
                                      ++retry,
                                      remote,
                                      data));
#ifdef DEBUG
      printf("\tIn PDClient::IterativeCheckAliveCallback, after Ping.\n");
#endif
    }
  } else {  // alive contacts
    data->alive_holders.push_back(remote);
    IterativeUpdateChunk(data);
  }
}

void PDClient::IterativeUpdateChunk(boost::shared_ptr<UpdateChunkData> data) {
  if (data->contacted_holders ==
      static_cast<int>(data->chunk_holders.size())) {
    // It's time to finish chunk updating
    UpdateResponse local_result;
    std::string local_result_str("");
    if (data->updated_copies >= kMinChunkCopies ||
        data->updated_copies == static_cast<int>(data->alive_holders.size()))
      local_result.set_result(kAck);
    else
      local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
    return;
  }
  // let's go for the next chunk updating
  if (data->active_updating < kad::kAlpha
      && data->index < static_cast<int>(data->alive_holders.size())) {
    kad::Contact remote = data->alive_holders[data->index];
    ++data->index;
    ++data->active_updating;
    boost::shared_ptr<UpdateArgs>
        update_args(new UpdateArgs(remote, 0, data));
    const boost::shared_ptr<UpdateResponse>
        update_response(new UpdateResponse());
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(this,
                                      &PDClient::IterativeUpdateChunkCallback,
                                      update_response,
                                      update_args);
#ifdef DEBUG
    printf("\tIn PDClient::IterativeUpdateChunk, before CheckContactLoca...\n");
#endif
    kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(update_args->chunk_holder_.node_id(),
                                       update_args->chunk_holder_.local_ip(),
                                       update_args->chunk_holder_.local_port(),
                                       update_args->chunk_holder_.host_ip());
#ifdef DEBUG
    printf("\tIn PDClient::IterativeUpdateChunk, after CheckContactLocal...\n");
#endif
    std::string ip = update_args->chunk_holder_.host_ip();
    uint16_t port = static_cast<uint16_t>(
                        update_args->chunk_holder_.host_port());
    if (conn_type == kad::LOCAL) {
      ip = update_args->chunk_holder_.local_ip();
      port = update_args->chunk_holder_.local_port();
      update_args->retry_remote = true;
    }
    rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//    client_rpcs_->Update(update_args->data_->chunk_name,
//                         update_args->data_->content,
//                         update_args->data_->pub_key,
//                         update_args->data_->sig_pub_key,
//                         update_args->data_->sig_req,
//                         update_args->data_->data_type,
//                         ip,
//                         port,
//                         update_args->chunk_holder_.rendezvous_ip(),
//                         update_args->chunk_holder_.rendezvous_port(),
//                         update_response.get(),
//                         controller,
//                         callback);
  }
}

void PDClient::IterativeUpdateChunkCallback(
    const boost::shared_ptr<UpdateResponse> update_response,
    boost::shared_ptr<UpdateArgs> update_args) {
  if (update_args->data_->is_callbacked || !knode_->is_joined()) {
    return;
  }
  if (update_response->IsInitialized() &&
      update_response->has_pmid_id() &&
      update_response->pmid_id() != update_args->chunk_holder_.node_id()) {
    if (update_args->retry_remote) {
      update_args->retry_remote = false;
#ifdef DEBUG
      printf("\tIn PDClient::IterativeUpdateChunkCallback, before Update...\n");
#endif
      knode_->UpdatePDRTContactToRemote(update_args->chunk_holder_.node_id());
#ifdef DEBUG
      printf("\tIn PDClient::IterativeUpdateChunkCallback, after UpdateP...\n");
#endif
      boost::shared_ptr<UpdateResponse> update_response(new UpdateResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                        &PDClient::IterativeUpdateChunkCallback,
                                        update_response,
                                        update_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//      client_rpcs_->Update(update_args->data_->chunk_name,
//                           update_args->data_->content,
//                           update_args->data_->pub_key,
//                           update_args->data_->sig_pub_key,
//                           update_args->data_->sig_req,
//                           update_args->data_->data_type,
//                           update_args->chunk_holder_.host_ip(),
//                           update_args->chunk_holder_.host_port(),
//                           update_args->chunk_holder_.rendezvous_ip(),
//                           update_args->chunk_holder_.rendezvous_port(),
//                           update_response.get(),
//                           controller,
//                           callback);
      return;
    }
  }
  if (!update_response->IsInitialized() ||
      update_response->result() == kNack) {
    if (update_args->retry_ > kMaxChunkStoreTries) {
#ifdef DEBUG
      printf("Failed to update chunk.\n");
#endif
      --update_args->data_->active_updating;
      ++update_args->data_->contacted_holders;
      IterativeUpdateChunk(update_args->data_);
    } else {
#ifdef DEBUG
      printf("Re-trying to update chunk.\n");
#endif
      ++update_args->retry_;
      const boost::shared_ptr<UpdateResponse>
          update_response(new UpdateResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                        &PDClient::IterativeUpdateChunkCallback,
                                        update_response,
                                        update_args);
#ifdef DEBUG
      printf("\tIn PDClient::IterativeUpdateChunkCallback, before CheckC...\n");
#endif
      kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(update_args->chunk_holder_.node_id(),
                                       update_args->chunk_holder_.local_ip(),
                                       update_args->chunk_holder_.local_port(),
                                       update_args->chunk_holder_.host_ip());
#ifdef DEBUG
      printf("\tIn PDClient::IterativeUpdateChunkCallback, after CheckCo...\n");
#endif
      std::string ip = update_args->chunk_holder_.host_ip();
      uint16_t port = static_cast<uint16_t>(
                          update_args->chunk_holder_.host_port());
      if (conn_type == kad::LOCAL) {
        ip = update_args->chunk_holder_.local_ip();
        port = update_args->chunk_holder_.local_port();
        update_args->retry_remote = true;
      }
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
//      client_rpcs_->Update(update_args->data_->chunk_name,
//                           update_args->data_->content,
//                           update_args->data_->pub_key,
//                           update_args->data_->sig_pub_key,
//                           update_args->data_->sig_req,
//                           update_args->data_->data_type,
//                           ip,
//                           port,
//                           update_args->chunk_holder_.rendezvous_ip(),
//                           update_args->chunk_holder_.rendezvous_port(),
//                           update_response.get(),
//                           controller,
//                           callback);
    }
  } else {
#ifdef DEBUG
    printf("Updated chunk successfully.\n");
#endif
    --update_args->data_->active_updating;
    ++update_args->data_->contacted_holders;
    ++update_args->data_->updated_copies;
    IterativeUpdateChunk(update_args->data_);
  }
}

void PDClient::DeleteChunk(const std::string &chunk_name,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const std::string &signed_request,
                           const maidsafe::ValueType &data_type,
                           base::callback_func_type cb) {
  // verify the chunk size
  // Look up the chunk references
#ifdef DEBUG
  printf("\tIn PDClient::DeleteChunk, before FindValue.\n");
#endif
  knode_->FindValue(chunk_name,
                    boost::bind(&PDClient::DeleteChunk_IterativeCheckAlive,
                                this,
                                _1,
                                chunk_name,
                                public_key,
                                signed_public_key,
                                signed_request,
                                data_type,
                                cb));
#ifdef DEBUG
  printf("\tIn PDClient::DeleteChunk, after FindValue.\n");
#endif
}

void PDClient::DeleteChunk_IterativeCheckAlive(const std::string &result,
                                               std::string non_hex_chunk_name,
                                               std::string public_key,
                                               std::string signed_public_key,
                                               std::string signed_request,
                                               maidsafe::ValueType data_type,
                                               base::callback_func_type cb) {
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
    DeleteResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  // Get the alive chunk holders by using simple ping operation
  boost::shared_ptr<DeleteChunkData>
      data(new DeleteChunkData(non_hex_chunk_name,
                               cb,
                               public_key,
                               signed_public_key,
                               signed_request,
                               data_type));
  bool correct_info = false;
  for (int i = 0; i < result_msg.values_size(); ++i) {
    kad::SignedValue signed_value;
    if (signed_value.ParseFromString(result_msg.values(i))) {
      std::string contact_info = signed_value.value();
      kad::Contact remote;
      if (remote.ParseFromString(contact_info)) {
        data->chunk_holders.push_back(remote);
        correct_info = true;
#ifdef DEBUG
        printf("\tIn PDClient::DeleteChunk_IterativeCheckAlive, before Ping\n");
#endif
        knode_->Ping(remote,
                     boost::bind(&PDClient::DeleteChunk_CheckAliveCallback,
                                 this,
                                 _1,
                                 1,
                                 remote,
                                 data));
#ifdef DEBUG
        printf("\tIn PDClient::DeleteChunk_IterativeCheckAlive, after Ping.\n");
#endif
      }
    }
  }
  if (!correct_info) {
    DeleteResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}

void PDClient::DeleteChunk_CheckAliveCallback(
    const std::string &result,
    int retry,
    kad::Contact remote,
    boost::shared_ptr<DeleteChunkData> data) {
  if (data->is_callbacked) {
    return;
  }
  kad::PingResponse result_msg;
  if ((!result_msg.ParseFromString(result)) ||
      (result_msg.result() == kad::kRpcResultFailure)) {
    // we assume the node to be dead if it fails to respond to kMaxPingRetries
    // consecutive pings
    if (retry > kMaxPingRetries) {
      // dead node
      ++data->contacted_holders;
      DeleteChunk_IterativeDeleteChunk(data);
    } else {  // ping again
#ifdef DEBUG
      printf("\tIn PDClient::DeleteChunk_CheckAliveCallback, before Ping.\n");
#endif
      knode_->Ping(remote,
                   boost::bind(&PDClient::DeleteChunk_CheckAliveCallback,
                               this,
                               _1,
                               ++retry,
                               remote,
                               data));
#ifdef DEBUG
      printf("\tIn PDClient::DeleteChunk_CheckAliveCallback, after Ping.\n");
#endif
    }
  } else {  // alive contacts
    data->alive_holders.push_back(remote);
    DeleteChunk_IterativeDeleteChunk(data);
  }
}

void PDClient::DeleteChunk_IterativeDeleteChunk(
    boost::shared_ptr<DeleteChunkData> data) {
  if (data->contacted_holders ==
      static_cast<int>(data->chunk_holders.size())) {
    DeleteResponse local_result;
    std::string local_result_str("");
    if (data->deleted_copies >= kMinChunkCopies ||
        data->deleted_copies == static_cast<int>(data->alive_holders.size()))
      local_result.set_result(kAck);
    else
      local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
    return;
  }
  // let's go for the next chunk deletion
  if (data->active_deleting < kad::kAlpha
      && data->index < static_cast<int>(data->alive_holders.size())) {
    kad::Contact remote = data->alive_holders[data->index];
    ++data->index;
    ++data->active_deleting;
    boost::shared_ptr<DeleteArgs>
        delete_args(new DeleteArgs(remote, data));
    const boost::shared_ptr<DeleteResponse>
        delete_response(new DeleteResponse());
    google::protobuf::Closure* callback =
        google::protobuf::NewCallback(
            this,
            &PDClient::DeleteChunk_DeleteChunkCallback,
            delete_response,
            delete_args);
#ifdef DEBUG
    printf("\tIn PDClient::DeleteChunk_IterativeDeleteChunk, before Chec...\n");
#endif
    kad::connect_to_node conn_type =
      knode_->CheckContactLocalAddress(delete_args->chunk_holder_.node_id(),
                                       delete_args->chunk_holder_.local_ip(),
                                       delete_args->chunk_holder_.local_port(),
                                       delete_args->chunk_holder_.host_ip());
#ifdef DEBUG
    printf("\tIn PDClient::DeleteChunk_IterativeDeleteChunk, after Chec....\n");
#endif
    std::string ip = delete_args->chunk_holder_.host_ip();
    uint16_t port = static_cast<uint16_t>(
                        delete_args->chunk_holder_.host_port());
    if (conn_type == kad::LOCAL) {
      ip = delete_args->chunk_holder_.local_ip();
      port = delete_args->chunk_holder_.local_port();
      delete_args->retry_remote = true;
    }
    rpcprotocol::Controller *controller = new rpcprotocol::Controller;
    client_rpcs_->Delete(delete_args->data_->chunk_name,
                         delete_args->data_->pub_key,
                         delete_args->data_->sig_pub_key,
                         delete_args->data_->sig_req,
                         delete_args->data_->data_type,
                         ip,
                         port,
                         delete_args->chunk_holder_.rendezvous_ip(),
                         delete_args->chunk_holder_.rendezvous_port(),
                         delete_response.get(),
                         controller,
                         callback);
  }
}

void PDClient::DeleteChunk_DeleteChunkCallback(
      const boost::shared_ptr<DeleteResponse> delete_response,
      boost::shared_ptr<DeleteArgs> delete_args) {
  if (delete_args->data_->is_callbacked) {
    return;
  }
  if (delete_response->IsInitialized() &&
      delete_response->has_pmid_id() &&
      delete_response->pmid_id() != delete_args->chunk_holder_.node_id()) {
    if (delete_args->retry_remote) {
      delete_args->retry_remote = false;
#ifdef DEBUG
      printf("\tIn PDClient::DeleteChunk_DeleteChunkCallback, before Up....\n");
#endif
      knode_->UpdatePDRTContactToRemote(delete_args->chunk_holder_.node_id());
#ifdef DEBUG
      printf("\tIn PDClient::DeleteChunk_DeleteChunkCallback, after Upd....\n");
#endif
      boost::shared_ptr<DeleteResponse> delete_response(new DeleteResponse());
      google::protobuf::Closure* callback =
          google::protobuf::NewCallback(this,
                                    &PDClient::DeleteChunk_DeleteChunkCallback,
                                    delete_response,
                                    delete_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
      client_rpcs_->Delete(delete_args->data_->chunk_name,
                           delete_args->data_->pub_key,
                           delete_args->data_->sig_pub_key,
                           delete_args->data_->sig_req,
                           delete_args->data_->data_type,
                           delete_args->chunk_holder_.host_ip(),
                           delete_args->chunk_holder_.host_port(),
                           delete_args->chunk_holder_.rendezvous_ip(),
                           delete_args->chunk_holder_.rendezvous_port(),
                           delete_response.get(),
                           controller,
                           callback);
      return;
    }
  }
  if (!delete_response->IsInitialized() ||
      delete_response->result() == kNack) {
    // failed to delete ...
    // we don't retry with same arguments to delete
    --delete_args->data_->active_deleting;
    ++delete_args->data_->contacted_holders;
    DeleteChunk_IterativeDeleteChunk(delete_args->data_);
  } else {  // update chunk successfully
    --delete_args->data_->active_deleting;
    ++delete_args->data_->contacted_holders;
    ++delete_args->data_->deleted_copies;
    DeleteChunk_IterativeDeleteChunk(delete_args->data_);
  }
}

void PDClient::FindValue(const std::string &key,
                         base::callback_func_type cb) {
#ifdef DEBUG
  printf("\tIn PDClient::FindValue, before FindValue.\n");
#endif
  knode_->FindValue(key, cb);
#ifdef DEBUG
  printf("\tIn PDClient::FindValue, after FindValue.\n");
#endif
}

void PDClient::OwnLocalVault(const std::string &priv_key,
      const std::string &pub_key, const std::string &signed_pub_key,
      const boost::uint32_t &port, const std::string &chunkstore_dir,
      const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb) {
  OwnVaultCallbackArgs cb_args;
  cb_args.cb = cb;
  cb_args.ctrl = new rpcprotocol::Controller;
  // 20 seconds, since the rpc is replied after the vault has
  // started successfully
  cb_args.ctrl->set_timeout(20);
  cb_args.response = new OwnVaultResponse;
  rpcprotocol::Channel channel(channel_manager_.get(), "127.0.0.1", kLocalPort,
      "", 0);
  google::protobuf::Closure* done = google::protobuf::NewCallback<PDClient,
      OwnVaultCallbackArgs>(this, &PDClient::OwnVaultCallback,
      cb_args);
  client_rpcs_->OwnVault(priv_key, pub_key, signed_pub_key, port,
      chunkstore_dir, space, cb_args.response,
      cb_args.ctrl, &channel, done);
}

void PDClient::OwnVaultCallback(OwnVaultCallbackArgs callback_args) {
  if (callback_args.ctrl->Failed() ||
      !callback_args.response->IsInitialized()) {
    delete callback_args.response;
    if (callback_args.ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args.cb(VAULT_IS_DOWN, "");
    else
      callback_args.cb(INVALID_OWNREQUEST, "");
    delete callback_args.ctrl;
    return;
  }
  std::string pmid_name;
  if (callback_args.response->has_pmid_name())
    pmid_name = callback_args.response->pmid_name();
  OwnVaultResult result = callback_args.response->result();
  delete callback_args.response;
  delete callback_args.ctrl;
  callback_args.cb(result, pmid_name);
}

void PDClient::IsLocalVaultOwned(boost::function<void(const VaultStatus&)>
    cb) {
  IsVaultOwnedCallbackArgs cb_args;
  cb_args.ctrl = new rpcprotocol::Controller;
  cb_args.response = new IsOwnedResponse;
  cb_args.cb = cb;
  rpcprotocol::Channel channel(channel_manager_.get(), "127.0.0.1", kLocalPort,
      "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback< PDClient,
      IsVaultOwnedCallbackArgs >(this, &PDClient::IsVaultOwnedCallback,
      cb_args);
  client_rpcs_->IsVaultOwned(cb_args.response, cb_args.ctrl, &channel, done);
}

void PDClient::IsVaultOwnedCallback(IsVaultOwnedCallbackArgs  callback_args) {
  if (callback_args.ctrl->Failed() ||
      !callback_args.response->IsInitialized()) {
    delete callback_args.response;
    if (callback_args.ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args.cb(DOWN);
    else
      callback_args.cb(ISOWNRPC_CANCELLED);
    delete callback_args.ctrl;
    return;
  }
  VaultStatus result = callback_args.response->status();
  delete callback_args.response;
  callback_args.cb(result);
}
}  // namespace maidsafe
