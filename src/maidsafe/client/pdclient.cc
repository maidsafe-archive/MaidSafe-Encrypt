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
  knode_->FindValue(chunk_name, false,
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
//      knode_->UpdatePDRTContactToRemote(delete_args->chunk_holder_.node_id());
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
      "", 0, "", 0);
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
      "", 0, "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback< PDClient,
      IsVaultOwnedCallbackArgs >(this, &PDClient::IsVaultOwnedCallback,
      cb_args);
  client_rpcs_->IsVaultOwned(cb_args.response, cb_args.ctrl, &channel, done);
}

void PDClient::IsVaultOwnedCallback(IsVaultOwnedCallbackArgs callback_args) {
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
