/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */

#ifndef MAIDSAFE_CLIENT_PDCLIENT_H_
#define MAIDSAFE_CLIENT_PDCLIENT_H_

#include <boost/filesystem.hpp>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <map>
#include <string>
#include <vector>

#include "maidsafe/client/clientrpc.h"

namespace fs = boost::filesystem;

namespace maidsafe {

struct LoadChunkData {
  LoadChunkData(const std::string &chunkname, base::callback_func_type cb)
    : chunk_holders(), failed_chunk_holders(), number_holders(0),
      failed_holders(0), is_active(false), chunk_name(chunkname), retry(0),
      cb(cb), is_callbacked(false), get_msgs(false), pub_key(""),
      sig_pub_key("") {}
  std::vector<kad::Contact> chunk_holders;
  std::vector<kad::Contact> failed_chunk_holders;
  int number_holders;
  int failed_holders;
  bool is_active;
  std::string chunk_name;
  int retry;
  base::callback_func_type cb;
  bool is_callbacked;
  // used only for get msgs
  bool get_msgs;
  std::string pub_key;
  std::string sig_pub_key;
};

struct StoreChunkData {
  StoreChunkData(const std::string &chunkname, const std::string &content,
    base::callback_func_type cb, const std::string &pub_key, const
    std::string &sig_pub_key, const std::string &sig_req,
    const maidsafe::ValueType &type)
    : chunk_holders(), failed_contacts(), active_contacts(),
    chunk_name(chunkname), content(content), index(0), stored_copies(0),
    parallelstores(0), active_contacts_done(0), retry(0), cb(cb),
    is_callbacked(false), pub_key(pub_key), sig_pub_key(sig_pub_key),
    sig_req(sig_req), data_type(type) {}
  std::vector<kad::Contact> chunk_holders;
  // contacts where the chunk has been stored
  std::vector<kad::Contact> failed_contacts;
  // contacts where it failed to store a chunk
  std::vector<kad::Contact> active_contacts;
  // selected contacts to try to store to
  std::string chunk_name;
  std::string content;
  int index;
  int stored_copies;
  int parallelstores;
  int active_contacts_done;
  int retry;
  base::callback_func_type cb;
  bool is_callbacked;
  std::string pub_key;
  std::string sig_pub_key;
  std::string sig_req;
  maidsafe::ValueType data_type;
};

struct UpdateChunkData {
  UpdateChunkData(const std::string &chunkname, const std::string &content,
    base::callback_func_type cb, const std::string &pub_key,
    const std::string &sig_pub_key, const std::string &sig_req,
    const maidsafe::ValueType &type) : chunk_holders(), alive_holders(),
    chunk_name(chunkname), content(content), updated_copies(0),
    active_updating(0), contacted_holders(0), index(0), cb(cb),
    is_callbacked(false), pub_key(pub_key), sig_pub_key(sig_pub_key),
    sig_req(sig_req), data_type(type) {}
  std::vector<kad::Contact> chunk_holders;
  std::vector<kad::Contact> alive_holders;
  std::string chunk_name;
  std::string content;
  int updated_copies;
  int active_updating;
  int contacted_holders;
  int index;
  base::callback_func_type cb;
  bool is_callbacked;
  std::string pub_key;
  std::string sig_pub_key;
  std::string sig_req;
  maidsafe::ValueType data_type;
};

struct DeleteChunkData {
  DeleteChunkData(const std::string &chunkname,
    base::callback_func_type cb, const std::string &pub_key,
    const std::string &sig_pub_key, const std::string &sig_req,
    const maidsafe::ValueType &type) : chunk_holders(), alive_holders(),
    chunk_name(chunkname), deleted_copies(0), active_deleting(0),
    contacted_holders(0), index(0), cb(cb), is_callbacked(false),
    pub_key(pub_key), sig_pub_key(sig_pub_key), sig_req(sig_req),
    data_type(type) {}
  std::vector<kad::Contact> chunk_holders;
  std::vector<kad::Contact> alive_holders;
  std::string chunk_name;
  int deleted_copies;
  int active_deleting;
  int contacted_holders;
  int index;
  base::callback_func_type cb;
  bool is_callbacked;
  std::string pub_key;
  std::string sig_pub_key;
  std::string sig_req;
  maidsafe::ValueType data_type;
};

struct GetArgs {
  GetArgs(const kad::Contact &chunk_holder,
          boost::shared_ptr<LoadChunkData> data)
      : chunk_holder_(chunk_holder), data_(data), retry_remote(false) {}
  const kad::Contact chunk_holder_;
  boost::shared_ptr<LoadChunkData> data_;
  bool retry_remote;
};

struct SendArgs {
  SendArgs(const kad::Contact &chunk_holder,
           int retry,
           boost::shared_ptr<StoreChunkData> data)
      : chunk_holder_(chunk_holder), retry_(retry), data_(data),
        retry_remote(false) {}
  const kad::Contact chunk_holder_;
  int retry_;
  boost::shared_ptr<StoreChunkData> data_;
  bool retry_remote;
};

struct UpdateArgs {
  UpdateArgs(const kad::Contact &chunk_holder,
             int retry,
             boost::shared_ptr<UpdateChunkData> data)
      : chunk_holder_(chunk_holder), retry_(retry), data_(data),
        retry_remote(false) {}
  const kad::Contact chunk_holder_;
  int retry_;
  boost::shared_ptr<UpdateChunkData> data_;
  bool retry_remote;
};

struct DeleteArgs {
  DeleteArgs(const kad::Contact &chunk_holder,
           boost::shared_ptr<DeleteChunkData> data)
      : chunk_holder_(chunk_holder), data_(data), retry_remote(false) {}
  const kad::Contact chunk_holder_;
  boost::shared_ptr<DeleteChunkData> data_;
  bool retry_remote;
};

struct OwnVaultCallbackArgs {
  OwnVaultCallbackArgs() : cb(), response(NULL), ctrl(NULL) {}
  boost::function<void(const OwnVaultResult&, const std::string&)> cb;
  maidsafe::OwnVaultResponse* response;
  rpcprotocol::Controller *ctrl;
};

struct IsVaultOwnedCallbackArgs {
  IsVaultOwnedCallbackArgs() : cb(), response(NULL), ctrl(NULL), priv_key(""),
      pub_key(""), signed_pub_key(""), chunkstore_dir(""), port(0), space(0) {}
  IsVaultOwnedCallbackArgs(const std::string &privkey, const std::string
      &pubkey, const std::string &sigpubkey, const std::string &dir, const
      boost::uint32_t &startport, const boost::uint64_t &av_space)
      : cb(), response(NULL), ctrl(NULL), priv_key(privkey), pub_key(pubkey),
        signed_pub_key(sigpubkey), chunkstore_dir(dir), port(startport),
        space(av_space) {}
  boost::function<void(const OwnVaultResult&, const std::string&)> cb;
  maidsafe::IsOwnedResponse* response;
  rpcprotocol::Controller *ctrl;
  std::string priv_key, pub_key, signed_pub_key, chunkstore_dir;
  boost::uint32_t port;
  boost::uint64_t space;
};

class PDClient {
 public:
  PDClient(boost::shared_ptr<rpcprotocol::ChannelManager> ch_mangr,
           boost::shared_ptr<kad::KNode> knode,
           ClientRpcs *client_rpcs) : channel_manager_(ch_mangr),
                                      knode_(knode),
                                      client_rpcs_(client_rpcs) {}

  ~PDClient() {}
  void GetMessages(const std::string &chunk_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   base::callback_func_type cb);
  void GetChunk(const std::string &chunk_name, base::callback_func_type cb);
  void StoreChunk(const std::string &chunk_name,
                  const std::string &content,
                  const std::string &public_key,
                  const std::string &signed_public_key,
                  const std::string &signed_request,
                  const maidsafe::ValueType &data_type,
                  base::callback_func_type cb);
  // Update the existing chunk with the new content
  void UpdateChunk(const std::string &chunk_name,
                   const std::string &content,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &signed_request,
                   const maidsafe::ValueType &data_type,
                   base::callback_func_type cb);
  // Delete signed chunks (system packets, buffer packets, signed DB)
  void DeleteChunk(const std::string &chunk_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &signed_request,
                   const maidsafe::ValueType &data_type,
                   base::callback_func_type cb);
  void FindValue(const std::string &key, base::callback_func_type cb);
  void OwnLocalVault(const std::string &priv_key, const std::string
      &pub_key, const std::string &signed_pub_key, const boost::uint32_t &port,
      const std::string &chunkstore_dir, const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb);

 private:
  // TODO(Jose) include ranking and client daemon

  // Checks to see if contact holds a copy of chunk
  void CheckChunk(boost::shared_ptr<GetArgs> get_args);
  void CheckChunkCallback(
      const boost::shared_ptr<CheckChunkResponse> check_chunk_response,
      boost::shared_ptr<GetArgs> get_args);
  void GetMessagesCallback(
      const boost::shared_ptr<GetMessagesResponse> get_messages_response,
      boost::shared_ptr<GetArgs> get_args);
  void GetChunkCallback(const boost::shared_ptr<GetResponse> get_response,
                        boost::shared_ptr<GetArgs> get_args);
  void RetryGetChunk(boost::shared_ptr<LoadChunkData> data);
  void FindChunkRef(boost::shared_ptr<LoadChunkData> data);
  void FindChunkRefCallback(const std::string &result,
                            boost::shared_ptr<LoadChunkData> data);
  void IterativeStoreChunk(boost::shared_ptr<StoreChunkData> data);
  int StoreChunkPrep(const std::string &chunkname,
                     const boost::uint64_t &data_size,
                     const std::string &public_key,
                     const std::string &signed_public_key,
                     const std::string &signed_request,
                     const std::string &remote_ip,
                     const uint16_t &remote_port,
                     const std::string &rendezvous_ip,
                     const uint16_t &rendezvous_port,
                     const std::string &remote_id);
  void StoreChunkPrepCallback(bool *store_prep_response_returned);
  void ExecuteStoreChunk(const kad::Contact &remote,
                         int retry,
                         boost::shared_ptr<StoreChunkData> data);
  void StoreChunkCallback(const boost::shared_ptr<StoreResponse> store_response,
                          boost::shared_ptr<SendArgs> send_args);
  void GetRandomContacts(const int &count,
                         const std::vector<kad::Contact> &exclude_contacts,
                         std::vector<kad::Contact> *contacts);
  void IterativeCheckAlive(const std::string &result,
                           std::string non_hex_chunk_name,
                           std::string content,
                           std::string public_key,
                           std::string signed_public_key,
                           std::string signed_request,
                           maidsafe::ValueType data_type,
                           base::callback_func_type cb);
  void IterativeCheckAliveCallback(const std::string &result,
                                   int retry,
                                   kad::Contact remote,
                                   boost::shared_ptr<UpdateChunkData> data);
  void IterativeUpdateChunk(boost::shared_ptr<UpdateChunkData> data);
  void IterativeUpdateChunkCallback(
      const boost::shared_ptr<UpdateResponse> update_response,
      boost::shared_ptr<UpdateArgs> update_args);
  void DeleteChunk_IterativeCheckAlive(const std::string &result,
                                       std::string non_hex_chunk_name,
                                       std::string public_key,
                                       std::string signed_public_key,
                                       std::string signed_request,
                                       maidsafe::ValueType data_type,
                                       base::callback_func_type cb);
  void DeleteChunk_CheckAliveCallback(const std::string &result,
                                      int retry,
                                      kad::Contact remote,
                                      boost::shared_ptr<DeleteChunkData> data);
  void DeleteChunk_IterativeDeleteChunk(
      boost::shared_ptr<DeleteChunkData> data);
  void DeleteChunk_DeleteChunkCallback(
      const boost::shared_ptr<DeleteResponse> delete_response,
      boost::shared_ptr<DeleteArgs> delete_args);
  void OwnVaultCallback(OwnVaultCallbackArgs  callback_args);
  void IsVaultOwnedCallback(IsVaultOwnedCallbackArgs  callback_args,
      rpcprotocol::Channel *channel);
  PDClient(const PDClient&);
  PDClient& operator=(const PDClient&);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  ClientRpcs *client_rpcs_;
};
}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_PDCLIENT_H_
