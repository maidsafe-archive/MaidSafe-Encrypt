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
  OwnVaultCallbackArgs& operator=(const maidsafe::OwnVaultCallbackArgs&) {
    return *this;
  }
  OwnVaultCallbackArgs(
      const maidsafe::OwnVaultCallbackArgs& ovca)
      : cb(ovca.cb), response(ovca.response), ctrl(ovca.ctrl) {
  }
  boost::function<void(const OwnVaultResult&, const std::string&)> cb;
  OwnVaultResponse* response;
  rpcprotocol::Controller *ctrl;
};

struct IsVaultOwnedCallbackArgs {
  IsVaultOwnedCallbackArgs() : cb(), response(NULL), ctrl(NULL) {}
  IsVaultOwnedCallbackArgs& operator=(
      const maidsafe::IsVaultOwnedCallbackArgs&) {
    return *this;
  }
  IsVaultOwnedCallbackArgs(
      const maidsafe::IsVaultOwnedCallbackArgs& ivoca)
      : cb(ivoca.cb), response(ivoca.response), ctrl(ivoca.ctrl) {
  }
  boost::function<void(const VaultStatus&)> cb;
  IsOwnedResponse* response;
  rpcprotocol::Controller *ctrl;
};

class PDClient {
 public:
  PDClient(boost::shared_ptr<rpcprotocol::ChannelManager> ch_mangr,
           boost::shared_ptr<kad::KNode> knode,
           boost::shared_ptr<ClientRpcs> client_rpcs)
               : channel_manager_(ch_mangr),
                 knode_(knode),
                 client_rpcs_(client_rpcs) {}

  ~PDClient() {}
  void DeleteChunk(const std::string &chunk_name,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const std::string &signed_request,
                   const maidsafe::ValueType &data_type,
                   base::callback_func_type cb);
  void OwnLocalVault(const std::string &priv_key, const std::string
      &pub_key, const std::string &signed_pub_key, const boost::uint32_t &port,
      const std::string &chunkstore_dir, const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb);
  void IsLocalVaultOwned(boost::function<void(const VaultStatus&)> cb);

 private:
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
  void IsVaultOwnedCallback(IsVaultOwnedCallbackArgs  callback_args);
  PDClient(const PDClient&);
  PDClient& operator=(const PDClient&);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<ClientRpcs> client_rpcs_;
};
}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_PDCLIENT_H_
