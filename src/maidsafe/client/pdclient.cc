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
  rpcprotocol::Channel channel(channel_manager_, transport_, "127.0.0.1",
      kLocalPort, "", 0, "", 0);
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
  rpcprotocol::Channel channel(channel_manager_, transport_, "127.0.0.1",
      kLocalPort, "", 0, "", 0);
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
