/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       Team www.maidsafe.net
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

#include <gtest/gtest.h>
#include <google/protobuf/descriptor.h>
#include <boost/shared_ptr.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/crypto.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vault/vaultdaemon.h"

inline void HandleDeadServer(const bool &, const std::string &,
  const boost::uint16_t&) {}

class NotifierHandler {
 public:
  NotifierHandler() : private_key_(""), public_key_(""), signed_public_key_(""),
      chunkstore_dir_(""), port_(-1), available_space_(0), received_rpc_(false)
      {}
  std::string private_key() const { return private_key_; }
  std::string public_key() const { return public_key_; }
  std::string signed_public_key() const { return signed_public_key_; }
  std::string chunkstore_dir() const { return chunkstore_dir_; }
  boost::int32_t port() const { return port_; }
  boost::uint64_t available_space() const { return available_space_; }
  bool received_rpc() const { return received_rpc_; }
  void OwnedNotification(const maidsafe::VaultConfig &vconfig) {
    private_key_ = vconfig.pmid_private();
    public_key_ = vconfig.pmid_public();
    signed_public_key_ = vconfig.signed_pmid_public();
    chunkstore_dir_ = vconfig.chunkstore_dir();
    port_ = vconfig.port();
    available_space_ = vconfig.available_space();
    received_rpc_ = true;
  }
  void Reset() {
    private_key_ = "";
    public_key_ = "";
    signed_public_key_ = "";
    chunkstore_dir_ = "";
    port_ = -1;
    available_space_ = 0;
    received_rpc_ = false;
  }
 private:
  std::string private_key_, public_key_, signed_public_key_, chunkstore_dir_;
  boost::int32_t  port_;
  boost::uint64_t available_space_;
  bool received_rpc_;
};

class OwnershipSenderHandler {
 public:
  OwnershipSenderHandler(): callback_arrived_(false), result_(),
      pmid_name_(""), remote_vault_status_() {}
  void Reset() {
    callback_arrived_ = false;
    pmid_name_ = "";
    result_ = maidsafe::INVALID_OWNREQUEST;
    remote_vault_status_ = maidsafe::NOT_OWNED;
  }
  void Callback(const maidsafe::OwnVaultResponse *response,
      rpcprotocol::Controller *ctrl) {
    callback_arrived_ = true;
    if ((ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kTimeOut) ||
         !response->IsInitialized()) {
      printf("Rpc timeout\n");
      result_ = maidsafe::VAULT_IS_DOWN;
      return;
    }
    result_ = response->result();
    if (response->has_pmid_name())
      pmid_name_ = response->pmid_name();
  }
  void Callback1(const maidsafe::IsOwnedResponse *response,
    rpcprotocol::Controller *ctrl) {
    callback_arrived_ = true;
    if ((ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kTimeOut) ||
         !response->IsInitialized()) {;
      return;
    }
    remote_vault_status_ = response->status();
  }
  std::string pmid_name() const { return pmid_name_; }
  maidsafe::OwnVaultResult result() const { return result_; }
  bool callback_arrived() const { return callback_arrived_; }
  maidsafe::VaultStatus remote_vault_status() const {
    return remote_vault_status_;
  }
 private:
  bool callback_arrived_;
  maidsafe::OwnVaultResult result_;
  std::string pmid_name_;
  maidsafe::VaultStatus remote_vault_status_;
};

class VaultRegistrationTest : public testing::Test {
 public:
  VaultRegistrationTest() : server(), client(),
      service_channel(new rpcprotocol::Channel(&server)), handler(),
      service() {}
  ~VaultRegistrationTest() {
      server.CleanUpTransport();
  }
 protected:
  virtual void SetUp() {
    ASSERT_EQ(0, server.StartLocalTransport(0));
    service.reset(new maidsafe_vault::RegistrationService(boost::bind(
          &NotifierHandler::OwnedNotification, &handler, _1)));
    service_channel->SetService(service.get());
    server.RegisterChannel(service->GetDescriptor()->name(),
        service_channel.get());
    ASSERT_EQ(0, client.StartTransport(0, boost::bind(&HandleDeadServer, _1, _2,
        _3)));
  }
  virtual void TearDown() {
    handler.Reset();
    server.StopTransport();
    client.StopTransport();
    server.ClearChannels();
  }
  rpcprotocol::ChannelManager server, client;
  boost::shared_ptr<rpcprotocol::Channel> service_channel;
  NotifierHandler handler;
  boost::shared_ptr<maidsafe_vault::RegistrationService> service;
};

TEST_F(VaultRegistrationTest, FUNC_MAID_CorrectOwnVault) {
  ASSERT_EQ(maidsafe::NOT_OWNED, service->status());
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string singed_pub_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + singed_pub_key, "",
    crypto::STRING_STRING, false);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, "127.0.0.1",
      server.external_port(), "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::OwnVaultRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  maidsafe::OwnVaultResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done1);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->set_status(maidsafe::OWNED);
  service->ReplyOwnVaultRequest(false);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());
  ASSERT_EQ(pmid_name, senderhandler.pmid_name());

  ASSERT_EQ(keypair.private_key(), handler.private_key());
  ASSERT_EQ(keypair.public_key(), handler.public_key());
  ASSERT_EQ(singed_pub_key, handler.signed_public_key());
  ASSERT_EQ(std::string("/ChunkStore"), handler.chunkstore_dir());
  ASSERT_EQ(server.external_port()+1, handler.port());
  ASSERT_EQ(1000, handler.available_space());

  ASSERT_EQ(maidsafe::OWNED, service->status());

  request.clear_port();
  response.Clear();
  handler.Reset();
  ctrl.Reset();
  senderhandler.Reset();
  request.set_port(0);

  service->set_status(maidsafe::NOT_OWNED);

  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done2);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->set_status(maidsafe::OWNED);
  service->ReplyOwnVaultRequest(false);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());

  ASSERT_EQ(keypair.private_key(), handler.private_key());
  ASSERT_EQ(keypair.public_key(), handler.public_key());
  ASSERT_EQ(singed_pub_key, handler.signed_public_key());
  ASSERT_EQ(std::string("/ChunkStore"), handler.chunkstore_dir());
  ASSERT_EQ(0, handler.port());
  ASSERT_EQ(1000, handler.available_space());
}

TEST_F(VaultRegistrationTest, FUNC_MAID_InvalidRequest) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_public_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, "127.0.0.1",
      server.external_port(), "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::OwnVaultRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key("invalidsignedpublickey");
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  maidsafe::OwnVaultResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key("invalidprivatekey");
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key("invalidpublickey");
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  // keys don't match
  std::string priv_key = keypair.private_key();
  std::string pub_key = keypair.public_key();
  keypair.ClearKeys();
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done4 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done4);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(priv_key);
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done5 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done5);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done6 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done6);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());

  // invalid port
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(client.external_port());
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done7 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done7);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_PORT, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());

  // space == 0
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(0);
  google::protobuf::Closure *done8 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done8);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NO_SPACE_ALLOCATED, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());
  // more space requested than available
  boost::filesystem::space_info info = boost::filesystem::space(
      boost::filesystem::path("/"));

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(info.available + 10);
  google::protobuf::Closure *done9 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done9);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_ENOUGH_SPACE, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  service->set_status(maidsafe::OWNED);
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done10 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done10);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
  ASSERT_EQ(std::string(""), handler.signed_public_key());
  ASSERT_EQ(std::string(""), handler.private_key());
  ASSERT_EQ(std::string(""), handler.public_key());
  ASSERT_EQ(std::string(""), handler.chunkstore_dir());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(0, handler.available_space());

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  service->set_status(maidsafe::NOT_OWNED);
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(server.external_port()+1);
  request.set_chunkstore_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done11 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done11);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->ReplyOwnVaultRequest(true);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::FAILED_TO_START_VAULT, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());
}

TEST_F(VaultRegistrationTest, FUNC_MAID_IsOwnedRpc) {
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, "127.0.0.1",
      server.external_port(), "", 0);
  maidsafe::IsOwnedRequest request;
  maidsafe::IsOwnedResponse response;
  OwnershipSenderHandler senderhandler;
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::IsOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice.IsVaultOwned(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, senderhandler.remote_vault_status());
  response.Clear();
  ctrl.Reset();
  senderhandler.Reset();
  service->set_status(maidsafe::OWNED);
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::IsOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice.IsVaultOwned(&ctrl, &request, &response, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, senderhandler.remote_vault_status());

  response.Clear();
  ctrl.Reset();
  senderhandler.Reset();
  rpcprotocol::Channel out_channel2(&client, "127.0.0.1",
      server.external_port()+1, "", 0);
  maidsafe::VaultRegistration::Stub stubservice2(&out_channel2);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::IsOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice2.IsVaultOwned(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, senderhandler.remote_vault_status());
}

int WriteToLog(std::string str) {
  printf("LOG: %s\n", str.c_str());
  return 0;
}

void Cleanup(boost::filesystem::path vaultpath) {
  boost::filesystem::remove(boost::filesystem::path(".config", fs::native));
  boost::filesystem::remove_all(boost::filesystem::path("ChunkStore"));
  if (vaultpath.string() != "") {
    vaultpath /= ".kadconfig";
    boost::filesystem::remove(vaultpath);
  }
}

void CreateVaultDaemon(bool *finished) {
  maidsafe_vault::VaultDaemon daemon(0);
  ASSERT_TRUE(daemon.StartVault());
  daemon.Status();
  boost::filesystem::path vaultpath = daemon.vault_path();
  boost::this_thread::at_thread_exit(boost::bind(&Cleanup, vaultpath));
  while (!*finished) {
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
}

TEST(VaultDaemonRegistrationTest, FUNC_MAID_VaultRegistration) {
  Cleanup(boost::filesystem::path());
  bool finished = false;
  boost::thread thrd(CreateVaultDaemon, &finished);
  boost::this_thread::sleep(boost::posix_time::seconds(3));

  rpcprotocol::ChannelManager client;
  ASSERT_EQ(0, client.StartTransport(0, boost::bind(&HandleDeadServer, _1, _2,
      _3)));
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string singed_pub_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + singed_pub_key, "",
    crypto::STRING_STRING, false);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, "127.0.0.1",
      kLocalPort, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::OwnVaultRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(0);
  request.set_chunkstore_dir("ChunkStore");
  request.set_space(1000);
  maidsafe::OwnVaultResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());
  ASSERT_EQ(pmid_name, senderhandler.pmid_name());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::OwnVaultResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.OwnVault(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, senderhandler.result());
  ASSERT_EQ(std::string(""), senderhandler.pmid_name());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  maidsafe::IsOwnedRequest req;
  maidsafe::IsOwnedResponse resp;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::IsOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &resp, &ctrl);
  stubservice.IsVaultOwned(&ctrl, &req, &resp, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, senderhandler.remote_vault_status());
  finished = true;
  thrd.join();
}
