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
#include <maidsafe/transportudt.h>
#include "fs/filesystem.h"
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/crypto.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vault/vaultdaemon.h"

inline void HandleDeadServer(const bool &, const std::string &,
  const boost::uint16_t&) {}

class NotifierHandler {
 public:
  NotifierHandler() : private_key_(),
                      public_key_(),
                      signed_public_key_(),
                      vault_dir_(),
                      port_(-1),
                      available_space_(0),
                      received_rpc_(false) {}
  std::string private_key() const { return private_key_; }
  std::string public_key() const { return public_key_; }
  std::string signed_public_key() const { return signed_public_key_; }
  std::string vault_dir() const { return vault_dir_; }
  boost::int32_t port() const { return port_; }
  boost::uint64_t available_space() const { return available_space_; }
  bool received_rpc() const { return received_rpc_; }
  void OwnedNotification(const maidsafe::VaultConfig &vconfig) {
    private_key_ = vconfig.pmid_private();
    public_key_ = vconfig.pmid_public();
    signed_public_key_ = vconfig.signed_pmid_public();
    vault_dir_ = vconfig.vault_dir();
    port_ = vconfig.port();
    available_space_ = vconfig.available_space();
    received_rpc_ = true;
  }
  void Reset() {
    private_key_.clear();
    public_key_.clear();
    signed_public_key_.clear();
    vault_dir_.clear();
    port_ = -1;
    available_space_ = 0;
    received_rpc_ = false;
  }
 private:
  std::string private_key_, public_key_, signed_public_key_, vault_dir_;
  boost::int32_t port_;
  boost::uint64_t available_space_;
  bool received_rpc_;
};

class OwnershipSenderHandler {
 public:
  OwnershipSenderHandler() : callback_arrived_(false),
                             result_(),
                             pmid_name_(),
                             remote_vault_status_() {}
  void Reset() {
    callback_arrived_ = false;
    pmid_name_.clear();
    result_ = maidsafe::INVALID_OWNREQUEST;
    remote_vault_status_ = maidsafe::NOT_OWNED;
  }
  void Callback(const maidsafe::SetLocalVaultOwnedResponse *response,
                rpcprotocol::Controller *ctrl) {
    callback_arrived_ = true;
    if ((ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kTimeOut)) {
      printf("Rpc timeout\n");
      result_ = maidsafe::VAULT_IS_DOWN;
      return;
    }
    if (!response->IsInitialized()) {
      printf("Rpc timeout - resp not initialised\n");
      result_ = maidsafe::VAULT_IS_DOWN;
      return;
    }
    result_ = response->result();
    if (response->has_pmid_name())
      pmid_name_ = response->pmid_name();
  }
  void Callback1(const maidsafe::LocalVaultOwnedResponse *response,
                 rpcprotocol::Controller *ctrl) {
    callback_arrived_ = true;
    if ((ctrl->Failed() && ctrl->ErrorText() == rpcprotocol::kTimeOut) ||
         !response->IsInitialized()) {;
      return;
    }
    remote_vault_status_ = response->status();
  }
  std::string pmid_name() const { return pmid_name_; }
  maidsafe::OwnLocalVaultResult result() const { return result_; }
  bool callback_arrived() const { return callback_arrived_; }
  maidsafe::VaultStatus remote_vault_status() const {
    return remote_vault_status_;
  }
 private:
  bool callback_arrived_;
  maidsafe::OwnLocalVaultResult result_;
  std::string pmid_name_;
  maidsafe::VaultStatus remote_vault_status_;
};

class VaultRegistrationTest : public testing::Test {
 public:
  VaultRegistrationTest()
      : server_transport_(),
        client_transport_(),
        server_transport_handler_(),
        client_transport_handler_(),
        server(&server_transport_handler_),
        client(&client_transport_handler_),
        service_channel(new rpcprotocol::Channel(&server,
                                                 &server_transport_handler_)),
        handler(),
        service() {}
  ~VaultRegistrationTest() {
      transport::TransportUDT::CleanUp();
  }
 protected:
  virtual void SetUp() {
    boost::int16_t client_transport_id, server_transport_id;
    ASSERT_EQ(0, client_transport_handler_.Register(&client_transport_,
                                                    &client_transport_id));
    ASSERT_TRUE(client.RegisterNotifiersToTransport());
    ASSERT_TRUE(client_transport_handler_.RegisterOnServerDown(boost::bind(
        &HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, client_transport_handler_.Start(0, client_transport_id));
    ASSERT_EQ(0, client.Start());
    ASSERT_EQ(0, server_transport_handler_.Register(&server_transport_,
                                                    &server_transport_id));
    ASSERT_TRUE(server.RegisterNotifiersToTransport());
    ASSERT_TRUE(server_transport_handler_.RegisterOnServerDown(boost::bind(
        &HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, server_transport_handler_.StartLocal(0, server_transport_id));
    ASSERT_EQ(0, server.Start());
    service.reset(new maidsafe_vault::RegistrationService(boost::bind(
          &NotifierHandler::OwnedNotification, &handler, _1)));
    service_channel->SetService(service.get());
    server.RegisterChannel(service->GetDescriptor()->name(),
        service_channel.get());
  }
  virtual void TearDown() {
    handler.Reset();
    server_transport_handler_.StopAll();
    server.Stop();
    client_transport_handler_.StopAll();
    client.Stop();
    server.ClearChannels();
  }
  transport::TransportUDT server_transport_, client_transport_;
  transport::TransportHandler server_transport_handler_,
      client_transport_handler_;
  rpcprotocol::ChannelManager server, client;
  boost::shared_ptr<rpcprotocol::Channel> service_channel;
  NotifierHandler handler;
  boost::shared_ptr<maidsafe_vault::RegistrationService> service;
};

TEST_F(VaultRegistrationTest, FUNC_MAID_CorrectSetLocalVaultOwned) {
  ASSERT_EQ(maidsafe::NOT_OWNED, service->status());
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_pub_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.GetID(), "127.0.0.1",
      server_transport_handler_.listening_port(server_transport_.GetID()), "",
      0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::SetLocalVaultOwnedRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1);
  request.set_vault_dir("/ChunkStore");
  request.set_space(1000);
  maidsafe::SetLocalVaultOwnedResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done1);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->set_status(maidsafe::OWNED);
  service->ReplySetLocalVaultOwnedRequest(false);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());
  ASSERT_EQ(pmid_name, senderhandler.pmid_name());

  ASSERT_EQ(keypair.private_key(), handler.private_key());
  ASSERT_EQ(keypair.public_key(), handler.public_key());
  ASSERT_EQ(signed_pub_key, handler.signed_public_key());
  ASSERT_EQ(std::string("/ChunkStore"), handler.vault_dir());
  ASSERT_EQ(
    server_transport_handler_.listening_port(server_transport_.GetID()) + 1,
    handler.port());
  ASSERT_EQ(boost::uint64_t(1000), handler.available_space());

  ASSERT_EQ(maidsafe::OWNED, service->status());

  request.clear_port();
  response.Clear();
  handler.Reset();
  ctrl.Reset();
  senderhandler.Reset();
  request.set_port(0);

  service->set_status(maidsafe::NOT_OWNED);

  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done2);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->set_status(maidsafe::OWNED);
  service->ReplySetLocalVaultOwnedRequest(false);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());

  ASSERT_EQ(keypair.private_key(), handler.private_key());
  ASSERT_EQ(keypair.public_key(), handler.public_key());
  ASSERT_EQ(signed_pub_key, handler.signed_public_key());
  ASSERT_EQ(std::string("/ChunkStore"), handler.vault_dir());
  ASSERT_EQ(0, handler.port());
  ASSERT_EQ(boost::uint64_t(1000), handler.available_space());
}

TEST_F(VaultRegistrationTest, FUNC_MAID_InvalidRequest) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string priv_key = keypair.private_key();
  std::string pub_key = keypair.public_key();
  // NB - In reality, key passed is PMID which is not self-signed, but no check
  // of this is done by service, so we're OK to pass a slef-signed key here.
  std::string signed_public_key = cobj.AsymSign(pub_key, "", priv_key,
      crypto::STRING_STRING);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.GetID(), "127.0.0.1",
      server_transport_handler_.listening_port(server_transport_.GetID()), "",
      0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::SetLocalVaultOwnedRequest request;
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(
      client_transport_handler_.listening_port(client_transport_.GetID()));
  request.set_vault_dir("/ChunkStore");
  request.set_space(1000);
  maidsafe::SetLocalVaultOwnedResponse response;
  google::protobuf::Closure *done7 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done7);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_PORT, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());
  ASSERT_TRUE(handler.signed_public_key().empty());
  ASSERT_TRUE(handler.private_key().empty());
  ASSERT_TRUE(handler.public_key().empty());
  ASSERT_TRUE(handler.vault_dir().empty());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(boost::uint64_t(0), handler.available_space());

  // space == 0
  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1);
  request.set_vault_dir("/ChunkStore");
  request.set_space(0);
  google::protobuf::Closure *done8 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done8);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NO_SPACE_ALLOCATED, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());
  ASSERT_TRUE(handler.signed_public_key().empty());
  ASSERT_TRUE(handler.private_key().empty());
  ASSERT_TRUE(handler.public_key().empty());
  ASSERT_TRUE(handler.vault_dir().empty());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(boost::uint64_t(0), handler.available_space());
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
  request.set_port(
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1);
  request.set_vault_dir("/ChunkStore");
  request.set_space(info.available + 10);
  google::protobuf::Closure *done9 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done9);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_ENOUGH_SPACE, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());
  ASSERT_TRUE(handler.signed_public_key().empty());
  ASSERT_TRUE(handler.private_key().empty());
  ASSERT_TRUE(handler.public_key().empty());
  ASSERT_TRUE(handler.vault_dir().empty());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(boost::uint64_t(0), handler.available_space());

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  service->set_status(maidsafe::OWNED);
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1);
  request.set_vault_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done10 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done10);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());
  ASSERT_TRUE(handler.signed_public_key().empty());
  ASSERT_TRUE(handler.private_key().empty());
  ASSERT_TRUE(handler.public_key().empty());
  ASSERT_TRUE(handler.vault_dir().empty());
  ASSERT_EQ(-1, handler.port());
  ASSERT_EQ(boost::uint64_t(0), handler.available_space());

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  service->set_status(maidsafe::NOT_OWNED);
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1);
  request.set_vault_dir("/ChunkStore");
  request.set_space(1000);
  google::protobuf::Closure *done11 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done11);
  while (!handler.received_rpc())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service->ReplySetLocalVaultOwnedRequest(true);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::FAILED_TO_START_VAULT, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());
}

TEST_F(VaultRegistrationTest, FUNC_MAID_LocalVaultOwnedRpc) {
  rpcprotocol::Controller ctrl;
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.GetID(), "127.0.0.1",
      server_transport_handler_.listening_port(server_transport_.GetID()), "",
      0, "", 0);
  maidsafe::LocalVaultOwnedRequest request;
  maidsafe::LocalVaultOwnedResponse response;
  OwnershipSenderHandler senderhandler;
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::LocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice.LocalVaultOwned(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, senderhandler.remote_vault_status());
  response.Clear();
  ctrl.Reset();
  senderhandler.Reset();
  service->set_status(maidsafe::OWNED);
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::LocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice.LocalVaultOwned(&ctrl, &request, &response, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, senderhandler.remote_vault_status());

  response.Clear();
  ctrl.Reset();
  senderhandler.Reset();
  rpcprotocol::Channel out_channel2(&client, &client_transport_handler_,
      client_transport_.GetID(), "127.0.0.1",
      server_transport_handler_.listening_port(server_transport_.GetID()) + 1,
      "", 0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice2(&out_channel2);
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::LocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &response, &ctrl);
  stubservice2.LocalVaultOwned(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, senderhandler.remote_vault_status());
}

int WriteToLog(std::string str) {
  printf("LOG: %s\n", str.c_str());
  return 0;
}

void CreateVaultDaemon(const std::string &test_dir, bool *finished) {
  maidsafe_vault::VaultDaemon daemon(0, test_dir);
  ASSERT_TRUE(daemon.StartVault());
  daemon.Status();
  boost::filesystem::path vaultpath = daemon.vault_path();
  while (!*finished) {
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
}

TEST(VaultDaemonRegistrationTest, FUNC_MAID_VaultRegistration) {
  ASSERT_FALSE(boost::filesystem::exists(file_system::ApplicationDataDir() /
      ".config"));
  bool finished = false;
  fs::path test_dir = file_system::TempDir() /
      ("maidsafe_TESTDaemon_" + base::RandomString(6));
  boost::thread thrd(CreateVaultDaemon, (test_dir / "Unowned").string(),
      &finished);

  transport::TransportUDT client_transport;
  transport::TransportHandler client_transport_handler;
  rpcprotocol::ChannelManager client(&client_transport_handler);
  boost::int16_t client_transport_id;
  ASSERT_EQ(0, client_transport_handler.Register(&client_transport,
                                                 &client_transport_id));
  ASSERT_TRUE(client.RegisterNotifiersToTransport());
  ASSERT_TRUE(client_transport_handler.RegisterOnServerDown(boost::bind(
      &HandleDeadServer, _1, _2, _3)));
  ASSERT_EQ(0, client_transport_handler.Start(0, client_transport_id));
  ASSERT_EQ(0, client.Start());
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_pub_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + signed_pub_key, "",
      crypto::STRING_STRING, false);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  ctrl.set_timeout(30);
  rpcprotocol::Channel out_channel(&client, &client_transport_handler,
      client_transport_id, "127.0.0.1", kLocalPort, "", 0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::SetLocalVaultOwnedRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(0);
  request.set_vault_dir((test_dir / "Owned").string());
  request.set_space(1000);
  maidsafe::SetLocalVaultOwnedResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, senderhandler.result());
  ASSERT_EQ(pmid_name, senderhandler.pmid_name());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  maidsafe::LocalVaultOwnedRequest req;
  maidsafe::LocalVaultOwnedResponse resp;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const maidsafe::LocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &resp, &ctrl);
  stubservice.LocalVaultOwned(&ctrl, &req, &resp, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, senderhandler.remote_vault_status());
  finished = true;
  thrd.join();
  if (boost::filesystem::exists(test_dir))
    boost::filesystem::remove_all(test_dir);
  if (boost::filesystem::exists(file_system::ApplicationDataDir() / ".config"))
    boost::filesystem::remove_all(file_system::ApplicationDataDir() /".config");
}
