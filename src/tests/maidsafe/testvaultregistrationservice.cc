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

#include <boost/shared_ptr.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <gtest/gtest.h>
#include <google/protobuf/descriptor.h>
#include <maidsafe/transport/transportudt.h>

#include "fs/filesystem.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/vault/vaultdaemon.h"
#include "maidsafe/vault/vaultservice.h"
#include "tests/maidsafe/cached_keys.h"

namespace fs = boost::filesystem;

inline void HandleDeadServer(const bool &, const std::string&,
                             const boost::uint16_t&) {}

namespace test_vault_registration_service {
static const boost::uint8_t K(4);
}  // namespace test_vault_service

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
        service(),
        keys_() {}
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
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(VaultRegistrationTest, FUNC_MAID_CorrectSetLocalVaultOwned) {
  ASSERT_EQ(maidsafe::NOT_OWNED, service->status());
  crypto::Crypto cobj;
  std::vector<crypto::RsaKeyPair> keys;
  cached_keys::MakeKeys(1, &keys);
  crypto::RsaKeyPair keypair = keys.at(0);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_pub_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + signed_pub_key, "",
    crypto::STRING_STRING, false);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  boost::uint16_t port;
  ASSERT_TRUE(server_transport_handler_.listening_port(
      server_transport_.transport_id(), &port));
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.transport_id(), "127.0.0.1", port, "", 0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::SetLocalVaultOwnedRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(port + 1);
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
  ASSERT_EQ(port + 1, handler.port());
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
  std::vector<crypto::RsaKeyPair> keys;
  cached_keys::MakeKeys(1, &keys);
  crypto::RsaKeyPair keypair = keys.at(0);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string priv_key = keypair.private_key();
  std::string pub_key = keypair.public_key();
  // NB - In reality, key passed is PMID which is not self-signed, but no check
  // of this is done by service, so we're OK to pass a slef-signed key here.
  std::string signed_public_key = cobj.AsymSign(pub_key, "", priv_key,
      crypto::STRING_STRING);
  OwnershipSenderHandler senderhandler;
  rpcprotocol::Controller ctrl;
  boost::uint16_t server_port, client_port;
  ASSERT_TRUE(server_transport_handler_.listening_port(
      server_transport_.transport_id(), &server_port));
  ASSERT_TRUE(client_transport_handler_.listening_port(
      client_transport_.transport_id(), &client_port));
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.transport_id(), "127.0.0.1", server_port, "", 0, "", 0);
  maidsafe::VaultRegistration::Stub stubservice(&out_channel);
  maidsafe::SetLocalVaultOwnedRequest request;
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_public_key);
  request.set_port(client_port);
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
  request.set_port(server_port + 1);
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
  fs::space_info info = fs::space(fs::path("/"));

  ctrl.Reset();
  request.Clear();
  response.Clear();
  senderhandler.Reset();
  handler.Reset();

  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(signed_public_key);
  request.set_port(server_port + 1);
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
  request.set_port(server_port + 1);
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
  request.set_port(server_port + 1);
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
  boost::uint16_t port;
  ASSERT_TRUE(server_transport_handler_.listening_port(
      server_transport_.transport_id(), &port));
  rpcprotocol::Channel out_channel(&client, &client_transport_handler_,
      client_transport_.transport_id(), "127.0.0.1", port, "", 0, "", 0);
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
      client_transport_.transport_id(), "127.0.0.1", port + 1, "", 0, "", 0);
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

namespace maidsafe {

namespace test {

class VaultDaemonRegistrationTest : public testing::Test {
 public:
  VaultDaemonRegistrationTest() : test_dir_(file_system::TempDir() /
                                            ("maidsafe_TESTDaemon_" +
                                            base::RandomAlphaNumericString(6))),
                                  finished_(false),
                                  thrd_() {}
  ~VaultDaemonRegistrationTest() {
    transport::TransportUDT::CleanUp();
  }
  void StartVaultDaemon() {
    maidsafe_vault::VaultDaemon daemon(0, (test_dir_ / "Unowned").string(),
                                       test_vault_registration_service::K);
    daemon.test_config_postfix_ = "_test_vrs";
    ASSERT_TRUE(daemon.StartVault());
    daemon.Status();
    fs::path vaultpath = daemon.vault_path();
    while (!finished_) {
      boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
    try {
      if (fs::exists(vaultpath))
        fs::remove_all(vaultpath);
    }
    catch(const std::exception &e) {
      printf("In Test: %s\n", e.what());
    }
  }
 protected:
  void SetUp() {
    fs::path config(file_system::ApplicationDataDir() / ".config_test_vrs");
    try {
      if (fs::exists(config))
        fs::remove_all(config);
    }
    catch(const std::exception &e) {
      printf("In Test: %s\n", e.what());
      FAIL();
    }
//     Make .kadconfig in new Owned dir to avoid overwriting default .kadconfig
//    fs::path new_kadconfig(test_dir_ / "Owned/.kadconfig");
//    try {
//      fs::create_directories(test_dir_ / "Owned");
//      std::fstream output(new_kadconfig.string().c_str(),
//          std::ios::out | std::ios::trunc | std::ios::binary);
//      output.close();
//      ASSERT_TRUE(fs::exists(new_kadconfig));
//    }
//    catch(const std::exception &e) {
//      printf("In StartVaultDaemon: %s\n", e.what());
//      FAIL();
//    }
    thrd_ = boost::thread(&VaultDaemonRegistrationTest::StartVaultDaemon, this);
  }
  void TearDown() {
    finished_ = true;
    thrd_.join();
    fs::path config(file_system::ApplicationDataDir() / ".config_test_vrs");
    try {
      if (fs::exists(config))
        fs::remove_all(config);
    }
    catch(const std::exception &e) {
      printf("In Test: %s\n", e.what());
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  fs::path test_dir_;
  bool finished_;
  boost::thread thrd_;
};

TEST_F(VaultDaemonRegistrationTest, FUNC_MAID_VaultRegistration) {
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
  std::vector<crypto::RsaKeyPair> keys;
  cached_keys::MakeKeys(1, &keys);
  crypto::RsaKeyPair keypair = keys.at(0);
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
  VaultRegistration::Stub stubservice(&out_channel);
  SetLocalVaultOwnedRequest request;
  request.set_private_key(keypair.private_key());
  request.set_public_key(keypair.public_key());
  request.set_signed_public_key(cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING));
  request.set_port(0);
  request.set_vault_dir((test_dir_ / "Owned").string());
  request.set_space(1000);
  SetLocalVaultOwnedResponse response;
  google::protobuf::Closure *done1 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done1);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(OWNED_SUCCESS, senderhandler.result());
  ASSERT_EQ(pmid_name, senderhandler.pmid_name());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  google::protobuf::Closure *done2 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const SetLocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback, &response, &ctrl);
  stubservice.SetLocalVaultOwned(&ctrl, &request, &response, done2);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(VAULT_ALREADY_OWNED, senderhandler.result());
  ASSERT_TRUE(senderhandler.pmid_name().empty());

  response.Clear();
  senderhandler.Reset();
  ctrl.Reset();
  LocalVaultOwnedRequest req;
  LocalVaultOwnedResponse resp;
  google::protobuf::Closure *done3 = google::protobuf::NewCallback<
      OwnershipSenderHandler, const LocalVaultOwnedResponse*,
      rpcprotocol::Controller*>(&senderhandler,
      &OwnershipSenderHandler::Callback1, &resp, &ctrl);
  stubservice.LocalVaultOwned(&ctrl, &req, &resp, done3);
  while (!senderhandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(OWNED, senderhandler.remote_vault_status());
}

}  // namespace test

}  // namespace maidsafe

