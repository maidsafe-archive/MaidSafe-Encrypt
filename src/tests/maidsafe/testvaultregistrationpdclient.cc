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
#include "maidsafe/client/packetfactory.h"
#include "maidsafe/client/pdclient.h"

inline void HandleDeadServer(const bool &, const std::string &,
  const boost::uint16_t&) {}

class RegistrationServiceHolder {
 public:
  RegistrationServiceHolder() : service_(boost::bind(
      &RegistrationServiceHolder::OwnNotifier, this, _1)),
      own_notification_arrived_(false) {}
  void RespondOwn(const bool &failstart) {
    service_.ReplyOwnVaultRequest(failstart);
  }
  void SetServiceVaultStatus(const maidsafe::VaultStatus &status) {
    service_.set_status(status);
  }
  maidsafe_vault::RegistrationService* pservice() { return &service_; }
  void OwnNotifier(const maidsafe::VaultConfig&) {
    own_notification_arrived_ = true;
  }
  void Reset() { own_notification_arrived_ = false; }
  bool own_notification_arrived() const { return own_notification_arrived_; }
 private:
  maidsafe_vault::RegistrationService service_;
  bool own_notification_arrived_;
};

class ResultHandler {
 public:
  ResultHandler() : result_(), pmid_name_(""), callback_arrived_(false),
      local_vault_status_(maidsafe::ISOWNRPC_CANCELLED) {}
  bool callback_arrived() const { return callback_arrived_; }
  std::string pmid_name() const { return pmid_name_; }
  maidsafe::OwnVaultResult result() const { return result_; }
  maidsafe::VaultStatus local_vault_status() const {
    return local_vault_status_;
  }
  void Reset() {
    result_ = maidsafe::INVALID_OWNREQUEST;
    pmid_name_ = "";
    callback_arrived_ = false;
    local_vault_status_ = maidsafe::ISOWNRPC_CANCELLED;
  }
  void OwnVault_Callback(const maidsafe::OwnVaultResult &result,
      const std::string &pmid_name) {
    pmid_name_ = pmid_name;
    result_ = result;
    callback_arrived_ = true;
  }
  void IsOwn_Callback(const maidsafe::VaultStatus &result) {
    local_vault_status_ = result;
    callback_arrived_ = true;
  }
 private:
  maidsafe::OwnVaultResult result_;
  std::string pmid_name_;
  bool callback_arrived_;
  maidsafe::VaultStatus local_vault_status_;
};

class TestPDClientOwnVault : public testing::Test {
 public:
  TestPDClientOwnVault() : resulthandler(), service(), client(new
      rpcprotocol::ChannelManager), server(), service_channel(new
      rpcprotocol::Channel(&server)), knode(), rpcs(
      new maidsafe::ClientRpcs(client)), pdclient(client, knode, rpcs),
      cb(boost::bind(&ResultHandler::OwnVault_Callback, &resulthandler, _1,
      _2)), cb1(boost::bind(&ResultHandler::IsOwn_Callback, &resulthandler, _1))
      {}
  ~TestPDClientOwnVault() {
    server.CleanUpTransport();
    delete rpcs;
  }
 protected:
  void SetUp() {
    ASSERT_EQ(0, client->StartTransport(0, boost::bind(&HandleDeadServer, _1,
        _2, _3)));
    ASSERT_EQ(0, server.StartLocalTransport(kLocalPort));
    service_channel->SetService(service.pservice());
    server.RegisterChannel(service.pservice()->GetDescriptor()->name(),
        service_channel.get());
  }
  void TearDown() {
    resulthandler.Reset();
    service.Reset();
    server.StopTransport();
    server.ClearChannels();
    client->StopTransport();
  }
  ResultHandler resulthandler;
  RegistrationServiceHolder service;
  boost::shared_ptr<rpcprotocol::ChannelManager> client;
  rpcprotocol::ChannelManager server;
  boost::shared_ptr<rpcprotocol::Channel> service_channel;
  boost::shared_ptr<kad::KNode> knode;
  maidsafe::ClientRpcs *rpcs;
  maidsafe::PDClient pdclient;
  boost::function<void(const maidsafe::OwnVaultResult&, const std::string&)> cb;
  boost::function<void(const maidsafe::VaultStatus&)> cb1;
 private:
  TestPDClientOwnVault(const TestPDClientOwnVault&);
  TestPDClientOwnVault &operator=(const TestPDClientOwnVault&);
};

TEST_F(TestPDClientOwnVault, FUNC_MAID_OwnLocalVault) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_public_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + signed_public_key,
    "", crypto::STRING_STRING, false);

  pdclient.IsLocalVaultOwned(cb1);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, resulthandler.local_vault_status());
  resulthandler.Reset();

  pdclient.OwnLocalVault(keypair.private_key(), keypair.public_key(),
      signed_public_key, 0, "ChunkStore", 1024, cb);
  while (!service.own_notification_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service.RespondOwn(false);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, resulthandler.result());
  ASSERT_EQ(pmid_name, resulthandler.pmid_name());
  service.SetServiceVaultStatus(maidsafe::OWNED);

  resulthandler.Reset();
  pdclient.IsLocalVaultOwned(cb1);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, resulthandler.local_vault_status());
}

TEST_F(TestPDClientOwnVault, FUNC_MAID_InvalidOwnLocalVault) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_public_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string priv_key = keypair.private_key();
  std::string pub_key = keypair.public_key();
  keypair.ClearKeys();
  keypair.GenerateKeys(packethandler::kRsaKeySize);
  pdclient.OwnLocalVault(keypair.private_key(), keypair.public_key(),
      signed_public_key, 0, "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(priv_key, keypair.public_key(),
      signed_public_key, 0, "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(keypair.private_key(), pub_key,
      signed_public_key, 0, "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(priv_key, pub_key,
      signed_public_key, client->external_port(), "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_PORT, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(priv_key, pub_key,
      signed_public_key, 0, "ChunkStore", 0, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NO_SPACE_ALLOCATED, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  boost::filesystem::space_info info = boost::filesystem::space(
      boost::filesystem::path("/"));
  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(priv_key, pub_key,
      signed_public_key, 0, "ChunkStore", info.available+10, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_ENOUGH_SPACE, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  pdclient.OwnLocalVault(priv_key, pub_key, signed_public_key, 0,
      "ChunkStore", 1024, cb);
  while (!service.own_notification_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service.RespondOwn(true);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::FAILED_TO_START_VAULT, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  service.SetServiceVaultStatus(maidsafe::OWNED);
  pdclient.OwnLocalVault(priv_key, pub_key, signed_public_key, 0,
      "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());

  resulthandler.Reset();
  service.Reset();
  server.StopTransport();
  pdclient.IsLocalVaultOwned(cb1);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::DOWN, resulthandler.local_vault_status());

  resulthandler.Reset();
  pdclient.OwnLocalVault(priv_key, pub_key, signed_public_key, 0,
      "ChunkStore", 1024, cb);
  while (!resulthandler.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_IS_DOWN, resulthandler.result());
  ASSERT_EQ(std::string(""), resulthandler.pmid_name());
}
