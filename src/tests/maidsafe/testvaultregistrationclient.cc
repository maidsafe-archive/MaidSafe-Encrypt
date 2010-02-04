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
#include "maidsafe/chunkstore.h"
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/packetfactory.h"

namespace test_vault_reg {

inline void HandleDeadServer(const bool&,
                             const std::string&,
                             const boost::uint16_t&) {}

class RegistrationServiceHolder {
 public:
  RegistrationServiceHolder()
      : service_(boost::bind(
            &RegistrationServiceHolder::OwnNotifier, this, _1)),
        own_notification_arrived_(false) {}
  void RespondOwn(const bool &failstart) {
    service_.ReplySetLocalVaultOwnedRequest(failstart);
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
  ResultHandler()
      : result_(),
        pmid_name_(),
        callback_arrived_(false),
        local_vault_status_(maidsafe::ISOWNRPC_CANCELLED) {}
  bool callback_arrived() const { return callback_arrived_; }
  std::string pmid_name() const { return pmid_name_; }
  maidsafe::OwnLocalVaultResult result() const { return result_; }
  maidsafe::VaultStatus local_vault_status() const {
    return local_vault_status_;
  }
  void Reset() {
    result_ = maidsafe::INVALID_OWNREQUEST;
    pmid_name_.clear();
    callback_arrived_ = false;
    local_vault_status_ = maidsafe::ISOWNRPC_CANCELLED;
  }
  void SetLocalVaultOwnedCallback(const maidsafe::OwnLocalVaultResult &result,
                                   const std::string &pmid_name) {
    pmid_name_ = pmid_name;
    result_ = result;
    callback_arrived_ = true;
  }
  void IsOwnCallback(const maidsafe::VaultStatus &result) {
    local_vault_status_ = result;
    callback_arrived_ = true;
  }
 private:
  maidsafe::OwnLocalVaultResult result_;
  std::string pmid_name_;
  bool callback_arrived_;
  maidsafe::VaultStatus local_vault_status_;
};

}  // namespace test_vault_reg

namespace maidsafe {

class MsmSetLocalVaultOwnedTest : public testing::Test {
 public:
  MsmSetLocalVaultOwnedTest()
      : test_root_dir_(file_system::FileSystem::TempDir() +
            "/maidsafe_TestSetLocalVaultOwned_" + base::RandomString(6)),
        chunkstore_(new maidsafe::ChunkStore(test_root_dir_, 1000000, 0)),
        msm_(chunkstore_),
        resulthandler_(),
        service_(),
        port_(0),
        server_transport_(),
        server_transport_handler_(),
        server_(&server_transport_handler_),
        service_channel_(new rpcprotocol::Channel(&server_,
                                                  &server_transport_handler_)),
        cb_(boost::bind(
            &test_vault_reg::ResultHandler::SetLocalVaultOwnedCallback,
            &resulthandler_, _1, _2)),
        cb1_(boost::bind(
            &test_vault_reg::ResultHandler::IsOwnCallback,
            &resulthandler_, _1)) {}
  ~MsmSetLocalVaultOwnedTest() {
    transport::TransportUDT::CleanUp();
  }
  void SetUp() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    boost::int16_t server_transport_id;
    ASSERT_EQ(0, server_transport_handler_.Register(&server_transport_,
                                                    &server_transport_id));
    ASSERT_TRUE(msm_.channel_manager_.RegisterNotifiersToTransport());
    ASSERT_TRUE(msm_.transport_handler_.RegisterOnServerDown(boost::bind(
        &test_vault_reg::HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, msm_.transport_handler_.Start(0, msm_.udt_transport_.GetID()));
    ASSERT_EQ(0, msm_.channel_manager_.Start());
    ASSERT_TRUE(server_.RegisterNotifiersToTransport());
    ASSERT_TRUE(server_transport_handler_.RegisterOnServerDown(boost::bind(
        &test_vault_reg::HandleDeadServer, _1, _2, _3)));
    ASSERT_EQ(0, server_transport_handler_.StartLocal(kLocalPort,
        server_transport_id));
    ASSERT_EQ(0, server_.Start());
    service_channel_->SetService(service_.pservice());
    server_.RegisterChannel(service_.pservice()->GetDescriptor()->name(),
        service_channel_.get());
    port_ = msm_.transport_handler_.listening_port(msm_.udt_transport_.GetID());
  }
  void TearDown() {
    resulthandler_.Reset();
    service_.Reset();
    server_transport_handler_.StopAll();
    server_.ClearChannels();
    msm_.transport_handler_.StopAll();
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  std::string test_root_dir_;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore_;
  maidsafe::MaidsafeStoreManager msm_;
  test_vault_reg::ResultHandler resulthandler_;
  test_vault_reg::RegistrationServiceHolder service_;
  boost::uint16_t port_;
  transport::TransportUDT server_transport_;
  transport::TransportHandler server_transport_handler_;
  rpcprotocol::ChannelManager server_;
  boost::shared_ptr<rpcprotocol::Channel> service_channel_;
  boost::function<void(const maidsafe::OwnLocalVaultResult&,
      const std::string&)> cb_;
  boost::function<void(const maidsafe::VaultStatus&)> cb1_;
 private:
  MsmSetLocalVaultOwnedTest(const MsmSetLocalVaultOwnedTest&);
  MsmSetLocalVaultOwnedTest &operator=(const MsmSetLocalVaultOwnedTest&);
};

TEST_F(MsmSetLocalVaultOwnedTest, BEH_MAID_SetLocalVaultOwned) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_public_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string pmid_name = cobj.Hash(keypair.public_key() + signed_public_key,
    "", crypto::STRING_STRING, false);

  msm_.LocalVaultOwned(cb1_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_OWNED, resulthandler_.local_vault_status());
  resulthandler_.Reset();

  msm_.SetLocalVaultOwned(keypair.private_key(), keypair.public_key(),
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!service_.own_notification_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service_.RespondOwn(false);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED_SUCCESS, resulthandler_.result());
  ASSERT_EQ(pmid_name, resulthandler_.pmid_name());
  service_.SetServiceVaultStatus(maidsafe::OWNED);

  resulthandler_.Reset();
  msm_.LocalVaultOwned(cb1_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::OWNED, resulthandler_.local_vault_status());
}

TEST_F(MsmSetLocalVaultOwnedTest, FUNC_MAID_InvalidSetLocalVaultOwned) {
  crypto::Crypto cobj;
  crypto::RsaKeyPair keypair;
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  cobj.set_hash_algorithm(crypto::SHA_512);
  std::string signed_public_key = cobj.AsymSign(keypair.public_key(), "",
      keypair.private_key(), crypto::STRING_STRING);
  std::string priv_key = keypair.private_key();
  std::string pub_key = keypair.public_key();
  keypair.ClearKeys();
  keypair.GenerateKeys(maidsafe::kRsaKeySize);
  msm_.SetLocalVaultOwned(keypair.private_key(), keypair.public_key(),
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(priv_key, keypair.public_key(),
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(keypair.private_key(), pub_key,
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_RSA_KEYS, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(priv_key, pub_key, signed_public_key, port_,
      test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::INVALID_PORT, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(priv_key, pub_key,
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", 0, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NO_SPACE_ALLOCATED, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  boost::filesystem::space_info info = boost::filesystem::space(
      boost::filesystem::path("/"));
  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(priv_key, pub_key,
      signed_public_key, 0, test_root_dir_ + "/ChunkStore", info.available+10,
      cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::NOT_ENOUGH_SPACE, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  msm_.SetLocalVaultOwned(priv_key, pub_key, signed_public_key, 0,
      test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!service_.own_notification_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  service_.RespondOwn(true);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::FAILED_TO_START_VAULT, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  service_.SetServiceVaultStatus(maidsafe::OWNED);
  msm_.SetLocalVaultOwned(priv_key, pub_key, signed_public_key, 0,
      test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_ALREADY_OWNED, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());

  resulthandler_.Reset();
  service_.Reset();
  server_transport_handler_.StopAll();
  server_.Stop();
  msm_.LocalVaultOwned(cb1_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::DOWN, resulthandler_.local_vault_status());

  resulthandler_.Reset();
  msm_.SetLocalVaultOwned(priv_key, pub_key, signed_public_key, 0,
      test_root_dir_ + "/ChunkStore", 1024, cb_);
  while (!resulthandler_.callback_arrived())
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(maidsafe::VAULT_IS_DOWN, resulthandler_.result());
  ASSERT_EQ(std::string(""), resulthandler_.pmid_name());
}

}  // namespace maidsafe
