/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for IMMessaging from Maidstoremanager
* Version:      1.0
* Created:      2010-04-14-10.09.29
* Revision:     none
* Compiler:     gcc
* Author:       Team
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
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/filesystem/fstream.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport-api.h>
#include <maidsafe/transportudt.h>
#include <maidsafe/general_messages.pb.h>
#include "fs/filesystem.h"
#include "maidsafe/client/imconnectionhandler.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

class TestImMessaging : public testing::Test {
 public:
  TestImMessaging() : vault_dir_(file_system::TempDir() /
                          ("maidsafe_TestVaults_" + base::RandomString(6))),
                      kad_config_file_(vault_dir_ / ".kadconfig"),
                      bootstrapping_vault_(),
                      ctc_trans_(),
                      ss_(maidsafe::SessionSingleton::getInstance()),
                      contactname_("Teh contact"),
                      ctc_ep_(),
                      sm_() {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    fs::create_directories(vault_dir_);
  }
  ~TestImMessaging() {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
  }
 protected:
  void SetUp() {
    crypto::Crypto co;
    crypto::RsaKeyPair keys;
    keys.GenerateKeys(maidsafe::kRsaKeySize);
    std::string signed_key = co.AsymSign(keys.public_key(), "",
                             keys.private_key(), crypto::STRING_STRING);
    std::string public_key = keys.public_key();
    std::string private_key = keys.private_key();
    std::string pmid = co.Hash(signed_key, "", crypto::STRING_STRING, false);
    fs::path local_dir(vault_dir_ / ("Vault_" +
          base::EncodeToHex(pmid).substr(0, 8)));
    if (!fs::exists(fs::path(local_dir))) {
      printf("creating_directories - %s\n", local_dir.string().c_str());
      fs::create_directories(local_dir);
    }
    bootstrapping_vault_.reset(new maidsafe_vault::PDVault(public_key,
        private_key, signed_key, local_dir, 0, false, false, kad_config_file_,
        1073741824, 0));
    bootstrapping_vault_->Start(true);
    ASSERT_EQ(maidsafe_vault::kVaultStarted,
            bootstrapping_vault_->vault_status());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id(bootstrapping_vault_->node_id());
    kad_contact->set_ip(bootstrapping_vault_->host_ip());
    kad_contact->set_port(bootstrapping_vault_->host_port());
    kad_contact->set_local_ip(bootstrapping_vault_->local_host_ip());
    kad_contact->set_local_port(bootstrapping_vault_->local_host_port());
    // default location in Maidsafestoremanager
    std::fstream output(".kadconfig",
                        std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output));
    output.close();
    printf("Vault 0 started.\n");
  }
  void TearDown() {
  }

  fs::path vault_dir_, kad_config_file_;
  boost::shared_ptr<maidsafe_vault::PDVault> bootstrapping_vault_;
  transport::TransportUDT ctc_trans_;
  maidsafe::SessionSingleton *ss_;
  std::string contactname_;
  maidsafe::EndPoint ctc_ep_;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm_;
 private:
  void OnMessage(const std::string &msg) {
  }
  void StatusUpdate(const std::string &contactname, const int &status) {
  }
};

TEST_F(TestImMessaging, FUNC_MAID_SendMessage) {
}
