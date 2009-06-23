/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Allows creation of gtest environment where pdvaults are set up
*               and started
* Version:      1.0
* Created:      2009-06-22-15.51.35
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef TESTS_MAIDSAFE_LOCALVAULTS_H_
#define TESTS_MAIDSAFE_LOCALVAULTS_H_

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "boost/filesystem.hpp"
#include "boost/thread/thread.hpp"
#include "maidsafe/client/authentication.h"
#include "maidsafe/crypto.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/general_messages.pb.h"

namespace fs = boost::filesystem;
namespace tt = boost::this_thread;
namespace p_time = boost::posix_time;

namespace localvaults {

void GeneratePmidStuff(std::string *public_key,
                       std::string *private_key,
                       std::string *signed_key,
                       std::string *pmid) {
  maidsafe_crypto::Crypto co;
  co.set_hash_algorithm("SHA512");
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(packethandler::kRsaKeySize);
  *signed_key = co.AsymSign(keys.public_key(), "", keys.private_key(),
                            maidsafe_crypto::STRING_STRING);
  *public_key = keys.public_key();
  *private_key = keys.private_key();
  *pmid = co.Hash(*signed_key, "", maidsafe_crypto::STRING_STRING, true);
}

class Env: public testing::Environment {
 public:
  Env(const int kNetworkSize,
      const int kTestK,
      std::vector<boost::shared_ptr<maidsafe_vault::PDVault> > *pdvaults)
      : vault_dir_("LocalVaults"),
        chunkstore_dir_(vault_dir_ + "/Chunkstores"),
        datastore_dir_(vault_dir_ + "/Datastores"),
        kad_config_file_(".kadconfig"),
        chunkstore_dirs_(),
        crypto_(),
        pdvaults_(pdvaults),
        kNetworkSize_(kNetworkSize),
        kTestK_(kTestK),
        current_nodes_created_(0),
        mutex_(),
        single_function_timeout(60) {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
      if (fs::exists(kad_config_file_))
        fs::remove(kad_config_file_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    fs::create_directories(datastore_dir_);
    crypto_.set_hash_algorithm("SHA512");
    crypto_.set_symm_algorithm("AES_256");
  }

  virtual ~Env() {}

  virtual void SetUp() {
    // Construct and start vaults
    printf("Starting vaults.\n");
    for (int i = 0; i < kNetworkSize_; ++i) {
      std::string chunkstore_local = chunkstore_dir_+"/Chunkstore"+
          base::itos(i);
      fs::path chunkstore_local_path(chunkstore_local, fs::native);
      fs::create_directories(chunkstore_local_path);
      chunkstore_dirs_.push_back(chunkstore_local_path);
      std::string datastore_local = datastore_dir_+"/Datastore"+
          base::itos(i);
      fs::create_directories(datastore_local);
      std::string public_key(""), private_key(""), signed_key(""), node_id("");
      GeneratePmidStuff(&public_key, &private_key, &signed_key, &node_id);
      ASSERT_TRUE(crypto_.AsymCheckSig(public_key, signed_key, public_key,
                                       maidsafe_crypto::STRING_STRING));
      kad_config_file_ = datastore_local + "/.kadconfig";
      boost::shared_ptr<maidsafe_vault::PDVault>
          pdvault_local(new maidsafe_vault::PDVault(public_key, private_key,
              signed_key, chunkstore_local, datastore_local, 0,
              kad_config_file_));
      pdvaults_->push_back(pdvault_local);
      ++current_nodes_created_;
    }
    // Start second vault and add as bootstrapping node for first vault
    (*pdvaults_)[1]->Start(false);
    p_time::ptime stop = p_time::second_clock::local_time() +
                         single_function_timeout;
    while (!(*pdvaults_)[1]->vault_started() &&
           p_time::second_clock::local_time() < stop) {
      tt::sleep(p_time::seconds(1));
    }
    ASSERT_TRUE((*pdvaults_)[1]->vault_started());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id((*pdvaults_)[1]->node_id());
    kad_contact->set_ip((*pdvaults_)[1]->host_ip());
    kad_contact->set_port((*pdvaults_)[1]->host_port());
    kad_contact->set_local_ip((*pdvaults_)[1]->local_host_ip());
    kad_contact->set_local_port((*pdvaults_)[1]->local_host_port());
    kad_config_file_ = datastore_dir_+"/Datastore0/.kadconfig";
    std::fstream output1(kad_config_file_.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output1));
    output1.close();
    // Start first vault, add him as bootstrapping node for all others and stop
    // second vault
    (*pdvaults_)[0]->Start(false);
    stop = p_time::second_clock::local_time() + single_function_timeout;
    while (!(*pdvaults_)[0]->vault_started() &&
           p_time::second_clock::local_time() < stop) {
      tt::sleep(p_time::seconds(1));
    }
    ASSERT_TRUE((*pdvaults_)[0]->vault_started());
    printf("Vault 0 started.\n\n");
    kad_contact->Clear();
    kad_config.Clear();
    kad_contact = kad_config.add_contact();
    kad_contact->set_node_id((*pdvaults_)[0]->node_id());
    kad_contact->set_ip((*pdvaults_)[0]->host_ip());
    kad_contact->set_port((*pdvaults_)[0]->host_port());
    kad_contact->set_local_ip((*pdvaults_)[0]->local_host_ip());
    kad_contact->set_local_port((*pdvaults_)[0]->local_host_port());
    ASSERT_EQ(0, (*pdvaults_)[1]->Stop());
    ASSERT_FALSE((*pdvaults_)[1]->vault_started());
    // Save kad config to files and start all remaining vaults
    for (int k = 1; k < kNetworkSize_; ++k) {
      kad_config_file_ = datastore_dir_+"/Datastore"+ base::itos(k) +
          "/.kadconfig";
      std::fstream output(kad_config_file_.c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output));
      output.close();
      (*pdvaults_)[k]->Start(false);
      stop = p_time::second_clock::local_time() + single_function_timeout;
      while (!(*pdvaults_)[k]->vault_started() &&
             p_time::second_clock::local_time() < stop) {
        tt::sleep(p_time::seconds(1));
      }
      ASSERT_TRUE((*pdvaults_)[k]->vault_started());
      printf("Vault %i started.\n\n", k);
//      tt::sleep(p_time::seconds(15));
    }
    // Make kad config file in ./ for clients' use.
    kad_config_file_ = ".kadconfig";
    std::fstream output2(kad_config_file_.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output2));
    output2.close();
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    printf("*-----------------------------------------------*\n");
    printf("*            %i local vaults running            *\n",
           kNetworkSize_);
    printf("*                                               *\n");
    printf("* No. Port   ID                                 *\n");
    for (int l = 0; l < kNetworkSize_; ++l)
      printf("* %2i  %5i  %s *\n", l, (*pdvaults_)[l]->host_port(),
             ((*pdvaults_)[l]->node_id().substr(0, 31) + "...").c_str());
    printf("*                                               *\n");
    printf("*-----------------------------------------------*\n\n");
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
  }

  virtual void TearDown() {
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 7 | 0 << 4);
#endif
    printf("In vault tear down.\n");
    bool success(false);
    for (int i = 0; i < current_nodes_created_; ++i) {
      printf("Trying to stop vault %i.\n", i);
      success = false;
      (*pdvaults_)[i]->Stop();
      printf("Stopped vault %i.\n", i);
      if (!(*pdvaults_)[i]->vault_started())
        printf("Vault %i stopped.\n", i);
      else
        printf("Vault %i failed to stop correctly.\n", i);
      if (i == current_nodes_created_ - 1)
        (*pdvaults_)[current_nodes_created_ - 1]->CleanUp();
//      (*pdvaults_)[i].reset();
    }
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
      if (fs::exists(kad_config_file_))
        fs::remove(kad_config_file_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    printf("Finished vault tear down.\n");
  }

  std::string vault_dir_, chunkstore_dir_, datastore_dir_, kad_config_file_;
  std::vector<fs::path> chunkstore_dirs_;
  maidsafe_crypto::Crypto crypto_;
  std::vector<boost::shared_ptr<maidsafe_vault::PDVault> > *pdvaults_;
  const int kNetworkSize_;
  const int kTestK_;
  int current_nodes_created_;
  boost::mutex mutex_;
  p_time::seconds single_function_timeout;

 private:
  Env(const Env&);
  Env &operator=(const Env&);
};

}  // namespace localvaults

#endif  // TESTS_MAIDSAFE_LOCALVAULTS_H_
