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

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <maidsafe/crypto.h>
#include <maidsafe/general_messages.pb.h>
#include <string>
#include <vector>
#include "fs/filesystem.h"
#include "maidsafe/client/authentication.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

namespace localvaults {

void GeneratePmidStuff(std::string *public_key,
                       std::string *private_key,
                       std::string *signed_key,
                       std::string *pmid) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(maidsafe::kRsaKeySize);
  *signed_key = co.AsymSign(keys.public_key(), "", keys.private_key(),
                            crypto::STRING_STRING);
  *public_key = keys.public_key();
  *private_key = keys.private_key();
  *pmid = co.Hash(*signed_key, "", crypto::STRING_STRING, true);
}

class Env: public testing::Environment {
 public:
  Env(const int kNetworkSize,
      const int kTestK,
      std::vector<boost::shared_ptr<maidsafe_vault::PDVault> > *pdvaults)
      : vault_dir_(file_system::FileSystem::TempDir()+"/maidsafe_TestVaults"),
        chunkstore_dir_(vault_dir_ + "/Chunkstores"),
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
    fs::create_directories(chunkstore_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
  }

  virtual ~Env() {
    try {
      if (fs::exists(vault_dir_))
        fs::remove_all(vault_dir_);
      if (fs::exists(kad_config_file_))
        fs::remove(kad_config_file_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::path temp_("VaultTest");
    try {
      if (fs::exists(temp_))
        fs::remove_all(temp_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    pdvaults_->clear();
  }

  virtual void SetUp() {
    // Construct and start vaults
    printf("Creating vaults");
    for (int i = 0; i < kNetworkSize_; ++i) {
      std::string chunkstore_local = chunkstore_dir_+"/Chunkstore"+
          base::itos(i);
      fs::path chunkstore_local_path(chunkstore_local, fs::native);
      fs::create_directories(chunkstore_local_path);
      chunkstore_dirs_.push_back(chunkstore_local_path);
      std::string public_key(""), private_key(""), signed_key(""), node_id("");
      GeneratePmidStuff(&public_key, &private_key, &signed_key, &node_id);
//      ASSERT_TRUE(crypto_.AsymCheckSig(public_key, signed_key, public_key,
//                                       crypto::STRING_STRING));
      kad_config_file_ = chunkstore_local + "/.kadconfig";
      boost::shared_ptr<maidsafe_vault::PDVault>
          pdvault_local(new maidsafe_vault::PDVault(public_key, private_key,
          signed_key, chunkstore_local, 0, false, false, kad_config_file_,
          1073741824, 0));
      pdvaults_->push_back(pdvault_local);
      ++current_nodes_created_;
      printf(".");
    }
    printf("\n");
    // Start second vault and add as bootstrapping node for first vault
    (*pdvaults_)[1]->Start(true);
    boost::posix_time::ptime stop =
        boost::posix_time::second_clock::local_time() + single_function_timeout;
    while (((*pdvaults_)[1]->vault_status() != maidsafe_vault::kVaultStarted) &&
           boost::posix_time::second_clock::local_time() < stop) {
      boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
    ASSERT_EQ(maidsafe_vault::kVaultStarted, (*pdvaults_)[1]->vault_status());
    base::KadConfig kad_config;
    base::KadConfig::Contact *kad_contact = kad_config.add_contact();
    kad_contact->set_node_id((*pdvaults_)[1]->hex_node_id());
    kad_contact->set_ip((*pdvaults_)[1]->host_ip());
    kad_contact->set_port((*pdvaults_)[1]->host_port());
    kad_contact->set_local_ip((*pdvaults_)[1]->local_host_ip());
    kad_contact->set_local_port((*pdvaults_)[1]->local_host_port());
    kad_config_file_ = chunkstore_dir_+"/Chunkstore0/.kadconfig";
    std::fstream output1(kad_config_file_.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
    ASSERT_TRUE(kad_config.SerializeToOstream(&output1));
    output1.close();
    // Start first vault, add him as bootstrapping node for all others and stop
    // second vault
    (*pdvaults_)[0]->Start(false);
    stop = boost::posix_time::second_clock::local_time() +
        single_function_timeout;
    while (((*pdvaults_)[0]->vault_status() != maidsafe_vault::kVaultStarted) &&
           boost::posix_time::second_clock::local_time() < stop) {
      boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
    ASSERT_EQ(maidsafe_vault::kVaultStarted, (*pdvaults_)[0]->vault_status());
    printf("Vault 0 started.\n");
    kad_contact->Clear();
    kad_config.Clear();
    kad_contact = kad_config.add_contact();
    kad_contact->set_node_id((*pdvaults_)[0]->hex_node_id());
    kad_contact->set_ip((*pdvaults_)[0]->host_ip());
    kad_contact->set_port((*pdvaults_)[0]->host_port());
    kad_contact->set_local_ip((*pdvaults_)[0]->local_host_ip());
    kad_contact->set_local_port((*pdvaults_)[0]->local_host_port());
    ASSERT_EQ(0, (*pdvaults_)[1]->Stop(true));
    ASSERT_NE(maidsafe_vault::kVaultStarted, (*pdvaults_)[1]->vault_status());
    // Save kad config to files and start all remaining vaults
    for (int k = 1; k < kNetworkSize_; ++k) {
      kad_config_file_ = chunkstore_dir_+"/Chunkstore"+ base::itos(k) +
          "/.kadconfig";
      std::fstream output(kad_config_file_.c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
      ASSERT_TRUE(kad_config.SerializeToOstream(&output));
      output.close();
      (*pdvaults_)[k]->Start(false);
      stop = boost::posix_time::second_clock::local_time() +
          single_function_timeout;
      while (((*pdvaults_)[k]->vault_status() != maidsafe_vault::kVaultStarted)
             && boost::posix_time::second_clock::local_time() < stop) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));
      }
      ASSERT_EQ(maidsafe_vault::kVaultStarted,
                (*pdvaults_)[k]->vault_status());
      printf("Vault %i started.\n", k);
//      boost::this_thread::sleep(boost::posix_time::seconds(15));
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
    printf("\n*-----------------------------------------------*\n");
    printf("*            %i local vaults running            *\n",
           kNetworkSize_);
    printf("*                                               *\n");
    printf("* No. Port   ID                                 *\n");
    for (int l = 0; l < kNetworkSize_; ++l)
      printf("* %2i  %5i  %s *\n", l, (*pdvaults_)[l]->host_port(),
             ((*pdvaults_)[l]->hex_node_id().substr(0, 31) + "...").c_str());
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
    for (int i = 0; i < current_nodes_created_; ++i)
      (*pdvaults_)[i]->StopRvPing();
    for (int i = 0; i < current_nodes_created_; ++i) {
      printf("Trying to stop vault %i.\n", i);
      success = false;
      (*pdvaults_)[i]->Stop(true);
      if ((*pdvaults_)[i]->vault_status() != maidsafe_vault::kVaultStarted)
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

  std::string vault_dir_, chunkstore_dir_, kad_config_file_;
  std::vector<fs::path> chunkstore_dirs_;
  crypto::Crypto crypto_;
  std::vector<boost::shared_ptr<maidsafe_vault::PDVault> > *pdvaults_;
  const int kNetworkSize_;
  const int kTestK_;
  int current_nodes_created_;
  boost::mutex mutex_;
  boost::posix_time::seconds single_function_timeout;

 private:
  Env(const Env&);
  Env &operator=(const Env&);
};

}  // namespace localvaults

#endif  // TESTS_MAIDSAFE_LOCALVAULTS_H_
