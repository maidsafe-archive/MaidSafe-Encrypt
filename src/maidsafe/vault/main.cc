/*
* ============================================================================
*
* Copyright 2009 maidsafe.net limited
*
* Description:  Runs PDVaults to allow testing
* Version:      1.0
* Created:      2009-04-08-09.49.39
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

#include <signal.h>

#include <boost/thread/thread.hpp>
#include <boost/thread/xtime.hpp>
#include <map>
#include <vector>
#include <fstream>  // NOLINT (Fraser) - for protobuf config file

#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"
#include "maidsafe/client/pdclient.h"
#include "maidsafe/client/systempackets.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/general_messages.pb.h"

namespace maidsafe_vault {

const int kTestK = 4;
static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static bool callback_prepared_ = false;

void PrepareCallbackResults() {
  callback_timed_out_ = true;
  callback_succeeded_ = false;
  callback_prepared_ = true;
}

void BluddyWaitFunction(int seconds, boost::mutex* mutex) {
  if (!callback_prepared_) {
    printf("Callback result variables were not set.\n");
    return;
  }
  for (int i = 0; i < seconds*100; ++i) {
    {
      boost::mutex::scoped_lock lock_(*mutex);
      if (!callback_timed_out_) {
        if (callback_succeeded_) {
  //        printf("Callback succeeded after %3.2f seconds\n",
  //               static_cast<float>(i)/100);
          callback_prepared_ = false;
          return;
        } else {
  //        printf("Callback failed after %3.2f seconds\n",
  //               static_cast<float>(i)/100);
          callback_prepared_ = false;
          return;
        }
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  callback_prepared_ = false;
  printf("Callback timed out after %i second(s)\n", seconds);
}

void GeneratePmidStuff(std::string *public_key,
                       std::string *private_key,
                       std::string *signed_key,
                       std::string *pmid) {
  maidsafe_crypto::Crypto co_;
  co_.set_hash_algorithm("SHA512");
  maidsafe_crypto::RsaKeyPair keys;
  keys.GenerateKeys(packethandler::kRsaKeySize);
  *signed_key = co_.AsymSign(keys.public_key(), "", keys.private_key(),
    maidsafe_crypto::STRING_STRING);
  *public_key = keys.public_key();
  *private_key = keys.private_key();
  *pmid = co_.Hash(*signed_key, "", maidsafe_crypto::STRING_STRING, true);
};

class RunPDVaults {
 public:
  RunPDVaults(const int &no_of_vaults,
              const std::string &test_dir,
              const std::string &bootstrap_id,
              const std::string &bootstrap_ip,
              const boost::uint16_t &bootstrap_port,
              const boost::uint16_t &initial_vault_port,
              const std::string &local_ip,
              const boost::uint16_t &local_port)
      : no_of_vaults_(no_of_vaults),
        test_dir_(test_dir),
        bootstrap_id_(bootstrap_id),
        bootstrap_ip_(bootstrap_ip),
        bootstrap_port_(bootstrap_port),
        initial_vault_port_(initial_vault_port),
        kad_config_(),
        chunkstore_dir_(test_dir_+"/Chunkstores"),
        datastore_dir_(test_dir_+"/Datastores"),
        kad_config_file_(datastore_dir_+"/.kadconfig"),
        chunkstore_dirs_(),
        mutices_(),
        cb_(),
        crypto_(),
        pdvaults_(new std::vector< boost::shared_ptr<PDVault> >),
        current_nodes_created_(0),
        mutex_(),
        bootstrap_file_prepared_(false),
        bootstrap_local_ip_(local_ip),
        bootstrap_local_port_(local_port) {
    fs::path temp_(test_dir_);
    fs::create_directories(datastore_dir_);
    fs::create_directories(chunkstore_dir_);
    crypto_.set_hash_algorithm("SHA512");
    crypto_.set_symm_algorithm("AES_256");
  }

  ~RunPDVaults() {
//    UDT::cleanup();
    fs::path temp_(test_dir_);
    printf("Are you really, really, really sure that you want to delete %s?\n",
           test_dir_.c_str());
    std::string delete_dir_("");
    while (delete_dir_ != "y" &&
           delete_dir_ != "Y" &&
           delete_dir_ != "n" &&
           delete_dir_ != "N") {
      delete_dir_ = "";
      printf("Enter \"y\" or \"n\": ");
      std::cin >> delete_dir_;
    }
    if (delete_dir_ == "y" || delete_dir_ == "Y") {
      try {
        if (fs::exists(temp_))
          fs::remove_all(temp_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }
  }

  void SetUp() {
    bootstrap_file_prepared_ = false;
    if (bootstrap_id_ != "") {
      kad_config_.Clear();
      base::KadConfig::Contact *kad_contact_ = kad_config_.add_contact();
//      std::string bin_id_("");
//      std::string bin_ip_("");
//      base::decode_from_hex(bootstrap_id_, bin_id_);
//      base::decode_from_hex(bootstrap_ip_, bin_ip_);
      kad_contact_->set_node_id(bootstrap_id_);
      kad_contact_->set_ip(bootstrap_ip_);
      kad_contact_->set_port(bootstrap_port_);
      kad_contact_->set_local_ip(bootstrap_local_ip_);
      kad_contact_->set_local_port(bootstrap_local_port_);
      for (int j = 0; j < no_of_vaults_; j++) {
        // Save kad_config to file
        std::string dir = datastore_dir_+"/Datastore"+ base::itos(64001+j);
        if (!boost::filesystem::exists(boost::filesystem::path(dir)))
          boost::filesystem::create_directories(dir);
        kad_config_file_ = dir + "/.kadconfig";
        std::fstream output(kad_config_file_.c_str(),
          std::ios::out | std::ios::trunc | std::ios::binary);
        kad_config_.SerializeToOstream(&output);
        output.close();
      }
      bootstrap_file_prepared_ = true;
//      printf("\nIn bootstrap ip: %s, port: %d\n",
//             kad_contact_->ip().c_str(),
//             kad_contact_->port());
    }
    // Construct (but don't start) vaults
    for (int i = 0; i < no_of_vaults_; ++i) {
      boost::uint16_t this_port = 0;
      if (initial_vault_port_ != 0)
        this_port = initial_vault_port_ + i;
      std::string chunkstore_local_ = chunkstore_dir_+"/Chunkstore"+
          base::itos(64001+i);
      fs::path chunkstore_local_path_(chunkstore_local_, fs::native);
      chunkstore_dirs_.push_back(chunkstore_local_path_);
      std::string datastore_local_ = datastore_dir_+"/Datastore"+
          base::itos(64001+i);
      kad_config_file_ = datastore_local_ + "/.kadconfig";
      std::string public_key_(""), private_key_(""), signed_key_("");
      std::string node_id_("");
      GeneratePmidStuff(&public_key_,
                        &private_key_,
                        &signed_key_,
                        &node_id_);
      boost::shared_ptr<boost::mutex> mutex_local_(new boost::mutex);
      mutices_.push_back(mutex_local_);

      boost::shared_ptr<PDVault>
          pdvault_local_(new PDVault(public_key_,
                                     private_key_,
                                     signed_key_,
                                     chunkstore_local_,
                                     datastore_local_,
                                     this_port,
                                     kad_config_file_));
      pdvaults_->push_back(pdvault_local_);
      ++current_nodes_created_;
      printf(".");
      if (i == 0 && !bootstrap_file_prepared_) {
        // Make the first vault as bootstrapping node
        kad_config_.Clear();
        base::KadConfig::Contact *kad_contact_ = kad_config_.add_contact();
//        std::string bin_id_("");
//        std::string bin_ip_("");
//        base::decode_from_hex(pdvault_local_->node_id(), bin_id_);
//        base::decode_from_hex(pdvault_local_->host_ip(), bin_ip_);
        kad_contact_->set_node_id(pdvault_local_->node_id());
        kad_contact_->set_ip(pdvault_local_->host_ip());
        kad_contact_->set_port(pdvault_local_->host_port());
        kad_contact_->set_local_ip(pdvault_local_->local_host_ip());
        kad_contact_->set_local_port(pdvault_local_->local_host_port());

//        printf("In kadcontact host ip: %s, host port: %d\n",
//          kad_contact_->ip().c_str(),
//          kad_contact_->port());
        // Save kad_config to file
        std::fstream output_(kad_config_file_.c_str(),
          std::ios::out | std::ios::trunc | std::ios::binary);
        kad_config_.SerializeToOstream(&output_);
        output_.close();
      }
    }
    printf("\n");
    // start vaults
    bool success_ = false;
    for (int i = 0; i < no_of_vaults_; ++i) {
      success_ = false;
      (*(pdvaults_))[i]->Start(false);
      for (int n = 0; n < 6000; ++n) {
        if ((*(pdvaults_))[i]->vault_started()) {
          success_ = true;
          break;
        }
      }
      if (!success_)
        return;
      printf("\tVault %i started.\n", i+1);
    }
  }

  void TearDown() {
    bool success_(false);
    for (int i = 0; i < no_of_vaults_; ++i) {
      success_ = false;
      (*(pdvaults_))[i]->Stop();
      for (int j = 0; j < 6000; ++j) {
        if (!(*(pdvaults_))[i]->vault_started()) {
          success_ = true;
          break;
        }
        boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      }
      if (success_)
        printf("\tVault %i stopped.\n", i+1);
      else
        printf("\tVault %i failed to stop correctly.\n", i+1);
      (*(pdvaults_))[i].reset();
    }
  }

 private:
  RunPDVaults(const RunPDVaults&);
  RunPDVaults &operator=(const RunPDVaults&);
  const int no_of_vaults_;
  std::string test_dir_;
  std::string bootstrap_id_;
  std::string bootstrap_ip_;
  boost::uint16_t bootstrap_port_;
  boost::uint16_t initial_vault_port_;
  base::KadConfig kad_config_;
  std::string chunkstore_dir_, datastore_dir_, kad_config_file_;
  std::vector<fs::path> chunkstore_dirs_;
  std::vector< boost::shared_ptr<boost::mutex> > mutices_;
  base::callback_func_type cb_;
  maidsafe_crypto::Crypto crypto_;
  boost::shared_ptr< std::vector< boost::shared_ptr<PDVault> > > pdvaults_;
  int current_nodes_created_;
  boost::mutex mutex_;
  bool bootstrap_file_prepared_;
  std::string bootstrap_local_ip_;
  boost::uint16_t bootstrap_local_port_;
};

}  // namespace maidsafe_vault

  volatile int ctrlc_pressed = 0;
  void ctrlc_handler(int ) {
    printf("\n\n\tStopping vaults...\n");
    ctrlc_pressed = 1;
  }

int main(int argc, char* argv[]) {
  int num(10);
  std::string root_dir("Vaults");
  std::string node_id("");
  std::string ip, local_ip;
  boost::uint16_t port, local_port;
  boost::uint16_t vault_port(0);

  if (argc < 3) {
    printf("\n\n\tWith no args, this runs 10 vaults in folder \"./Vaults\"\n");
    printf("\n\tTo include args, enter \"testvault [no. of nodes (int)] ");
    printf("[root directory of test]\n\tIf directory doesn't exist, it will ");
    printf("be created (and deleted on close).\n\tOptionally a bootstrap");
    printf("contact can be added to the end of the args in the form [Kad ID] ");
    printf("[IP] [port] [local IP] [local port].\n\tEg:");
    printf(" testvault 5 C:\\TestVault cf83e1357eefb8bdf15");
    printf("42850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff83");
    printf("18d2877eec2f63b931bd47417a81a538327af927da3e 192.168.2.104 61111");
    printf(" 192.168.2.104 61111");
    printf("\n\n\tTo quit, press Ctrl+C.\n");
  } else {
    std::string number(argv[1]);
    num = base::stoi(number);
    std::string root(argv[2]);
    root_dir = root;
    if (argc > 4) {
      node_id = argv[3];
      ip = argv[4];
      std::string prt(argv[5]);
      local_ip = argv[6];
      local_port = atoi(argv[7]);
      port = base::stoi(prt);
      std::string v_port(argv[8]);
      vault_port = base::stoi(v_port);
    }
  }
  {
    printf("\n\n\tCreating vaults");
    maidsafe_vault::RunPDVaults vaults(num, root_dir, node_id, ip, port,
      vault_port, local_ip, local_port);
    vaults.SetUp();
    signal(SIGINT, ctrlc_handler);
    while (!ctrlc_pressed) {
      boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
    vaults.TearDown();
  }
  return 0;
}

//  int main(int argc, char* argv[]) {
//    if (argc < 2) {
//      printf("Enter \"testvault [path to application dir. (eg. \"C:\\Progra");
//      printf("mData\\maidsafe\" or \"/var/cache/maidsafe/\" or \"/Library/m");
//      printf("aidsafe/\")] [port]\"\n");
//      return -1;
//    } else {
//      std::string app_dir(argv[1]);
//      std::string port_string(argv[2]);
//      fs::path vault_path(app_dir, fs::native);
//      vault_path /= "vault";
//      maidsafe_crypto::Crypto co_;
//      co_.set_symm_algorithm("AES_256");
//      co_.set_hash_algorithm("SHA512");
//      fs::path config_file(".config");
//      base::VaultConfig vault_config;
//      int port = base::stoi(port_string);
//      maidsafe_crypto::RsaKeyPair keys;
//      keys.GenerateKeys(packethandler::kRsaKeySize);
//      vault_config.set_pmid_public(keys.public_key());
//      vault_config.set_pmid_private(keys.private_key());
//      vault_config.set_signed_pmid_public(
//          co_.AsymSign(keys.public_key(), "", keys.private_key(),
//          maidsafe_crypto::STRING_STRING));
//      vault_config.set_port(port);
//      fs::path chunkstore_path(vault_path);
//      chunkstore_path /= "Chunkstore";
//      co_.set_hash_algorithm("SHA1");
//      chunkstore_path /= co_.Hash(keys.public_key(), "",
//                                  maidsafe_crypto::STRING_STRING, true);
//      vault_config.set_chunkstore_dir(chunkstore_path.string());
//      fs::path datastore_path(vault_path);
//      datastore_path /= "Datastore";
//      datastore_path /= co_.Hash(keys.public_key(), "",
//                                 maidsafe_crypto::STRING_STRING, true);
//      vault_config.set_datastore_dir(datastore_path.string());
//      std::fstream output(config_file.string().c_str(),
//                          std::ios::out | std::ios::trunc | std::ios::binary);
//      if (!vault_config.SerializeToOstream(&output)) {
//        printf("Failed to write vault configuration file.\n");
//        return -2;
//      }
//      output.close();
//      printf(".config file created successfully in the directory where this");
//      printf(" is being run.\n\n%s", vault_config.DebugString().c_str());
//      return 0;
//    }
//  }
