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
#include <maidsafe/crypto.h>
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <map>
#include <vector>
#include <fstream>  // NOLINT (Fraser) - for protobuf config file

#include "maidsafe/client/systempackets.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

const int kTestK = 16;

void GeneratePmidStuff(std::string *public_key,
                       std::string *private_key,
                       std::string *signed_key,
                       std::string *pmid) {
  crypto::Crypto co_;
  co_.set_hash_algorithm(crypto::SHA_512);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(maidsafe::kRsaKeySize);
  *signed_key = co_.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  *public_key = keys.public_key();
  *private_key = keys.private_key();
  *pmid = co_.Hash(*signed_key, "", crypto::STRING_STRING, true);
};

class RunPDVaults {
 public:
  RunPDVaults(const int &no_of_vaults,
              const std::string &test_dir,
              const base::KadConfig &kadconfig,
              const std::string &bootstrap_id,
              const std::string &bootstrap_ip,
              const boost::uint16_t &bootstrap_port,
              const std::string &local_ip,
              const boost::uint16_t &local_port,
              const boost::uint16_t &initial_vault_port,
              const std::string &initial_vault_pmid_public,
              const std::string &initial_vault_pmid_private,
              const std::string &initial_vault_signed_pmid_public)
      : no_of_vaults_(no_of_vaults),
        test_dir_(test_dir),
        bootstrap_id_(bootstrap_id),
        bootstrap_ip_(bootstrap_ip),
        bootstrap_port_(bootstrap_port),
        initial_vault_port_(initial_vault_port),
        initial_vault_pmid_public_(initial_vault_pmid_public),
        initial_vault_pmid_private_(initial_vault_pmid_private),
        initial_vault_signed_pmid_public_(initial_vault_signed_pmid_public),
        initial_vault_node_id_(""),
        kad_config_(kadconfig),
        chunkstore_dir_(test_dir_+"/Chunkstores"),
        kad_config_file_(".kadconfig"),
        chunkstore_dirs_(),
        mutices_(),
        cb_(),
        crypto_(),
        pdvaults_(new std::vector< boost::shared_ptr<PDVault> >),
        current_nodes_created_(0),
        mutex_(),
        bootstrap_local_ip_(local_ip),
        bootstrap_local_port_(local_port),
        single_function_timeout_(60) {
    fs::create_directories(chunkstore_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    initial_vault_node_id_ = crypto_.Hash(initial_vault_signed_pmid_public_, "",
                                          crypto::STRING_STRING, true);
  }

  ~RunPDVaults() {
    fs::path temp_(test_dir_);
    printf("Are you really, really, really sure that you want to delete %s?\n",
           test_dir_.c_str());
    std::string delete_dir_;
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
    if (kad_config_.contact_size() || bootstrap_id_ != "") {
      if (!kad_config_.contact_size()) {
        kad_config_.Clear();
        base::KadConfig::Contact *kad_contact_ = kad_config_.add_contact();
        kad_contact_->set_node_id(bootstrap_id_);
        kad_contact_->set_ip(bootstrap_ip_);
        kad_contact_->set_port(bootstrap_port_);
        kad_contact_->set_local_ip(bootstrap_local_ip_);
        kad_contact_->set_local_port(bootstrap_local_port_);
      }
      boost::posix_time::ptime stop;
      for (int j = 0; j < no_of_vaults_; ++j) {
        // Save kad_config to file
        std::string dir = chunkstore_dir_+"/Chunkstore"+ base::itos(j);
        if (!fs::exists(fs::path(dir)))
          fs::create_directories(dir);
        chunkstore_dirs_.push_back(dir);
        std::string kad_config_location = dir + "/" + kad_config_file_;
        printf("\nkad config: %s", kad_config_location.c_str());
        std::fstream output(kad_config_location.c_str(),
          std::ios::out | std::ios::trunc | std::ios::binary);
        kad_config_.SerializeToOstream(&output);
        output.close();
        boost::uint16_t this_port = 0;
        std::string public_key, private_key, signed_key, node_id;
        if (j == 0 && initial_vault_port_ != 0) {
          this_port = initial_vault_port_;
          public_key = initial_vault_pmid_public_;
          private_key = initial_vault_pmid_private_;
          signed_key = initial_vault_signed_pmid_public_;
          node_id = initial_vault_node_id_;
        } else {
          GeneratePmidStuff(&public_key, &private_key, &signed_key, &node_id);
        }
        boost::shared_ptr<maidsafe_vault::PDVault>
            pdvault_local(new maidsafe_vault::PDVault(public_key, private_key,
            signed_key, dir, 0, false, false, kad_config_location,
            1073741824, 0));
        pdvaults_->push_back(pdvault_local);
        ++current_nodes_created_;
        (*pdvaults_)[j]->Start(false);
        stop = boost::posix_time::second_clock::local_time() +
            single_function_timeout_;
        while (((*pdvaults_)[j]->vault_status() !=
               maidsafe_vault::kVaultStarted)
               && boost::posix_time::second_clock::local_time() < stop) {
          boost::this_thread::sleep(boost::posix_time::seconds(1));
        }
        if (maidsafe_vault::kVaultStarted != (*pdvaults_)[j]->vault_status()) {
          printf("\nVault %i didn't start properly!\n", j);
          return;
        }
        printf(".");
      }
      printf("\n");
//      printf("\nIn bootstrap ip: %s, port: %d\n",
//             kad_contact_->ip().c_str(),
//             kad_contact_->port());
    } else {
      // Construct (but don't start) vaults
      for (int i = 0; i < no_of_vaults_; ++i) {
        boost::uint16_t this_port = 0;
        std::string chunkstore_local = chunkstore_dir_+"/Chunkstore"+
            base::itos(i);
        fs::path chunkstore_local_path(chunkstore_local, fs::native);
        fs::create_directories(chunkstore_local_path);
        chunkstore_dirs_.push_back(chunkstore_local_path);
        std::string kad_config_location = chunkstore_local + "/" +
            kad_config_file_;
        std::string public_key, private_key, signed_key, node_id;
        if (i == 0 && initial_vault_port_ != 0) {
          this_port = initial_vault_port_;
          public_key = initial_vault_pmid_public_;
          private_key = initial_vault_pmid_private_;
          signed_key = initial_vault_signed_pmid_public_;
          node_id = initial_vault_node_id_;
        } else {
          GeneratePmidStuff(&public_key, &private_key, &signed_key, &node_id);
        }
        boost::shared_ptr<maidsafe_vault::PDVault>
            pdvault_local(new maidsafe_vault::PDVault(public_key, private_key,
            signed_key, chunkstore_local, this_port, false, false,
            kad_config_location, 1073741824, 0));
        pdvaults_->push_back(pdvault_local);
        ++current_nodes_created_;
        printf(".");
      }
      printf("\n\tStarting vaults");
      // Start first vault, add him as bootstrapping node for all others & start
      // them all.
      (*pdvaults_)[0]->Start(true);
      boost::posix_time::ptime stop =
          boost::posix_time::second_clock::local_time() +
          single_function_timeout_;
      while (((*pdvaults_)[0]->vault_status() != kVaultStarted) &&
             boost::posix_time::second_clock::local_time() < stop) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));
      }
      if (maidsafe_vault::kVaultStarted != (*pdvaults_)[0]->vault_status()) {
        printf("\nVault 0 didn't start properly!\n");
        return;
      }

      printf(".");
      base::KadConfig kad_config;
      base::KadConfig::Contact *kad_contact = kad_config.add_contact();
      kad_contact->set_node_id((*pdvaults_)[0]->hex_node_id());
      kad_contact->set_ip((*pdvaults_)[0]->host_ip());
      kad_contact->set_port((*pdvaults_)[0]->host_port());
      kad_contact->set_local_ip((*pdvaults_)[0]->local_host_ip());
      kad_contact->set_local_port((*pdvaults_)[0]->local_host_port());
      // Save kad config to files and start all remaining vaults
      for (int k = 1; k < no_of_vaults_; ++k) {
        kad_config_file_ = chunkstore_dir_+"/Chunkstore"+ base::itos(k) +
            "/.kadconfig";
        std::fstream output(kad_config_file_.c_str(),
                            std::ios::out | std::ios::trunc | std::ios::binary);
        if (!kad_config.SerializeToOstream(&output)) {
          printf("\nDidn't serialise kadconfig properly.\n");
          return;
        }
        output.close();
        (*pdvaults_)[k]->Start(false);
        stop = boost::posix_time::second_clock::local_time() +
            single_function_timeout_;
        while (((*pdvaults_)[k]->vault_status() != kVaultStarted)
               && boost::posix_time::second_clock::local_time() < stop) {
          boost::this_thread::sleep(boost::posix_time::seconds(1));
        }
        if (maidsafe_vault::kVaultStarted != (*pdvaults_)[k]->vault_status()) {
          printf("\nVault %i didn't start properly!\n", k);
          return;
        }
        printf(".");
      }
    }
    printf("\n");
#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    printf("\n*-----------------------------------------------*\n");
    printf("*            %i local vaults running            *\n",
           no_of_vaults_);
    printf("*                                               *\n");
    printf("* No. Port   ID                                 *\n");
    for (int l = 0; l < no_of_vaults_; ++l)
      printf("* %2i  %5i  %s *\n", l, (*pdvaults_)[l]->host_port(),
             ((*pdvaults_)[l]->hex_node_id().substr(0, 31) + "...").c_str());
    printf("*                                               *\n");
    printf("*-----------------------------------------------*\n\n");
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
//    // print id and port of last vault to use it as bootstrap for other nodes
//    printf("Last node: IP(%s), port(%d), PMID(%s)\n",
//          (*(pdvaults_))[no_of_vaults_ - 1]->host_ip().c_str(),
//          (*(pdvaults_))[no_of_vaults_ - 1]->host_port(),
//          (*(pdvaults_))[no_of_vaults_ - 1]->hex_node_id().c_str());
  }

  void TearDown() {
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
      (*pdvaults_)[i]->Stop();
      if ((*pdvaults_)[i]->vault_status() != maidsafe_vault::kVaultStarted)
        printf("Vault %i stopped.\n", i);
      else
        printf("Vault %i failed to stop correctly.\n", i);
      if (i == current_nodes_created_ - 1)
        (*pdvaults_)[current_nodes_created_ - 1]->CleanUp();
//      (*pdvaults_)[i].reset();
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      if (fs::exists(kad_config_file_))
        fs::remove(kad_config_file_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    printf("Finished vault tear down.\n");
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
  std::string initial_vault_pmid_public_;
  std::string initial_vault_pmid_private_;
  std::string initial_vault_signed_pmid_public_;
  std::string initial_vault_node_id_;
  base::KadConfig kad_config_;
  std::string chunkstore_dir_, kad_config_file_;
  std::vector<fs::path> chunkstore_dirs_;
  std::vector< boost::shared_ptr<boost::mutex> > mutices_;
  base::callback_func_type cb_;
  crypto::Crypto crypto_;
  boost::shared_ptr< std::vector< boost::shared_ptr<PDVault> > > pdvaults_;
  int current_nodes_created_;
  boost::mutex mutex_;
  std::string bootstrap_local_ip_;
  boost::uint16_t bootstrap_local_port_;
  boost::posix_time::seconds single_function_timeout_;
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
  std::string node_id;
  std::string ip, local_ip;
  boost::uint16_t port, local_port;
  boost::uint16_t initial_vault_port(0);
  std::string initial_vault_pmid_public;
  std::string initial_vault_pmid_private;
  std::string initial_vault_signed_pmid_public;
  base::KadConfig kad_config;

  try {
    fs::path local_config_file(".config", fs::native);
    if (fs::exists(local_config_file)) {
      std::ifstream input(local_config_file.string().c_str(),
                          std::ios::in | std::ios::binary);
      maidsafe::VaultConfig vault_config;
      if (!vault_config.ParseFromIstream(&input)) {
        printf("Failed to parse configuration file.\n");
        return -1;
      }
      initial_vault_port = vault_config.port();
      initial_vault_pmid_public = vault_config.pmid_public();
      initial_vault_pmid_private = vault_config.pmid_private();
      initial_vault_signed_pmid_public = vault_config.signed_pmid_public();
    }
  }
  catch(const std::exception &e) {
    printf("In main, %s\n", e.what());
  }
  if (argc < 3) {
    printf("\n\n\tWith no args, this runs 10 vaults in folder \"./Vaults\"\n");
    printf("\n\tTo include args, enter \"testvault [no. of nodes (int)] ");
    printf("[root directory of test]\n\tIf directory doesn't exist, it will ");
    printf("be created (and deleted on close).\n\n\tOptionally a bootstrap ");
    printf("contact can be added to the end of the args in the form [Kad ID] ");
    printf("[IP] [port] [local IP] [local port].\n\t");
    printf("e.g. testvault 5 C:\\TestVaults cf83e1357eefb8bdf15");
    printf("42850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff83");
    printf("18d2877eec2f63b931bd47417a81a538327af927da3e 192.168.2.104 61111");
    printf(" 192.168.2.104 61111");
    printf("\n\n\tAlternatively, the path to an existing .kadconfig file can ");
    printf("be entered.\n\te.g. testvault 5 C:\\TestVaults C:\\.kadconfig");
    printf("\n\n\tTo quit, press Ctrl+C.\n");
  } else {
    std::string number(argv[1]);
    num = base::stoi(number);
    std::string root(argv[2]);
    root_dir = root;
    if (argc == 4) {
      std::string file(argv[3]);
      try {
        std::fstream infile(file.c_str(), std::ios::in | std::ios::binary);
        kad_config.ParseFromIstream(&infile);
        if (kad_config.contact_size()) {
          if (kad_config.contact(0).has_node_id()) {
            printf("\n%s\n\n", kad_config.DebugString().c_str());
          } else {
            printf("\n%s is not a kadconfig file.\n\n", file.c_str());
            return -1;
          }
        } else {
            printf("\n%s is either not a kadconfig file, or it's empty.\n\n",
                   file.c_str());
            return -2;
        }
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    } else if (argc > 4) {
      node_id = argv[3];
      ip = argv[4];
      std::string prt(argv[5]);
      local_ip = argv[6];
      local_port = atoi(argv[7]);
      port = base::stoi(prt);
    }
  }
  {
    if (initial_vault_port != 0) {
      printf("\n\n\tFound a .config file - using this for first ");
      printf("vault's details.");
    }
    printf("\n\n\tCreating vaults");
    maidsafe_vault::RunPDVaults vaults(
        num,
        root_dir,
        kad_config,
        node_id,
        ip,
        port,
        local_ip,
        local_port,
        initial_vault_port,
        initial_vault_pmid_public,
        initial_vault_pmid_private,
        initial_vault_signed_pmid_public);
    vaults.SetUp();
    signal(SIGINT, ctrlc_handler);
    while (!ctrlc_pressed) {
      boost::this_thread::sleep(boost::posix_time::seconds(1));
    }
    vaults.TearDown();
  }
  return 0;
}
