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
#include <maidsafe/base/crypto.h>
#include <maidsafe/protobuf/general_messages.pb.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/base/utils.h>

#include <map>
#include <vector>
#include <fstream>  // NOLINT (Fraser) - for protobuf config file

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/systempackets.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "tests/maidsafe/mocksessionsingleton.h"

namespace fs = boost::filesystem;

volatile int ctrlc_pressed = 0;
void ctrlc_handler(int ) {
  printf("\nStopping vaults, please wait...\n\n");
  ctrlc_pressed = 1;
}

static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static std::string callback_content_ = "";
static bool callback_prepared_ = false;
static boost::mutex callback_mutex_;
static std::list<std::string> callback_packets_;
static std::list<std::string> callback_messages_;

namespace testpdvault {

void PrepareCallbackResults() {
  callback_timed_out_ = true;
  callback_succeeded_ = false;
  callback_content_ = "";
  callback_prepared_ = true;
  callback_packets_.clear();
  callback_messages_.clear();
}

static void GeneralCallback(const std::string &result) {
  maidsafe::GenericResponse result_msg;
  if ((!result_msg.ParseFromString(result))||
      (result_msg.result() != kAck)) {
    callback_succeeded_ = false;
    callback_timed_out_ = false;
  } else {
    callback_succeeded_ = true;
    callback_timed_out_ = false;
  }
}

void WaitFunction(int seconds, boost::mutex* mutex) {
  if (!callback_prepared_) {
    printf("Callback result variables were not set.\n");
    return;
  }
  bool got_callback = false;
  // for (int i = 0; i < seconds*100; ++i) {
  while (!got_callback) {
    {
      boost::mutex::scoped_lock lock_(*mutex);
      if (!callback_timed_out_) {
        got_callback = true;
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

}  // namespace testpdvault

namespace maidsafe_vault {

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
  *pmid = co_.Hash(*signed_key, "", crypto::STRING_STRING, false);
};

struct ClientData {
  explicit ClientData(const std::string &root_dir)
    : chunkstore_dir(root_dir + "/ClientChunkstore_" + base::RandomString(8)),
      mss(),
      pmid_pub_key(),
      pmid_priv_key(),
      pmid_pub_key_sig(),
      pmid_name(),
      chunkstore(),
      msm(),
      pmid_keys(),
      maid_keys(),
      stored_chunks() {}

  std::string chunkstore_dir;
  maidsafe::MockSessionSingleton mss;
  std::string pmid_pub_key, pmid_priv_key, pmid_pub_key_sig, pmid_name;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> msm;
  crypto::RsaKeyPair pmid_keys, maid_keys;
  std::set<std::string> stored_chunks;
};

class RunPDVaults {
 public:
  RunPDVaults(const int &no_of_vaults,
              const int &no_of_clients,
              const fs::path &test_dir,
              const fs::path &kad_config_path)
      : no_of_vaults_(no_of_vaults),
        no_of_clients_(no_of_clients),
        test_dir_(test_dir),
        kad_config_path_(kad_config_path),
        kad_config_(),
        vault_dirs_(),
        mutices_(),
        crypto_(),
        pdvaults_(new std::vector< boost::shared_ptr<PDVault> >),
        current_nodes_created_(0),
        mutex_(),
        single_function_timeout_(60),
        clients_(),
        total_chunks_stored_(0),
        total_chunks_retrieved_(0) {
    if (kad_config_path_.empty())
      kad_config_path_ = test_dir / ".kadconfig";
    fs::create_directories(test_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    for (int i = 0; i < no_of_clients_; ++i) {
      boost::shared_ptr<ClientData> client(new ClientData(test_dir_.string()));
      clients_.push_back(client);
      printf("Generating MAID Keys for client %d of %d...\n", i + 1,
             no_of_clients_);
      clients_[i]->maid_keys.GenerateKeys(maidsafe::kRsaKeySize);
      std::string maid_priv_key = clients_[i]->maid_keys.private_key();
      std::string maid_pub_key = clients_[i]->maid_keys.public_key();
      std::string maid_pub_key_sig = crypto_.AsymSign(maid_pub_key, "",
          maid_priv_key, crypto::STRING_STRING);
      std::string maid_name = crypto_.Hash(maid_pub_key + maid_pub_key_sig, "",
                                           crypto::STRING_STRING, false);
      clients_[i]->mss.AddKey(maidsafe::MAID, maid_name, maid_priv_key,
                              maid_pub_key, maid_pub_key_sig);
      printf(" >> public key:   %s\n", HexSubstr(maid_pub_key).c_str());
      printf(" >> pub key sig:  %s\n", HexSubstr(maid_pub_key_sig).c_str());
      printf(" >> hash/name:    %s\n", HexSubstr(maid_name).c_str());

      printf("Generating PMID Keys for client %d of %d...\n", i + 1,
             no_of_clients_);
      clients_[i]->pmid_keys.GenerateKeys(maidsafe::kRsaKeySize);
      clients_[i]->pmid_priv_key = clients_[i]->pmid_keys.private_key();
      clients_[i]->pmid_pub_key = clients_[i]->pmid_keys.public_key();
      clients_[i]->pmid_pub_key_sig = crypto_.AsymSign(
          clients_[i]->pmid_pub_key, "", maid_priv_key, crypto::STRING_STRING);
      clients_[i]->pmid_name = crypto_.Hash(
          clients_[i]->pmid_pub_key + clients_[i]->pmid_pub_key_sig, "",
          crypto::STRING_STRING, false);
      clients_[i]->mss.AddKey(maidsafe::PMID,
          clients_[i]->pmid_name, clients_[i]->pmid_priv_key,
          clients_[i]->pmid_pub_key, clients_[i]->pmid_pub_key_sig);
      printf(" >> public key:   %s\n",
             HexSubstr(clients_[i]->pmid_pub_key).c_str());
      printf(" >> pub key sig:  %s\n",
             HexSubstr(clients_[i]->pmid_pub_key_sig).c_str());
      printf(" >> hash/name:    %s\n",
             HexSubstr(clients_[i]->pmid_name).c_str());
      clients_[i]->mss.SetConnectionStatus(0);
    }
  }

  ~RunPDVaults() {
    printf("Are you really, really, really sure that you want to delete %s?\n",
           test_dir_.string().c_str());
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
        if (fs::exists(test_dir_))
          fs::remove_all(test_dir_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }
  }

  void SetUp() {
    printf("Starting %d vaults and %d clients...\n", no_of_vaults_,
           no_of_clients_);
    boost::posix_time::ptime stop;
    for (int j = 0; j < no_of_vaults_; ++j) {
      int client_idx = j + no_of_clients_ - no_of_vaults_;
      boost::uint16_t this_port = 0;
      std::string public_key, private_key, signed_key, node_id;
      if (client_idx >= 0) {
        // taking over vault when creating it
        printf("Setting up client %d of %d...\n", client_idx + 1,
               no_of_clients_);
        clients_[client_idx]->chunkstore =
            boost::shared_ptr<maidsafe::ChunkStore> (new maidsafe::ChunkStore(
            clients_[client_idx]->chunkstore_dir, 0, 0));
        clients_[client_idx]->chunkstore->Init();
        boost::shared_ptr<maidsafe::MaidsafeStoreManager>
            sm_local_(new maidsafe::MaidsafeStoreManager(
                      clients_[client_idx]->chunkstore));
        clients_[client_idx]->msm = sm_local_;
        clients_[client_idx]->msm->ss_ = &clients_[client_idx]->mss;
        clients_[client_idx]->msm->kad_config_location_ =
            kad_config_path_.string();
        testpdvault::PrepareCallbackResults();
        clients_[client_idx]->msm->Init(0,
            boost::bind(&testpdvault::GeneralCallback, _1), "");
        testpdvault::WaitFunction(60, &mutex_);
        public_key = clients_[client_idx]->pmid_pub_key;
        private_key = clients_[client_idx]->pmid_priv_key;
        signed_key = clients_[client_idx]->pmid_pub_key_sig;
        node_id = clients_[client_idx]->pmid_name;
      } else {
        GeneratePmidStuff(&public_key, &private_key, &signed_key, &node_id);
      }
      fs::path dir(test_dir_ / ("Vault_" +
          base::EncodeToHex(node_id).substr(0, 8)));
      if (!fs::exists(fs::path(dir))) {
        printf("creating_directories - %s\n", dir.string().c_str());
        fs::create_directories(dir);
      }
      vault_dirs_.push_back(dir);
      boost::shared_ptr<maidsafe_vault::PDVault>
          pdvault_local(new maidsafe_vault::PDVault(public_key, private_key,
          signed_key, dir, this_port, false, false, kad_config_path_,
          1073741824, 0));
      pdvaults_->push_back(pdvault_local);
      ++current_nodes_created_;
      bool first = ((j == 0) && (!fs::exists(kad_config_path_)));
      (*pdvaults_)[j]->Start(first);
      if (!(*pdvaults_)[j]->WaitForStartup(10)) {
        printf("Vault %i didn't start properly!\n", j);
        return;
      }
      if (first) {
        base::KadConfig kad_config;
        base::KadConfig::Contact *kad_contact = kad_config.add_contact();
        kad_contact->set_node_id(base::EncodeToHex((*pdvaults_)[j]->node_id()));
        kad_contact->set_ip((*pdvaults_)[j]->host_ip());
        kad_contact->set_port((*pdvaults_)[j]->host_port());
        kad_contact->set_local_ip((*pdvaults_)[j]->local_host_ip());
        kad_contact->set_local_port((*pdvaults_)[j]->local_host_port());
        std::fstream output(kad_config_path_.string().c_str(),
                            std::ios::out | std::ios::trunc | std::ios::binary);
        kad_config.SerializeToOstream(&output);
        output.close();
      }
    }

#ifdef WIN32
    HANDLE hconsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hconsole, 10 | 0 << 4);
#endif
    printf("\n");
    printf("*-----------------------------------------------*\n");
    printf("*            %2i local vaults running           *\n",
           no_of_vaults_);
    printf("*                                               *\n");
    printf("* No. Port   ID                                 *\n");
    for (int l = 0; l < no_of_vaults_; ++l)
      printf("* %2i  %5i  %s *\n", l, (*pdvaults_)[l]->host_port(),
             (base::EncodeToHex((*pdvaults_)[l]->node_id()).substr(0, 31) +
             "...").c_str());
    printf("*                                               *\n");
    if (no_of_clients_ > 0) {
      printf("*           %2i local clients running            *\n",
             no_of_clients_);
      printf("*                                               *\n");
      printf("* No. Port   ID                                 *\n");
      for (int l = 0; l < no_of_clients_; ++l)
        printf("* %2i  %5i  %s... *\n", l,
               clients_[l]->msm->knode_->host_port(),
               clients_[l]->msm->knode_->node_id().ToStringEncoded()
               .substr(0, 31).c_str());
      printf("*                                               *\n");
    }
    printf("*-----------------------------------------------*\n\n");
#ifdef WIN32
    SetConsoleTextAttribute(hconsole, 11 | 0 << 4);
#endif
//    // print id and port of last vault to use it as bootstrap for other nodes
//    printf("Last node: IP(%s), port(%d), PMID(%s)\n",
//          (*(pdvaults_))[no_of_vaults_ - 1]->host_ip().c_str(),
//          (*(pdvaults_))[no_of_vaults_ - 1]->host_port(),
//          HexSubstr((*(pdvaults_))[no_of_vaults_ - 1]->node_id()).c_str());

    // Wait for account creation and syncing
    for (int i = 0; i < no_of_vaults_; ++i)
      (*pdvaults_)[i]->WaitForSync();
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
    for (int i = 0; i < no_of_clients_; ++i) {
      testpdvault::PrepareCallbackResults();
      clients_[i]->msm->Close(
          boost::bind(&testpdvault::GeneralCallback, _1), true);
      testpdvault::WaitFunction(60, &mutex_);
    }
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
      if (fs::exists(kad_config_path_))
        fs::remove(kad_config_path_);
    }
    catch(const std::exception &e_) {
      printf("%s\n", e_.what());
    }
    printf("Finished vault tear down.\n");
  }

  void Process() {
    crypto::Crypto cryobj_;
    cryobj_.set_hash_algorithm(crypto::SHA_512);
    cryobj_.set_symm_algorithm(crypto::AES_256);

    for (int i = 0; i < no_of_clients_; ++i) {
      // check for existance of stored chunks
      for (std::set<std::string>::iterator it =
               clients_[i]->stored_chunks.begin();
           it != clients_[i]->stored_chunks.end();
           ++it) {
        if (ctrlc_pressed)
          break;

        clients_[i]->chunkstore->DeleteChunk(*it);
        std::string data;
        if (0 == clients_[i]->msm->LoadChunk(*it, &data) &&
            *it == crypto_.Hash(data, "", crypto::STRING_STRING, false)) {
          printf("Successfully loaded chunk %s for client %s. (%d/%d)\n",
                 HexSubstr(*it).c_str(),
                 HexSubstr(clients_[i]->pmid_name).c_str(),
                 total_chunks_retrieved_, total_chunks_stored_);
          clients_[i]->stored_chunks.erase(it);
          ++total_chunks_retrieved_;
          // TODO(Team#) physically delete chunk from network
        } else {
          printf("Could not load chunk %s for client %s. (%d/%d)\n",
                 HexSubstr(*it).c_str(),
                 HexSubstr(clients_[i]->pmid_name).c_str(),
                 total_chunks_retrieved_, total_chunks_stored_);
        }
      }

      if (ctrlc_pressed)
        return;

      // store random chunks
      int no_of_chunks = (total_chunks_stored_ < 500) ?
                          base::RandomUint32() % 6 : 0;
      for (int j = 0; j < no_of_chunks; ++j) {
        if (ctrlc_pressed)
          break;

        std::string chunk_content =
            base::RandomString(base::RandomInt32() % 10000 * 10 + 10);
        std::string chunk_name = cryobj_.Hash(chunk_content, "",
                                              crypto::STRING_STRING, false);
        fs::path chunk_path(test_dir_);
        printf("Storing chunk %s for client %s ...\n",
               HexSubstr(chunk_name).c_str(),
               HexSubstr(clients_[i]->pmid_name).c_str());
        chunk_path /= base::EncodeToHex(chunk_name);
        std::ofstream ofs_;
        ofs_.open(chunk_path.string().c_str());
        ofs_ << chunk_content;
        ofs_.close();
        clients_[i]->chunkstore->AddChunkToOutgoing(chunk_name, chunk_path);
        clients_[i]->msm->StoreChunk(chunk_name, maidsafe::PRIVATE, "");
        clients_[i]->stored_chunks.insert(chunk_name);
        ++total_chunks_stored_;
        fs::remove(chunk_path);
      }
    }
  }

 private:
  RunPDVaults(const RunPDVaults&);
  RunPDVaults &operator=(const RunPDVaults&);
  const int no_of_vaults_;
  const int no_of_clients_;
  fs::path test_dir_, kad_config_path_;
  base::KadConfig kad_config_;
  std::vector<fs::path> vault_dirs_;
  std::vector< boost::shared_ptr<boost::mutex> > mutices_;
  crypto::Crypto crypto_;
  boost::shared_ptr< std::vector< boost::shared_ptr<PDVault> > > pdvaults_;
  int current_nodes_created_;
  boost::mutex mutex_;
  boost::posix_time::seconds single_function_timeout_;
  std::vector< boost::shared_ptr<ClientData> > clients_;
  int total_chunks_stored_, total_chunks_retrieved_;
};

}  // namespace maidsafe_vault

int main(int argc, char* argv[]) {
  int num_v(16), num_c(0);
  fs::path root_dir("TestVaults_" + base::RandomString(6));
  fs::path kad_config_path;
  printf("=== Vault Test Network ===\n\n");
  if ((argc == 2) || (argc > 4)) {
    printf("  With no args, this runs %d vaults in folder \"%s\"\n\n", num_v,
           root_dir.string().c_str());
    printf("  To include args, enter \"testvault <#nodes>[:<#clients>] ");
    printf("<root directory>\".\n");
    printf("  If the directory doesn't exist, it will be created (and ");
    printf("deleted on close).\n\n");
    printf("  Examples:\n    testvault 5 ~/Vaults\n    testvault 7:2 ");
    printf("C:\\TestVaults\n\n");
    printf("  Optionally, a path to an existing .kadconfig file can be ");
    printf("appended: \n    \"... [<kad config path>]\"\n\n");
    printf("  Example:\n    testvault 5 ~/Vaults ~/.kadconfig\n\n");
    printf("  To quit, press Ctrl+C.\n\n");
    return 0;
  } else if (argc > 1) {
    std::string number(argv[1]);
    size_t sep = number.find(':');
    if (sep == std::string::npos) {
      num_v = boost::lexical_cast<int>(number);
    } else {
      num_v = boost::lexical_cast<int>(number.substr(0, sep));
      num_c = boost::lexical_cast<int>(number.substr(sep + 1));
    }
    // printf("vaults: %d  clients: %d\n", num_v, num_c);
    if (num_v < 1 || num_c < 0) {
      printf("Must specify at least one vault to be set up.\n");
      return -1;
    }
    if (num_v <= num_c) {
      printf("Must specify to set up more vaults than clients.\n");
      return -2;
    }
    std::string root(argv[2]);
    root_dir = root;
    if (argc == 4) {
      std::string file(argv[3]);
      try {
        std::fstream infile(file.c_str(), std::ios::in | std::ios::binary);
        base::KadConfig kad_config;
        kad_config.ParseFromIstream(&infile);
        if (kad_config.contact_size()) {
          if (kad_config.contact(0).has_node_id()) {
            printf("%s\n\n", kad_config.DebugString().c_str());
          } else {
            printf("%s is not a kadconfig file.\n", file.c_str());
            return -3;
          }
        } else {
            printf("%s is either not a kadconfig file, or it's empty.\n",
                   file.c_str());
            return -4;
        }
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
      kad_config_path = file;
    }
  }
  maidsafe_vault::RunPDVaults vaults(num_v, num_c, root_dir, kad_config_path);
  vaults.SetUp();
  signal(SIGINT, ctrlc_handler);
  while (!ctrlc_pressed) {
    vaults.Process();
    if (!ctrlc_pressed)
      boost::this_thread::sleep(boost::posix_time::seconds(5));
  }
  vaults.TearDown();
  return 0;
}
