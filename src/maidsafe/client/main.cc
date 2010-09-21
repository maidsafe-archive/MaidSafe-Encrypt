/*
* ============================================================================
*
* Copyright 2010 maidsafe.net limited
*
* Description:  Command line client for chunk storage testing
* Created:      2010-09-14
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
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/systempackets.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static std::string callback_content_ = "";
static bool callback_prepared_ = false;
static boost::mutex callback_mutex_;
static std::list<std::string> callback_packets_;
static std::list<std::string> callback_messages_;

namespace testpdclient {

static const boost::uint8_t K(4);

struct ClientData {
  explicit ClientData(const std::string &root_dir)
    : chunkstore_dir(root_dir + "/ClientChunkstore_" +
                     base::RandomAlphaNumericString(8)),
      chunkstore(),
      msm(),
      returning(false) {}
  std::string chunkstore_dir;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> msm;
  bool returning;
};

void PrepareCallbackResults() {
  callback_timed_out_ = true;
  callback_succeeded_ = false;
  callback_content_.clear();
  callback_prepared_ = true;
  callback_packets_.clear();
  callback_messages_.clear();
}

static void GeneralCallback(const maidsafe::ReturnCode &result) {
  if (result != maidsafe::kSuccess) {
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

void PrintRpcTimings(const rpcprotocol::RpcStatsMap &rpc_timings) {
  printf("Calls  RPC Name                                            "
         "min/avg/max\n");
  for (rpcprotocol::RpcStatsMap::const_iterator it = rpc_timings.begin();
       it != rpc_timings.end();
       ++it) {
    printf("%5llux %-50s  %.2f/%.2f/%.2f s\n",
           it->second.Size(),
           it->first.c_str(),
           it->second.Min() / 1000.0,
           it->second.Mean() / 1000.0,
           it->second.Max() / 1000.0);
  }
}

}  // namespace testpdclient

namespace maidsafe {

class RunPDClient {
 public:
  RunPDClient(const fs::path &test_dir,
              const fs::path &kad_config_path)
      : test_dir_(test_dir),
        kad_config_path_(kad_config_path),
        kad_config_(),
        crypto_(),
        mutex_(),
        single_function_timeout_(60),
        client_()  {
    if (kad_config_path_.empty())
      kad_config_path_ = test_dir / ".kadconfig";
    fs::create_directories(test_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    client_.reset(new testpdclient::ClientData(test_dir_.string()));
    ReadChunkList();
    
    std::string maid_priv_key, maid_pub_key, maid_pub_key_sig, maid_name;
    std::string pmid_priv_key, pmid_pub_key, pmid_pub_key_sig, pmid_name;
    client_->returning = ReadClientData(&maid_priv_key, &maid_pub_key,
                                        &pmid_priv_key, &pmid_pub_key);
    if (!client_->returning) {
      printf("Generating keys...\n");
      crypto::RsaKeyPair maid_keys, pmid_keys;
      maid_keys.GenerateKeys(maidsafe::kRsaKeySize);
      maid_priv_key = maid_keys.private_key();
      maid_pub_key = maid_keys.public_key();
      pmid_keys.GenerateKeys(maidsafe::kRsaKeySize);
      pmid_priv_key = pmid_keys.private_key();
      pmid_pub_key = pmid_keys.public_key();
      WriteClientData(maid_priv_key, maid_pub_key, pmid_priv_key, pmid_pub_key);
    }

    maid_pub_key_sig = crypto_.AsymSign(maid_pub_key, "", maid_priv_key,
                                        crypto::STRING_STRING);
    maid_name = crypto_.Hash(maid_pub_key + maid_pub_key_sig, "",
                             crypto::STRING_STRING, false);
    pmid_pub_key_sig = crypto_.AsymSign(pmid_pub_key, "", maid_priv_key,
                                        crypto::STRING_STRING);
    pmid_name = crypto_.Hash(pmid_pub_key + pmid_pub_key_sig, "",
                             crypto::STRING_STRING, false);
                             
    SessionSingleton::getInstance()->AddKey(maidsafe::MAID, maid_name,
        maid_priv_key, maid_pub_key, maid_pub_key_sig);
    SessionSingleton::getInstance()->AddKey(maidsafe::PMID, pmid_name,
        pmid_priv_key, pmid_pub_key, pmid_pub_key_sig);
    SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  ~RunPDClient() {

  }

  bool SetUp() {
    printf("Starting client...\n");
    boost::posix_time::ptime stop;
    client_->chunkstore = boost::shared_ptr<maidsafe::ChunkStore> (
        new maidsafe::ChunkStore(client_->chunkstore_dir, 0, 0));
    if (!client_->chunkstore->Init()) {
      printf("Failed initialising chunkstore.\n");
      return false;
    }
    client_->msm.reset(new maidsafe::MaidsafeStoreManager(
        client_->chunkstore, testpdclient::K));

    testpdclient::PrepareCallbackResults();
    client_->msm->Init(boost::bind(&testpdclient::GeneralCallback, _1),
                       kad_config_path_, 0);
    testpdclient::WaitFunction(60, &mutex_);
    if (!callback_succeeded_ || callback_timed_out_) {
      printf("Failed initialising store manager.\n");
      return false;
    }

    if (!client_->returning) {
      int tries(0);
      while (tries < 3 && client_->msm->CreateAccount(1 << 20) != kSuccess) {
        printf("Retrying to create account...\n");
        boost::this_thread::sleep(boost::posix_time::seconds(10));
        ++tries;
      }
      if (tries == 3) {
        printf("Failed creating account.\n");
        return false;
      }
    }

    return true;
  }

  void TearDown() {
    testpdclient::PrepareCallbackResults();
    client_->msm->Close(boost::bind(&testpdclient::GeneralCallback, _1), true);
    testpdclient::WaitFunction(60, &mutex_);
  }

  void List() {
    if (chunks_.size() == 0) {
      printf("No chunks in list.\n");
      return;
    }

    printf("Locally available chunks:\n");
    for (std::map<std::string, std::string>::iterator it = chunks_.begin();
         it != chunks_.end(); ++it) {
      fs::path chunk_path = test_dir_ / base::EncodeToHex(it->second);
      boost::uint64_t chunk_size(0);
      if (boost::filesystem::exists(chunk_path))
        chunk_size = boost::filesystem::file_size(chunk_path);
      printf(" %s (%s, %llu KB)\n", it->first.c_str(),
             HexSubstr(it->second).c_str(), chunk_size / 1024);
    }
  }

  void Create(const std::string &name) {
    if (chunks_.count(name) != 0) {
      printf("A chunk with name '%s' already exists.\n", name.c_str());
      return;
    }

    // generate chunk content and name
    boost::uint64_t chunk_size = 1024 << rand() % 10;
    std::string chunk_content = base::RandomString(chunk_size);
    std::string chunk_name = crypto_.Hash(chunk_content, "",
                                          crypto::STRING_STRING, false);
    fs::path chunk_path(test_dir_);
    chunk_path /= base::EncodeToHex(chunk_name);
    std::ofstream ofs;
    ofs.open(chunk_path.string().c_str());
    ofs << chunk_content;
    ofs.close();
    chunks_[name] = chunk_name;
    printf("Chunk '%s' (%s) of size %llu KB created locally.\n", name.c_str(),
           HexSubstr(chunk_name).c_str(), chunk_size / 1024);
    WriteChunkList();
  }

  void Remove(const std::string &name) {
    if (chunks_.count(name) == 0) {
      printf("A chunk with name '%s' does not exist.\n", name.c_str());
      return;
    }

    std::string chunk_name(chunks_[name]);
    fs::path chunk_path(test_dir_);
    chunk_path /= base::EncodeToHex(chunk_name);
    fs::remove(chunk_path);
    chunks_.erase(name);
    printf("Chunk '%s' (%s) removed locally.\n", name.c_str(),
           HexSubstr(chunk_name).c_str());
    WriteChunkList();
  }

  void Store(const std::string &name) {
    if (chunks_.count(name) == 0) {
      printf("A chunk with name '%s' does not exist.\n", name.c_str());
      return;
    }
    
    std::string chunk_name(chunks_[name]);
    fs::path chunk_path(test_dir_);
    chunk_path /= base::EncodeToHex(chunk_name);
    if (client_->chunkstore->
            AddChunkToOutgoing(chunk_name, chunk_path) == kSuccess &&
        client_->msm->
            StoreChunk(chunk_name, maidsafe::PRIVATE, "") == kSuccess) {
      printf("Started storing chunk '%s' (%s)....\n", name.c_str(),
             HexSubstr(chunk_name).c_str());
    } else {
      printf("Could not store chunk '%s' (%s).\n", name.c_str(),
             HexSubstr(chunk_name).c_str());
    }
  }

  void Load() {
    if (chunks_.size() == 0) {
      printf("No chunks in list.\n");
      return;
    }

    for (std::map<std::string, std::string>::iterator it = chunks_.begin();
         it != chunks_.end(); ++it) {
      Load(it->first);
    }
  }

  void Load(const std::string &name) {
    if (chunks_.count(name) == 0) {
      printf("A chunk with name '%s' does not exist.\n", name.c_str());
      return;
    }

    std::string chunk_name(chunks_[name]);
    client_->chunkstore->DeleteChunk(chunk_name);
    std::string data;
    boost::uint64_t time_start = base::GetEpochMilliseconds();
    if (client_->msm->LoadChunk(chunk_name, &data) == kSuccess) {
      boost::uint64_t time_end = base::GetEpochMilliseconds();
      printf("Successfully loaded chunk '%s' (%s) in %.2fs.\n",
             name.c_str(), HexSubstr(chunk_name).c_str(),
             (time_end - time_start) / 1000.0);
    } else {
      printf("Could not load chunk '%s' (%s).\n", name.c_str(),
             HexSubstr(chunk_name).c_str());
      return;
    }
    if (crypto_.Hash(data, "", crypto::STRING_STRING, false) == chunk_name) {
      printf("Successfully verified chunk '%s'.\n", name.c_str());
    } else {
      printf("Could not verify chunk '%s'.\n", name.c_str());
    }
  }

  void Delete(const std::string&) {
    printf("Sorry, command not available yet.\n");
    // client_->msm->DeleteChunk()
  }

  void Account() {
    uint64_t offered, given, taken;
    client_->msm->GetAccountStatus(&offered, &given, &taken);
    printf("Space offered: %llu\n", offered);
    printf("Space given: %llu\n", given);
    printf("Space taken: %llu\n", taken);
  }

  void Rpc() {
    testpdclient::PrintRpcTimings(client_->msm->channel_manager_.RpcTimings());
  }

 private:
  void ReadChunkList() {
    std::string data(FileToString(test_dir_ / "chunks.cfg"));
    boost::tokenizer<> tok(data);
    std::string name, hash;
    int idx(0);
    for (boost::tokenizer<>::iterator it = tok.begin(); it != tok.end();
          ++it) {
      if (idx == 0)
        name = *it;
      else if (idx == 1)
        hash = base::DecodeFromHex(*it);
      ++idx;
      if (idx == 2) {
        if (!name.empty() && !hash.empty())
          chunks_[name] = hash;
        idx = 0;
        name.clear();
        hash.clear();
      }
    }
  }

  void WriteChunkList() {
    fs::path cfg(test_dir_);
    cfg /= "chunks.cfg";
    std::ofstream ofs;
    ofs.open(cfg.string().c_str());
    for (std::map<std::string, std::string>::iterator it = chunks_.begin();
         it != chunks_.end(); ++it) {
      ofs << it->first << ' ' << base::EncodeToHex(it->second) << '\n';
    }
    ofs.close();
  }

  bool ReadClientData(std::string *maid_priv, std::string *maid_pub,
                      std::string *pmid_priv, std::string *pmid_pub) {
    std::string data(FileToString(test_dir_ / "client.cfg"));
    boost::tokenizer<> tok(data);
    std::string fields[4];
    int idx(0);
    for (boost::tokenizer<>::iterator it = tok.begin(); it != tok.end();
          ++it) {
      if (idx < 4) {
        fields[idx] = base::DecodeFromHex(*it);
        ++idx;
      }
    }
    if (idx >= 4) {
      *maid_priv = fields[0];
      *maid_pub = fields[1];
      *pmid_priv = fields[2];
      *pmid_pub = fields[3];
      return true;
    } else {
      return false;
    }
  }

  void WriteClientData(const std::string &maid_priv,
                       const std::string &maid_pub,
                       const std::string &pmid_priv,
                       const std::string &pmid_pub) {
    fs::path cfg(test_dir_);
    cfg /= "client.cfg";
    std::ofstream ofs;
    ofs.open(cfg.string().c_str());
    ofs << base::EncodeToHex(maid_priv) << '\n'
        << base::EncodeToHex(maid_pub) << '\n'
        << base::EncodeToHex(pmid_priv) << '\n'
        << base::EncodeToHex(pmid_pub) << '\n';
    ofs.close();
  }

  std::string FileToString(const fs::path &file) {
    if (!fs::exists(file))
      return "";
    
    std::ifstream ifs;
    ifs.open(file.string().c_str());
    boost::uint64_t fsize(fs::file_size(file));
    boost::scoped_array<char> temp(new char[fsize]);
    ifs.read(temp.get(), fsize);
    ifs.close();
    return std::string(static_cast<const char*>(temp.get()), fsize);
  }
   
  RunPDClient(const RunPDClient&);
  RunPDClient &operator=(const RunPDClient&);
  fs::path test_dir_, kad_config_path_;
  base::KadConfig kad_config_;
  crypto::Crypto crypto_;
  boost::mutex mutex_;
  boost::posix_time::seconds single_function_timeout_;
  boost::shared_ptr<testpdclient::ClientData> client_;
  std::map<std::string, std::string> chunks_;
};

}  // namespace maidsafe_vault

int main(int argc, char* argv[]) {
  fs::path root_dir("TestClient");
  fs::path kad_config_path;
  printf("=== Test Client ===\n\n");
  if (argc <= 1) {
    printf("  This app sets up a client with data in folder \"%s\".\n\n",
           root_dir.string().c_str());
    printf("  To execute, call \"%s <kad config path>\"\n\n", argv[0]);
    return 0;
  } else {
    // load kad config
    std::string file(argv[1]);
    try {
      std::fstream infile(file.c_str(), std::ios::in | std::ios::binary);
      base::KadConfig kad_config;
      kad_config.ParseFromIstream(&infile);
      if (kad_config.contact_size()) {
        if (kad_config.contact(0).has_node_id()) {
          // printf("%s\n\n", kad_config.DebugString().c_str());
        } else {
          printf("%s is not a kadconfig file.\n", file.c_str());
          return -1;
        }
      } else {
          printf("%s is either not a kadconfig file, or it's empty.\n",
                  file.c_str());
          return -2;
      }
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    kad_config_path = file;
  }
  maidsafe::RunPDClient client(root_dir, kad_config_path);
  if (client.SetUp()) {
    bool stop(false);
    printf("\n");
    while (!stop) {
      std::cout << "client > ";
      std::string cmdline;
      std::getline(std::cin, cmdline);
      std::string cmd;
      std::vector<std::string> args;
      try {
        boost::char_separator<char> sep(" ");
        boost::tokenizer< boost::char_separator<char> > tok(cmdline, sep);
        for (boost::tokenizer< boost::char_separator<char> >::iterator
            it = tok.begin(); it != tok.end(); ++it) {
          if (it == tok.begin())
            cmd = *it;
          else
            args.push_back(*it);
        }
      }
      catch(const std::exception &ex) {
        printf("Error processing command: %s\n", ex.what());
        stop = true;
      }

      if (!stop) {
        int req_args(0);
        if (cmd == "exit" || cmd == "quit" || cmd == "q") {
          stop = true;
        } else if (cmd == "help") {
          printf("Available commands:\n"
                 "  list           show a list of previously created chunks\n"
                 "  create <name>  generate a new chunk with given name\n"
                 "  remove <name>  delete the named chunk locally\n"
                 "  store <name>   store a previously created chunk on the "
                 "network\n"
                 "  load [<name>]  load a chunk from the network\n"
                 "  delete <name>  delete a chunk from the network\n"
                 "  rpc            show timing statistics for executed RPCs\n"
                 "  account        show account status\n"
                 "  help           display this information\n"
                 "  exit, quit, q  terminate the application\n\n"
                 "The argument [name] signifies an arbitrary chunk name "
                 "used as substitute for the hexadecimal hash that identifies "
                 "a chunk on the network. Where it is optional, omitting it "
                 "refers to all known chunks.\n\n");
        } else if (cmd == "list") {
          client.List();
        } else if (cmd == "create") {
          if (args.size() >= 1)
            client.Create(args[0]);
          else
            req_args = 1;
        } else if (cmd == "remove") {
          if (args.size() >= 1)
            client.Remove(args[0]);
          else
            req_args = 1;
        } else if (cmd == "store") {
          if (args.size() >= 1)
            client.Store(args[0]);
          else
            req_args = 1;
        } else if (cmd == "load") {
          if (args.size() >= 1)
            client.Load(args[0]);
          else
            client.Load();
        } else if (cmd == "delete") {
          if (args.size() >= 1)
            client.Delete(args[0]);
          else
            req_args = 1;
        } else if (cmd == "rpc") {
          client.Rpc();
        } else if (cmd == "account") {
          client.Account();
        } else if (!cmd.empty()) {
          printf("Unknown command: %s\n"
                 "Type 'help' to see a list of commands.\n",
                 cmd.c_str());
        }
        if (req_args > 0) {
          printf("Command '%s' requires %d arguments, got %d.\n"
                 "Type 'help' to see a list of commands.\n",
                 cmd.c_str(), req_args, args.size());
        }
      }
    }
  } else {
    printf("\nError during client setup. Terminating...\n\n");
  }
  client.TearDown();
  return 0;
}
