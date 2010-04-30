/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for pdvault
* Version:      1.0
* Created:      2009-03-23-21.28.20
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

#include <boost/progress.hpp>
#include <gtest/gtest.h>
#include <maidsafe/base/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/base/utils.h>

#include <map>
#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/kadops.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/clientrpc.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/systempackets.h"
#include "maidsafe/vault/pdvault.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/localvaults.h"
#include "tests/maidsafe/mocksessionsingleton.h"

static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static std::string callback_content_ = "";
static bool callback_prepared_ = false;
static boost::mutex callback_mutex_;
static std::list<std::string> callback_packets_;
static std::list<std::string> callback_messages_;

namespace testpdvault {

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
      maid_keys() {}
  std::string chunkstore_dir;
  maidsafe::MockSessionSingleton mss;
  std::string pmid_pub_key, pmid_priv_key, pmid_pub_key_sig, pmid_name;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> msm;
  crypto::RsaKeyPair pmid_keys, maid_keys;
};

inline void DeleteCallback(const std::string &result) {
  maidsafe::DeleteChunkResponse resp;
  if (!resp.ParseFromString(result) || resp.result() != kAck) {
    callback_succeeded_ = false;
    callback_timed_out_ = false;
  } else {
    callback_succeeded_ = true;
    callback_timed_out_ = false;
  }
}

void PrepareCallbackResults() {
  callback_timed_out_ = true;
  callback_succeeded_ = false;
  callback_content_.clear();
  callback_prepared_ = true;
  callback_packets_.clear();
  callback_messages_.clear();
}

static void GeneralCallback(const std::string &result) {
  maidsafe::GenericResponse result_msg;
  if ((!result_msg.ParseFromString(result)) || (result_msg.result() != kAck)) {
    callback_succeeded_ = false;
    callback_timed_out_ = false;
  } else {
    callback_succeeded_ = true;
    callback_timed_out_ = false;
  }
}

static void GetChunkCallback(bool *finished) {
  *finished = true;
}

void DeadRvNotifier(const bool&, const std::string&, const boost::uint16_t&) {}

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

void MakeChunks(const std::vector< boost::shared_ptr<ClientData> > &clients,
                int no_of_chunks,
                const fs::path &test_root_dir,
                std::map<std::string, std::string> *chunks) {
  crypto::Crypto cryobj_;
  cryobj_.set_hash_algorithm(crypto::SHA_512);
  cryobj_.set_symm_algorithm(crypto::AES_256);
  for (int i = 0; i < no_of_chunks; ++i) {
    std::string chunk_content = base::RandomString(100 + i);
    std::string chunk_name = cryobj_.Hash(chunk_content, "",
                                          crypto::STRING_STRING, false);
    fs::path chunk_path(test_root_dir / base::EncodeToHex(chunk_name));
    printf("Chunk %i - %s\n", i, HexSubstr(chunk_name).c_str());
    std::ofstream ofs_;
    ofs_.open(chunk_path.string().c_str());
    ofs_ << chunk_content;
    ofs_.close();
    for (size_t j = 0; j < clients.size(); ++j)
      clients[j]->chunkstore->AddChunkToOutgoing(chunk_name, chunk_path);
    chunks->insert(std::pair<std::string, std::string>
        (chunk_name, chunk_content));
  }
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

}  // namespace testpdvault

namespace maidsafe_vault {

static std::vector< boost::shared_ptr<PDVault> > pdvaults_;
static const int kNumOfClients = 2;
static const int kNetworkSize = kad::K + kNumOfClients;
static const int kNumOfTestChunks = kNetworkSize + 1;
/**
 * Note: StoreAndGetChunks only works for small K due to resource problems
 *       Recommended are K = 8 and kMinSuccessfulPecentageStore = 50%
 */

class PDVaultTest : public testing::Test {
 protected:
  PDVaultTest() : test_root_dir_(file_system::TempDir() /
                      ("maidsafe_TestVault_" + base::RandomString(6))),
                  clients_(),
                  mutex_(),
                  crypto_() {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::create_directories(test_root_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);

    for (int i = 0; i < kNumOfClients; ++i) {
      {
        boost::shared_ptr<testpdvault::ClientData>
            client(new testpdvault::ClientData(test_root_dir_.string()));
        clients_.push_back(client);
      }
      printf("Generating MAID Keys for client %d of %d...\n", i + 1,
             kNumOfClients);
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
             kNumOfClients);
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
    // maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  virtual ~PDVaultTest() {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }

  virtual void SetUp() {
    // stop the vaults that will be replaced
    for (int i = kNetworkSize - kNumOfClients; i < kNetworkSize; ++i) {
      pdvaults_[i]->Stop();
    }

    // look up the stopped vaults to flush routing tables
    for (int i = 0; i < kNetworkSize - kNumOfClients; ++i) {
      for (int j = kNetworkSize - kNumOfClients; j < kNetworkSize; ++j) {
        maidsafe::CallbackObj cb;
        pdvaults_[i]->kad_ops_->GetNodeContactDetails(
            kad::KadId(pdvaults_[i]->pmid_, false),
            boost::bind(&maidsafe::CallbackObj::CallbackFunc, &cb, _1),
            false);
        cb.WaitForCallback();
      }
    }

    // create each client and take over a vault
    for (int i = 0; i < kNumOfClients; ++i) {
      printf("Setting up client %d of %d...\n", i + 1, kNumOfClients);
      clients_[i]->chunkstore = boost::shared_ptr<maidsafe::ChunkStore>
          (new maidsafe::ChunkStore(clients_[i]->chunkstore_dir, 0, 0));
      ASSERT_TRUE(clients_[i]->chunkstore->Init());
      boost::shared_ptr<maidsafe::MaidsafeStoreManager>
          sm_local_(new maidsafe::MaidsafeStoreManager(
                    clients_[i]->chunkstore));
      clients_[i]->msm = sm_local_;
      clients_[i]->msm->ss_ = &clients_[i]->mss;
      testpdvault::PrepareCallbackResults();
      clients_[i]->msm->Init(0, boost::bind(&testpdvault::GeneralCallback, _1),
                             "");
      testpdvault::WaitFunction(60, &mutex_);
      ASSERT_TRUE(callback_succeeded_);
      ASSERT_FALSE(callback_timed_out_);

      // poor man's vault takeover
      const size_t vlt(kNetworkSize - kNumOfClients + i);
      printf("Taking over vault #%d: %s => %s\n", vlt,
             HexSubstr(pdvaults_[vlt]->pmid_).c_str(),
             HexSubstr(clients_[i]->pmid_name).c_str());
      // pdvaults_[vlt]->Stop();
      fs::path dir(pdvaults_[vlt]->vault_chunkstore_.ChunkStoreDir());
      boost::uint64_t used(pdvaults_[vlt]->vault_chunkstore_.used_space());
      boost::uint64_t avlb(pdvaults_[vlt]->vault_chunkstore_.available_space());
      fs::path kad_cfg(pdvaults_[vlt]->kad_config_file_);
      pdvaults_[vlt].reset(new PDVault(clients_[i]->pmid_pub_key,
                                       clients_[i]->pmid_priv_key,
                                       clients_[i]->pmid_pub_key_sig, dir, 0,
                                       false, false, kad_cfg, avlb, used));
      pdvaults_[vlt]->Start(false);
    }

    // wait for the vaults to restart
    for (int i = 0; i < kNumOfClients; ++i) {
      const size_t vlt(kNetworkSize - kNumOfClients + i);
      int n(0);
      while (pdvaults_[vlt]->vault_status() != kVaultStarted && n < 10) {
        n++;
        boost::this_thread::sleep(boost::posix_time::seconds(1));
      }
      ASSERT_EQ(kVaultStarted, pdvaults_[vlt]->vault_status());
      printf("Vault #%d restarted.\n", vlt);
    }

    printf("--- SetUp completed. ---\n\n");
  }

  virtual void TearDown() {
    for (int i = 0; i < kNumOfClients; ++i) {
      testpdvault::PrepareCallbackResults();
      clients_[i]->msm->Close(boost::bind(&testpdvault::GeneralCallback, _1),
                             true);
      testpdvault::WaitFunction(60, &mutex_);
      ASSERT_TRUE(callback_succeeded_);
      ASSERT_FALSE(callback_timed_out_);
    }
  }

  fs::path test_root_dir_;
  std::vector< boost::shared_ptr<testpdvault::ClientData> > clients_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;

 private:
  PDVaultTest(const PDVaultTest&);
  PDVaultTest &operator=(const PDVaultTest&);
};

TEST_F(PDVaultTest, FUNC_MAID_VaultStartStop) {
  // check pdvaults can be started and stopped multiple times
  bool success_(false);
  const int kTestVaultNo(kNetworkSize / 2);
  for (int loop = 0; loop < 7; ++loop) {
    success_ = false;
    pdvaults_[kTestVaultNo]->Stop();
    ASSERT_NE(kVaultStarted, pdvaults_[kTestVaultNo]->vault_status());
    printf("Vault stopped - iteration %i.\n", loop+1);
    pdvaults_[kTestVaultNo]->Start(false);
    ASSERT_EQ(kVaultStarted, pdvaults_[kTestVaultNo]->vault_status());
    printf("Vault started - iteration %i.\n", loop+1);
  }
}

TEST_F(PDVaultTest, FUNC_MAID_StoreAndGetChunks) {
  std::map<std::string, std::string> chunks;
  testpdvault::MakeChunks(clients_, kNumOfTestChunks, test_root_dir_, &chunks);

  boost::uint64_t data_size(0);
  std::map<std::string, std::string>::iterator it;
  for (it = chunks.begin(); it != chunks.end(); ++it) {
    data_size += (*it).second.size();
  }

  // wait for account creation of our vaults
  printf("Waiting for account creation...\n");
  boost::this_thread::sleep(boost::posix_time::seconds(20));

  // make sure accounts for clients are in the right places
  printf("\n-- Checking accounts locally... --\n");
  for (int i = 0; i < kNumOfClients; ++i) {
    std::string client_pmid(pdvaults_[kNetworkSize - kNumOfClients + i]->pmid_);
    std::string account_name(crypto_.Hash(client_pmid + kAccount, "",
                                          crypto::STRING_STRING, false));
    printf("Client %s, account %s:\n", HexSubstr(client_pmid).c_str(),
           HexSubstr(account_name).c_str());
    std::set<std::string> closest;
    std::vector<kad::Contact> contacts;
    clients_[i]->msm->kad_ops_->FindKClosestNodes(
        kad::KadId(account_name, false), &contacts);
    for (size_t j = 0; j < contacts.size(); ++j) {
      closest.insert(contacts[j].node_id().ToStringDecoded());
    }
    for (int j = 0; j < kNetworkSize; ++j) {
      bool client = pdvaults_[j]->pmid_ == client_pmid;
      bool holder = pdvaults_[j]->vault_service_->HaveAccount(client_pmid);
      bool close = closest.count(pdvaults_[j]->pmid_) == 1;
      printf(" Vault %s%s%s%s\n", HexSubstr(pdvaults_[j]->pmid_).c_str(),
             client ? " - client's" : "",
             holder ? " - holder" : "",
             close ? " - close" : "");
      // ASSERT_FALSE(close && !(!holder ^ !client));
    }
  }

  // store chunks to network with each client
  for (int i = 0; i < kNumOfClients; ++i)
    for (it = chunks.begin(); it != chunks.end(); ++it)
      clients_[i]->msm->StoreChunk((*it).first, maidsafe::PRIVATE, "");
  printf("\n-- Enqueued %s chunks for storing, total %s bytes. --\n",
         boost::lexical_cast<std::string>(kNumOfTestChunks).c_str(),
         boost::lexical_cast<std::string>(data_size).c_str());

  printf("\nWaiting for chunks to get stored...\n");
  boost::this_thread::sleep(boost::posix_time::seconds(15));

  printf("\nChecking chunks locally...\n");

  // checking for chunks
  std::set<std::string> stored_chunks;
  int iteration = 0;
  while (stored_chunks.size() < chunks.size() && iteration < 18) {
    ++iteration;
    printf("\n-- Sleeping iteration %i --\n\n", iteration);
    boost::this_thread::sleep(boost::posix_time::seconds(10));

    for (it = chunks.begin(); it != chunks.end(); ++it) {
      int chunk_count(0);
      std::vector<std::string> values;

      for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
        if (stored_chunks.count((*it).first) == 0 &&
            pdvaults_[vault_no]->vault_chunkstore_.Has((*it).first)) {
          printf("Vault %d (%s) has chunk %s.\n", vault_no,
                 HexSubstr(pdvaults_[vault_no]->pmid_).c_str(),
                 HexSubstr((*it).first).c_str());
          ++chunk_count;
        }
      }

      if (stored_chunks.count((*it).first) == 0) {
        if (chunk_count >= kNumOfClients) {
          stored_chunks.insert((*it).first);
        } else {
          printf("Only %d copies of %s stored so far.\n", chunk_count,
                 HexSubstr((*it).first).c_str());
        }
      }
    }
  }

  ASSERT_EQ(chunks.size(), stored_chunks.size());
  stored_chunks.clear();

  printf("\nTrying to retrieve stored chunks...\n");

  // Check each chunk can be retrieved correctly
  for (int i = 0; i < kNumOfClients; ++i) {
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      ASSERT_EQ(0, clients_[i]->chunkstore->DeleteChunk((*it).first));
      printf(">> Client %d, getting chunk %s\n", i + 1,
             HexSubstr((*it).first).c_str());
      std::string data;
      ASSERT_EQ(0, clients_[i]->msm->LoadChunk((*it).first, &data));
      ASSERT_EQ(data, (*it).second);
      ASSERT_EQ((*it).first, crypto_.Hash(data, "", crypto::STRING_STRING,
                                          false));
    }
  }

  printf("\nMaking each chunk unique, but keep references...\n");

  // Remove all but one copy of each chunk, but leave reference list showing
  // multiple chunk holders.
  for (it = chunks.begin(); it != chunks.end(); ++it) {
    bool first_copy(true);
    for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
      if (pdvaults_[vault_no]->vault_chunkstore_.Has((*it).first)) {
        if (first_copy) {
          first_copy = false;
          continue;
        }
        printf(">> Deleting chunk %s from vault %d\n",
               HexSubstr((*it).first).c_str(), vault_no);
        ASSERT_EQ(0, pdvaults_[vault_no]->
            vault_chunkstore_.DeleteChunk((*it).first));
      }
    }
  }

  printf("\nTrying to retrieve stored (unique) chunks...\n");

  // Check each chunk can (still) be retrieved correctly
  for (int i = 0; i < kNumOfClients; ++i) {
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      ASSERT_EQ(0, clients_[i]->chunkstore->DeleteChunk((*it).first));
      printf(">> Client %d, getting chunk %s\n", i + 1,
             HexSubstr((*it).first).c_str());
      std::string data;
      ASSERT_EQ(0, clients_[i]->msm->LoadChunk((*it).first, &data));
      ASSERT_EQ(data, (*it).second);
      ASSERT_EQ((*it).first, crypto_.Hash(data, "", crypto::STRING_STRING,
                                          false));
    }
  }

  if (kNumOfClients >= 2 && kNumOfTestChunks >= 2) {
    printf("\nRemoving all chunks except one...\n");

    // Remove all copies of each chunk except the first one, but leave reference
    // list showing multiple chunk holders.
    bool first_chunk(true);
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has((*it).first)) {
          if (first_chunk) {
            first_chunk = false;
            continue;
          }
          printf(">> Deleting chunk %s from vault %d\n",
                 HexSubstr((*it).first).c_str(), vault_no);
          ASSERT_EQ(0, pdvaults_[vault_no]->
              vault_chunkstore_.DeleteChunk((*it).first));
        }
      }
    }

    printf("\nTrying to retrieve first chunk, fail other chunks...\n");

    // Check only first chunk can be retrieved from the net
    for (int i = 0; i < kNumOfClients; ++i) {
      for (it = chunks.begin(); it != chunks.end(); ++it) {
        ASSERT_EQ(0, clients_[i]->chunkstore->DeleteChunk((*it).first));
        printf(">> Client %d, getting chunk %s\n", i + 1,
               HexSubstr((*it).first).c_str());
        std::string data;
        if (it == chunks.begin()) {
          ASSERT_EQ(0, clients_[i]->msm->LoadChunk((*it).first, &data));
          ASSERT_EQ(data, (*it).second);
          ASSERT_EQ((*it).first, crypto_.Hash(data, "", crypto::STRING_STRING,
                                              false));
        } else {
          ASSERT_NE(0, clients_[i]->msm->LoadChunk((*it).first, &data));
        }
      }
    }
  }

  for (int i = 0; i < kNumOfClients; ++i) {
    printf("\nStatistics for client %d:\n", i + 1);
    testpdvault::PrintRpcTimings(
        clients_[i]->msm->channel_manager_.RpcTimings());
  }
  for (int i = 0; i < kNetworkSize; ++i) {
    printf("\nStatistics for vault %d:\n", i);
    testpdvault::PrintRpcTimings(
        pdvaults_[i]->channel_manager_.RpcTimings());
  }
}

TEST_F(PDVaultTest, FUNC_MAID_Cachechunk) {
  transport::TransportUDT udt_transport;
  transport::TransportHandler transport_handler;
  boost::int16_t trans_id;
  transport_handler.Register(&udt_transport, &trans_id);
  rpcprotocol::ChannelManager channel_manager(&transport_handler);
  maidsafe::ClientRpcs client_rpcs(&transport_handler, &channel_manager);
  ASSERT_TRUE(transport_handler.RegisterOnServerDown(boost::bind(
              &testpdvault::DeadRvNotifier, _1, _2, _3)));
  ASSERT_TRUE(channel_manager.RegisterNotifiersToTransport());
  ASSERT_EQ(0, transport_handler.Start(0, trans_id));
  ASSERT_EQ(0, channel_manager.Start());

  boost::uint16_t cache_vault_index(0), chunk_vault_index(0);
  cache_vault_index = base::RandomUint32() % kNetworkSize;
  while (chunk_vault_index == 0 || cache_vault_index == chunk_vault_index)
    chunk_vault_index = base::RandomUint32() % kNetworkSize;

  kad::ContactInfo kc_cacher_vault;
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content(base::RandomString(10000));
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  while (pdvaults_[chunk_vault_index]->vault_chunkstore_.Has(chunkname)) {
    content = base::RandomString(10000);
    chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
  }

  ASSERT_EQ(kSuccess,
            pdvaults_[chunk_vault_index]->vault_chunkstore_.Store(chunkname,
                                                                  content));
  kc_cacher_vault = pdvaults_[cache_vault_index]->knode_->contact_info();
  std::string ser_kc_cacher_vault = kc_cacher_vault.SerializeAsString();

  kad::Contact peer(pdvaults_[chunk_vault_index]->knode_->contact_info());
  maidsafe::GetChunkRequest request;
  request.set_chunkname(chunkname);
  request.set_serialised_cacher_contact(ser_kc_cacher_vault);
  maidsafe::GetChunkResponse response;
  rpcprotocol::Controller controller;
  bool finished(false);
  google::protobuf::Closure *done =
      google::protobuf::NewCallback(&testpdvault::GetChunkCallback, &finished);
  client_rpcs.GetChunk(peer, false, trans_id, &request, &response, &controller,
                       done);

  while (!finished)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(static_cast<boost::uint32_t>(kAck), response.result());
  ASSERT_EQ(content, response.content());
  ASSERT_EQ(pdvaults_[chunk_vault_index]->pmid_, response.pmid());

  boost::progress_timer t;
  while (!pdvaults_[cache_vault_index]->vault_chunkstore_.Has(chunkname) &&
         t.elapsed() < 5)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_TRUE(pdvaults_[cache_vault_index]->vault_chunkstore_.Has(chunkname));

  transport_handler.StopAll();
  channel_manager.Stop();
}

//  TEST_F(PDVaultTest, DISABLED_FUNC_MAID_SwapChunk) {
//  }
//
//  TEST_F(PDVaultTest, DISABLED_FUNC_MAID_VaultValidateChunk) {
//    // check pre-loaded chunks are not corrupted
//  }
//
//  TEST_F(PDVaultTest, DISABLED_FUNC_MAID_VaultRepublishChunkRef) {
//  }

}  // namespace maidsafe_vault

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(maidsafe_vault::kNetworkSize,
                           &maidsafe_vault::pdvaults_));
  return RUN_ALL_TESTS();
}
