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
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/base/utils.h>

#include <map>
#include <vector>

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/kadops.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/client/clientrpc.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/pdvault.h"
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/sharedtest/cached_keys.h"
#include "maidsafe/sharedtest/localvaults.h"
#include "maidsafe/sharedtest/mocksessionsingleton.h"
#include "maidsafe/sharedtest/networktest.h"
#include "maidsafe/sharedtest/testcallback.h"

static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static std::string callback_content_ = "";
static bool callback_prepared_ = false;
static boost::mutex callback_mutex_;
static std::list<std::string> callback_packets_;
static std::list<std::string> callback_messages_;

namespace testpdvault {

static const boost::uint8_t K(4);

struct ClientData {
  explicit ClientData(const std::string &root_dir)
    : chunkstore_dir(root_dir + "/ClientChunkstore_" +
                     base::RandomAlphaNumericString(8)),
      mss(),
      chunkstore(),
      msm(),
      pmid_keys(),
      maid_keys() {}
  std::string chunkstore_dir;
  maidsafe::MockSessionSingleton mss;
  // std::string pmid_pub_key, pmid_priv_key, pmid_pub_key_sig, pmid_name;
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> msm;
  crypto::RsaKeyPair pmid_keys, maid_keys;
};

inline void DeleteCallback(const std::string &result) {
  maidsafe::DeleteChunkResponse resp;
  if (!resp.ParseFromString(result) || resp.result() != maidsafe::kAck) {
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

static void GeneralCallback(const maidsafe::ReturnCode &result) {
  if (result != maidsafe::kSuccess) {
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
  for (int i = 0; i < no_of_chunks; ++i) {
    std::string chunk_content = base::RandomString(100 + i);
    std::string chunk_name = maidsafe::SHA512String(chunk_content);
    fs::path chunk_path(test_root_dir / base::EncodeToHex(chunk_name));
    printf("Chunk %i - %s\n", i, maidsafe::HexSubstr(chunk_name).c_str());
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

}  // namespace testpdvault

namespace maidsafe {

namespace vault {

namespace test {

static std::vector< boost::shared_ptr<PDVault> > pdvaults_;
static const int kNumOfClients = 1;
static const int kNetworkSize = 2 * testpdvault::K + kNumOfClients;
static const int kNumOfTestChunks = kNetworkSize * 1.5;
static boost::filesystem::path kadconfig_;

class PDVaultTest : public testing::Test {
 protected:
  PDVaultTest() : test_root_dir_(file_system::TempDir() / ("maidsafe_TestVault_"
                                 + base::RandomAlphaNumericString(6))),
                  clients_(),
                  mutex_() {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::create_directories(test_root_dir_);

    for (int i = 0; i < kNumOfClients; ++i) {
      {
        boost::shared_ptr<testpdvault::ClientData>
            client(new testpdvault::ClientData(test_root_dir_.string()));
        clients_.push_back(client);
      }
      clients_[i]->mss.CreateTestPackets("");
      printf("MAID Keys for client %d of %d:\n", i + 1, kNumOfClients);
      printf(" >> public key:   %s\n", HexSubstr(clients_[i]->
             mss.PublicKey(passport::MAID, true)).c_str());
      printf(" >> pub key sig:  %s\n", HexSubstr(clients_[i]->
             mss.PublicKeySignature(passport::MAID, true)).c_str());
      printf(" >> hash/name:    %s\n", HexSubstr(clients_[i]->
             mss.Id(passport::MAID, true)).c_str());

      printf("PMID Keys for client %d of %d:\n", i + 1, kNumOfClients);
      printf(" >> public key:   %s\n", HexSubstr(clients_[i]->
             mss.PublicKey(passport::PMID, true)).c_str());
      printf(" >> pub key sig:  %s\n", HexSubstr(clients_[i]->
             mss.PublicKeySignature(passport::PMID, true)).c_str());
      printf(" >> hash/name:    %s\n", HexSubstr(clients_[i]->
             mss.Id(passport::PMID, true)).c_str());
      clients_[i]->mss.SetConnectionStatus(0);
    }
    // SessionSingleton::getInstance()->SetConnectionStatus(0);
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
        kad::Contact contact;
        pdvaults_[i]->kad_ops_->BlockingGetNodeContactDetails(
            pdvaults_[i]->pmid_, &contact, false);
      }
    }

    // create each client and take over a vault
    for (int i = 0; i < kNumOfClients; ++i) {
      printf("Setting up client %d of %d...\n", i + 1, kNumOfClients);
      clients_[i]->chunkstore = boost::shared_ptr<ChunkStore>
          (new ChunkStore(clients_[i]->chunkstore_dir, 0, 0));
      ASSERT_TRUE(clients_[i]->chunkstore->Init());
      boost::shared_ptr<MaidsafeStoreManager>
          sm_local_(new MaidsafeStoreManager(
                    clients_[i]->chunkstore, testpdvault::K));
      clients_[i]->msm = sm_local_;
      clients_[i]->msm->ss_ = &clients_[i]->mss;

      // poor man's vault takeover
      const size_t vlt(kNetworkSize - kNumOfClients + i);
      printf("Taking over vault #%d: %s => %s\n", vlt,
             HexSubstr(pdvaults_[vlt]->pmid_).c_str(),
             HexSubstr(clients_[i]->
                mss.PublicKey(passport::PMID, true)).c_str());
      // pdvaults_[vlt]->Stop();
      fs::path dir(pdvaults_[vlt]->vault_chunkstore_->ChunkStoreDir());
      boost::uint16_t port(pdvaults_[vlt]->port_);
      boost::uint64_t used(pdvaults_[vlt]->vault_chunkstore_->used_space());
      boost::uint64_t avlb(
          pdvaults_[vlt]->vault_chunkstore_->available_space());
      fs::path kad_cfg(pdvaults_[vlt]->kad_config_file_);
      pdvaults_[vlt].reset(new PDVault(
          clients_[i]->mss.PublicKey(passport::PMID, true),
          clients_[i]->mss.PrivateKey(passport::PMID, true),
          clients_[i]->mss.PublicKeySignature(passport::PMID, true),
          dir, port, false, false, kad_cfg, avlb, used, testpdvault::K));
      pdvaults_[vlt]->Start(false);
    }

    // wait for the vaults to restart, and init client's store manager
    for (int i = 0; i < kNumOfClients; ++i) {
      const size_t vlt(kNetworkSize - kNumOfClients + i);
      ASSERT_TRUE(pdvaults_[vlt]->WaitForStartup(10));
      printf("Vault #%d restarted.\n", vlt);
      testpdvault::PrepareCallbackResults();
      clients_[i]->msm->Init(boost::bind(&testpdvault::GeneralCallback, _1),
                             7000 + kNetworkSize + i);
      testpdvault::WaitFunction(60, &mutex_);
      ASSERT_TRUE(callback_succeeded_);
      ASSERT_FALSE(callback_timed_out_);
    }

    // wait for the vaults to sync
    for (int i = 0; i < kNumOfClients; ++i) {
      const size_t vlt(kNetworkSize - kNumOfClients + i);
      ASSERT_TRUE(pdvaults_[vlt]->WaitForSync());
      printf("Vault #%d synced.\n", vlt);
    }

    // let the vaults create their accounts again, to include new vaults
    for (int i = 0; i < kNetworkSize; ++i) {
      ASSERT_EQ(kSuccess, pdvaults_[i]->AmendAccount(
          pdvaults_[i]->available_space()));
    }

    // wait for internal contact lists to be updated
    for (int i = 0; i < kNumOfClients; ++i) {
      while (clients_[i]->msm->
                account_holders_manager_.account_holder_group().size() <
                clients_[i]->msm->kUpperThreshold_)
        boost::this_thread::sleep(boost::posix_time::seconds(2));
      clients_[i]->msm->own_vault_.WaitForUpdate();
    }

    printf("\n--- SetUp completed. ---\n\n");
  }

  virtual void TearDown() {
    for (int i = 0; i < kNumOfClients; ++i) {
      printf("\nStatistics for client %d:\n", i + 1);
      maidsafe::test::localvaults::PrintRpcTimings(
          clients_[i]->msm->channel_manager_.RpcTimings());
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

 private:
  PDVaultTest(const PDVaultTest&);
  PDVaultTest &operator=(const PDVaultTest&);
};

TEST_MS_NET(PDVaultTest, FUNC, MAID, Dummy) {
  boost::this_thread::sleep(boost::posix_time::seconds(1));
}

TEST_MS_NET(PDVaultTest, FUNC, MAID, StoreAndGetChunks) {
  std::map<std::string, std::string> chunks;
  testpdvault::MakeChunks(clients_, kNumOfTestChunks, test_root_dir_, &chunks);

  boost::uint64_t data_size(0);
  std::map<std::string, std::string>::iterator it;
  for (it = chunks.begin(); it != chunks.end(); ++it) {
    data_size += (*it).second.size();
  }

  // make sure accounts are in the right places
  std::map<std::string, int> client_pmids;
  printf("\n-- Checking accounts locally... --\n");
  for (int i = 0; i < kNumOfClients; ++i)
    client_pmids[pdvaults_[kNetworkSize - kNumOfClients + i]->pmid_] = i;
  for (int i = 0; i < kNetworkSize; ++i) {
    std::string pmid(pdvaults_[i]->pmid_);
    std::string account_name(SHA512String(pmid + kAccount));
    std::string client_idx(client_pmids.count(pmid) > 0 ?
      " - client " + base::IntToString(client_pmids[pmid]) : "");
    printf("Account for %s (name %s)%s:\n", HexSubstr(pmid).c_str(),
           HexSubstr(account_name).c_str(), client_idx.c_str());
    
    std::set<std::string> closest;
    std::vector<kad::Contact> contacts;
    pdvaults_[i]->kad_ops_->BlockingFindKClosestNodes(account_name, &contacts);
    for (size_t j = 0; j < contacts.size(); ++j) {
      closest.insert(contacts[j].node_id().String());
    }
    int correct_holders(0);
    for (int j = 0; j < kNetworkSize; ++j) {
      bool subject = pdvaults_[j]->pmid_ == pmid;
      bool holder = pdvaults_[j]->vault_service_->HaveAccount(pmid);
      bool close = closest.count(pdvaults_[j]->pmid_) == 1;
      printf(" Vault %s%s%s%s\n", HexSubstr(pdvaults_[j]->pmid_).c_str(),
             subject ? " - subject" : "",
             holder ? " - holder" : "",
             close ? " - close" : "");
      // EXPECT_TRUE(!close || holder || subject);
      // EXPECT_FALSE(!close && holder);
      EXPECT_FALSE(subject && holder);
      if (close && holder)
        ++correct_holders;
    }
    EXPECT_LE(testpdvault::K * kMinSuccessfulPecentageStore, correct_holders);
  }

  // store chunks to network with each client
  for (int i = 0; i < kNumOfClients; ++i)
    for (it = chunks.begin(); it != chunks.end(); ++it)
      clients_[i]->msm->StoreChunk((*it).first, PRIVATE, "");
  printf("\n-- Enqueued %s chunks for storing, total %s bytes. --\n",
         boost::lexical_cast<std::string>(kNumOfTestChunks).c_str(),
         boost::lexical_cast<std::string>(data_size).c_str());

  printf("\nWaiting for chunks to get stored...\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));

  printf("\nChecking chunks locally...\n");
  // TODO(Team#5#): use callback/signal at end of StoreChunk instead
  std::set<std::string> stored_chunks;
  int iteration = 0;
  const int kMaxIterations = 18;  // 3 minutes
  int remaining_tasks = 1;
  while ((stored_chunks.size() < chunks.size() || remaining_tasks > 0) &&
         iteration < kMaxIterations) {
    ++iteration;
    printf("\n[ Sleeping iteration %i of %i ]\n\n", iteration, kMaxIterations);
    boost::this_thread::sleep(boost::posix_time::seconds(10));

    // get amendment results
    for (int i = 0; i < kNumOfClients; ++i)
      clients_[i]->msm->account_status_manager_.Update();

    for (it = chunks.begin(); it != chunks.end(); ++it) {
      int chunk_count(0);
      std::vector<std::string> values;

      for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
        if (stored_chunks.count((*it).first) == 0 &&
            pdvaults_[vault_no]->vault_chunkstore_->Has((*it).first)) {
          printf("# Vault %d (%s) has chunk %s.\n", vault_no,
                 HexSubstr(pdvaults_[vault_no]->pmid_).c_str(),
                 HexSubstr((*it).first).c_str());
          ++chunk_count;
        }
      }

      if (stored_chunks.count((*it).first) == 0) {
        if (chunk_count >= kNumOfClients) {
          stored_chunks.insert((*it).first);
        } else {
          printf("# Only %d copies of %s stored so far.\n", chunk_count,
                 HexSubstr((*it).first).c_str());
        }
      }
    }

    remaining_tasks = 0;
    for (int i = 0; i < kNumOfClients; ++i) {
      remaining_tasks += clients_[i]->msm->tasks_handler_.TasksCount();
      printf("# %d storing tasks remaining on client %d.\n",
             clients_[i]->msm->tasks_handler_.TasksCount(), i);
      for (it = chunks.begin(); it != chunks.end(); ++it) {
        maidsafe::TaskId task_id(clients_[i]->msm->tasks_handler_.
            GetOldestActiveTaskByDataNameAndType(
                (*it).first, maidsafe::kSpaceTakenIncConfirmation));
        if (task_id != maidsafe::kRootTask) {
          boost::uint8_t successes_required, max_failures, success_count,
              failures_count;
          clients_[i]->msm->tasks_handler_.GetTaskProgress(task_id,
              &successes_required, &max_failures,
              &success_count, &failures_count);
          printf("# -> chunk %s: %d of %d succ, %d of %d fail\n",
                 HexSubstr((*it).first).c_str(), success_count,
                 successes_required, failures_count, max_failures);
        }
      }
    }
  }

  EXPECT_EQ(0, remaining_tasks);
  EXPECT_EQ(chunks.size(), stored_chunks.size());
  stored_chunks.clear();

  printf("\nProcess pending amend account requests...\n");
  for (int i = 0; i < kNetworkSize; ++i) {
    pdvaults_[i]->vault_service_->aah_.CleanUp();
  }
  boost::this_thread::sleep(boost::posix_time::seconds(3));

  printf("\nGenerating chunk info inventory...\n");
  for (int i = 0; i < kNetworkSize; ++i) {
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      ChunkInfo ci;
      if (pdvaults_[i]->vault_service_->cih_.GetChunkInfo(it->first, &ci) ==
          kSuccess) {
        printf("# Vault %d (%s) has chunk info %s:\n", i,
                HexSubstr(pdvaults_[i]->pmid_).c_str(),
                HexSubstr((*it).first).c_str());
        for (std::list<ReferenceListEntry>::iterator ref =
                ci.reference_list.begin(); ref != ci.reference_list.end();
                ++ref) {
          printf("  - reference %s\n", HexSubstr(ref->pmid).c_str());
        }
        for (std::list<WatchListEntry>::iterator wtch =
                ci.watch_list.begin(); wtch != ci.watch_list.end(); ++wtch) {
          printf("  - watcher %s%s\n", HexSubstr(wtch->pmid).c_str(),
                 wtch->can_delete ? " (can delete)" : "");
        }
        for (std::list<WaitingListEntry>::iterator wait =
                ci.waiting_list.begin(); wait != ci.waiting_list.end();
                ++wait) {
          printf("  - waiting %s\n", HexSubstr(wait->pmid).c_str());
        }
      }
    }
  }

  printf("\nTrying to retrieve stored chunks...\n");
  for (int i = 0; i < kNumOfClients; ++i) {
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      ASSERT_EQ(0, clients_[i]->chunkstore->DeleteChunk((*it).first));
      printf(">> Client %d, getting chunk %s\n", i + 1,
             HexSubstr((*it).first).c_str());
      std::string data;
      ASSERT_EQ(0, clients_[i]->msm->LoadChunk((*it).first, &data));
      ASSERT_EQ(data, (*it).second);
      ASSERT_EQ((*it).first, SHA512String(data));
    }
  }

  printf("\nMaking each chunk unique, but keep references...\n");
  // Remove all but one copy of each chunk, but leave reference list showing
  // multiple chunk holders.
  for (it = chunks.begin(); it != chunks.end(); ++it) {
    bool first_copy(true);
    for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
      if (pdvaults_[vault_no]->vault_chunkstore_->Has((*it).first)) {
        if (first_copy) {
          first_copy = false;
          continue;
        }
        printf(">> Deleting chunk %s from vault %d\n",
               HexSubstr((*it).first).c_str(), vault_no);
        ASSERT_EQ(0, pdvaults_[vault_no]->
            vault_chunkstore_->DeleteChunk((*it).first));
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
      ASSERT_EQ((*it).first, SHA512String(data));
    }
  }

  if (kNumOfClients >= 2 && kNumOfTestChunks >= 2) {
    printf("\nRemoving all chunks except one...\n");
    // Remove all copies of each chunk except the first one, but leave reference
    // list showing multiple chunk holders.
    bool first_chunk(true);
    for (it = chunks.begin(); it != chunks.end(); ++it) {
      for (int vault_no = 0; vault_no < kNetworkSize; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_->Has((*it).first)) {
          if (first_chunk) {
            first_chunk = false;
            continue;
          }
          printf(">> Deleting chunk %s from vault %d\n",
                 HexSubstr((*it).first).c_str(), vault_no);
          ASSERT_EQ(0, pdvaults_[vault_no]->
              vault_chunkstore_->DeleteChunk((*it).first));
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
          ASSERT_EQ((*it).first, SHA512String(data));
        } else {
          ASSERT_NE(0, clients_[i]->msm->LoadChunk((*it).first, &data));
        }
      }
    }
  }
}

TEST_MS_NET(PDVaultTest, FUNC, MAID, VaultStartStop) {
  // check pdvaults can be started and stopped multiple times
  const int kTestVaultNo(kNetworkSize / 2);
  for (int loop = 0; loop < 7; ++loop) {
    pdvaults_[kTestVaultNo]->Stop();
    ASSERT_NE(kVaultStarted, pdvaults_[kTestVaultNo]->vault_status());
    printf("Vault stopped - iteration %i.\n", loop+1);
    pdvaults_[kTestVaultNo]->Start(false);
    ASSERT_TRUE(pdvaults_[kTestVaultNo]->WaitForStartup(30));
    printf("Vault started - iteration %i.\n", loop+1);
  }
  ASSERT_TRUE(pdvaults_[kTestVaultNo]->WaitForSync());
}

TEST_MS_NET(PDVaultTest, FUNC, MAID, Cachechunk) {
  transport::TransportUDT udt_transport;
  transport::TransportHandler transport_handler;
  boost::int16_t trans_id;
  transport_handler.Register(&udt_transport, &trans_id);
  rpcprotocol::ChannelManager channel_manager(&transport_handler);
  ClientRpcs client_rpcs(&transport_handler, &channel_manager);
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
  std::string content(base::RandomString(10000));
  std::string chunkname(SHA512String(content));
  while (pdvaults_[chunk_vault_index]->vault_chunkstore_->Has(chunkname)) {
    content = base::RandomString(10000);
    chunkname = SHA512String(content);
  }

  ASSERT_EQ(kSuccess,
            pdvaults_[chunk_vault_index]->vault_chunkstore_->Store(chunkname,
                                                                  content));
  kc_cacher_vault = pdvaults_[cache_vault_index]->kad_ops_->contact_info();
  std::string ser_kc_cacher_vault = kc_cacher_vault.SerializeAsString();

  kad::Contact peer(pdvaults_[chunk_vault_index]->kad_ops_->contact_info());
  GetChunkRequest request;
  request.set_chunkname(chunkname);
  request.set_serialised_cacher_contact(ser_kc_cacher_vault);
  GetChunkResponse response;
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
  while (!pdvaults_[cache_vault_index]->vault_chunkstore_->Has(chunkname) &&
         t.elapsed() < 5)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_TRUE(pdvaults_[cache_vault_index]->vault_chunkstore_->Has(chunkname));

  transport_handler.StopAll();
  channel_manager.Stop();
}

//  TEST_MS_NET(PDVaultTest, DISABLED_FUNC, MAID, SwapChunk) {
//  }
//
//  TEST_MS_NET(PDVaultTest, DISABLED_FUNC, MAID, VaultValidateChunk) {
//    // check pre-loaded chunks are not corrupted
//  }
//
//  TEST_MS_NET(PDVaultTest, DISABLED_FUNC, MAID, VaultRepublishChunkRef) {
//  }

}  // namespace test

}  // namespace vault

}  // namespace maidsafe

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  // setting output to be stderr
#ifndef HAVE_GLOG
  bool FLAGS_logtostderr;
#endif
//  FLAGS_logtostderr = true;
  testing::InitGoogleTest(&argc, argv);
  try {
    if (boost::filesystem::exists(".kadconfig"))
      boost::filesystem::remove(".kadconfig");
  }
  catch(const std::exception& e) {
    printf("%s\n", e.what());
  }
  testing::AddGlobalTestEnvironment(new maidsafe::test::localvaults::Env(
      testpdvault::K, maidsafe::vault::test::kNetworkSize,
      &maidsafe::vault::test::pdvaults_, &maidsafe::vault::test::kadconfig_));

  int result(RUN_ALL_TESTS());
  try {
    if (boost::filesystem::exists(".kadconfig"))
      boost::filesystem::remove(".kadconfig");
  }
  catch(const std::exception& e) {
    printf("%s\n", e.what());
  }
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}

