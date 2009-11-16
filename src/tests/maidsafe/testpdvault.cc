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

#include <gtest/gtest.h>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <map>
#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/systempackets.h"
#include "maidsafe/kademlia_service_messages.pb.h"
#include "maidsafe/vault/pdvault.h"
#include "tests/maidsafe/localvaults.h"

static bool callback_timed_out_ = true;
static bool callback_succeeded_ = false;
static std::string callback_content_ = "";
static bool callback_prepared_ = false;
static boost::mutex callback_mutex_;
static std::list<std::string> callback_packets_;
static std::list<std::string> callback_messages_;

namespace testpdvault {

inline void DeleteCallback(const std::string &result) {
  maidsafe::DeleteResponse resp;
  if (!resp.ParseFromString(result) ||
      resp.result() != kAck) {
    callback_succeeded_ = false;
    callback_timed_out_ = false;
  } else {
    callback_succeeded_ = true;
    callback_timed_out_ = false;
  }
}

inline void GetPacketCallback(const std::string &result) {
//  maidsafe::GetResponse resp;
//  boost::mutex::scoped_lock lock(callback_mutex_);
//  if (!resp.ParseFromString(result) || resp.result() != kAck) {
//    callback_packets_.push_back("Failed");
//  } else {
//    callback_packets_.push_back(resp.content());
//  }
  boost::mutex::scoped_lock lock(callback_mutex_);
  callback_packets_.push_back(result);
}

inline void GetMessagesCallback(const std::string &result) {
  maidsafe::GetBPMessagesResponse resp;
  if (!resp.ParseFromString(result) ||
      resp.result() != kAck) {
    callback_succeeded_ = false;
    callback_timed_out_ = false;
  } else {
    callback_succeeded_ = true;
    callback_timed_out_ = false;
    for (int i = 0; i < resp.messages_size(); i++) {
      callback_messages_.push_back(resp.messages(i));
    }
  }
}

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

void MakeChunks(boost::shared_ptr<maidsafe::ChunkStore> chunkstore,
                int no_of_chunks,
                std::map<std::string, std::string> *chunks) {
  crypto::Crypto cryobj_;
  cryobj_.set_hash_algorithm(crypto::SHA_512);
  cryobj_.set_symm_algorithm(crypto::AES_256);
  for (int i = 0; i < no_of_chunks; ++i) {
    std::string chunk_content_ = base::RandomString(100);
    std::string non_hex_chunk_name_ = cryobj_.Hash(chunk_content_,
        "", crypto::STRING_STRING, false);
    fs::path chunk_path_(file_system::FileSystem::TempDir() +
                         "/maidsafe_TestVault");
    std::string hex_chunk_name_ = base::EncodeToHex(non_hex_chunk_name_);
    printf("Chunk %i - %s\n", i, HexSubstr(non_hex_chunk_name_).c_str());
    chunk_path_ /= hex_chunk_name_;
    std::ofstream ofs_;
    ofs_.open(chunk_path_.string().c_str());
    ofs_ << chunk_content_;
    ofs_.close();
    chunkstore->AddChunkToOutgoing(non_hex_chunk_name_, chunk_path_);
    chunks->insert(std::pair<std::string, std::string>
        (hex_chunk_name_, chunk_content_));
  }
}

void CreatePacketType(const std::string &priv_key,
                      int no_of_packets,
                      std::map<std::string, std::string> *packets) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (int i = 0; i < no_of_packets; ++i) {
    maidsafe::GenericPacket gp;
    gp.set_data(base::RandomString(4096));
    gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
      crypto::STRING_STRING));
    std::string ser_packet;
    gp.SerializeToString(&ser_packet);
    std::string packet_name = co.Hash(ser_packet, "", crypto::STRING_STRING,
                                      false);
//    chunkstore->AddChunkToOutgoing(*packet_name, *ser_packet);
    packets->insert(std::pair<std::string, std::string>
        (base::EncodeToHex(packet_name), ser_packet));
//    printf("Created packet %i.\n", packets->size());
  }
}

void CreateChunkPackets(const std::vector<std::string> &priv_keys,
                        std::vector<std::string> *packets) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (size_t i = 0; i < priv_keys.size(); ++i) {
    maidsafe::GenericPacket gp;
    gp.set_data(base::RandomString(4096));
    gp.set_signature(co.AsymSign(gp.data(), "", priv_keys[i],
                     crypto::STRING_STRING));
    std::string ser_gp;
    gp.SerializeToString(&ser_gp);
    packets->push_back(ser_gp);
  }
  printf("Leaving CreateChunkPackets\n");
}

void CreateBufferPacket(const std::string &owner,
                        const std::string &public_key,
                        const std::string &private_key,
                        std::string *packet_name,
                        std::string *ser_packet) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  *packet_name = co.Hash(owner + "BUFFER", "", crypto::STRING_STRING,
                         false);
  maidsafe::BufferPacket buffer_packet;
  maidsafe::GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  maidsafe::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(false);
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(co.AsymSign(ser_info, "", private_key,
    crypto::STRING_STRING));
  buffer_packet.SerializeToString(ser_packet);
}

void CreateMessage(const std::string &message,
                   const std::string &public_key,
                   const std::string &private_key,
                   const std::string &sender_id,
                   const maidsafe::MessageType &m_type,
                   std::string *ser_message,
                   std::string *ser_expected_msg) {
  std::string key("AESkey");
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  co.set_symm_algorithm(crypto::AES_256);
  maidsafe::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(sender_id);
  bpmsg.set_rsaenc_key(co.AsymEncrypt(key, "", public_key,
    crypto::STRING_STRING));
  bpmsg.set_aesenc_message(co.SymmEncrypt(message, "",
    crypto::STRING_STRING, key));
  bpmsg.set_type(m_type);
  bpmsg.set_sender_public_key(public_key);
  std::string ser_bpmsg;
  bpmsg.SerializeToString(&ser_bpmsg);
  maidsafe::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(co.AsymSign(ser_bpmsg, "", private_key,
    crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  bpmsg_gp.SerializeToString(ser_message);

  // Expected result for GetMsgs
  maidsafe::ValidatedBufferPacketMessage val_msg;
  val_msg.set_index(bpmsg.rsaenc_key());
  val_msg.set_message(bpmsg.aesenc_message());
  val_msg.set_sender(bpmsg.sender_id());
  val_msg.set_type(bpmsg.type());
  val_msg.SerializeToString(ser_expected_msg);
}

size_t CheckStoredCopies(std::map<std::string, std::string> chunks,
                         const int &timeout_seconds,
                         boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm) {
  size_t chunk_count = 0;
  int time_count = 0;
  std::map<std::string, std::string>::iterator it;
  for (it = chunks.begin(); it != chunks.end(); ++it) {
    std::string hex_chunk_name = (*it).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    kad::ContactInfo cache_holder;
    std::vector<std::string> chunk_holders_ids;
    std::string needs_cache_copy_id;
    while (time_count < timeout_seconds) {
      sm->FindValue(non_hex_name, false, &cache_holder, &chunk_holders_ids,
          &needs_cache_copy_id);
      if (chunk_holders_ids.size() >= size_t(kMinChunkCopies)) {
        ++chunk_count;
        break;
      } else {
        time_count += 10;
        boost::this_thread::sleep(boost::posix_time::seconds(10));
      }
    }
  }
  return chunk_count;
}

//  typedef boost::mp_math::mp_int<> BigInt;
//
//  BigInt KademliaDistance(const std::string &key1, const std::string &key2) {
//    std::string hex_key1 = base::EncodeToHex(key1);
//    std::string hex_key2 = base::EncodeToHex(key2);
//  //  printf("Dist between %s... & %s... is ", hex_key1.substr(0, 10).c_str(),
//  //         hex_key2.substr(0, 10).c_str());
//    hex_key1 = "0x" + hex_key1;
//    hex_key2 = "0x" + hex_key2;
//    BigInt value1(hex_key1);
//    BigInt value2(hex_key2);
//    BigInt kad_distance(value1 ^ value2);
//  //  std::cout << kad_distance << std::endl;
//    return kad_distance;
//  }

}  // namespace testpdvault

namespace maidsafe_vault {

static std::vector< boost::shared_ptr<PDVault> > pdvaults_;
static const int kNetworkSize_ = 20;
static const int kTestK_ = 16;

class PDVaultTest : public testing::Test {
 protected:
  PDVaultTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                 "/maidsafe_TestVault"),
                  client_chunkstore_dir_(test_root_dir_ + "/ClientChunkstore"),
                  client_chunkstore_(),
                  chunkstore_dirs_(),
                  sm_(),
                  client_pmid_keys_(),
                  client_maid_keys_(),
                  client_pmid_public_signature_(),
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
    client_maid_keys_.GenerateKeys(maidsafe::kRsaKeySize);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, true);
    maidsafe::SessionSingleton::getInstance()->AddKey(maidsafe::MAID, maid_name,
        maid_pri, maid_pub, maid_pub_key_signature);
    client_pmid_keys_.GenerateKeys(maidsafe::kRsaKeySize);
    std::string pmid_pri = client_pmid_keys_.private_key();
    std::string pmid_pub = client_pmid_keys_.public_key();
    client_pmid_public_signature_ = crypto_.AsymSign(pmid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string pmid_name = crypto_.Hash(pmid_pub +
        client_pmid_public_signature_, "", crypto::STRING_STRING, true);
    maidsafe::SessionSingleton::getInstance()->AddKey(maidsafe::PMID, pmid_name,
        pmid_pri, pmid_pub, client_pmid_public_signature_);
    maidsafe::SessionSingleton::getInstance()->SetConnectionStatus(0);
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
    client_chunkstore_ = boost::shared_ptr<maidsafe::ChunkStore>
        (new maidsafe::ChunkStore(client_chunkstore_dir_, 0, 0));
    boost::shared_ptr<maidsafe::MaidsafeStoreManager>
        sm_local_(new maidsafe::MaidsafeStoreManager(client_chunkstore_));
    sm_ = sm_local_;
    testpdvault::PrepareCallbackResults();
    sm_->Init(0, boost::bind(&testpdvault::GeneralCallback, _1));
    testpdvault::WaitFunction(60, &mutex_);
    ASSERT_TRUE(callback_succeeded_);
    ASSERT_FALSE(callback_timed_out_);
  }
  virtual void TearDown() {
    testpdvault::PrepareCallbackResults();
    sm_->Close(boost::bind(&testpdvault::GeneralCallback, _1), true);
    testpdvault::WaitFunction(60, &mutex_);
    ASSERT_TRUE(callback_succeeded_);
    ASSERT_FALSE(callback_timed_out_);
  }

  std::string test_root_dir_, client_chunkstore_dir_;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  std::vector<fs::path> chunkstore_dirs_;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;

 private:
  PDVaultTest(const PDVaultTest&);
  PDVaultTest &operator=(const PDVaultTest&);
};

TEST_F(PDVaultTest, FUNC_MAID_VaultStartStop) {
  // check pdvaults can be started and stopped multiple times
  bool success_(false);
  const int kTestVaultNo(4);
  for (int loop = 0; loop < 7; ++loop) {
    success_ = false;
    pdvaults_[kTestVaultNo]->Stop(true);
    ASSERT_NE(kVaultStarted, pdvaults_[kTestVaultNo]->vault_status());
    printf("Vault stopped - iteration %i.\n", loop+1);
    pdvaults_[kTestVaultNo]->Start(false);
    ASSERT_EQ(kVaultStarted, pdvaults_[kTestVaultNo]->vault_status());
    printf("Vault started - iteration %i.\n", loop+1);
  }
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks1) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks2) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks3) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks4) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks5) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks6) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks7) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreChunks8) {
  // add some valid chunks to client chunkstore and store to network
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(1);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  printf("%i chunks enqueued for storing.\n\n", kNumOfTestChunks);
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      chunk_count = 0;
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
          ASSERT_EQ(0, pdvaults_[vault_no]->vault_chunkstore_.
              HashCheckChunk(non_hex_name));
          printf("Found chunk %s\n", HexSubstr(non_hex_name).c_str());
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk1) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk2) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk3) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk4) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk ";
          trace += HexSubstr(non_hex_name);
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk5) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk6) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk7) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetChunk8) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(20);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // Check each chunk can be retrieved correctly
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    printf("Getting test chunk locally.\n");
    std::string hex_chunk_name = (*it_).first;
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  ASSERT_EQ(chunks_.size(), testpdvault::CheckStoredCopies(chunks_, 300, sm_));
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetNonDuplicatedChunk) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(3);
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  int i = 0;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
    ++i;
  }
  // iterate through all vault chunkstores to ensure each chunk stored
  // enough times.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    int chunk_count = 0;
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Vault[" + base::itos(vault_no) + "] has chunk.";
          SCOPED_TRACE(trace);
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    ASSERT_GE(chunk_count, kMinChunkCopies);
  }

  // Remove all but one copy of each chunk, but leave reference packet showing
  // multiple chunk holders.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    bool first_copy(true);
    for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
      if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
        if (first_copy) {
          first_copy = false;
          continue;
        }
        std::string trace = "Deleting chunk " + (*it_).first.substr(0, 10) +
            "from vault[" + base::itos(vault_no) + "] on port " +
            base::itos(pdvaults_[vault_no]->host_port()) + ".";
        SCOPED_TRACE(trace);
        ASSERT_EQ(0, pdvaults_[vault_no]->
            vault_chunkstore_.DeleteChunk(non_hex_name));
        printf("%s\n", trace.c_str());
      }
    }
  }
  // Check each chunk can be retrieved correctly from the net with all chunk
  // holders but one missing.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
}

TEST_F(PDVaultTest, FUNC_MAID_GetMissingChunk) {
  std::map<std::string, std::string> chunks_;
  const boost::uint32_t kNumOfTestChunks(3);
  ASSERT_GE(kNumOfTestChunks, boost::uint32_t(2)) <<
      "Need at least 2 copies for this test.";
  testpdvault::MakeChunks(client_chunkstore_, kNumOfTestChunks, &chunks_);
  std::map<std::string, std::string>::iterator it_;
  int i = 0;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    sm_->StoreChunk(hex_chunk_name, maidsafe::PRIVATE, "");
    ++i;
  }
  // Remove all copies of each chunk except the last one, but leave reference
  // packet showing multiple chunk holders.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
  int timeout(300);  // seconds.
  int chunk_number(0);
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_, ++chunk_number) {
    if (chunk_number == kNumOfTestChunks -1)
      break;
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name = base::DecodeFromHex(hex_chunk_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Trying to delete chunk from vault["
              + base::itos(vault_no) + "].";
          SCOPED_TRACE(trace);
          ASSERT_EQ(0, pdvaults_[vault_no]->
              vault_chunkstore_.DeleteChunk(non_hex_name));
          ++chunk_count;
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
  }
  // Check each chunk except the last cannot be retrieved correctly from the net
  chunk_number = 0;
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_, ++chunk_number) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name = base::DecodeFromHex(hex_chunk_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Trying to get test chunk remotely.\n");
    std::string data;
    if (chunk_number == kNumOfTestChunks -1) {
      ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
      ASSERT_EQ(data, (*it_).second);
      ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
          true));
    } else {
      ASSERT_NE(0, sm_->LoadChunk(hex_chunk_name, &data));
    }
  }
}

TEST_F(PDVaultTest, FUNC_MAID_StoreSystemPacket) {
  std::map<std::string, std::string> packets;
  const boost::uint32_t kNumOfTestPackets(29);
  testpdvault::CreatePacketType(client_maid_keys_.private_key(),
      kNumOfTestPackets, &packets);
  std::map<std::string, std::string>::iterator it;
//  int i(0);
  for (it = packets.begin(); it != packets.end(); ++it) {
    std::string hex_packet_name = (*it).first;
    std::string packet_content = (*it).second;
//    printf("Trying to store packet %i.\n", i);
    ASSERT_EQ(0, sm_->StorePacket(hex_packet_name, packet_content,
        maidsafe::PMID, maidsafe::PRIVATE, ""));
//    printf("Packet %i stored.\n", i);
//    ++i;
  }
                      boost::this_thread::sleep(boost::posix_time::seconds(1));
//  printf("About to prepare callback results\n");
  // Check the packets can be retrieved correctly from the network
  testpdvault::PrepareCallbackResults();
//  printf("Prepared callback results\n");
  for (it = packets.begin(); it != packets.end(); ++it) {
//    printf("Getting test packet remotely.\n");
    std::string hex_packet_name = (*it).first;
    std::string non_hex_packet_name = base::DecodeFromHex(hex_packet_name);
    ASSERT_EQ(0, client_chunkstore_->DeleteChunk(non_hex_packet_name));
    std::string packet_content;
    sm_->LoadPacket(hex_packet_name, &packet_content);
    callback_packets_.push_back(packet_content);
  }
  // Wait for all packets to load
//  size_t callback_packets_size(0);
//  while (callback_packets_size < kNumOfTestPackets) {
//    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
//    {
//      boost::mutex::scoped_lock lock(callback_mutex_);
//      callback_packets_size = callback_packets_.size();
//    }
//  }
  while (!callback_packets_.empty()) {
    std::string packet_content = callback_packets_.front();
    std::string hex_packet_name = crypto_.Hash(packet_content, "",
        crypto::STRING_STRING, true);
    if (packets.find(hex_packet_name) == packets.end())
      FAIL() << "Didn't find packet " << hex_packet_name.substr(0, 10);
    callback_packets_.pop_front();
  }
}

TEST_F(PDVaultTest, FUNC_MAID_StoreInvalidSystemPacket) {
  std::map<std::string, std::string> packets;
  testpdvault::CreatePacketType(client_maid_keys_.private_key(), 1,
      &packets);
  std::string hex_packet_name((*packets.begin()).first);
  // Try to store system packet with other incorrect content
  std::string packet_content("not a system packet");
  ASSERT_EQ(maidsafe::kSendPacketFailure, sm_->StorePacket(hex_packet_name,
      packet_content, maidsafe::MPID, maidsafe::PRIVATE, ""));
  packet_content = "some other bollocks";
  ASSERT_EQ(maidsafe::kSendPacketFailure, sm_->StorePacket(hex_packet_name,
      packet_content, maidsafe::MPID, maidsafe::PRIVATE, ""));
}

TEST_F(PDVaultTest, FUNC_MAID_StoreLoadPacketAsChunk) {
  std::vector<std::string> priv_keys;
  std::vector<std::string> names_for_packets;
  std::vector<maidsafe::PacketType> type_of_packet;
  std::vector<maidsafe::PacketType> signing_packet;
  for (int n = 0; n < 4; ++n) {
    crypto::RsaKeyPair rkp;
    rkp.GenerateKeys(4096);
    std::string pub_key_signature = crypto_.AsymSign(rkp.public_key(), "",
                                    rkp.private_key(), crypto::STRING_STRING);
    std::string packetname = crypto_.Hash(rkp.public_key() + pub_key_signature,
                             "", crypto::STRING_STRING, false);
    switch (n) {
      case 0: type_of_packet.push_back(maidsafe::MID);
              signing_packet.push_back(maidsafe::ANMID);
              names_for_packets.push_back(crypto_.Hash("MID", "",
                                          crypto::STRING_STRING, true));
              break;
      case 1: type_of_packet.push_back(maidsafe::SMID);
              signing_packet.push_back(maidsafe::ANSMID);
              names_for_packets.push_back(crypto_.Hash("SMID", "",
                                          crypto::STRING_STRING, true));
              break;
      case 2: type_of_packet.push_back(maidsafe::MSID);
              names_for_packets.push_back(crypto_.Hash("MSID", "",
                                          crypto::STRING_STRING, true));
              break;
      case 3: type_of_packet.push_back(maidsafe::PD_DIR);
              names_for_packets.push_back(crypto_.Hash("PD_DIR", "",
                                          crypto::STRING_STRING, true));
              break;
    }
    if (n < 2)
      maidsafe::SessionSingleton::getInstance()->AddKey(signing_packet[n],
          packetname, rkp.private_key(), rkp.public_key(), pub_key_signature);
    priv_keys.push_back(rkp.private_key());
  }
  std::vector<std::string> gps;
  testpdvault::CreateChunkPackets(priv_keys, &gps);
  for (size_t nn = 0; nn < gps.size(); ++nn) {
    printf("Store cycle ---- %u\n", nn);
    ASSERT_EQ(maidsafe::kSuccess, sm_->StorePacket(names_for_packets[nn],
              gps[nn], type_of_packet[nn], maidsafe::PRIVATE, ""));
  }

  // Wait until last packet is loadable
  std::string value;
  bool ready = false;
  int count = 0;
  int timeout = 120;  // seconds
  while (!ready && count < timeout) {
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    ready = (sm_->LoadPacket(names_for_packets[names_for_packets.size() - 1],
             &value) == kSuccess);
    count += 10;
  }
  ASSERT_TRUE(ready);
  ASSERT_EQ(gps[names_for_packets.size() - 1], value);
  // Get other packets back
  for (size_t nnn = 0; nnn < gps.size() - 1; ++nnn) {
    printf("Load cycle ---- %u\n", nnn);
    ASSERT_EQ(maidsafe::kSuccess, sm_->LoadPacket(names_for_packets[nnn],
              &value));
    ASSERT_EQ(gps[nnn], value);
  }

  // Check we can't get a non-existent packet
  ASSERT_NE(maidsafe::kSuccess, sm_->LoadPacket(
            crypto_.Hash("some packet taht don exist", "",
            crypto::STRING_STRING, true), &value));
  ASSERT_EQ("", value);

  // Check overwriting packet succeeds (first three packets above all overwrite)
  maidsafe::GenericPacket gp;
  gp.set_data(base::RandomString(4096));
  gp.set_signature(crypto_.AsymSign(gp.data(), "", priv_keys[0],
                   crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  ASSERT_EQ(kSuccess, sm_->StorePacket(names_for_packets[0], ser_gp,
            type_of_packet[0], maidsafe::PRIVATE, ""));
  ASSERT_EQ(kSuccess, sm_->LoadPacket(names_for_packets[0], &value));
  ASSERT_EQ(ser_gp, value);
  std::vector<std::string> values;
  values.push_back("a");
  values.push_back("b");
  ASSERT_EQ(kSuccess, sm_->LoadPacket(names_for_packets[0], &values));
  ASSERT_EQ(size_t(1), values.size());
  ASSERT_EQ(ser_gp, values[0]);

  // Check appending to a packet succeeds (last packet above appends)
  gp.set_data(base::RandomString(4096));
  gp.set_signature(crypto_.AsymSign(gp.data(), "",
                   priv_keys[names_for_packets.size() - 1],
                   crypto::STRING_STRING));
  ser_gp.clear();
  gp.SerializeToString(&ser_gp);
  ASSERT_EQ(maidsafe::kSuccess, sm_->StorePacket(
            names_for_packets[names_for_packets.size() - 1],
            ser_gp, type_of_packet[names_for_packets.size() - 1],
            maidsafe::PRIVATE, ""));
  ASSERT_EQ(maidsafe::kSuccess, sm_->LoadPacket(
            names_for_packets[names_for_packets.size() - 1], &value));
  ASSERT_EQ(ser_gp, value);
  values.push_back("a");
  values.push_back("b");
  ASSERT_EQ(kSuccess, sm_->LoadPacket(
            names_for_packets[names_for_packets.size() - 1], &values));
  ASSERT_EQ(size_t(2), values.size());
  ASSERT_EQ(ser_gp, values[0]);
  ASSERT_EQ(gps[names_for_packets.size() - 1], values[1]);
}

/*
TEST_F(PDVaultTest, FUNC_MAID_UpdatePDDirNotSigned) {
  std::string non_hex_chunk_name = crypto_.Hash("abc", "",
                                        crypto::STRING_STRING, false);
  std::string chunk_content = base::RandomString(200);
  std::string hex_chunk_name = base::EncodeToHex(non_hex_chunk_name);
  std::string signed_request_ =
        crypto_.AsymSign(crypto_.Hash(client_public_key_ +
                                      client_signed_public_key_ +
                                      non_hex_chunk_name,
                                      "",
                                      crypto::STRING_STRING,
                                      false),
                         "",
                         client_private_key_,
                         crypto::STRING_STRING);
  testpdvault::PrepareCallbackResults();
  pdclient_->StoreChunk(non_hex_chunk_name,
                        chunk_content,
                        client_public_key_,
                        client_signed_public_key_,
                        signed_request_,
                        maidsafe::PDDIR_NOTSIGNED,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  // fail to store again on same key
  std::string new_chunk_content = base::RandomString(200);
//  testpdvault::PrepareCallbackResults();
//  pdclient_->StoreChunk(non_hex_chunk_name,
//                        new_chunk_content,
//                        client_public_key_,
//                        client_signed_public_key_,
//                        signed_request_,
//                        maidsafe::PDDIR_NOTSIGNED,
//                        boost::bind(&testpdvault::StoreChunkCallback,
//                                    _1));
//  testpdvault::WaitFunction(120, recursive_mutex_client_.get());
//  ASSERT_FALSE(callback_succeeded_);
//  ASSERT_FALSE(callback_timed_out_);

  // Updating chunk
  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                         new_chunk_content,
                         client_public_key_,
                         client_signed_public_key_,
                         signed_request_,
                         maidsafe::PDDIR_NOTSIGNED,
                         boost::bind(&testpdvault::StoreChunkCallback,
                                     _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  // loading chunk
  testpdvault::PrepareCallbackResults();
  pdclient_->GetChunk(non_hex_chunk_name,
                      boost::bind(&testpdvault::GetChunkCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_EQ(callback_content_, new_chunk_content);
  ASSERT_FALSE(callback_timed_out_);
}

TEST_F(PDVaultTest, FUNC_MAID_UpdateSystemPacket) {
  std::string non_hex_chunk_name, chunk_content;
  testpdvault::CreatePacketType(client_private_key_, &non_hex_chunk_name,
    &chunk_content);
  std::string hex_chunk_name = base::EncodeToHex(non_hex_chunk_name);
  std::string signed_request =
      crypto_.AsymSign(crypto_.Hash(client_public_key_ +
                                    client_signed_public_key_ +
                                    non_hex_chunk_name,
                                    "",
                                    crypto::STRING_STRING,
                                    false),
                       "",
                       client_private_key_,
                       crypto::STRING_STRING);
  testpdvault::PrepareCallbackResults();
  pdclient_->StoreChunk(non_hex_chunk_name,
                        chunk_content,
                        client_public_key_,
                        client_signed_public_key_,
                        signed_request,
                        maidsafe::SYSTEM_PACKET,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  std::string new_chunk_content;
  std::string new_non_hex_chunk_name;
  testpdvault::CreatePacketType(client_private_key_, &new_non_hex_chunk_name,
    &new_chunk_content);
  ASSERT_NE(chunk_content, new_chunk_content);

  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                        new_chunk_content,
                        client_public_key_,
                        client_signed_public_key_,
                        signed_request,
                        maidsafe::SYSTEM_PACKET,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  testpdvault::PrepareCallbackResults();
  pdclient_->GetChunk(non_hex_chunk_name,
                      boost::bind(&testpdvault::GetChunkCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_EQ(callback_content_, new_chunk_content);
  ASSERT_FALSE(callback_timed_out_);
}

TEST_F(PDVaultTest, FUNC_MAID_UpdateInvalidSystemPacket) {
  std::string non_hex_chunk_name, chunk_content;
  testpdvault::CreatePacketType(client_private_key_, &non_hex_chunk_name,
    &chunk_content);
  std::string hex_chunk_name = base::EncodeToHex(non_hex_chunk_name);
  std::string signed_request =
      crypto_.AsymSign(crypto_.Hash(client_public_key_ +
                                    client_signed_public_key_ +
                                    non_hex_chunk_name,
                                    "",
                                    crypto::STRING_STRING,
                                    false),
                       "",
                       client_private_key_,
                       crypto::STRING_STRING);
  testpdvault::PrepareCallbackResults();
  pdclient_->StoreChunk(non_hex_chunk_name,
                        chunk_content,
                        client_public_key_,
                        client_signed_public_key_,
                        signed_request,
                        maidsafe::SYSTEM_PACKET,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(2));

  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                         std::string("this is not a system packet"),
                         client_public_key_,
                         client_signed_public_key_,
                         signed_request,
                         maidsafe::SYSTEM_PACKET,
                         boost::bind(&testpdvault::StoreChunkCallback,
                                     _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // Udating different type
  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                         std::string("this is not a system packet"),
                         client_public_key_,
                         client_signed_public_key_,
                         signed_request,
                         maidsafe::PDDIR_NOTSIGNED,
                         boost::bind(&testpdvault::StoreChunkCallback,
                                     _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // System packet signed with different keys
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(kRsaKeySize);
  std::string new_chunk_content;
  std::string new_non_hex_chunk_name;
  testpdvault::CreatePacketType(keys.private_key(), &new_non_hex_chunk_name,
    &new_chunk_content);
  std::string sig_pubkey = crypto_.AsymSign(keys.public_key(), "",
     keys.private_key(), crypto::STRING_STRING);
  signed_request =
      crypto_.AsymSign(crypto_.Hash(keys.public_key() +
                                    client_signed_public_key_ +
                                    new_non_hex_chunk_name,
                                    "",
                                    crypto::STRING_STRING,
                                    false),
                       "",
                       keys.private_key(),
                       crypto::STRING_STRING);
  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                        std::string("this is not a system packet"),
                        keys.public_key(),
                        sig_pubkey,
                        signed_request,
                        maidsafe::SYSTEM_PACKET,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
}
*/

TEST_F(PDVaultTest, DISABLED_FUNC_MAID_SwapChunk) {
}

TEST_F(PDVaultTest, DISABLED_FUNC_MAID_VaultValidateChunk) {
  // check pre-loaded chunks are not corrupted
}

TEST_F(PDVaultTest, DISABLED_FUNC_MAID_VaultRepublishChunkRef) {
}

}  // namespace maidsafe_vault

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(
      new localvaults::Env(maidsafe_vault::kNetworkSize_,
                           maidsafe_vault::kTestK_,
                           &maidsafe_vault::pdvaults_));
  return RUN_ALL_TESTS();
}
