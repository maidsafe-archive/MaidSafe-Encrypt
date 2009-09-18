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

#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <map>
#include <vector>

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
  maidsafe::GetResponse resp;
  boost::mutex::scoped_lock lock(callback_mutex_);
  if (!resp.ParseFromString(result) || resp.result() != kAck) {
    callback_packets_.push_back("Failed");
  } else {
    callback_packets_.push_back(resp.content());
  }
}

inline void GetMessagesCallback(const std::string &result) {
  maidsafe::GetMessagesResponse resp;
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
    fs::path chunk_path_("./TestVault");
    std::string hex_chunk_name_("");
    base::encode_to_hex(non_hex_chunk_name_, &hex_chunk_name_);
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

void CreateSystemPackets(const std::string &priv_key,
                         int no_of_packets,
                         std::map<std::string, std::string> *packets) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (int i = 0; i < no_of_packets; ++i) {
    packethandler::GenericPacket gp;
    gp.set_data(base::RandomString(4096));
    gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
      crypto::STRING_STRING));
    std::string ser_packet;
    gp.SerializeToString(&ser_packet);
    std::string packet_name = co.Hash(ser_packet, "", crypto::STRING_STRING,
                                      false);
    std::string hex_packet_name("");
    base::encode_to_hex(packet_name, &hex_packet_name);
//    chunkstore->AddChunkToOutgoing(*packet_name, *ser_packet);
    packets->insert(std::pair<std::string, std::string>
        (hex_packet_name, ser_packet));
  }
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
  packethandler::BufferPacket buffer_packet;
  packethandler::GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  packethandler::BufferPacketInfo buffer_packet_info;
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
                   const packethandler::MessageType &m_type,
                   std::string *ser_message,
                   std::string *ser_expected_msg) {
  std::string key("AESkey");
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  co.set_symm_algorithm(crypto::AES_256);
  packethandler::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(sender_id);
  bpmsg.set_rsaenc_key(co.AsymEncrypt(key, "", public_key,
    crypto::STRING_STRING));
  bpmsg.set_aesenc_message(co.SymmEncrypt(message, "",
    crypto::STRING_STRING, key));
  bpmsg.set_type(m_type);
  bpmsg.set_sender_public_key(public_key);
  std::string ser_bpmsg;
  bpmsg.SerializeToString(&ser_bpmsg);
  packethandler::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(co.AsymSign(ser_bpmsg, "", private_key,
    crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  bpmsg_gp.SerializeToString(ser_message);

  // Expected result for GetMsgs
  packethandler::ValidatedBufferPacketMessage val_msg;
  val_msg.set_index(bpmsg.rsaenc_key());
  val_msg.set_message(bpmsg.aesenc_message());
  val_msg.set_sender(bpmsg.sender_id());
  val_msg.set_type(bpmsg.type());
  val_msg.SerializeToString(ser_expected_msg);
}

}  // namespace testpdvault

namespace maidsafe_vault {

static std::vector< boost::shared_ptr<PDVault> > pdvaults_;
#ifdef MAIDSAFE_WIN32
static const int kNetworkSize_ = 20;
#else
// Fedora doesn't appear to be able to handle more than 16 vaults' threads.
// TODO(Fraser#5#): 2009-09-10 - See if there's a fix for this - not ideal
//                               having network size == k.
static const int kNetworkSize_ = 16;
#endif
static const int kTestK_ = 16;

class TestPDVault : public testing::Test {
 protected:
  TestPDVault() : client_chunkstore_dir_("./TestVault/ClientChunkstore"),
                  client_chunkstore_(),
                  chunkstore_dirs_(),
                  sm_(),
                  client_pmid_keys_(),
                  client_maid_keys_(),
                  client_pmid_public_signature_(),
                  mutex_(),
                  crypto_() {
    try {
      boost::filesystem::remove_all("./TestVault");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::create_directories("./TestVault");
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    client_maid_keys_.GenerateKeys(packethandler::kRsaKeySize);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, true);
    maidsafe::SessionSingleton::getInstance()->AddKey(maidsafe::MAID, maid_name,
        maid_pri, maid_pub, maid_pub_key_signature);
    client_pmid_keys_.GenerateKeys(packethandler::kRsaKeySize);
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

  virtual ~TestPDVault() {
    try {
      boost::filesystem::remove_all("./TestVault");
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

  std::string client_chunkstore_dir_;
  boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore_;
  std::vector<fs::path> chunkstore_dirs_;
  boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;

 private:
  TestPDVault(const TestPDVault&);
  TestPDVault &operator=(const TestPDVault&);
};

TEST_F(TestPDVault, FUNC_MAID_VaultStartStop) {
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

TEST_F(TestPDVault, FUNC_MAID_StoreChunks) {
  // add some valid chunks to client chunkstore and store to network
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
  // enough times and each chunk copy is valid (i.e. name == Hash(contents))
  boost::this_thread::sleep(boost::posix_time::seconds(15));
  int timeout(300);  // seconds.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_name);
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
        }
      }
      time_count += 10;
      boost::this_thread::sleep(boost::posix_time::seconds(10));
    }
    EXPECT_GE(chunk_count, kMinChunkCopies);
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
}

TEST_F(TestPDVault, FUNC_MAID_GetChunk) {
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
    std::string non_hex_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_name);
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
  // Check each chunk can be retrieved correctly from the net
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_chunk_name);
    ASSERT_TRUE(client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
}

TEST_F(TestPDVault, FUNC_MAID_GetNonDuplicatedChunk) {
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
    std::string non_hex_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_name);
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
    std::string non_hex_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_name);
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
        ASSERT_TRUE(pdvaults_[vault_no]->
            vault_chunkstore_.DeleteChunk(non_hex_name));
        printf("%s\n", trace.c_str());
      }
    }
  }
  // Check each chunk can be retrieved correctly from the net with all chunk
  // holders but one missing.
  for (it_ = chunks_.begin(); it_ != chunks_.end(); ++it_) {
    std::string hex_chunk_name = (*it_).first;
    std::string non_hex_chunk_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_chunk_name);
    ASSERT_TRUE(client_chunkstore_->DeleteChunk(non_hex_chunk_name));
    printf("Getting test chunk remotely.\n");
    std::string data;
    ASSERT_EQ(0, sm_->LoadChunk(hex_chunk_name, &data));
    ASSERT_EQ(data, (*it_).second);
    ASSERT_EQ(hex_chunk_name, crypto_.Hash(data, "", crypto::STRING_STRING,
        true));
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
}

TEST_F(TestPDVault, FUNC_MAID_GetMissingChunk) {
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
    std::string non_hex_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_name);
    int chunk_count = 0;
    int time_count = 0;
    while ((time_count < timeout) && (chunk_count < kMinChunkCopies)) {
      for (int vault_no = 0; vault_no < kNetworkSize_; ++vault_no) {
        if (pdvaults_[vault_no]->vault_chunkstore_.Has(non_hex_name)) {
          std::string trace = "Trying to delete chunk from vault["
              + base::itos(vault_no) + "].";
          SCOPED_TRACE(trace);
          ASSERT_TRUE(pdvaults_[vault_no]->
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
    std::string non_hex_chunk_name;
    base::decode_from_hex(hex_chunk_name, &non_hex_chunk_name);
    ASSERT_TRUE(client_chunkstore_->DeleteChunk(non_hex_chunk_name));
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
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(60));
}

TEST_F(TestPDVault, FUNC_MAID_StoreSystemPacket) {
  std::map<std::string, std::string> packets;
  const boost::uint32_t kNumOfTestPackets(23);
  testpdvault::CreateSystemPackets(client_maid_keys_.private_key(),
      kNumOfTestPackets, &packets);
  std::map<std::string, std::string>::iterator it;
  for (it = packets.begin(); it != packets.end(); ++it) {
    std::string hex_packet_name = (*it).first;
    std::string packet_content = (*it).second;
    ASSERT_EQ(0, sm_->StorePacket(hex_packet_name, packet_content,
        packethandler::PMID, maidsafe::PRIVATE, ""));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  // Check the packets can be retrieved correctly from the network
  testpdvault::PrepareCallbackResults();
  for (it = packets.begin(); it != packets.end(); ++it) {
    printf("Getting test packet remotely.\n");
    std::string hex_packet_name = (*it).first;
    std::string non_hex_packet_name;
    base::decode_from_hex(hex_packet_name, &non_hex_packet_name);
    ASSERT_TRUE(client_chunkstore_->DeleteChunk(non_hex_packet_name));
    sm_->LoadPacket(hex_packet_name,
        boost::bind(&testpdvault::GetPacketCallback, _1));
  }
  // Wait for all packets to load
  size_t callback_packets_size(0);
  while (callback_packets_size < kNumOfTestPackets) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
    {
      boost::mutex::scoped_lock lock(callback_mutex_);
      callback_packets_size = callback_packets_.size();
    }
  }
  while (!callback_packets_.empty()) {
    std::string packet_content = callback_packets_.front();
    std::string hex_packet_name = crypto_.Hash(packet_content, "",
        crypto::STRING_STRING, true);
    if (packets.find(hex_packet_name) == packets.end())
      FAIL() << "Didn't find packet " << hex_packet_name.substr(0, 10);
    callback_packets_.pop_front();
  }
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

TEST_F(TestPDVault, FUNC_MAID_StoreInvalidSystemPacket) {
  std::map<std::string, std::string> packets;
  // Making a PMID packet signed with PMID private key (should be signed with
  // MAID private key)
  testpdvault::CreateSystemPackets(client_maid_keys_.private_key(), 1,
      &packets);
  std::string hex_packet_name = (*packets.begin()).first;
  std::string packet_content = (*packets.begin()).second;
  crypto::RsaKeyPair rsa_kp;
  rsa_kp.GenerateKeys(packethandler::kRsaKeySize);
  std::string non_hex_packet_name;
  base::decode_from_hex(hex_packet_name, &non_hex_packet_name);
//  ASSERT_EQ(0, sm_->StorePacket(hex_packet_name, packet_content,
//      packethandler::PD_DIR, maidsafe::PRIVATE, ""));
//  ASSERT_NE(0, sm_->StorePacket(hex_packet_name, packet_content,
//      packethandler::PMID, maidsafe::PRIVATE, ""));
  // Try to store system packet with other incorrect content
  packet_content = "not a system packet";
  EXPECT_EQ(0, sm_->StorePacket(hex_packet_name, packet_content,
      packethandler::PD_DIR, maidsafe::PRIVATE, ""));
  packet_content = "some other bollocks";
  EXPECT_EQ(0, sm_->StorePacket(hex_packet_name, packet_content,
      packethandler::PD_DIR, maidsafe::PRIVATE, ""));
  // We need to allow enough time to let the vaults finish publishing themselves
  // as chunk holders and retrieving their IOUs.
  boost::this_thread::sleep(boost::posix_time::seconds(10));
}

/*
TEST_F(TestPDVault, FUNC_MAID_UpdatePDDirNotSigned) {
  std::string non_hex_chunk_name = crypto_.Hash("abc", "",
                                        crypto::STRING_STRING, false);
  std::string chunk_content = base::RandomString(200);
  std::string hex_chunk_name("");
  base::encode_to_hex(non_hex_chunk_name, &hex_chunk_name);
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

TEST_F(TestPDVault, FUNC_MAID_UpdateSystemPacket) {
  std::string non_hex_chunk_name, chunk_content;
  testpdvault::CreateSystemPackets(client_private_key_, &non_hex_chunk_name,
    &chunk_content);
  std::string hex_chunk_name("");
  base::encode_to_hex(non_hex_chunk_name, &hex_chunk_name);
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
  testpdvault::CreateSystemPackets(client_private_key_, &new_non_hex_chunk_name,
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

TEST_F(TestPDVault, FUNC_MAID_UpdateInvalidSystemPacket) {
  std::string non_hex_chunk_name, chunk_content;
  testpdvault::CreateSystemPackets(client_private_key_, &non_hex_chunk_name,
    &chunk_content);
  std::string hex_chunk_name("");
  base::encode_to_hex(non_hex_chunk_name, &hex_chunk_name);
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
  keys.GenerateKeys(packethandler::kRsaKeySize);
  std::string new_chunk_content;
  std::string new_non_hex_chunk_name;
  testpdvault::CreateSystemPackets(keys.private_key(), &new_non_hex_chunk_name,
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

TEST_F(TestPDVault, FUNC_MAID_AddGetMessages) {
  std::string non_hex_chunk_name, chunk_content;
  testpdvault::CreateBufferPacket("publicuser", client_public_key_,
      client_private_key_,
    &non_hex_chunk_name, &chunk_content);
  std::string hex_chunk_name("");
  base::encode_to_hex(non_hex_chunk_name, &hex_chunk_name);
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
                        maidsafe::BUFFER_PACKET,
                        boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  boost::this_thread::sleep(boost::posix_time::seconds(3));

  // Updating bufferpacket info not being the owner
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(packethandler::kRsaKeySize);
  std::string new_content;
  std::string expected_res;
  testpdvault::CreateMessage("test message", keys.public_key(),
    keys.private_key(), "public user2", packethandler::ADD_CONTACT_RQST,
    &new_content, &expected_res);
  std::string sig_pubkey = crypto_.AsymSign(keys.public_key(), "",
    keys.private_key(), crypto::STRING_STRING);

  signed_request =
      crypto_.AsymSign(crypto_.Hash(keys.public_key() + sig_pubkey +
                                    non_hex_chunk_name,
                                    "",
                                    crypto::STRING_STRING,
                                    false),
                       "",
                       keys.private_key(),
                       crypto::STRING_STRING);
  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                         new_content,
                         keys.public_key(),
                         sig_pubkey,
                         signed_request,
                         maidsafe::BUFFER_PACKET_INFO,
                         boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  testpdvault::PrepareCallbackResults();
  pdclient_->UpdateChunk(non_hex_chunk_name,
                         new_content,
                         keys.public_key(),
                         sig_pubkey,
                         signed_request,
                         maidsafe::BUFFER_PACKET_MESSAGE,
                         boost::bind(&testpdvault::StoreChunkCallback,
                                    _1));
  testpdvault::WaitFunction(120, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // Getting the complete buffer packet
  testpdvault::PrepareCallbackResults();
  pdclient_->GetChunk(non_hex_chunk_name,
                      boost::bind(&testpdvault::GetChunkCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  // verifying the buffer packet
  packethandler::BufferPacket rec_bp;
  ASSERT_TRUE(rec_bp.ParseFromString(callback_content_));
  ASSERT_EQ(1, rec_bp.messages_size());

  // Getting only the messages not owner
  testpdvault::PrepareCallbackResults();
  pdclient_->GetMessages(non_hex_chunk_name, keys.public_key(), sig_pubkey,
                      boost::bind(&testpdvault::GetMessagesCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // Getting messages
  testpdvault::PrepareCallbackResults();
  pdclient_->GetMessages(non_hex_chunk_name,
                         client_public_key_,
                         client_signed_public_key_,
                         boost::bind(&testpdvault::GetMessagesCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  ASSERT_EQ(size_t(1), callback_messages_.size());
  ASSERT_EQ(expected_res, callback_messages_.front());
  // Deleting the messages not owner
  testpdvault::PrepareCallbackResults();
  pdclient_->DeleteChunk(non_hex_chunk_name,
                         keys.public_key(),
                         sig_pubkey,
                         signed_request,
                         maidsafe::BUFFER_PACKET_MESSAGE,
                         boost::bind(&testpdvault::DeleteCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_FALSE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // Deleting messages
  signed_request =
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
  pdclient_->DeleteChunk(non_hex_chunk_name,
                         client_public_key_,
                         client_signed_public_key_,
                         signed_request,
                         maidsafe::BUFFER_PACKET_MESSAGE,
                         boost::bind(&testpdvault::DeleteCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);

  // Getting messages again
  testpdvault::PrepareCallbackResults();
  pdclient_->GetMessages(non_hex_chunk_name,
                         client_public_key_,
                         client_signed_public_key_,
                         boost::bind(&testpdvault::GetMessagesCallback, _1));
  testpdvault::WaitFunction(60, &mutex_);
  ASSERT_TRUE(callback_succeeded_);
  ASSERT_FALSE(callback_timed_out_);
  ASSERT_EQ(size_t(0), callback_messages_.size());
}
*/
TEST_F(TestPDVault, DISABLED_FUNC_MAID_SwapChunk) {
}

TEST_F(TestPDVault, DISABLED_FUNC_MAID_VaultValidateChunk) {
  // check pre-loaded chunks are not corrupted
}

TEST_F(TestPDVault, DISABLED_FUNC_MAID_VaultRepublishChunkRef) {
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
