/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
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
#include <boost/signals2/connection.hpp>

#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/sharedtest/cachepassport.h"
#include "maidsafe/sharedtest/mocksessionsingleton.h"
#include "maidsafe/sharedtest/testcallback.h"

namespace fs = boost::filesystem;

namespace test_lsm {

static const boost::uint8_t K(4);
static const boost::uint8_t upper_threshold_(static_cast<boost::uint8_t>
                            (K * maidsafe::kMinSuccessfulPecentageStore));


void CreateChunkage(std::map<std::string, std::string> *chunks_map,
                    int chunk_number,  fs::path test_root_dir_,
                    boost::shared_ptr<maidsafe::ChunkStore> client_chunkstore) {
  chunks_map->clear();
  while (chunks_map->size() < size_t(chunk_number)) {
    std::string chunk(base::RandomString(256 * 1024));
    std::string name(maidsafe::SHA512String(chunk));
    (*chunks_map)[name] = chunk;
    fs::path chunk_path(test_root_dir_ / base::EncodeToHex(name));
    fs::ofstream ofs;
    ofs.open(chunk_path, std::ofstream::binary | std::ofstream::ate);
    ofs.write(chunk.data(), chunk.size());
    ofs.close();
    client_chunkstore->AddChunkToOutgoing(name, chunk_path);
  }
}

void ChunkDone(const std::string &chunkname, maidsafe::ReturnCode rc,
               std::map<std::string, std::string> *chunks_map, int *count,
               boost::mutex *m) {
  boost::mutex::scoped_lock loch_schmer(*m);
  ASSERT_EQ(maidsafe::kSuccess, rc);
  std::map<std::string, std::string>::iterator it = chunks_map->find(chunkname);
  if (it != chunks_map->end()) {
    chunks_map->erase(it);
    --(*count);
  }
}

}  // namespace test_lsm

namespace maidsafe {

namespace test {

class LocalStoreManagerTest : public testing::Test {
 public:
  LocalStoreManagerTest()
      : test_root_dir_(file_system::TempDir() / ("maidsafe_TestStoreManager_" +
                       base::RandomAlphaNumericString(6))),
        client_chunkstore_(),
        sm_(),
        cb_(),
        ss_(SessionSingleton::getInstance()),
        functor_(),
        anmaid_private_key_(),
        mpid_public_key_() {}
  ~LocalStoreManagerTest() {
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }

 protected:
  void SetUp() {
    ss_->ResetSession();
    try {
      if (fs::exists(test_root_dir_))
        fs::remove_all(test_root_dir_);
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    client_chunkstore_ = boost::shared_ptr<ChunkStore>
                             (new ChunkStore(test_root_dir_.string(),
                                                       0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    int count(0);
    while (!client_chunkstore_->is_initialised() && count < 10000) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    sm_ = new LocalStoreManager(client_chunkstore_, test_lsm::K,
                                test_root_dir_);
    sm_->Init(boost::bind(&CallbackObject::ReturnCodeCallback, &cb_, _1), 0);
    if (cb_.WaitForReturnCodeResult() != kSuccess) {
      FAIL();
      return;
    }
    ss_ = SessionSingleton::getInstance();
    boost::shared_ptr<passport::test::CachePassport> passport(
        new passport::test::CachePassport(kRsaKeySize, 5, 10));
    passport->Init();
    ss_->passport_ = passport;
    ss_->ResetSession();
    ss_->CreateTestPackets("Me");
    cb_.Reset();
    functor_ = boost::bind(&CallbackObject::ReturnCodeCallback, &cb_, _1);
    anmaid_private_key_ = ss_->PrivateKey(passport::ANMAID, true);
    mpid_public_key_ = ss_->PublicKey(passport::MPID, true);
  }

  void TearDown() {
    ss_->ResetSession();
    cb_.Reset();
    sm_->Close(functor_, true);
    if (cb_.WaitForReturnCodeResult() == kSuccess) {
      try {
        if (fs::exists(test_root_dir_))
          fs::remove_all(test_root_dir_);
        if (fs::exists(file_system::LocalStoreManagerDir()))
          fs::remove_all(file_system::LocalStoreManagerDir());
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }
  }
  fs::path test_root_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  LocalStoreManager *sm_;
  test::CallbackObject cb_;
  SessionSingleton *ss_;
  boost::function<void(const ReturnCode &)> functor_;
  std::string anmaid_private_key_, mpid_public_key_;

 private:
  LocalStoreManagerTest(const LocalStoreManagerTest&);
  LocalStoreManagerTest &operator=(const LocalStoreManagerTest&);
};

TEST_F(LocalStoreManagerTest, BEH_MAID_RemoveAllPacketsFromKey) {
  kad::SignedValue gp;
  std::string gp_name;

  // Store packets with same key, different values
  gp_name = SHA512String("aaa");
  for (int i = 0; i < 5; ++i) {
    gp.set_value("Generic System Packet Data" +
                  boost::lexical_cast<std::string>(i));
    cb_.Reset();
    sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "",
                     functor_);
    ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  }

  // Remove said packets
  cb_.Reset();
  sm_->DeletePacket(gp_name, std::vector<std::string>(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  // Ensure they're all gone
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreSystemPacket) {
  kad::SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  std::string gp_name = SHA512String(gp.value() + gp.value_signature());
  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));
  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  kad::SignedValue gp_res;
  ASSERT_TRUE(gp_res.ParseFromString(res[0]));
  ASSERT_EQ(gp.value(), gp_res.value());
  ASSERT_EQ(gp.value_signature(), gp_res.value_signature());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_DeleteSystemPacketOwner) {
  kad::SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  std::string gp_name = SHA512String(gp.value() + gp.value_signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());

  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.value());
  cb_.Reset();
  sm_->DeletePacket(gp_name, values, passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());

  ASSERT_TRUE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_MAID_DeleteSystemPacketNotOwner) {
  kad::SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  std::string gp_name = SHA512String(gp.value() + gp.value_signature());

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));

  std::vector<std::string> values(1, gp.value());

  // Overwrite original signature packets
  ss_->passport_ = boost::shared_ptr<passport::Passport>(
      new passport::Passport(kRsaKeySize, 5));
  ss_->passport_->Init();
  ss_->CreateTestPackets("");

  cb_.Reset();
  sm_->DeletePacket(gp_name, values, passport::MAID, PRIVATE, "", functor_);
  ASSERT_NE(kSuccess, cb_.WaitForReturnCodeResult());
  ASSERT_FALSE(sm_->KeyUnique(gp_name, false));
}

TEST_F(LocalStoreManagerTest, BEH_MAID_UpdatePacket) {
  // Store one packet
  kad::SignedValue gp;
  gp.set_value("Generic System Packet Data");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  std::string gp_name(SHA512String(gp.value() + gp.value_signature()));

  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());

  std::vector<std::string> res;
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  ASSERT_EQ(gp.SerializeAsString(), res[0]);

  // Update the packet
  kad::SignedValue new_gp;
  new_gp.set_value("Mis bolas enormes y peludas");
  new_gp.set_value_signature(RSASign(new_gp.value(), anmaid_private_key_));
  cb_.Reset();
  sm_->UpdatePacket(gp_name, gp.value(), new_gp.value(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(size_t(1), res.size());
  ASSERT_EQ(new_gp.SerializeAsString(), res[0]);

  // Store another value with that same key
  gp.set_value("Mira nada mas que chichotas");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  cb_.Reset();
  sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(size_t(2), res.size());
  for (size_t n = 0; n < res.size(); ++n)
    ASSERT_TRUE(res[n] == gp.SerializeAsString() ||
                res[n] == new_gp.SerializeAsString());

  // Change one of the values
  kad::SignedValue other_gp = gp;
  gp.set_value("En esa cola si me formo");
  gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
  cb_.Reset();
  sm_->UpdatePacket(gp_name, new_gp.value(), gp.value(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(size_t(2), res.size());
  std::set<std::string> all_values;
  for (size_t n = 0; n < res.size(); ++n) {
    ASSERT_TRUE(res[n] == gp.SerializeAsString() ||
                res[n] == other_gp.SerializeAsString()) << n;
    all_values.insert(res[n]);
  }

  // Store several values with that same key
  for (size_t a = 0; a < 5; ++a) {
    gp.set_value("value" + base::IntToString(a));
    gp.set_value_signature(RSASign(gp.value(), anmaid_private_key_));
    cb_.Reset();
    sm_->StorePacket(gp_name, gp.value(), passport::MAID, PRIVATE, "",
                     functor_);
    ASSERT_EQ(kSuccess, cb_.WaitForReturnCodeResult());
    all_values.insert(gp.SerializeAsString());
  }
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(all_values.size(), res.size());
  std::set<std::string>::iterator it;
  for (size_t n = 0; n < res.size(); ++n) {
    it = all_values.find(res[n]);
    ASSERT_FALSE(it == all_values.end());
  }

  // Try to change one of the values to another one
  cb_.Reset();
  sm_->UpdatePacket(gp_name, "value0", "value2", passport::MAID, PRIVATE, "",
                    functor_);
  ASSERT_EQ(kStoreManagerError, cb_.WaitForReturnCodeResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(all_values.size(), res.size());
  for (size_t n = 0; n < res.size(); ++n) {
    it = all_values.find(res[n]);
    ASSERT_FALSE(it == all_values.end());
  }

  // Try to update with different keys
  ss_->passport_ = boost::shared_ptr<passport::Passport>(
      new passport::Passport(kRsaKeySize, 5));
  ss_->passport_->Init();
  ss_->CreateTestPackets("");

  cb_.Reset();
  sm_->UpdatePacket(gp_name, gp.value(), new_gp.value(), passport::MAID,
                    PRIVATE, "", functor_);
  ASSERT_EQ(kStoreManagerError, cb_.WaitForReturnCodeResult());
  res.clear();
  ASSERT_EQ(kSuccess, sm_->LoadPacket(gp_name, &res));
  ASSERT_EQ(all_values.size(), res.size());
  for (size_t n = 0; n < res.size(); ++n) {
    it = all_values.find(res[n]);
    ASSERT_FALSE(it == all_values.end());
  }
  all_values = std::set<std::string>(res.begin(), res.end());
  it = all_values.find("value1234");
  ASSERT_TRUE(it == all_values.end());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreChunk) {
  std::map<std::string, std::string> chunkies;
  int count(1), count2(count);
  boost::mutex m;
  std::string chunk_content = base::RandomAlphaNumericString(256 * 1024);
  std::string chunk_name = SHA512String(chunk_content);
  chunkies[chunk_name] = chunk_content;
  boost::signals2::connection c =
      sm_->ConnectToOnChunkUploaded(boost::bind(&test_lsm::ChunkDone, _1, _2,
                                                &chunkies, &count, &m));

  std::string hex_chunk_name = base::EncodeToHex(chunk_name);
  fs::path chunk_path(test_root_dir_ / hex_chunk_name);
  fs::ofstream ofs;
  ofs.open(chunk_path.string().c_str());
  ofs << chunk_content;
  ofs.close();
  client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_path);
  ASSERT_TRUE(sm_->KeyUnique(chunk_name, false));

  sm_->StoreChunk(chunk_name, PRIVATE, "");
  while (count2 != 0) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_juan(m);
      count2 = count;
    }
  }

  ASSERT_FALSE(sm_->KeyUnique(chunk_name, false));
  std::string result_str;
  ASSERT_EQ(0, sm_->LoadChunk(chunk_name, &result_str));
  ASSERT_EQ(chunk_content, result_str);
}

TEST_F(LocalStoreManagerTest, FUNC_MAID_StoreSeveralChunksWithSignals) {
  std::map<std::string, std::string> chunkies, chunkies2;
  test_lsm::CreateChunkage(&chunkies, 50, test_root_dir_, client_chunkstore_);
  printf("Done creating chunks.\n");
  int count(50), count2(count);
  boost::mutex m;
  boost::signals2::connection c =
      sm_->ConnectToOnChunkUploaded(boost::bind(&test_lsm::ChunkDone, _1, _2,
                                                &chunkies, &count, &m));
  // Store the chunks
  {
    boost::mutex::scoped_lock loch_juan(m);
    for (std::map<std::string, std::string>::iterator it = chunkies.begin();
         it != chunkies.end(); ++it) {
      ASSERT_TRUE(sm_->KeyUnique((*it).first, false));
      sm_->StoreChunk((*it).first, PRIVATE, "");
    }
    chunkies2 = chunkies;
  }
  printf("Done adding chunks.\n");

  while (count2 != 0) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
    {
      boost::mutex::scoped_lock loch_juan(m);
      count2 = count;
    }
  }
  printf("Done collecting results.\n");

  // Evaluate the size
  ASSERT_TRUE(chunkies.empty());
  for (std::map<std::string, std::string>::iterator it = chunkies2.begin();
       it != chunkies2.end(); ++it)
    ASSERT_FALSE(sm_->KeyUnique((*it).first, false));
  printf("Done checking assertions.\n");
  c.disconnect();
}

TEST_F(LocalStoreManagerTest, BEH_MAID_StoreAndLoadBufferPacket) {
  std::string bufferpacketname =
      SHA512String(ss_->PublicUsername() + mpid_public_key_);
  ASSERT_TRUE(sm_->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, sm_->CreateBP());
  ASSERT_FALSE(sm_->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  sm_->LoadChunk(bufferpacketname, &packet_content);
  BufferPacket buffer_packet;
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  ASSERT_EQ(1, buffer_packet.owner_info_size());
  ASSERT_EQ(0, buffer_packet.messages_size());
  GenericPacket gp = buffer_packet.owner_info(0);
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  BufferPacketInfo bpi;
  ASSERT_TRUE(bpi.ParseFromString(gp.data()));
  ASSERT_EQ(ss_->PublicUsername(), bpi.owner());
  ASSERT_EQ(mpid_public_key_, bpi.owner_publickey());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_ModifyBufferPacketInfo) {
  std::string bufferpacketname =
      SHA512String(ss_->PublicUsername() + mpid_public_key_);
  ASSERT_TRUE(sm_->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, sm_->CreateBP());
  ASSERT_FALSE(sm_->KeyUnique(bufferpacketname, false));
  std::string packet_content;
  sm_->LoadChunk(bufferpacketname, &packet_content);
  BufferPacket buffer_packet;
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  ASSERT_EQ(1, buffer_packet.owner_info_size());
  ASSERT_EQ(0, buffer_packet.messages_size());
  GenericPacket gp = buffer_packet.owner_info(0);
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  BufferPacketInfo bpi;
  ASSERT_TRUE(bpi.ParseFromString(gp.data()));
  ASSERT_EQ(ss_->PublicUsername(), bpi.owner());
  ASSERT_EQ(mpid_public_key_, bpi.owner_publickey());

  // Modifying the BP info
  BufferPacketInfo buffer_packet_info;
  std::string ser_info;
  buffer_packet_info.set_owner(ss_->PublicUsername());
  buffer_packet_info.set_owner_publickey(mpid_public_key_);
  buffer_packet_info.add_users("Juanito");
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, sm_->ModifyBPInfo(ser_info));
  packet_content.clear();
  ASSERT_EQ(0, sm_->LoadChunk(bufferpacketname, &packet_content));
  ASSERT_TRUE(buffer_packet.ParseFromString(packet_content));
  gp = buffer_packet.owner_info(0);
  std::string ser_gp;
  ASSERT_TRUE(gp.SerializeToString(&ser_gp));
  ASSERT_TRUE(RSACheckSignedData(gp.data(), gp.signature(), mpid_public_key_));
  ASSERT_EQ(ser_info, gp.data());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_AddAndGetBufferPacketMessages) {
  std::string bufferpacketname =
      SHA512String(ss_->PublicUsername() + mpid_public_key_);
  ASSERT_TRUE(sm_->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, sm_->CreateBP());
  ASSERT_FALSE(sm_->KeyUnique(bufferpacketname, false));
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->PublicUsername());
  buffer_packet_info.set_owner_publickey(mpid_public_key_);
  buffer_packet_info.add_users(SHA512String("Juanito"));
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, sm_->ModifyBPInfo(ser_info));

  // Create the user "Juanito", add to session, then the message and send it
  MockSessionSingleton ss1;
  ss1.CreateTestPackets("Juanito");
  sm_->ss_ = &ss1;
  ASSERT_EQ(0, ss1.AddContact(ss_->PublicUsername(), mpid_public_key_, "", "",
                              "", 'U', 1, 2, "", 'C', 0, 0));

  std::vector<std::string> pulbicusernames;
  std::string test_msg("There are strange things done in the midnight sun");
  pulbicusernames.push_back(ss_->PublicUsername());
  std::map<std::string, ReturnCode> add_results;
  ASSERT_EQ(static_cast<int>(pulbicusernames.size()),
            sm_->SendMessage(pulbicusernames, test_msg, INSTANT_MSG,
                              &add_results));

  // Retrive message and check that it is the correct one
  sm_->ss_ = SessionSingleton::getInstance();
  std::list<ValidatedBufferPacketMessage> messages;
  ASSERT_EQ(test_lsm::upper_threshold_, sm_->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_EQ("", messages.front().index());
  ASSERT_EQ(INSTANT_MSG, messages.front().type());

  // Check message is gone
  ASSERT_EQ(test_lsm::upper_threshold_, sm_->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(0), messages.size());
}

TEST_F(LocalStoreManagerTest, BEH_MAID_AddRequestBufferPacketMessage) {
  std::string bufferpacketname =
      SHA512String(ss_->PublicUsername() + mpid_public_key_);
  ASSERT_TRUE(sm_->KeyUnique(bufferpacketname, false));
  ASSERT_EQ(0, sm_->CreateBP());
  ASSERT_FALSE(sm_->KeyUnique(bufferpacketname, false));
  std::string me_pubusername = ss_->PublicUsername();

  // Create the user "Juanito", add to session, then the message and send it
  MockSessionSingleton ss1;
  ss1.CreateTestPackets("Juanito");
  sm_->ss_ = &ss1;
  ASSERT_EQ(0, ss1.AddContact(me_pubusername, mpid_public_key_, "", "", "", 'U',
                              1, 2, "", 'C', 0, 0));
  std::vector<std::string> pulbicusernames;
  std::string test_msg("There are strange things done in the midnight sun");
  pulbicusernames.push_back(me_pubusername);
  std::map<std::string, ReturnCode> add_results;
  ASSERT_EQ(0, sm_->SendMessage(pulbicusernames, test_msg,
            INSTANT_MSG, &add_results));
  add_results.clear();
  ASSERT_EQ(static_cast<int>(pulbicusernames.size()),
            sm_->SendMessage(pulbicusernames, test_msg,
                              ADD_CONTACT_RQST, &add_results));

  // Back to "Me"
  sm_->ss_ = SessionSingleton::getInstance();
  std::list<ValidatedBufferPacketMessage> messages;
  ASSERT_EQ(test_lsm::upper_threshold_, sm_->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_EQ("", messages.front().index());
  ASSERT_EQ(ADD_CONTACT_RQST, messages.front().type());
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->PublicUsername());
  buffer_packet_info.set_owner_publickey(mpid_public_key_);
  buffer_packet_info.add_users(SHA512String("Juanito"));
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ASSERT_EQ(0, sm_->ModifyBPInfo(ser_info));

  // Back to "Juanito"
  sm_->ss_ = &ss1;
  pulbicusernames.clear();
  pulbicusernames.push_back(me_pubusername);
  add_results.clear();
  ASSERT_EQ(static_cast<int>(pulbicusernames.size()),
            sm_->SendMessage(pulbicusernames, test_msg, INSTANT_MSG,
                              &add_results));

  // Back to "Me"
  sm_->ss_ = SessionSingleton::getInstance();
  messages.clear();
  ASSERT_EQ(test_lsm::upper_threshold_, sm_->LoadBPMessages(&messages));
  ASSERT_EQ(size_t(1), messages.size());
  ASSERT_EQ("Juanito", messages.front().sender());
  ASSERT_EQ(test_msg, messages.front().message());
  ASSERT_EQ("", messages.front().index());
  ASSERT_EQ(INSTANT_MSG, messages.front().type());
}

}  // namespace test

}  // namespace maidsafe
