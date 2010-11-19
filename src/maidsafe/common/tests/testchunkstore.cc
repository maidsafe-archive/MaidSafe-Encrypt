/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Oct 14, 2008
 *      Author: Jose, Haiyang
 */

#include <boost/thread.hpp>
#include <boost/filesystem/fstream.hpp>
#include <gtest/gtest.h>
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/packet.pb.h"
#include "maidsafe/common/returncodes.h"
#include "maidsafe/sharedtest/chunkstoreops.h"

namespace maidsafe {

namespace test {

TEST_F(ChunkstoreTest, BEH_MAID_Init) {
  std::string invalid_path_length(257, ' ');
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(invalid_path_length,
                                                          1073741824, 0));
  ASSERT_FALSE(chunkstore->Init());
  ASSERT_FALSE(chunkstore->is_initialised());
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  ASSERT_FALSE(chunkstore->Has(h_name.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Store(h_name.at(0), h_value.at(0)));
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Store(h_name.at(0), file_path));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->AddChunkToOutgoing(h_name.at(0), h_value.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->DeleteChunk(h_name.at(0)));
  std::string value("value");
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Load(h_name.at(0), &value));
  ASSERT_EQ("", value);
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->HashCheckChunk(h_name.at(0)));
  maidsafe::ChunkType type = maidsafe::kHashable | maidsafe::kNormal;
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->ChangeChunkType(h_name.at(0), type));
  boost::shared_ptr<ChunkStore> chunkstore1(new ChunkStore(storedir.string(),
                                                           1073741824, 0));
  ASSERT_TRUE(chunkstore1->Init());
  test_chunkstore::WaitForInitialisation(chunkstore1, 60000);
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_TRUE(chunkstore1->Init());
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_EQ(storedir.string(), chunkstore1->ChunkStoreDir());
}

TEST_F(ChunkstoreTest, BEH_MAID_GetChunkPath) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  std::string test_chunk_name = SHA512String("test");
  fs::path test_chunk_path(storedir);
  test_chunk_path /= "Hashable";
  test_chunk_path /= "Normal";
  test_chunk_path /= "e";
  test_chunk_path /= "e";
  test_chunk_path /= "2";
  test_chunk_path /= base::EncodeToHex(test_chunk_name);
  // Chunk name empty
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("",
            (maidsafe::kHashable | maidsafe::kNormal), false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("",
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // Chunk name not kKeySize in length
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("A",
            (maidsafe::kHashable | maidsafe::kNormal), false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("A",
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // Invalid chunk type
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name, 3, false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name, 3, true));
  // Valid name, but chunk doesn't exist and create_path == false
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), false));
  // All valid - if this fails, check permissions to create dir in /temp
  ASSERT_EQ(test_chunk_path, chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // OK now - chunk exists
  ASSERT_EQ(test_chunk_path, chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), false));
}

TEST_F(ChunkstoreTest, BEH_MAID_StoreChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check we can't overwrite existing value using Store
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->Store(h_name.at(test_chunk), file_path));
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->Store(h_name.at(test_chunk), std::string("New value")));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  // check contents of file
  ASSERT_FALSE(found.filename().empty());
  size_t chunk_size = static_cast<size_t>(fs::file_size(found));
  ASSERT_EQ(h_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(h_name.at(test_chunk)));
  boost::scoped_ptr<char> temp1(new char[chunk_size]);
  fs::ifstream fstr1;
  fstr1.open(found, std::ios_base::binary);
  fstr1.read(temp1.get(), chunk_size);
  fstr1.close();
  std::string stored_value1(static_cast<const char*>(temp1.get()), chunk_size);
  ASSERT_EQ(h_value.at(test_chunk), stored_value1);
  // move to Outgoing and check we can store again
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kOutgoing));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check a hashable chunk which is already cached can be stored
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kCache));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kTempCache));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check we can add a chunk which is stored as a file
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(0, chunkstore->Store(hash_file_content, file_path));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 2,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, hash_file_content, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                 nh_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 3,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
      chunkstore->kNonHashableLeaf_, chunkstore->kNormalLeaf_));
  // check contents of file
  ASSERT_FALSE(found.filename().empty());
  chunk_size = static_cast<size_t>(fs::file_size(found));
  ASSERT_EQ(nh_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(nh_name.at(test_chunk)));
  boost::scoped_ptr<char> temp2(new char[chunk_size]);
  fs::ifstream fstr2;
  fstr2.open(found, std::ios_base::binary);
  fstr2.read(temp2.get(), chunk_size);
  fstr2.close();
  std::string stored_value2(static_cast<const char*>(temp2.get()), chunk_size);
  ASSERT_EQ(nh_value.at(test_chunk), stored_value2);
  // check we can add a chunk which is stored as a file
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(0, chunkstore->Store(other_hash, file_path));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 4,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, other_hash, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check values can't be stored under keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(maidsafe::kIncorrectKeySize,
      chunkstore->Store(wrong_length_key, h_value.at(0)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 4,
            chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(test_chunkstore::FindFile(storedir, wrong_length_key, &found));
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_AddChunkToOutgoing) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                              h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // try to add file again (should return kChunkExistsInChunkstore as file now
  // stored)
  ASSERT_EQ(maidsafe::kChunkExistsInChunkstore,
            chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                           h_value.at(test_chunk)));

  // TODO(Team#5#): 2009-04-06 - Decide when to overwrite file using Store
  //  std::string new_val("New value");
  //  ASSERT_NE(0, chunkstore->Store(h_name.at(test_chunk), new_val));
  //  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
  //            chunkstore->chunkstore_set_.size());

  // check contents of file
  ASSERT_FALSE(found.filename().empty());
  size_t chunk_size = static_cast<size_t>(fs::file_size(found));
  ASSERT_EQ(h_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(h_name.at(test_chunk)));
  boost::scoped_ptr<char> temp1(new char[chunk_size]);
  fs::ifstream fstr1;
  fstr1.open(found, std::ios_base::binary);
  fstr1.read(temp1.get(), chunk_size);
  fstr1.close();
  std::string stored_value1(static_cast<const char*>(temp1.get()), chunk_size);
  ASSERT_EQ(h_value.at(test_chunk), stored_value1);
  // check we can add a chunk which is stored as a file
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(hash_file_content, file_path));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 2,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, hash_file_content, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(nh_name.at(test_chunk),
                                              nh_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 3,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
      chunkstore->kNonHashableLeaf_, chunkstore->kOutgoingLeaf_));
  // try to add file again (should return kChunkExistsInChunkstore as file now
  // stored)
  ASSERT_EQ(maidsafe::kChunkExistsInChunkstore,
            chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                           h_value.at(test_chunk)));
  // check contents of file
  ASSERT_FALSE(found.filename().empty());
  chunk_size = static_cast<size_t>(fs::file_size(found));
  ASSERT_EQ(nh_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(nh_name.at(test_chunk)));
  boost::scoped_ptr<char> temp2(new char[chunk_size]);
  fs::ifstream fstr2;
  fstr2.open(found, std::ios_base::binary);
  fstr2.read(temp2.get(), chunk_size);
  fstr2.close();
  std::string stored_value2(static_cast<const char*>(temp2.get()), chunk_size);
  ASSERT_EQ(nh_value.at(test_chunk), stored_value2);
  // check we can add a chunk which is stored as a file
  fs::ofstream ofs;
  ofs.open(file_path);
  ofs << file_content;
  ofs.close();
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(other_hash, file_path));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 4,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, other_hash, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check values can't be stored under keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize,
            chunkstore->Store(wrong_length_key, h_value.at(0)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 4,
            chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(test_chunkstore::FindFile(storedir, wrong_length_key, &found));
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_LoadChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  std::string rec_value("Value");
  ASSERT_EQ(0, chunkstore->Load(h_name.at(test_chunk), &rec_value));
  ASSERT_EQ(h_value.at(test_chunk), rec_value);
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(nh_name.at(test_chunk), &rec_value));
  ASSERT_EQ(nh_value.at(test_chunk), rec_value);
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(othername, &rec_value));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->Load(wrong_length_key, &rec_value));
}

TEST_F(ChunkstoreTest, BEH_MAID_HasChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->Has(h_name.at(test_chunk)));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->Has(nh_name.at(test_chunk)));
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_FALSE(chunkstore->Has(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_DeleteChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->Has(h_name.at(test_chunk)));
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_FALSE(found.filename().empty());
  ASSERT_TRUE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->Has(h_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->Has(nh_name.at(test_chunk)));
  found = fs::path("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  ASSERT_FALSE(found.filename().empty());
  ASSERT_TRUE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->Has(nh_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_EQ(0, chunkstore->DeleteChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->DeleteChunk(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_HashCheckChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  boost::posix_time::ptime original_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(
        h_name.at(test_chunk));
    original_check_time = (*itr).last_checked_;
  }
  // Allow thread to sleep to ensure different check times.
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(0, chunkstore->HashCheckChunk(h_name.at(test_chunk)));
  boost::posix_time::ptime later_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(
        h_name.at(test_chunk));
    later_check_time = (*itr).last_checked_;
  }
  ASSERT_GT(later_check_time - original_check_time,
            boost::posix_time::milliseconds(0));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(kHashCheckFailure,
            chunkstore->HashCheckChunk(nh_name.at(test_chunk)));
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_EQ(kInvalidChunkType, chunkstore->HashCheckChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->HashCheckChunk(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChangeChunkType) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = chunkstore->path_map_.size();  // 8
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(0), nh_value.at(0)));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(1), nh_value.at(1)));
  // Move a chunk to each of the different types and the single chunk to the
  // original type of all the others.
  maidsafe::path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                             (*path_map_itr).first));
    fs::path found_path("");
    ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(i), &found_path));
    found.push_back(found_path);
    ++i;
  }
  path_map_itr = chunkstore->path_map_.begin();
  ASSERT_EQ(0, chunkstore->ChangeChunkType(nh_name.at(0),
                                           (*path_map_itr).first));
  fs::path found_path("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(0), &found_path));
  // Check each chunk has the correct type
  i = 0;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    {
      boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
      maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
          chunkstore_set_.get<maidsafe::non_hex_name>().find(h_name.at(i));
      ASSERT_EQ((*path_map_itr).first, (*itr).type_);
    }
    ++i;
  }
  path_map_itr = chunkstore->path_map_.begin();
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(nh_name.at(0));
    ASSERT_EQ((*path_map_itr).first, (*itr).type_);
  }
  // Check each has been moved to the correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(0),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(1),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(2),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(3),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(4),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(5),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(6),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(7),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found_path,
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using invalid type
  maidsafe::ChunkType type = 3;
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->ChangeChunkType(nh_name.at(1), type));
  type = (maidsafe::kNonHashable | maidsafe::kNormal);
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(nh_name.at(1));
    ASSERT_EQ(type, (*itr).type_);
  }
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(1), &found_path));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found_path,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_EQ(kChunkstoreError, chunkstore->ChangeChunkType(othername,
            (maidsafe::kHashable | maidsafe::kNormal)));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->ChangeChunkType(wrong_length_key,
            (maidsafe::kHashable | maidsafe::kNormal)));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkType) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = chunkstore->path_map_.size();  // 8
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  // Move a chunk to each of the different types.
  maidsafe::path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                             (*path_map_itr).first));
    ++i;
  }
  // Check each chunk has the correct type
  i = 0;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ((*path_map_itr).first, chunkstore->chunk_type(h_name.at(i)));
    ++i;
  }
}

TEST_F(ChunkstoreTest, BEH_MAID_ReuseDirectory) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  // Move 5 chunks to each of the different types.
  maidsafe::path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    for (int j = 0; j < 5; ++j) {
      ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                               (*path_map_itr).first));
      fs::path found_path("");
      ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(i),
                                            &found_path));
      found.push_back(found_path);
      ++i;
    }
  }
  // Create a new chunkstore that has same root dir
  boost::shared_ptr<ChunkStore> chunkstore2(new ChunkStore(storedir.string(),
                                                           1073741824, 0));
  ASSERT_TRUE(chunkstore2->Init());
  test_chunkstore::WaitForInitialisation(chunkstore2, 60000);
  ASSERT_TRUE(chunkstore2->is_initialised());
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + kNumberOfChunks,
            chunkstore2->chunkstore_set_.size());
  for (int k = 0; k < kNumberOfChunks; k++) {
    ASSERT_TRUE(chunkstore2->Has(h_name.at(k)));
    std::string rec_value("Value");
    ASSERT_EQ(0, chunkstore2->Load(h_name.at(k), &rec_value));
  }
}

TEST_F(ChunkstoreTest, BEH_MAID_Clear) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));

  // Clear empty chunk store
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(static_cast<size_t>(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));

  // Empty with one chunk in
  ASSERT_TRUE(chunkstore->Init());
  ASSERT_EQ(0, chunkstore->Store(h_name.at(0), h_value.at(0)));
  std::string tempval;
  ASSERT_EQ(0, chunkstore->Load(h_name.at(0), &tempval));
  ASSERT_EQ(h_value.at(0), tempval);
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(static_cast<size_t>(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));

  // Empty with kNumberOfChunks chunks
  ASSERT_TRUE(chunkstore->Init());
  for (size_t i = 0; i < h_value.size(); ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + kNumberOfChunks,
            chunkstore->chunkstore_set_.size());
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(static_cast<size_t>(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));
}

TEST_F(ChunkstoreTest, BEH_MAID_ThreadedStoreAndLoad) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Store each chunk after a 50 ms delay
  boost::posix_time::milliseconds store_delay(50);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  // Start checking for each chunk via Has with no delay
  bool result(false);
  std::vector<boost::shared_ptr<bool> > has_chunk;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<bool> res(new bool(false));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    has_chunk.push_back(res);
  }
  const boost::uint64_t kTimeout(5000);
  boost::uint64_t count(0);
  boost::posix_time::milliseconds has_delay(0);
  while (count < kTimeout && !result) {
    boost::thread_group has_thread_group;
    for (int i = 0; i < kNumberOfChunks; ++i) {
      has_thread_group.create_thread(boost::bind(
          &test_chunkstore::ThreadedTest::Has, tester, has_delay,
          h_name.at(i), has_chunk.at(i)));
    }
    has_thread_group.join_all();
    result = true;
    for (int i = 0; i < kNumberOfChunks; ++i)
      result = result && *has_chunk.at(i);
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  ASSERT_TRUE(result);
  // Check all stores returned 0
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Load back all chunks
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  // Check all loads returned 0 and all values loaded correctly
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_EQ(h_value.at(i), *load_value.at(i));
    result = result && (*load_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
}

TEST_F(ChunkstoreTest, BEH_MAID_ThreadedDelete) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 1000, 32000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare delete vectors
  boost::posix_time::milliseconds delete_delay(0);
  std::vector<boost::shared_ptr<int> > delete_result;
  boost::thread_group delete_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    delete_result.push_back(res);
  }
  // Store chunks
  boost::posix_time::milliseconds store_delay(0);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  // Start deleting chunks in reverse order once first chunk has been stored to
  // ensure some update failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    delete_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::DeleteChunk, tester, delete_delay,
        h_name.at(i), delete_result.at(i)));
  }
  delete_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Check all deletes returned true with possibly one or two having failed if
  // it threw a filesystem exception
  int successful_deletes(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*delete_result.at(i) == 0)
      ++successful_deletes;
  }
  ASSERT_GE(successful_deletes, kNumberOfChunks - 2);
  // Load back any remaining chunks and check they are OK
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*load_result.at(i) == 0)
      ASSERT_EQ(h_value.at(i), *load_value.at(i));
  }
}

TEST_F(ChunkstoreTest, BEH_MAID_ThreadedCheckSingle) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 1000, 32000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare hash check vectors
  boost::posix_time::milliseconds check_delay(0);
  std::vector<boost::shared_ptr<int> > check_result;
  boost::thread_group check_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(5318008));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    check_result.push_back(res);
  }
  // Store chunks
  boost::posix_time::milliseconds store_delay(0);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  // Start checking chunks in reverse order once first chunk has been stored to
  // ensure some check failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    check_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::HashCheckChunk, tester, check_delay,
        h_name.at(i), check_result.at(i)));
  }
  store_thread_group.join_all();
  check_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Do hash check again now that all chunks are available
  for (int i = 0; i < kNumberOfChunks; ++i) {
    check_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::HashCheckChunk, tester, check_delay,
        h_name.at(i), check_result.at(i)));
  }
  check_thread_group.join_all();
  // Check all checks returned true
  int result_int(0);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result_int += *check_result.at(i);
  ASSERT_EQ(0, result_int);
}

TEST_F(ChunkstoreTest, BEH_MAID_ThreadedChangeType) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string(),
                                                          1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 80;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 16000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare change_type vectors
  boost::posix_time::milliseconds change_type_delay(0);
  std::vector<boost::shared_ptr<int> > change_type_result;
  std::vector<maidsafe::ChunkType> chunk_type;
  int count(0);
  while (count < kNumberOfChunks) {
    maidsafe::path_map_iterator path_map_itr = chunkstore->path_map_.begin();
    chunk_type.push_back((*path_map_itr).first);
    ++path_map_itr;
    if (path_map_itr == chunkstore->path_map_.end())
      path_map_itr = chunkstore->path_map_.begin();
    ++count;
  }
  boost::thread_group change_type_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(5318008));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    change_type_result.push_back(res);
  }
  // Store chunks
  boost::posix_time::milliseconds store_delay(0);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  // Start changing chunks' types in reverse order once first chunk has been
  // stored to ensure some failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    change_type_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::ChangeChunkType, tester,
        change_type_delay, h_name.at(i), chunk_type.at(i),
        change_type_result.at(i)));
  }
  change_type_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Run change types again
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    change_type_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::ChangeChunkType, tester,
        change_type_delay, h_name.at(i), chunk_type.at(i),
        change_type_result.at(i)));
  }
  change_type_thread_group.join_all();
  // Count number of successful updates
  int successful_changes(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*change_type_result.at(i) == 0)
      ++successful_changes;
  }
  ASSERT_EQ(kNumberOfChunks, successful_changes);
  // Load back all chunks
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  // Check all loads returned 0 and all values loaded correctly
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_TRUE(h_value.at(i) == *load_value.at(i));
    result = result && (*load_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
}

}  // namespace test

}  // namespace maidsafe
