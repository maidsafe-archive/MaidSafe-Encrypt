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


#include <boost/filesystem/fstream.hpp>
#include <gtest/gtest.h>
#include "base/utils.h"
#include "base/crypto.h"
#include "maidsafe/vault/chunkstore.h"

class TestChunkstore : public testing::Test {
 protected:
  TestChunkstore()
      : storedir("./TESTSTORAGE"),
        cry_obj(),
        chunkstore(storedir.string()) {}
  void SetUp() {
    cry_obj.set_symm_algorithm("AES_256");
    cry_obj.set_hash_algorithm("SHA512");
  }
  void TearDown() {
    fs::remove_all(storedir);
  }
  fs::path storedir;
  crypto::Crypto cry_obj;
  maidsafe_vault::ChunkStore chunkstore;
};

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreStoreChunk) {
  std::string value = base::RandomString(250*1024);
  fs::path filename(storedir);
  std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
  ASSERT_TRUE(chunkstore.StoreChunk(name, value));
  std::string enc_name;
  base::encode_to_hex(name, enc_name);
  filename = filename / enc_name;
  ASSERT_TRUE(fs::exists(filename));
  boost::uintmax_t size = fs::file_size(filename);
  ASSERT_EQ((unsigned)250*1024, size);
  char *temp;
  temp = new char[size];
  fs::ifstream fstr;
  fstr.open(filename, std::ios_base::binary);
  fstr.read(temp, size);
  fstr.close();
  std::string stored_value((const char*)temp, size);
  ASSERT_EQ(value, stored_value);
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreLoadChunk) {
  std::string value = base::RandomString(250*1024);
  std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
  ASSERT_TRUE(chunkstore.StoreChunk(name, value));
  std::string rec_value;
  ASSERT_TRUE(chunkstore.LoadChunk(name, &rec_value));
  ASSERT_EQ(value, rec_value);
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreHasChunk) {
  std::string value = base::RandomString(250*1024);
  std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
  ASSERT_TRUE(chunkstore.StoreChunk(name, value));
  ASSERT_TRUE(chunkstore.HasChunk(name));
  name = cry_obj.Hash("otherfile", "", crypto::STRING_STRING, false);
  ASSERT_FALSE(chunkstore.HasChunk(name));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreDeleteChunk) {
  std::string value = base::RandomString(250*1024);
  std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
  ASSERT_TRUE(chunkstore.StoreChunk(name, value));
  ASSERT_TRUE(chunkstore.HasChunk(name));
  fs::path filename(storedir);
  std::string enc_name;
  base::encode_to_hex(name, enc_name);
  filename /= enc_name;
  ASSERT_TRUE(fs::exists(filename));
  ASSERT_TRUE(chunkstore.DeleteChunk(name));
  ASSERT_FALSE(chunkstore.HasChunk(name));
  ASSERT_FALSE(fs::exists(filename));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreLoadRandomChunk) {
  std::string key, value;
  ASSERT_FALSE(chunkstore.LoadRandomChunk(&key, &value));
  ASSERT_EQ(key, std::string(""));
  ASSERT_EQ(value, std::string(""));
  for (int i = 0; i < 10; i++) {
    value = base::RandomString(1024);
    key = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
    ASSERT_TRUE(chunkstore.StoreChunk(key, value));
  }
  key = "";
  value = "";
  ASSERT_TRUE(chunkstore.LoadRandomChunk(&key, &value));
  std::string enc_key;
  base::encode_to_hex(key, enc_key);
  fs::path filename(storedir);
  filename /= enc_key;
  ASSERT_TRUE(fs::exists(filename));
  boost::uint64_t size = fs::file_size(filename);
  ASSERT_EQ(static_cast<unsigned int>(1024), size);
  char *temp;
  temp = new char[size];
  fs::ifstream fstr;
  fstr.open(filename, std::ios_base::binary);
  fstr.read(temp, size);
  fstr.close();
  std::string stored_value((const char*)temp, size);
  ASSERT_EQ(value, stored_value);
  stored_value = "";
  ASSERT_TRUE(chunkstore.LoadChunk(key, &stored_value));
  ASSERT_EQ(value, stored_value);
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreReuseDirectory) {
  std::string keys[10];
  std::string values[10];
  for (int i = 0; i < 10; i++) {
    values[i] = base::RandomString(1024);
    keys[i] = cry_obj.Hash(values[i], "", crypto::STRING_STRING, false);
    ASSERT_TRUE(chunkstore.StoreChunk(keys[i], values[i]));
  }
  for (int i = 0; i < 10; i++)
    ASSERT_TRUE(chunkstore.HasChunk(keys[i]));
  for (int i = 0; i < 10; i++) {
    std::string value;
    ASSERT_TRUE(chunkstore.LoadChunk(keys[i], &value));
    ASSERT_EQ(values[i], value);
  }
  std::string randkey, randvalue;
  ASSERT_TRUE(chunkstore.LoadRandomChunk(&randkey, &randvalue));
  // creating a new chunkstore that has same root dir
  fs::path currdir1(storedir);
  maidsafe_vault::ChunkStore chunkstore1(currdir1.string().c_str());
  for (int i = 0; i < 10; i++)
    ASSERT_TRUE(chunkstore1.HasChunk(keys[i]));
  for (int i = 0; i < 10; i++) {
    std::string value;
    ASSERT_TRUE(chunkstore1.LoadChunk(keys[i], &value));
    ASSERT_EQ(values[i], value);
  }
  ASSERT_TRUE(chunkstore1.LoadRandomChunk(&randkey, &randvalue));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreGetAllChunks) {
  std::list<std::string> ret_chunk_names;
  chunkstore.GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(static_cast<unsigned int>(0), ret_chunk_names.size());
  // store 100 chunks
  std::list<std::string> chunk_names;
  for (int i = 0; i < 100; i++) {
    std::string value = base::RandomString(1024);
    std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
    ASSERT_TRUE(chunkstore.StoreChunk(name, value));
    chunk_names.push_back(name);
  }
  // get them back
  chunkstore.GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(static_cast<unsigned int>(100), ret_chunk_names.size());
  chunk_names.sort();
  ret_chunk_names.sort();
  for (int i = 0; i < 100; i++) {
    ASSERT_EQ(chunk_names.front(), ret_chunk_names.front());
    chunk_names.pop_front();
    ret_chunk_names.pop_front();
  }
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreUpdateChunk) {
  std::string value = base::RandomString(250*1024);
  std::string name = cry_obj.Hash(value, "", crypto::STRING_STRING, false);
  ASSERT_TRUE(chunkstore.StoreChunk(name, value));
  std::string value1 = base::RandomString(250*1024);
  ASSERT_NE(value, value1);
  ASSERT_TRUE(chunkstore.UpdateChunk(name, value1));
  std::string ret_value;
  ASSERT_TRUE(chunkstore.LoadChunk(name, &ret_value));
  ASSERT_EQ(value1, ret_value);
  std::string non_existing_key("abcvsdfeed");
  ASSERT_FALSE(chunkstore.LoadChunk(non_existing_key, &ret_value));
}
