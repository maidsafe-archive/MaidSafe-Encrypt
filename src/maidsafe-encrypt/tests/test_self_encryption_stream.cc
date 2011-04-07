/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_self_encryption_stream.cc
 * @brief Tests for the self-encryption stream.
 * @date  2011-02-19
 */

#include <cstdint>
#include <functional>
#include <memory>

#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption_stream.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

class SelfEncryptionStreamTest : public testing::Test {
 public:
  SelfEncryptionStreamTest()
      : hash_func_(std::bind(&crypto::Hash<crypto::SHA512>,
                             std::placeholders::_1)) {}
  virtual ~SelfEncryptionStreamTest() {}
 protected:
  MemoryChunkStore::HashFunc hash_func_;
};

TEST_F(SelfEncryptionStreamTest, BEH_Append) {
  SelfEncryptionParams sep(256, 64, 128);
  std::string data(RandomString(1024));  // 1 KiB = 4 chunks

  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  SelfEncryptionStream stream(data_map, chunk_store, sep);

  // write first 100 Bytes, should end up in DM
  stream.write(&(data[0]), 100);
  EXPECT_EQ(100, stream.tellp());
  stream.flush();
  EXPECT_EQ(100, data_map->size);
  EXPECT_EQ(data.substr(0, 100), data_map->content);
  EXPECT_TRUE(data_map->chunks.empty());
  EXPECT_TRUE(chunk_store->Empty());

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(100, 0);
    stream2.read(&(data_out[0]), 100);
    EXPECT_EQ(100, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data.substr(0, 100)), EncodeToHex(data_out));
  }

  // write next 50 Bytes, should now be stored as 3 chunks at 50 Bytes each
  stream.write(&(data[100]), 50);
  EXPECT_EQ(150, stream.tellp());
  stream.flush();
  EXPECT_EQ(150, data_map->size);
  EXPECT_TRUE(data_map->content.empty());
  EXPECT_EQ(3, data_map->chunks.size());
  EXPECT_EQ(3, chunk_store->Count());
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_EQ(50, data_map->chunks[i].pre_size);
    EXPECT_TRUE(chunk_store->Validate(data_map->chunks[i].hash));
  }

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(150, 0);
    stream2.read(&(data_out[0]), 150);
    EXPECT_EQ(150, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data.substr(0, 150)), EncodeToHex(data_out));
  }

  // write next 600 bytes -> 3 chunks at 250 Bytes
  stream.write(&(data[150]), 600);
  EXPECT_EQ(750, stream.tellp());
  stream.flush();
  EXPECT_EQ(750, data_map->size);
  EXPECT_TRUE(data_map->content.empty());
  EXPECT_EQ(3, data_map->chunks.size());
  EXPECT_EQ(3, chunk_store->Count());
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_EQ(250, data_map->chunks[i].pre_size);
    EXPECT_TRUE(chunk_store->Validate(data_map->chunks[i].hash));
  }

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(750, 0);
    stream2.read(&(data_out[0]), 750);
    EXPECT_EQ(750, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data.substr(0, 750)), EncodeToHex(data_out));
  }

  // write next 50 bytes -> 3 chunks at 256 Bytes, 32 Bytes in DM
  stream.write(&(data[750]), 50);
  EXPECT_EQ(800, stream.tellp());
  stream.flush();
  EXPECT_EQ(800, data_map->size);
  EXPECT_EQ(data.substr(768, 32), data_map->content);
  EXPECT_EQ(3, data_map->chunks.size());
  EXPECT_EQ(3, chunk_store->Count());
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_EQ(256, data_map->chunks[i].pre_size);
    EXPECT_TRUE(chunk_store->Validate(data_map->chunks[i].hash));
  }

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(800, 0);
    stream2.read(&(data_out[0]), 800);
    EXPECT_EQ(800, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data.substr(0, 800)), EncodeToHex(data_out));
  }

  // write next 50 bytes -> 3 chunks at 256 Bytes, 1 at 82 Bytes
  stream.write(&(data[800]), 50);
  EXPECT_EQ(850, stream.tellp());
  stream.flush();
  EXPECT_EQ(850, data_map->size);
  EXPECT_TRUE(data_map->content.empty());
  EXPECT_EQ(4, data_map->chunks.size());
  EXPECT_EQ(4, chunk_store->Count());
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_EQ(i == 3 ? 82 : 256, data_map->chunks[i].pre_size);
    EXPECT_TRUE(chunk_store->Validate(data_map->chunks[i].hash));
  }

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(850, 0);
    stream2.read(&(data_out[0]), 850);
    EXPECT_EQ(850, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data.substr(0, 850)), EncodeToHex(data_out));
  }

  // write final 174 bytes -> 4 chunks at 256 Bytes
  stream.write(&(data[850]), 174);
  EXPECT_EQ(1024, stream.tellp());
  stream.flush();
  EXPECT_EQ(1024, data_map->size);
  EXPECT_TRUE(data_map->content.empty());
  EXPECT_EQ(4, data_map->chunks.size());
  EXPECT_EQ(4, chunk_store->Count());
  for (size_t i = 0; i < data_map->chunks.size(); ++i) {
    EXPECT_EQ(256, data_map->chunks[i].pre_size);
    EXPECT_TRUE(chunk_store->Validate(data_map->chunks[i].hash));
  }

  // check via separate stream
  {
    SelfEncryptionStream stream2(data_map, chunk_store, sep);
    std::string data_out(1024, 0);
    stream2.read(&(data_out[0]), 1024);
    EXPECT_EQ(1024, stream2.gcount());
    ASSERT_EQ(EncodeToHex(data), EncodeToHex(data_out));
  }
}

TEST_F(SelfEncryptionStreamTest, BEH_ChunksExist) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  EXPECT_FALSE(ChunksExist(std::shared_ptr<DataMap>(), chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, std::shared_ptr<ChunkStore>(), NULL));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
  std::vector<std::string> missing_chunks;
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
  missing_chunks.push_back("test chunk name");
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
  }
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  ASSERT_EQ(2, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks[0]);
  EXPECT_EQ(data_map->chunks[1].hash, missing_chunks[1]);
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[1].hash, RandomString(123)));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, NULL));
  EXPECT_FALSE(ChunksExist(data_map, chunk_store, &missing_chunks));
  ASSERT_EQ(1, missing_chunks.size());
  EXPECT_EQ(data_map->chunks[0].hash, missing_chunks[0]);
  EXPECT_TRUE(chunk_store->Store(data_map->chunks[0].hash, RandomString(123)));
  EXPECT_TRUE(ChunksExist(data_map, chunk_store, &missing_chunks));
  EXPECT_TRUE(missing_chunks.empty());
}

TEST_F(SelfEncryptionStreamTest, BEH_DeleteChunks) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  EXPECT_FALSE(DeleteChunks(std::shared_ptr<DataMap>(), chunk_store));
  EXPECT_FALSE(DeleteChunks(data_map, std::shared_ptr<ChunkStore>()));
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
  }
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_TRUE(data_map->chunks.empty());

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    EXPECT_TRUE(chunk_store->Store(crypto::Hash<crypto::SHA512>("chunk3"),
                                   "foo"));
  }
  EXPECT_EQ(3, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_EQ(1, chunk_store->Count());
  EXPECT_TRUE(data_map->chunks.empty());
  chunk_store->Clear();

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "foo"));
  }
  EXPECT_EQ(2, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_EQ(1, chunk_store->Count());
  EXPECT_TRUE(data_map->chunks.empty());
  chunk_store->Clear();

  {
    ChunkDetails chunk;
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk1");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "moo"));
    chunk.hash = crypto::Hash<crypto::SHA512>("chunk2");
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "boo"));
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(chunk_store->Store(chunk.hash, "foo"));
  }
  EXPECT_EQ(2, chunk_store->Count());
  EXPECT_TRUE(DeleteChunks(data_map, chunk_store));
  EXPECT_TRUE(chunk_store->Empty());
  EXPECT_TRUE(data_map->chunks.empty());
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
