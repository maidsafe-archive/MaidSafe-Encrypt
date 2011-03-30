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
 * @brief Tests for the self-encryption streaming interface.
 * @date  2011-02-19
 */

#include <cstdint>
#include <memory>
#include <iostream>  // NOLINT

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "gtest/gtest.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption_stream.h"
#include "maidsafe-encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace test_ses {

const std::uint32_t kDefaultSelfEncryptionType(
    kHashingSha512 | kCompressionNone | kObfuscationRepeated | kCryptoAes256);

}  // namespace test_ses

TEST(SelfEncryptionDeviceTest, BEH_ENCRYPT_Read) {
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string content(10, 0);
    EXPECT_EQ(-1, sed.read(&(content[0]), 10));
    EXPECT_EQ(-1, sed.read(&(content[0]), 0));
  }
  {  // unencrypted whole content in DataMap
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
    data_map->content = RandomString(100);
    data_map->size = data_map->content.size();

    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string content1(data_map->content.size(), 0);
    EXPECT_EQ(0, sed.read(&(content1[0]), 0));
    EXPECT_EQ(data_map->content.size(),
              sed.read(&(content1[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content, content1);
    EXPECT_EQ(-1, sed.read(&(content1[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content, content1);
    std::string content2(data_map->content.size(), 0);
    EXPECT_EQ(data_map->content.size() - 10, sed.seek(-10, std::ios_base::end));
    EXPECT_EQ(10, sed.read(&(content2[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content.substr(data_map->content.size() - 10),
              content2.substr(0, 10));
    std::string content3(data_map->content.size(), 0);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(10, sed.read(&(content3[0]), 10));
    EXPECT_EQ(data_map->content.substr(0, 10), content3.substr(0, 10));
  }
  {  // unencrypted chunk in DataMap
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
    data_map->content = RandomString(100);
    data_map->size = data_map->content.size();
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;

    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string content1(data_map->content.size(), 0);
    EXPECT_EQ(data_map->content.size(),
              sed.read(&(content1[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content, content1);
    EXPECT_EQ(-1, sed.read(&(content1[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content, content1);
    std::string content2(data_map->content.size(), 0);
    EXPECT_EQ(data_map->content.size() - 10, sed.seek(-10, std::ios_base::end));
    EXPECT_EQ(10, sed.read(&(content2[0]), data_map->content.size()));
    EXPECT_EQ(data_map->content.substr(data_map->content.size() - 10),
              content2.substr(0, 10));
    std::string content3(data_map->content.size(), 0);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(10, sed.read(&(content3[0]), 10));
    EXPECT_EQ(data_map->content.substr(0, 10), content3.substr(0, 10));
  }
  {  // single chunk in file
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    std::string content_orig(RandomString(100));
    std::string hash_orig(crypto::Hash<crypto::SHA512>(content_orig));
    std::string content_enc(utils::SelfEncryptChunk(
        content_orig, hash_orig, hash_orig,
        test_ses::kDefaultSelfEncryptionType));
    std::string hash_enc(crypto::Hash<crypto::SHA512>(content_enc));
    EXPECT_TRUE(chunk_store->Store(hash_enc, content_enc));
    ChunkDetails chunk;
    chunk.pre_hash = hash_orig;
    chunk.pre_size = content_orig.size();
    chunk.hash = hash_enc;
    chunk.size = content_enc.size();
    data_map->chunks.push_back(chunk);
    data_map->size = content_orig.size();

    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string content1(content_orig.size(), 0);
    EXPECT_EQ(content_orig.size(),
              sed.read(&(content1[0]), content_orig.size()));
    EXPECT_EQ(content_orig, content1);
    std::string content2(content_orig.size(), 0);
    EXPECT_TRUE(chunk_store->Delete(hash_enc));
    EXPECT_EQ(-1, sed.read(&(content2[0]), content_orig.size()));
    EXPECT_TRUE(chunk_store->Store(hash_enc, RandomString(123)));
    EXPECT_EQ(-1, sed.read(&(content2[0]), content_orig.size()));
  }
  { // read across borders of multiple chunks
    const size_t kChunkCount(5);
    const size_t kChunkSize(10);
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    std::vector<std::string> content_orig;

    for (size_t i = 0; i < kChunkCount; ++i) {
      ChunkDetails chunk;
      content_orig.push_back(std::string(kChunkSize,
                                         'a' + static_cast<char>(i)));
      chunk.pre_hash = crypto::Hash<crypto::SHA512>(content_orig.back());
      chunk.pre_size = content_orig.back().size();
      data_map->chunks.push_back(chunk);
      data_map->size += chunk.pre_size;
    }

    for (size_t i = 0; i < kChunkCount; ++i) {
      std::string content_enc(utils::SelfEncryptChunk(
          content_orig[i], data_map->chunks[(i + 1) % kChunkCount].pre_hash,
          data_map->chunks[(i + 2) % kChunkCount].pre_hash,
          test_ses::kDefaultSelfEncryptionType));
      std::string hash_enc(crypto::Hash<crypto::SHA512>(content_enc));
      data_map->chunks[i].hash = hash_enc;
      data_map->chunks[i].size = content_enc.size();
      EXPECT_TRUE(chunk_store->Store(hash_enc, content_enc));
    }

    SelfEncryptionDevice sed(data_map, chunk_store);

    // read and check each character in the stream
    for (size_t i = 0; i < kChunkCount * kChunkSize; ++i) {
      char c(0);
      EXPECT_EQ(1, sed.read(&c, 1));
      EXPECT_EQ('a' + static_cast<char>(i / kChunkSize), c);
    }

    // read and check each chunk
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    for (size_t i = 0; i < kChunkCount; ++i) {
      std::string content(kChunkSize, 0);
      EXPECT_EQ(kChunkSize, sed.read(&(content[0]), kChunkSize));
      EXPECT_EQ(std::string(kChunkSize, 'a' + static_cast<char>(i)), content);
    }

    // read half of one chunk and half of the next
    EXPECT_EQ(kChunkSize / 2, sed.seek(kChunkSize / 2, std::ios_base::beg));
    for (size_t i = 0; i < kChunkCount - 1; ++i) {
      std::string content(kChunkSize, 0);
      EXPECT_EQ(kChunkSize, sed.read(&(content[0]), kChunkSize));
      EXPECT_EQ(std::string(kChunkSize / 2, 'a' + static_cast<char>(i)).
                append(kChunkSize / 2, 'b' + static_cast<char>(i)), content);
    }

    std::string expected_content;
    for (size_t i = 0; i < kChunkCount; ++i)
      expected_content.append(kChunkSize, 'a' + static_cast<char>(i));

    // read the whole file
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    std::string content(kChunkCount * kChunkSize, 0);
    EXPECT_EQ(content.size(), sed.read(&(content[0]), content.size()));
    EXPECT_EQ(expected_content, content);

    // read the whole file except first and last byte
    EXPECT_EQ(1, sed.seek(1, std::ios_base::beg));
    content.resize(kChunkCount * kChunkSize - 2);
    EXPECT_EQ(content.size(), sed.read(&(content[0]), content.size()));
    EXPECT_EQ(expected_content.substr(1, content.size()), content);
  }
}

TEST(SelfEncryptionDeviceTest, BEH_ENCRYPT_Write) {
  // write not implemented, so always expect failure
  std::shared_ptr<DataMap> data_map(new DataMap);
  data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
  std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
  SelfEncryptionDevice sed(data_map, chunk_store);
  std::string content(10, 0);
  EXPECT_EQ(-1, sed.write(&(content[0]), 10));
}

TEST(SelfEncryptionDeviceTest, BEH_ENCRYPT_Seek) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
  std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
  {
    SelfEncryptionDevice sed(data_map, chunk_store);
    EXPECT_EQ(-1, sed.seek(1, static_cast<std::ios_base::seekdir>(-1)));

    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
  }
  for (int i = 1; i <= 5; ++i) {
    ChunkDetails chunk;
    chunk.pre_size = i * 100;
    data_map->chunks.push_back(chunk);
    data_map->size += chunk.pre_size;
  }
  {
    SelfEncryptionDevice sed(data_map, chunk_store);
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(123, sed.seek(123, std::ios_base::beg));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(1500, sed.seek(1500, std::ios_base::beg));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1501, std::ios_base::beg));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(0, sed.seek(0, std::ios_base::beg));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(0, sed.seek(0, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(123, sed.seek(123, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(246, sed.seek(123, std::ios_base::cur));
    EXPECT_EQ(246, sed.offset_);
    EXPECT_EQ(-1, sed.seek(1400, std::ios_base::cur));
    EXPECT_EQ(246, sed.offset_);
    EXPECT_EQ(123, sed.seek(-123, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-124, std::ios_base::cur));
    EXPECT_EQ(123, sed.offset_);
    EXPECT_EQ(0, sed.seek(-123, std::ios_base::cur));
    EXPECT_EQ(0, sed.offset_);

    EXPECT_EQ(-1, sed.seek(1, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
    EXPECT_EQ(1500, sed.seek(0, std::ios_base::end));
    EXPECT_EQ(1500, sed.offset_);
    EXPECT_EQ(500, sed.seek(-1000, std::ios_base::end));
    EXPECT_EQ(500, sed.offset_);
    EXPECT_EQ(-1, sed.seek(-1501, std::ios_base::end));
    EXPECT_EQ(500, sed.offset_);
    EXPECT_EQ(0, sed.seek(-1500, std::ios_base::end));
    EXPECT_EQ(0, sed.offset_);
  }
}

TEST(SelfEncryptionDeviceTest, DISABLED_BEH_ENCRYPT_Flush) {
  FAIL() << "Not implemented.";
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
    SelfEncryptionDevice sed(data_map, chunk_store);
    // ...
  }
}

TEST(SelfEncryptionStreamTest, BEH_ENCRYPT_Dummy) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  data_map->self_encryption_type = test_ses::kDefaultSelfEncryptionType;
  std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true));
  SelfEncryptionStream stream(data_map, chunk_store);
  std::string test("test");
  DLOG(INFO) << "write #1" << std::endl;
  stream.write(test.data(), test.size());
  DLOG(INFO) << "write #2" << std::endl;
  stream.write(test.data(), test.size());
  DLOG(INFO) << "flush" << std::endl;
  stream.flush();
  DLOG(INFO) << "write #3" << std::endl;
  stream.write(test.data(), test.size());
  DLOG(INFO) << "read" << std::endl;
  stream.read(&(test[0]), test.size());
  DLOG(INFO) << "close" << std::endl;
  stream.close();
  DLOG(INFO) << "end" << std::endl;
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
