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
 * @file  test_self_encryption_device.cc
 * @brief Tests for the self-encryption streaming device.
 * @date  2011-02-19
 */

#include <cstdint>
#include <functional>
#include <memory>

#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryption_device.h"
#include "maidsafe/encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

namespace test_sed {

const std::uint32_t kDefaultSelfEncryptionType(
    kHashingSha512 | kCompressionNone | kObfuscationRepeated | kCryptoAes256);

}  // namespace test_ses

class SelfEncryptionDeviceTest : public testing::Test {
 public:
  SelfEncryptionDeviceTest()
      : hash_func_(std::bind(&crypto::Hash<crypto::SHA512>,
                             std::placeholders::_1)) {}
  virtual ~SelfEncryptionDeviceTest() {}
 protected:
  MemoryChunkStore::HashFunc hash_func_;
};

TEST_F(SelfEncryptionDeviceTest, BEH_Read) {
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string content(10, 0);
    EXPECT_EQ(-1, sed.read(&(content[0]), 10));
    EXPECT_EQ(0, sed.read(&(content[0]), 0));
  }
  {  // unencrypted whole content in DataMap
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    data_map->content = RandomString(100);
    data_map->size = data_map->content.size();

    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
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
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    data_map->content = RandomString(100);
    data_map->size = data_map->content.size();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;

    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
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
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
    std::string content_orig(RandomString(100));
    std::string hash_orig(crypto::Hash<crypto::SHA512>(content_orig));
    std::string content_enc(utils::SelfEncryptChunk(
        content_orig, hash_orig, hash_orig,
        test_sed::kDefaultSelfEncryptionType));
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
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    std::shared_ptr<ChunkStore> chunk_store(
        new MemoryChunkStore(true, hash_func_));
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
          test_sed::kDefaultSelfEncryptionType));
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

TEST_F(SelfEncryptionDeviceTest, BEH_Write) {
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    // No data sent to write
    EXPECT_EQ(-1, sed.write(NULL, 1));
    for (uint32_t i = 0; i < kMinChunks ; ++i)
      EXPECT_EQ(0, sed.chunk_buffers_[i].content.size());
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size - 100);
    EXPECT_EQ(0, data_map->size);
    // invalid stream size
    EXPECT_EQ(-1, sed.write(&data[0], 0));
  }
  {
    // data small enough to fit in datamap
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(1020);
    // invalid offset at this stage, force UpdateCurrentChunkDetails fail
    sed.offset_ = 1;
    EXPECT_EQ(-1, sed.write(&data[0], 1));
    sed.offset_ = 0;
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_EQ(data.size(), sed.chunk_buffers_[0].content.size());
    for (uint32_t i = 1; i < kMinChunks ; ++i) {
      EXPECT_EQ(0, sed.chunk_buffers_[i].content.size());
      EXPECT_EQ(0, sed.chunk_buffers_[i].hash.size());
    }
    EXPECT_EQ(0, data_map->size);
    EXPECT_EQ(0, chunk_store->Size());
    EXPECT_EQ(0, chunk_store->Count());
    EXPECT_EQ(0, sed.pending_chunks_.size());
    EXPECT_TRUE(sed.flush());
    EXPECT_EQ(1020, data_map->size);
    EXPECT_EQ(1020, data_map->content.size());
    EXPECT_EQ(0, chunk_store->Size());
    EXPECT_EQ(0, chunk_store->Count());
    EXPECT_EQ(0, sed.pending_chunks_.size());
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size - 100);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_EQ(data.size(), sed.chunk_buffers_[0].content.size());
    // further data filling rest of buffer 1 and into buffer 2
    std::string data2 = RandomString(
        sed.self_encryption_params_.max_chunk_size);
    EXPECT_EQ(data2.size(), sed.write(&data2[0], data2.size()));
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size,
              sed.chunk_buffers_[0].content.size());
    EXPECT_LT(0, sed.chunk_buffers_[0].hash.size());
    EXPECT_EQ(1, sed.pending_chunks_.size());
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size,
              sed.current_chunk_offset_);
    EXPECT_EQ(1, sed.current_chunk_index_);
    EXPECT_EQ(0, sed.chunk_buffers_[2].content.size());
    EXPECT_EQ(0, data_map->size);
    EXPECT_EQ(0, chunk_store->Count());

    // fill buffer 3 with more data than free space, causing buffer 1 to be
    // flushed, 2 and 3 to be added to pending
    std::string data3 = RandomString(
        sed.self_encryption_params_.max_chunk_size + 150);
    EXPECT_LT(0, sed.write(&data3[0], data3.size()));
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size, data_map->size);
    EXPECT_GT(sed.chunk_buffers_[0].index, sed.chunk_buffers_[2].index);
    EXPECT_EQ(sed.chunk_buffers_[0].content.size(),
              ((data.size() + data2.size() + data3.size()) -
              (sed.self_encryption_params_.max_chunk_size * 3)));
    EXPECT_EQ(2, sed.pending_chunks_.size());
    EXPECT_GT(sed.offset_, sed.current_chunk_offset_);
    EXPECT_EQ(sed.current_chunk_index_, 3);
    EXPECT_EQ(1, chunk_store->Count());
  }
  {
    // write chunks then change data at some point through the file, dependent
    // chunks should be modified
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        (sed.self_encryption_params_.max_chunk_size) * 8);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    DataMap data_map_copy = *data_map;
    std::string data5 = RandomString(
        sed.self_encryption_params_.max_chunk_size);
    sed.offset_ = 917504;
    EXPECT_EQ(data5.size(), sed.write(&data5[0], data5.size()));
    EXPECT_TRUE(sed.flush());
    for (int i = 1; i < 5; ++i)
      EXPECT_NE(data_map->chunks[i].hash, data_map_copy.chunks[i].hash);
    DataMap data_map_copy2 = *data_map;
    std::string data2 = RandomString(20000);
    sed.write_mode_ = true;
    EXPECT_LT(0, sed.seek(-1000, std::ios_base::end));
    EXPECT_EQ(data2.size(), sed.write(&data2[0], data2.size()));
    EXPECT_TRUE(sed.flush());
    for (int i = 5; i < 8; ++i)
      EXPECT_NE(data_map->chunks[i].hash, data_map_copy2.chunks[i].hash);
  }
  {
    // fill buffers 1-3, force LoadChunkIntoBuffer fail
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size*3);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_TRUE(sed.flush());
    for (uint32_t i = 0; i < kMinChunks ; ++i)
      sed.chunk_buffers_[i].index = i+1;
    sed.data_map_->chunks[0].pre_size = 10;
    EXPECT_EQ(-1, sed.write(&data[0], data.size()));
  }
  {
    // small chunks resized and amended
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size*3 - 10);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_EQ(2, sed.current_chunk_index_);
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size * 2,
              sed.current_chunk_offset_);
    EXPECT_EQ(262144, sed.chunk_buffers_[0].content.size());
    EXPECT_TRUE(sed.flush());
    EXPECT_NE(262144, data_map->chunks[0].size);
    EXPECT_EQ(data.size(), (data_map->chunks[0].size +
                            data_map->chunks[1].size +
                            data_map->chunks[2].size));
    EXPECT_EQ(3, sed.chunk_store_->Count());
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_EQ(5, sed.current_chunk_index_);
    EXPECT_EQ(262144, data_map->chunks[0].size);
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size * 5,
              sed.current_chunk_offset_);
  }
  {
    // write same data several times - chunk store should only have
    // 1 copy of each chunk, datamap as many as written.
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size*3);
    for (int i = 0; i < 3; ++i)
      EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    for (int i = 0; i < 3; ++i)
      EXPECT_EQ(data_map->chunks[i].hash, data_map->chunks[i+3].hash);
    EXPECT_TRUE(sed.flush());
    EXPECT_EQ(9, sed.data_map_->chunks.size());
    EXPECT_EQ(0, sed.pending_chunks_.size());
    EXPECT_EQ(3, sed.chunk_store_->Count());
  }
  {
    // final chunk size small enough for datamap inclusion
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(sed.self_encryption_params_.max_chunk_size*4
        + sed.self_encryption_params_.max_includable_chunk_size);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_TRUE(sed.flush());
    EXPECT_EQ(4, sed.chunk_store_->Count());
    EXPECT_EQ(4, sed.data_map_->chunks.size());
    EXPECT_EQ(sed.self_encryption_params_.max_includable_chunk_size,
              sed.data_map_->content.size());
    EXPECT_EQ(data.size(), sed.data_map_->size);
  }
  {
    // write less than total data size
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size*5);
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size + 10,
              sed.write(&data[0],
                        sed.self_encryption_params_.max_chunk_size + 10));
    EXPECT_TRUE(sed.flush());
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size + 10,
              sed.data_map_->size);
    EXPECT_EQ(3, sed.chunk_store_->Count());
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size + 10,
              (sed.chunk_store_->Size(sed.data_map_->chunks[0].hash) +
               sed.chunk_store_->Size(sed.data_map_->chunks[1].hash) +
               sed.chunk_store_->Size(sed.data_map_->chunks[2].hash)));
  }
  {
    // fill buffers then return to first and rewrite - buffers 2 and 3
    // queued until flushed
    std::shared_ptr<DataMap> data_map(new DataMap);
    chunk_store->Clear();
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(
        sed.self_encryption_params_.max_chunk_size*6);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_LT(0, sed.seek(sed.self_encryption_params_.max_chunk_size * 3,
                          std::ios_base::beg));
    EXPECT_EQ(sed.self_encryption_params_.max_chunk_size * 3,
              sed.data_map_->size);
    EXPECT_EQ(3, sed.chunk_store_->Count());
    std::array<SelfEncryptionDevice::ChunkBuffer, kMinChunks> temp_buf =
        sed.chunk_buffers_;
    std::string data2 = RandomString(
        sed.self_encryption_params_.max_chunk_size);
    EXPECT_EQ(data2.size(), sed.write(&data2[0], data2.size()));
    EXPECT_NE(temp_buf[0].content, sed.chunk_buffers_[0].content);
    EXPECT_EQ(temp_buf[1].content, sed.chunk_buffers_[1].content);
    EXPECT_EQ(temp_buf[2].content, sed.chunk_buffers_[2].content);
    EXPECT_TRUE(sed.flush());
  }
}

TEST_F(SelfEncryptionDeviceTest, BEH_Seek) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
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

TEST_F(SelfEncryptionDeviceTest, BEH_InitialiseDataMap) {
  std::shared_ptr<DataMap> data_map(new DataMap);
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  SelfEncryptionDevice sed(data_map, chunk_store);
  SelfEncryptionDevice::ChunkBuffer buffer;
  {
    // buffer content > kCompressionSampleSize
    std::string data = RandomString(SelfEncryptionParams().max_chunk_size);
    buffer.content = data;
    sed.InitialiseDataMap(buffer);
    EXPECT_EQ(0, sed.data_map_->size);
    EXPECT_EQ(0, sed.data_map_->chunks.size());
    EXPECT_EQ("", sed.data_map_->content);
    EXPECT_EQ(8722, sed.data_map_->self_encryption_type);
  }
  {
    // buffer content < kCompressionSampleSize
    std::string data = RandomString(200);
    buffer.content = data;
    sed.InitialiseDataMap(buffer);
    EXPECT_EQ(0, sed.data_map_->size);
    EXPECT_EQ(0, sed.data_map_->chunks.size());
    EXPECT_EQ("", sed.data_map_->content);
    EXPECT_EQ(8722, sed.data_map_->self_encryption_type);
  }
  {
    // buffer content compressible
    std::string data = RandomString(200);
    buffer.content = data + data + data + data + data;
    sed.InitialiseDataMap(buffer);
    EXPECT_EQ(0, sed.data_map_->size);
    EXPECT_EQ(0, sed.data_map_->chunks.size());
    EXPECT_EQ("", sed.data_map_->content);
    EXPECT_EQ(sed.default_self_encryption_type_,
              sed.data_map_->self_encryption_type);
  }
  {
    // datamap not empty when Initialise called - should be reset
    std::string data = RandomString(SelfEncryptionParams().max_chunk_size);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_TRUE(sed.flush());
    EXPECT_EQ(data.size(), sed.data_map_->size);
    EXPECT_EQ(3, sed.data_map_->chunks.size());
    std::string data2 = RandomString(200);
    buffer.content = data2;
    sed.InitialiseDataMap(buffer);
    EXPECT_EQ(0, sed.data_map_->size);
    EXPECT_EQ(0, sed.data_map_->chunks.size());
    EXPECT_EQ(8722, sed.data_map_->self_encryption_type);
  }
  {
    // call with empty buffer
    sed.InitialiseDataMap(buffer);
    EXPECT_EQ(8722, sed.data_map_->self_encryption_type);
  }
}

TEST_F(SelfEncryptionDeviceTest, BEH_UpdateCurrentChunkDetails) {
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  std::shared_ptr<DataMap> data_map(new DataMap);
  data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
  SelfEncryptionDevice sed(data_map, chunk_store);
  std::string data = RandomString(SelfEncryptionParams().max_chunk_size *9 + 8);
  EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
  EXPECT_TRUE(sed.flush());

  sed.offset_ += 1;
  // offset > total size
  EXPECT_FALSE(sed.UpdateCurrentChunkDetails());
  sed.offset_ -= 1;
  EXPECT_EQ(data.size(), sed.offset_);
  EXPECT_EQ(SelfEncryptionParams().max_chunk_size*9,
            sed.current_chunk_offset_);
  EXPECT_EQ(9, sed.current_chunk_index_);
  // offset > current chunk offset
  EXPECT_TRUE(sed.UpdateCurrentChunkDetails());
  EXPECT_EQ(SelfEncryptionParams().max_chunk_size*9,
            sed.current_chunk_offset_);
  EXPECT_EQ(9, sed.current_chunk_index_);

  EXPECT_LT(0, sed.seek(SelfEncryptionParams().max_chunk_size,
                        std::ios_base::beg));
  // offset < current chunk offset
  EXPECT_TRUE(sed.UpdateCurrentChunkDetails());
  EXPECT_EQ(0, sed.current_chunk_index_);
  EXPECT_EQ(0, sed.current_chunk_offset_);

  EXPECT_LT(0, sed.seek(SelfEncryptionParams().max_chunk_size * 3.5,
                        std::ios_base::beg));
  // offset > current chunk offset & current chunk index < total chunks
  EXPECT_TRUE(sed.UpdateCurrentChunkDetails());
  EXPECT_EQ(3, sed.current_chunk_index_);
  EXPECT_EQ(SelfEncryptionParams().max_chunk_size * 3,
            sed.current_chunk_offset_);
}

TEST_F(SelfEncryptionDeviceTest, BEH_FinaliseWriting) {
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    EXPECT_EQ(0, sed.pending_chunks_.size());
    // empty chunk buffer
    size_t index = 0;
    EXPECT_FALSE(sed.FinaliseWriting(index));
    EXPECT_EQ(0, sed.pending_chunks_.size());
    // index mismatch
    std::string data = RandomString(300);
    sed.chunk_buffers_[0].content = data;
    index = 3;
    EXPECT_FALSE(sed.FinaliseWriting(index));
    EXPECT_EQ(0, sed.pending_chunks_.size());
    // already hashed
    std::string data_hash = utils::Hash(data,
                                        test_sed::kDefaultSelfEncryptionType);
    sed.chunk_buffers_[0].hash = data_hash;
    EXPECT_TRUE(sed.FinaliseWriting(0));
    EXPECT_EQ(0, sed.pending_chunks_.size());
    // no change
    sed.chunk_buffers_[0].hash = "";
    ChunkDetails chunk;
    chunk.hash = data_hash;
    chunk.pre_hash = data_hash;
    chunk.size = data.size();
    chunk.pre_size = data.size();
    data_map->chunks.push_back(chunk);
    EXPECT_TRUE(sed.FinaliseWriting(0));
    EXPECT_EQ(0, sed.pending_chunks_.size());
    // queue dependents
    std::string data2 = RandomString(400);
    sed.chunk_buffers_[1].content = data2;
    sed.chunk_buffers_[1].index = 1;
    EXPECT_EQ(0, sed.pending_chunks_.size());
    EXPECT_TRUE(sed.FinaliseWriting(1));
    EXPECT_EQ(2, sed.pending_chunks_.size());
    // update pre-predecessor, fail to retrieve encryption hash
    sed.pending_chunks_.clear();
    sed.chunk_buffers_[2].content = data;
    sed.chunk_buffers_[2].index = 2;
    sed.chunk_buffers_[1].hash = "";
    EXPECT_FALSE(sed.FinaliseWriting(2));
    EXPECT_EQ(0, sed.pending_chunks_.size());
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(SelfEncryptionParams().max_chunk_size * 7);
    EXPECT_EQ(0, sed.pending_chunks_.size());
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_EQ(2, sed.pending_chunks_.size());
    int i = 4;
    for (auto it = sed.pending_chunks_.begin();
         it != sed.pending_chunks_.end(); ++it) {
      EXPECT_EQ(i, *it);
      ++i;
    }
    i = 5;
    EXPECT_TRUE(sed.FinaliseWriting(6));
    for (auto it = sed.pending_chunks_.begin();
         it != sed.pending_chunks_.end(); ++it) {
      EXPECT_EQ(i, *it);
      ++i;
    }
    EXPECT_FALSE(sed.FinaliseWriting(3));
  }
}

TEST_F(SelfEncryptionDeviceTest, BEH_LoadChunkIntoBuffer) {
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(1000);
    // empty datamap and buffer
    SelfEncryptionDevice::ChunkBuffer buffer;
    EXPECT_FALSE(sed.LoadChunkIntoBuffer(0, &buffer));
    EXPECT_EQ("", sed.chunk_buffers_[0].content);
    // already loaded
    sed.chunk_buffers_[0].content = data;
    EXPECT_TRUE(sed.LoadChunkIntoBuffer(0, &sed.chunk_buffers_[0]));
    EXPECT_EQ(data, sed.chunk_buffers_[0].content);
    // invalid index
    sed.chunk_buffers_[0].content = "";
    EXPECT_FALSE(sed.LoadChunkIntoBuffer(1, &sed.chunk_buffers_[0]));
    EXPECT_EQ("", sed.chunk_buffers_[0].content);
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(1000);
    // contents in datamap (head chunk)
    data_map->content = data;
    EXPECT_TRUE(sed.LoadChunkIntoBuffer(0, &sed.chunk_buffers_[0]));
    EXPECT_EQ(data, sed.chunk_buffers_[0].content);
    // content in datamap (tail chunk)
    ChunkDetails chunk1, chunk2;
    std::string data1 = RandomString(1000);
    std::string data2 = RandomString(1000);
    std::string data1_hash = utils::Hash(data1,
                                         test_sed::kDefaultSelfEncryptionType);
    std::string data2_hash = utils::Hash(data2,
                                         test_sed::kDefaultSelfEncryptionType);
    chunk1.hash = data1_hash;
    chunk1.pre_hash = data1_hash;
    chunk1.size = data1.size();
    chunk1.pre_size = data1.size();
    chunk2.hash = data2_hash;
    chunk2.pre_hash = data2_hash;
    chunk2.size = data2.size();
    chunk2.pre_size = data2.size();
    data_map->chunks.push_back(chunk1);
    data_map->chunks.push_back(chunk2);
    EXPECT_EQ("", sed.chunk_buffers_[2].content);
    EXPECT_TRUE(sed.LoadChunkIntoBuffer(2, &sed.chunk_buffers_[2]));
    EXPECT_EQ(data, sed.chunk_buffers_[2].content);
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    std::string data = RandomString(SelfEncryptionParams().max_chunk_size * 7);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    EXPECT_TRUE(sed.flush());
    for (int i = 4; i < 7; ++i) {
      EXPECT_EQ(data_map->chunks[i].pre_hash,
                sed.chunk_buffers_[i % kMinChunks].hash);
      EXPECT_EQ(sed.chunk_buffers_[i % kMinChunks].index, i);
    }
    SelfEncryptionDevice::ChunkBuffer temp_buffer = sed.chunk_buffers_[2];
    EXPECT_TRUE(sed.LoadChunkIntoBuffer(2, &sed.chunk_buffers_[2]));
    EXPECT_EQ(data_map->chunks[2].pre_hash, sed.chunk_buffers_[2].hash);
    EXPECT_NE(temp_buffer.content, sed.chunk_buffers_[2].content);
    EXPECT_NE(temp_buffer.index, sed.chunk_buffers_[2].index);
    // force validation fail
    data_map->chunks[3].hash = data_map->chunks[2].hash;
    EXPECT_FALSE(sed.LoadChunkIntoBuffer(3, &sed.chunk_buffers_[0]));
    EXPECT_EQ(std::string(data_map->chunks[3].pre_size, 0),
              sed.chunk_buffers_[0].content);
  }
}

TEST_F(SelfEncryptionDeviceTest, BEH_StoreChunkFromBuffer) {
  std::shared_ptr<ChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func_));
  SelfEncryptionDevice::ChunkBuffer buffer;
  std::string enc_hash, obf_hash, data;
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    // empty chunk buffer
    EXPECT_FALSE(sed.StoreChunkFromBuffer(&buffer, enc_hash, obf_hash));
    // store to datamap
    data = RandomString(SelfEncryptionParams().max_chunk_size);
    buffer.content = data;
    EXPECT_TRUE(sed.StoreChunkFromBuffer(&buffer, enc_hash, obf_hash));
    EXPECT_EQ(data.size(), data_map->size);
    EXPECT_EQ(data, data_map->content);
    EXPECT_EQ("", buffer.content);
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    // fail to encrypt
    data = RandomString(SelfEncryptionParams().max_chunk_size);
    buffer.content = data;
    enc_hash = utils::Hash(RandomString(SelfEncryptionParams().max_chunk_size),
                           data_map->self_encryption_type);
    EXPECT_FALSE(sed.StoreChunkFromBuffer(&buffer, enc_hash, obf_hash));
    EXPECT_EQ(0, data_map->size);
    obf_hash = enc_hash;
    enc_hash = "";
    EXPECT_FALSE(sed.StoreChunkFromBuffer(&buffer, enc_hash, obf_hash));
    EXPECT_EQ(0, data_map->size);
  }
  {
    std::shared_ptr<DataMap> data_map(new DataMap);
    data_map->self_encryption_type = test_sed::kDefaultSelfEncryptionType;
    SelfEncryptionDevice sed(data_map, chunk_store);
    data = RandomString(SelfEncryptionParams().max_chunk_size*7);
    EXPECT_EQ(data.size(), sed.write(&data[0], data.size()));
    // store new chunk
    enc_hash = sed.chunk_buffers_[2].hash;
    obf_hash = utils::Hash(sed.chunk_buffers_[0].content,
                           data_map->self_encryption_type);
    EXPECT_EQ(4, data_map->chunks.size());
    EXPECT_EQ(4, chunk_store->Count());
    EXPECT_TRUE(sed.StoreChunkFromBuffer(&sed.chunk_buffers_[1],
                                         enc_hash, obf_hash));
    EXPECT_EQ(5, data_map->chunks.size());
    EXPECT_EQ(5, chunk_store->Count());
    // attempt to store again unchanged
    EXPECT_TRUE(sed.StoreChunkFromBuffer(&sed.chunk_buffers_[1],
                                         enc_hash, obf_hash));
    EXPECT_EQ(5, data_map->chunks.size());
    EXPECT_EQ(5, chunk_store->Count());
    // modify same chunk and store again
    sed.chunk_buffers_[1].content =
        RandomString(SelfEncryptionParams().max_chunk_size);
    EXPECT_EQ(0, sed.deletable_chunks_.size());
    EXPECT_TRUE(sed.StoreChunkFromBuffer(&sed.chunk_buffers_[1],
                                         enc_hash, obf_hash));
    EXPECT_EQ(1, sed.deletable_chunks_.size());
    EXPECT_EQ(5, data_map->chunks.size());
    EXPECT_EQ(6, chunk_store->Count());
  }
}

}  // namespace encrypt

}  // namespace test

}  // namespace maidsafe
