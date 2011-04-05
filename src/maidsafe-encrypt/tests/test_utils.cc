/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_utils.cc
 * @brief Tests for the self-encryption helper functions.
 * @date  2011-04-05
 */

#include <cstdint>

#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/utils.h"

namespace maidsafe {

namespace encrypt {

namespace utils {

namespace test {

TEST(SelfEncryptionUtilsTest, BEH_Serialisation) {
  DataMap data_map;
  {
    data_map.content = "abcdefg";
    data_map.size = 12345;
    ChunkDetails chunk;
    chunk.hash = "test123";
    chunk.size = 10000;
    data_map.chunks.push_back(chunk);
    chunk.hash = "test456";
    chunk.size = 2345;
    data_map.chunks.push_back(chunk);
  }
  std::stringstream ser_data_map;
  {  // serialise DataMap to string stream
    boost::archive::text_oarchive oa(ser_data_map);
    oa << data_map;
  }
  {
    DataMap restored_data_map;
    boost::archive::text_iarchive ia(ser_data_map);
    ia >> restored_data_map;
    EXPECT_EQ(data_map.content, restored_data_map.content);
    EXPECT_EQ(data_map.size, restored_data_map.size);
    EXPECT_EQ(data_map.chunks.size(), restored_data_map.chunks.size());
    EXPECT_EQ(data_map.chunks[0].hash, restored_data_map.chunks[0].hash);
    EXPECT_EQ(data_map.chunks[0].size, restored_data_map.chunks[0].size);
    EXPECT_EQ(data_map.chunks[1].hash, restored_data_map.chunks[1].hash);
    EXPECT_EQ(data_map.chunks[1].size, restored_data_map.chunks[1].size);
  }
}

TEST(SelfEncryptionUtilsTest, BEH_IsCompressedFile) {
  EXPECT_TRUE(IsCompressedFile("test.7z"));
  EXPECT_TRUE(IsCompressedFile("test.jpg"));
  EXPECT_TRUE(IsCompressedFile("test.JPG"));
  EXPECT_TRUE(IsCompressedFile("test.txt.rar"));
  EXPECT_TRUE(IsCompressedFile("test.ZiP"));
  EXPECT_FALSE(IsCompressedFile("test.txt"));
  EXPECT_FALSE(IsCompressedFile("test.jpg.txt"));
}

TEST(SelfEncryptionUtilsTest, BEH_CheckCompressibility) {
  // TODO(Steve) add more compression types

  // no data
  std::string sample;
  EXPECT_FALSE(CheckCompressibility(sample, kCompressionGzip));

  //  make compressible string
  sample = std::string(kCompressionSampleSize, 'x');
  EXPECT_TRUE(CheckCompressibility(sample, kCompressionGzip));

  //  make incompressible string
  sample = RandomString(kCompressionSampleSize);
  EXPECT_FALSE(CheckCompressibility(sample, kCompressionGzip));
}

TEST(SelfEncryptionUtilsTest, DISABLED_BEH_CheckParams) {
  FAIL() << "Not implemented.";
}

TEST(SelfEncryptionUtilsTest, DISABLED_BEH_Compress) {
  FAIL() << "Not implemented.";
}

TEST(SelfEncryptionUtilsTest, DISABLED_BEH_Hash) {
  FAIL() << "Not implemented.";
}

TEST(SelfEncryptionUtilsTest, BEH_ResizeObfuscationHash) {
  std::string output;
  EXPECT_FALSE(ResizeObfuscationHash("abc", 10, NULL));
  EXPECT_FALSE(ResizeObfuscationHash("", 10, &output));
  EXPECT_TRUE(output.empty());
  EXPECT_TRUE(ResizeObfuscationHash("abc", 0, &output));
  EXPECT_TRUE(output.empty());
  EXPECT_TRUE(ResizeObfuscationHash("abc", 1, &output));
  EXPECT_EQ("a", output);
  EXPECT_TRUE(ResizeObfuscationHash("abc", 3, &output));
  EXPECT_EQ("abc", output);
  EXPECT_TRUE(ResizeObfuscationHash("abc", 4, &output));
  EXPECT_EQ("abca", output);
  EXPECT_TRUE(ResizeObfuscationHash("abc", 9, &output));
  EXPECT_EQ("abcabcabc", output);
  EXPECT_TRUE(ResizeObfuscationHash("abc", 11, &output));
  EXPECT_EQ("abcabcabcab", output);
  EXPECT_TRUE(ResizeObfuscationHash("a", 5, &output));
  EXPECT_EQ("aaaaa", output);

  SelfEncryptionParams sep;
  const std::string kInput(RandomString(64));
  const int kRepetitions(25000);
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  for (int i = 0; i < kRepetitions; ++i) {
    output.clear();
    ResizeObfuscationHash(kInput, sep.max_chunk_size, &output);
  }
  std::uint64_t duration =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  printf("Resized hash to %u Bytes %d times in %.2f ms.\n",
         sep.max_chunk_size, kRepetitions, duration / 1000.0);
}

TEST(SelfEncryptionUtilsTest, BEH_SelfEnDecryptChunk) {
  const std::uint32_t kDefaultSelfEncryptionType(
    kHashingSha512 | kCompressionNone | kObfuscationRepeated | kCryptoAes256);

  std::string content(RandomString(3000 + RandomUint32() % 1000));
  std::string hash1(RandomString(64)), hash2(RandomString(64));
  ASSERT_NE(hash1, hash2);

  // TODO(Steve) parametrise SE type, *.empty()

  EXPECT_EQ("", SelfEncryptChunk("", hash1, hash2,
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfEncryptChunk(content, "", hash2,
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfEncryptChunk(content, hash1, "",
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfEncryptChunk(content, hash1, hash2, 0));

  EXPECT_EQ("", SelfDecryptChunk("", hash1, hash2,
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfDecryptChunk(content, "", hash2,
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfDecryptChunk(content, hash1, "",
                                 kDefaultSelfEncryptionType));
  EXPECT_EQ("", SelfDecryptChunk(content, hash1, hash2, 0));

  EXPECT_EQ(content, SelfDecryptChunk(
      SelfEncryptChunk(content, hash1, hash2, kDefaultSelfEncryptionType),
      hash1, hash2, kDefaultSelfEncryptionType));

  EXPECT_NE(content, SelfDecryptChunk(
      SelfEncryptChunk(content, hash1, hash2, kDefaultSelfEncryptionType),
      hash2, hash1, kDefaultSelfEncryptionType));
}

}  // namespace test

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
