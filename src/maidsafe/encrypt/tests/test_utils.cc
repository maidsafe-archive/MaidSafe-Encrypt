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

#include <array>
#include <cstdint>
#include <vector>

#ifdef WIN32
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#ifdef WIN32
#  pragma warning(pop)
#endif
#include "boost/archive/text_iarchive.hpp"
#include "boost/timer.hpp"
#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/utils.h"

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
  // no data
  EXPECT_FALSE(CheckCompressibility("", kCompressionNone));
  EXPECT_FALSE(CheckCompressibility("", kCompressionGzip));

  //  make compressible string
  std::string sample(kCompressionSampleSize, 'x');
  EXPECT_FALSE(CheckCompressibility(sample, 0));
  EXPECT_FALSE(CheckCompressibility(sample, kCompressionNone));
  EXPECT_TRUE(CheckCompressibility(sample, kCompressionGzip));

  //  make incompressible string
  sample = RandomString(kCompressionSampleSize);
  EXPECT_FALSE(CheckCompressibility(sample, 0));
  EXPECT_FALSE(CheckCompressibility(sample, kCompressionNone));
  EXPECT_FALSE(CheckCompressibility(sample, kCompressionGzip));
}

TEST(SelfEncryptionUtilsTest, BEH_CheckParams) {
  EXPECT_FALSE(CheckParams(SelfEncryptionParams(0, 0, kMinChunks - 1)));
  EXPECT_FALSE(CheckParams(SelfEncryptionParams(1, 0, 0)));
  EXPECT_FALSE(CheckParams(SelfEncryptionParams(1, 10, 10)));
  EXPECT_FALSE(CheckParams(SelfEncryptionParams(10, 0, 10 * kMinChunks + 1)));
  EXPECT_FALSE(CheckParams(SelfEncryptionParams(10, 10, 10 * kMinChunks)));
  EXPECT_TRUE(CheckParams(SelfEncryptionParams(1, 0, 2)));
  EXPECT_TRUE(CheckParams(SelfEncryptionParams(1 << 18, 1 << 8, 1 << 10)));
}

TEST(SelfEncryptionUtilsTest, BEH_Compress) {
  std::string data_raw(RandomString(123 + RandomUint32() % 456));
  EXPECT_TRUE(Compress(data_raw, 0).empty());
  EXPECT_FALSE(Compress("", kCompressionGzip).empty());
  EXPECT_EQ(data_raw, Compress(data_raw, kCompressionNone));
  std::string data_gzip(Compress(data_raw, kCompressionGzip));
  EXPECT_FALSE(data_gzip.empty());
  EXPECT_NE(data_raw, data_gzip);
  EXPECT_TRUE(Uncompress(data_gzip, 0).empty());
  EXPECT_TRUE(Uncompress("", kCompressionNone).empty());
  EXPECT_EQ(data_raw, Uncompress(data_raw, kCompressionNone));
  EXPECT_TRUE(Uncompress(data_raw, kCompressionGzip).empty());
  EXPECT_EQ(data_raw, Uncompress(data_gzip, kCompressionGzip));
}

TEST(SelfEncryptionUtilsTest, BEH_Hash) {
  std::string data_raw(RandomString(123));
  EXPECT_EQ("", Hash("", 0));
  EXPECT_EQ("", Hash(data_raw, 0));
  EXPECT_EQ(crypto::Hash<crypto::SHA1>(data_raw), Hash(data_raw, kHashingSha1));
  EXPECT_EQ(crypto::Hash<crypto::SHA512>(data_raw),
            Hash(data_raw, kHashingSha512));
  EXPECT_EQ(crypto::Hash<crypto::Tiger>(data_raw),
            Hash(data_raw, kHashingTiger));
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

TEST(SelfEncryptionUtilsTest, XORtest) {
 // EXPECT_TRUE(XOR("A", "").empty()); // Exception - no pad
  EXPECT_TRUE(XOR("", "B").empty());
  EXPECT_EQ(XOR("A", "BB"), XOR("B", "A"));
  const size_t kStringSize(1024*256);
  std::string str1 = RandomString(kStringSize);
  std::string str2 = RandomString(kStringSize);
  std::string obfuscated = XOR(str1, str2);
  EXPECT_EQ(kStringSize, obfuscated.size());
  EXPECT_EQ(obfuscated, XOR(str2, str1));
  EXPECT_EQ(str1, XOR(obfuscated, str2));
  EXPECT_EQ(str2, XOR(obfuscated, str1));
  const std::string kZeros(kStringSize, 0);
  EXPECT_EQ(kZeros, XOR(str1, str1));
  EXPECT_EQ(str1, XOR(kZeros, str1));
  const std::string kKnown1("\xa5\x5a");
  const std::string kKnown2("\x5a\xa5");
  EXPECT_EQ(std::string("\xff\xff"), XOR(kKnown1, kKnown2));
  
}
TEST(SelfEncryptionUtilsTest, BEH_SelfEnDecrypt) {
  const std::string data("this is the password");
  std::string enc_hash = Hash(data, kHashingSha512);
  const std::string input(RandomString(1024*256));
  std::string encrypted, decrypted;
  CryptoPP::StringSource(input,
                          true,
       new AESFilter(
             new CryptoPP::StringSink(encrypted),
      enc_hash,
      true));

  CryptoPP::StringSource(encrypted,
                          true,
        new AESFilter(
             new CryptoPP::StringSink(decrypted),
        enc_hash,
        false));
  EXPECT_EQ(decrypted.size(), input.size());
  EXPECT_EQ(decrypted, input);
  EXPECT_NE(encrypted, decrypted);
        }

TEST(SelfEncryptionUtilsTest, BEH_AnchorXorAes) {
  const std::string data("this is the password");
  std::string enc_hash = Hash(data, kHashingSha512);
  const std::string input(RandomString(6000));
  const std::string pad(RandomString(600));
  std::string encrypted, decrypted;


Anchor Encryptor;
       Encryptor.Attach(new AESFilter(
             new CryptoPP::StringSink(encrypted),
      enc_hash,
      true));
       Encryptor.Attach(new XORFilter(
             new CryptoPP::StringSink(encrypted),
      pad));
       
Anchor Decryptor;
       Decryptor.Attach(new XORFilter(
             new CryptoPP::StringSink(decrypted),
       pad)); 
       Decryptor.Attach(new AESFilter(
             new CryptoPP::StringSink(decrypted),
        enc_hash,
        false));


  Encryptor.Put(reinterpret_cast<const byte*>(input.c_str()), input.size());
  Encryptor.MessageEnd();

  Decryptor.Put(reinterpret_cast<const byte*>(encrypted.c_str()), input.size());
  Decryptor.MessageEnd();

  EXPECT_EQ(encrypted.size(), input.size());
  EXPECT_EQ(decrypted.size(), input.size());
  EXPECT_EQ(decrypted, input);
  EXPECT_NE(encrypted, decrypted);
        }

TEST(SelfEncryptionUtilsTest, BEH_SelfEnDecryptChunk) {
  // leaving out hashing, since it's not relevant
  const std::array<std::uint32_t, 8> combinations = { {
    kCompressionNone | kObfuscationNone | kCryptoNone,
    kCompressionNone | kObfuscationNone | kCryptoAes256,
    kCompressionNone | kObfuscationRepeated | kCryptoNone,
    kCompressionNone | kObfuscationRepeated | kCryptoAes256,
    kCompressionGzip | kObfuscationNone | kCryptoNone,
    kCompressionGzip | kObfuscationNone | kCryptoAes256,
    kCompressionGzip | kObfuscationRepeated | kCryptoNone,
    kCompressionGzip | kObfuscationRepeated | kCryptoAes256
  } };

  std::string content(RandomString(3000 + RandomUint32() % 1000));
  std::string hash1(RandomString(64)), hash2(hash1);
  while (hash2 == hash1)
    hash2 = RandomString(64);

  std::array<std::string, 8> content_enc;
  for (size_t i = 0; i < combinations.size(); ++i) {
    EXPECT_TRUE(SelfEncryptChunk("", hash1, hash2, combinations[i]).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, "", hash2, combinations[i]).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, hash1, "", combinations[i]).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, hash1, hash2, 0).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, hash1, hash2,
        combinations[i] & (kObfuscationMask | kCryptoMask)).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, hash1, hash2,
        combinations[i] & (kCompressionMask | kCryptoMask)).empty());
    EXPECT_TRUE(SelfEncryptChunk(content, hash1, hash2,
        combinations[i] & (kCompressionMask | kObfuscationMask)).empty());
    content_enc[i] = SelfEncryptChunk(content, hash1, hash2, combinations[i]);
    if (combinations[i] == (kCompressionNone | kObfuscationNone | kCryptoNone))
      EXPECT_EQ(content, content_enc[i]) << i;
    else
      EXPECT_NE(content, content_enc[i]) << i;
  }

  for (size_t i = 0; i < combinations.size(); ++i) {
    EXPECT_TRUE(SelfDecryptChunk("", hash1, hash2, combinations[i]).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], "", hash2,
                                 combinations[i]).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], hash1, "",
                                 combinations[i]).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], hash1, hash2, 0).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], hash1, hash2,
        combinations[i] & (kObfuscationMask | kCryptoMask)).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], hash1, hash2,
        combinations[i] & (kCompressionMask | kCryptoMask)).empty());
    EXPECT_TRUE(SelfDecryptChunk(content_enc[i], hash1, hash2,
        combinations[i] & (kCompressionMask | kObfuscationMask)).empty());

    if ((combinations[i] & (kObfuscationMask | kCryptoMask)) ==
            (kObfuscationNone | kCryptoNone))
      EXPECT_EQ(content, SelfDecryptChunk(content_enc[i], hash2, hash1,
                                          combinations[i])) << i;
    else
      EXPECT_NE(content, SelfDecryptChunk(content_enc[i], hash2, hash1,
                                          combinations[i])) << i;
    for (size_t j = 0; j < combinations.size(); ++j)
      if (i == j) {
        EXPECT_EQ(content, SelfDecryptChunk(content_enc[i], hash1, hash2,
                                            combinations[j])) << i << " " << j;
      } else {
        EXPECT_NE(content, SelfDecryptChunk(content_enc[i], hash1, hash2,
                                            combinations[j])) << i << " " << j;
      }
  }
}

}  // namespace test

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
