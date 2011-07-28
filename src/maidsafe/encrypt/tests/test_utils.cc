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
#include <exception>
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
#include "maidsafe/common/memory_chunk_store.h"

namespace maidsafe {

namespace encrypt {

namespace utils {

namespace test {

// TEST(SelfEncryptionUtilsTest, BEH_Serialisation) {
//   DataMap data_map;
//   {
//     data_map.content = "abcdefg";
//     data_map.size = 12345;
//     ChunkDetails chunk;
//     chunk.hash = "test123";
//     chunk.size = 10000;
//     data_map.chunks.push_back(chunk);
//     chunk.hash = "test456";
//     chunk.size = 2345;
//     data_map.chunks.push_back(chunk);
//   }
//   std::stringstream ser_data_map;
//   {  // serialise DataMap to string stream
//     boost::archive::text_oarchive oa(ser_data_map);
//     oa << data_map;
//   }
//   {
//     DataMap restored_data_map;
//     boost::archive::text_iarchive ia(ser_data_map);
//     ia >> restored_data_map;
//     EXPECT_EQ(data_map.content, restored_data_map.content);
//     EXPECT_EQ(data_map.size, restored_data_map.size);
//     EXPECT_EQ(data_map.chunks.size(), restored_data_map.chunks.size());
//     EXPECT_EQ(data_map.chunks[0].hash, restored_data_map.chunks[0].hash);
//     EXPECT_EQ(data_map.chunks[0].size, restored_data_map.chunks[0].size);
//     EXPECT_EQ(data_map.chunks[1].hash, restored_data_map.chunks[1].hash);
//     EXPECT_EQ(data_map.chunks[1].size, restored_data_map.chunks[1].size);
//   }
// }

// TEST(SelfEncryptionUtilsTest, XORtest) {
//  // EXPECT_TRUE(XOR("A", "").empty()); // Exception - no pad
//   XORFilter XOR;
//   EXPECT_TRUE(XOR("", "B").empty());
//   EXPECT_EQ(XOR("A", "BB"), XOR("B", "A"));
//   EXPECT_EQ(XOR("AAAA", "BB"), XOR("BBBB", "AA"));
//   const size_t kStringSize(1024*256);
//   std::string str1 = RandomString(kStringSize);
//   std::string str2 = RandomString(kStringSize);
//   std::string obfuscated = XOR(str1, str2);
//   EXPECT_EQ(kStringSize, obfuscated.size());
//   EXPECT_EQ(obfuscated, XOR(str2, str1));
//   EXPECT_EQ(str1, XOR(obfuscated, str2));
//   EXPECT_EQ(str2, XOR(obfuscated, str1));
//   const std::string kZeros(kStringSize, 0);
//   EXPECT_EQ(kZeros, XOR(str1, str1));
//   EXPECT_EQ(str1, XOR(kZeros, str1));
//   const std::string kKnown1("\xa5\x5a");
//   const std::string kKnown2("\x5a\xa5");
//   EXPECT_EQ(std::string("\xff\xff"), XOR(kKnown1, kKnown2));
// 
// }

/*TEST(SelfEncryptionUtilsTest, BEH_SelfEnDecrypt) {
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
*/


TEST(SelfEncryptionUtilsTest, BEH_SEtest_basic) {
  MemoryChunkStore::HashFunc hash_func = std::bind(&crypto::Hash<crypto::SHA512>,
                                                   std::placeholders::_1);
  std::shared_ptr<MemoryChunkStore> chunk_store(new MemoryChunkStore (true, hash_func));
  SE selfenc(chunk_store);

  std::string content(RandomString(300000 + RandomUint32() % 1000));
  std::string one_mb(RandomString(1024*1024));
  std::string hundred_mb;
  for (int i =0; i < 500; ++i)
    hundred_mb += one_mb; 
  std::string data;
  
//   char *stuff = new char[40];
//   std::copy(content.c_str(), content.c_str() + 40, stuff);
//   EXPECT_TRUE(selfenc.Write(stuff, 40, true));

  char *chunksstuff = new char[1048576];
  for (int i = 0; i <= 1048576; ++i) {
    chunksstuff[i] = 'a';
  }
  EXPECT_TRUE(selfenc.Write(chunksstuff, 1048576, true));

  const char *onemb = one_mb.c_str();
  EXPECT_TRUE(selfenc.Write(onemb, 1024*1024, false));

  const char *hundredmb = hundred_mb.c_str();

  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  EXPECT_TRUE(selfenc.Write(hundredmb, 1024*1024*500, true));
  std::uint64_t duration =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  if (duration == 0)
    duration = 1;
  printf("Self-encrypted  %d bytes in %.2f seconds "
         "(%.3f MB/s).\n", 1024*1024*500, duration / 1000000.0,
           1024*1024*500 / duration / 1.048576);
}

}  // namespace test

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
