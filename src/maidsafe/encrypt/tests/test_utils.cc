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
#include "maidsafe/common/test.h"
#include "cryptopp/modes.h"
#include "cryptopp/sha.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/utils.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/common/memory_chunk_store.h"


namespace maidsafe {

namespace encrypt {


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

  std::string content(RandomString(40));

  char *stuff = new char[40];
  std::copy(content.c_str(), content.c_str() + 40, stuff);
  EXPECT_TRUE(selfenc.Write(stuff, 40));
  EXPECT_EQ(0, selfenc.getDataMap().chunks.size());
  EXPECT_EQ(0, selfenc.getDataMap().size);
  EXPECT_EQ(0, selfenc.getDataMap().content_size);
  EXPECT_TRUE(selfenc.FinaliseWrite());
  EXPECT_EQ(40, selfenc.getDataMap().size);
  EXPECT_EQ(40, selfenc.getDataMap().content_size);
  EXPECT_EQ(0, selfenc.getDataMap().chunks.size());
  EXPECT_EQ(static_cast<char>(*stuff),
            static_cast<char>(*selfenc.getDataMap().content));

  EXPECT_TRUE(selfenc.ReInitialise());
  size_t test_data_size(1024*1024*2);
  char *hundredmb = new char[test_data_size];
  for (size_t i = 0; i < test_data_size; ++i) {
    hundredmb[i] = 'a';
  }
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  EXPECT_TRUE(selfenc.Write(hundredmb, test_data_size));
  EXPECT_TRUE(selfenc.FinaliseWrite());
  std::uint64_t duration =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  if (duration == 0)
    duration = 1;
  DLOG(INFO) << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
             << " in " << (duration / 1000000.0)
             << " at a speed of " << test_data_size / duration / 1.048576
             << "mB/s"
             << std::endl;
  DLOG(INFO) << " Created " << selfenc.getDataMap().chunks.size()
            << " Chunks!!" << std::endl;

  std::string str, str1;
  for(size_t j = 0; j < selfenc.getDataMap().chunks.size(); ++j) {
    for (size_t i =0; i < 64;++i) {
      str += static_cast<char>(selfenc.getDataMap().chunks[j].pre_hash[i]);
      str1 += static_cast<char>(selfenc.getDataMap().chunks[j].hash[i]);
    }
  DLOG(INFO) << "pre  hash chunk " << j  << ": " << EncodeToHex(str);
  DLOG(INFO) <<  std::endl;
  DLOG(INFO) << "post hash chunk " << j  << ": " << EncodeToHex(str1);
  DLOG(INFO) <<  std::endl;
  DLOG(INFO) <<  std::endl;
  str = ""; str1 = "";
  }

  for (int i = 0; i < 64; ++i) {         
    EXPECT_EQ(selfenc.getDataMap().chunks.at(3).pre_hash[i],
              selfenc.getDataMap().chunks.at(4).pre_hash[i]);
    ASSERT_EQ(selfenc.getDataMap().chunks.at(5).hash[i],
              selfenc.getDataMap().chunks.at(3).hash[i]);
   }
}

TEST(SelfEncryptionUtilsTest, BEH_SE_manual_check) {
  MemoryChunkStore::HashFunc hash_func =
      std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1);
  std::shared_ptr<MemoryChunkStore> chunk_store(
      new MemoryChunkStore(true, hash_func));
  SE selfenc(chunk_store);

  size_t chunk_size(1024*256); // system default
  size_t num_chunks(10);
  char * extra_content = new char[5]{'1','2','3','4','5'};
  size_t expected_content_size(sizeof(extra_content));
  size_t file_size(chunk_size*num_chunks + expected_content_size); 
  byte *pre_enc_chunk = new byte[chunk_size];
  byte *pad = new byte[144];
  byte *xor_res = new byte[chunk_size];
  byte *prehash = new byte[CryptoPP::SHA512::DIGESTSIZE];
  byte *posthash = new byte[CryptoPP::SHA512::DIGESTSIZE];
  byte *postenc = new byte[chunk_size];
  byte *key = new byte[32];
  byte *iv = new byte[16];
  char *pre_enc_file = new char[file_size];

  for (size_t i = 0; i < chunk_size; ++i) {
    pre_enc_chunk[i] = 'b';
  }

  for (size_t i = 0; i < file_size; ++i) {
     pre_enc_file[i] = 'b';
  }


  EXPECT_TRUE(selfenc.ReInitialise());
  EXPECT_TRUE(selfenc.Write(pre_enc_file, file_size));
  EXPECT_TRUE(selfenc.FinaliseWrite());
// Do some testing on results
  EXPECT_EQ(num_chunks,  selfenc.getDataMap().chunks.size());
  EXPECT_EQ(expected_content_size,  selfenc.getDataMap().content_size);
  EXPECT_EQ(file_size, selfenc.getDataMap().size);


  CryptoPP::SHA512().CalculateDigest(prehash, pre_enc_chunk, chunk_size);
  
  for (int i = 0; i < 64; ++i) {
    pad[i] = prehash[i];
    pad[i+64] = prehash[i];
  }
  for (int i = 0; i < 16; ++i) {
    pad[i+128] = prehash[i+48];
  }
  std::copy(prehash, prehash + 32, key);
  std::copy(prehash + 32, prehash + 48, iv);
  std::cout << "key = " << EncodeToHex(reinterpret_cast<const char*>(key)) << std::endl;
  std::cout << "iv  = " << EncodeToHex(reinterpret_cast<const char*>(iv)) << std::endl;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc(key, 32, iv);
  enc.ProcessData(postenc, pre_enc_chunk, chunk_size);
  std::cout << "post aes = " << EncodeToHex(reinterpret_cast<const char*>(postenc)) << std::endl;
  for (size_t i = 0; i < chunk_size; ++i) {
    xor_res[i] = postenc[i]^pad[i%144];
  }
  std::cout << "post xor = " << EncodeToHex(reinterpret_cast<const char*>(xor_res)) << std::endl;

  CryptoPP::SHA512().CalculateDigest(posthash, xor_res, chunk_size);
  std:: cout << " num chunks " << selfenc.getDataMap().chunks.size() << std::endl;
  // TODO FIXME - hashing issue unsure whether test or code as of yet
  for (int i = 0; i < 64; ++i) {
    EXPECT_EQ(prehash[i], selfenc.getDataMap().chunks[4].pre_hash[i]);
 //   EXPECT_EQ(posthash[i], selfenc.getDataMap().chunks[4].hash[i]);
  }

  for (size_t i = 0; i < selfenc.getDataMap().chunks.size(); ++i)
    std::cout << "chunk "<< i << " prehash = "
              << EncodeToHex(reinterpret_cast<const char*>
                  (selfenc.getDataMap().chunks[i].pre_hash)) << std::endl;
  for (size_t i = 0; i < selfenc.getDataMap().chunks.size(); ++i) {
    std::cout << "chunk "<< i << " enchash = "
              << EncodeToHex(reinterpret_cast<const char*>
                  (selfenc.getDataMap().chunks[i].hash)) << std::endl;
    std::cout << "chunk "<< i << " presize = "
              << selfenc.getDataMap().chunks[i].pre_size << std::endl;
    std::cout << "chunk "<< i << " postsize = "
              << selfenc.getDataMap().chunks[i].size << std::endl;
  }
  std::cout << "test hash = "
            << EncodeToHex(reinterpret_cast<const char*>(posthash))
            << std::endl;
  std::cout << "Total number of chunks =  " << selfenc.getDataMap().chunks.size() << std::endl;
  std::cout << "Content size = " << selfenc.getDataMap().size << std::endl;
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
