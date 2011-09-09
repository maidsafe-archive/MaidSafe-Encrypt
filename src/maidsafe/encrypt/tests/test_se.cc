
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
 *******************************************************************************
 * @file  test_utils.cc
 * @brief Tests for the self-encryption helper functions.
 * @date  2011-04-05
 */

#ifdef WIN32
#  pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
#ifdef WIN32
#  pragma warning(pop)
#endif
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/scoped_array.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encrypt.h"
#include "maidsafe/encrypt/log.h"

#include <array>
#include <string>

namespace bptime = boost::posix_time;

namespace maidsafe {
namespace encrypt {
namespace test {

namespace {
typedef std::shared_ptr<MemoryChunkStore> MemoryChunkStorePtr;
MemoryChunkStore::HashFunc g_hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
}  // unnamed namespace


TEST(SelfEncryptionTest, BEH_40Charsonly) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  std::string content(RandomString(40));
  boost::scoped_array<char>stuff(new char[40]);
  boost::scoped_array<char>answer(new char[40]);
  std::copy(content.data(), content.data() + 40, stuff.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff.get(), 40));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
    // read before write - all in queue
    EXPECT_TRUE(selfenc.Read(answer.get(), 40));
    EXPECT_EQ(*stuff.get(), *answer.get());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(40, data_map->size);
  EXPECT_EQ(40, data_map->content_size);
  EXPECT_EQ(0, data_map->chunks.size());
  EXPECT_EQ(*stuff.get(), *data_map->content.c_str());
  EXPECT_TRUE(selfenc.Read(answer.get(), 40));
  EXPECT_EQ(*stuff.get(), *answer.get());
}
/*
// This test get passed in Debug mode,
// but will get segmentation fail in Release mode
// The breaking point is : CryptoPP::Put2 being called by SelfEncryptor::Write
//                         in SelfEncryptor::EnptySedquence during destruction
TEST(SelfEncryptionTest, BEH_40CharPlusPadding) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  std::string content(RandomString(40));
  boost::scoped_array<char>stuff(new char[40]);
  boost::scoped_array<char>answer(new char[80]);
  std::copy(content.data(), content.data() + 40, stuff.get());
{
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_TRUE(selfenc.Write(stuff.get(), 40, 40));
  EXPECT_EQ(0, selfenc.data_map()->chunks.size());
  EXPECT_EQ(0, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(80, selfenc.data_map()->size);
  EXPECT_EQ(80, selfenc.data_map()->content_size);
  EXPECT_EQ(0, selfenc.data_map()->chunks.size());
  for( size_t i = 0; i < 40; ++i) {
    EXPECT_TRUE(selfenc.Read(&answer[i], 1, i));
  }
}*/




TEST(SelfEncryptionTest, BEH_1023Chars) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  std::string content(RandomString(1023));
  boost::scoped_array<char> stuff1(new char[1023]);
  std::copy(content.c_str(), content.c_str() + 1023, stuff1.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff1.get(), 1023));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  EXPECT_EQ(1023, data_map->size);
  EXPECT_EQ(1023, data_map->content_size);
  EXPECT_EQ(0, data_map->chunks.size());
}

TEST(SelfEncryptionTest, BEH_1025Chars3chunks) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  std::string content(RandomString(1025));
  boost::scoped_array<char> stuff1(new char[1025]);
  std::copy(content.c_str(), content.c_str() + 1025, stuff1.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff1.get(), 1025));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(1025, selfenc.data_map()->size);
  EXPECT_EQ(1025, selfenc.data_map()->content_size);
  EXPECT_EQ(0, selfenc.data_map()->chunks.size());
}

TEST(SelfEncryptionTest, BEH_BenchmarkMemOnly) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  SelfEncryptor selfenc(data_map, chunk_store);

  const uint32_t kTestDataSize(1024 * 1024 * 20);
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (size_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] = 'a';
  }
  // Memory chunkstore
  // Write as complete stream
  bptime::ptime time =
      bptime::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize));
  // TODO(dirvine) FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
  uint64_t duration =
      (bptime::microsec_clock::universal_time() - time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(kTestDataSize)
            << " in " << (duration / 1000000.0) << " seconds at a speed of "
            << BytesToBinarySiUnits(speed) << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_Benchmark4kBytes) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  SelfEncryptor selfenc(data_map, chunk_store);

  const uint32_t kTestDataSize(1024 * 1024 * 20);
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] = 'a';
  }
  // Write in 4kB byte chunks
  uint32_t fourkB(4096);
  bptime::ptime time = bptime::microsec_clock::universal_time();
  for (uint32_t i = 0; i < kTestDataSize; i += fourkB)
    ASSERT_TRUE(selfenc.Write(&plain_data[i], fourkB, i));
  // TODO(dirvine) FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
  uint64_t duration =
      (bptime::microsec_clock::universal_time() - time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(kTestDataSize)
            << " in " << (duration / 1000000.0) << " seconds at a speed of "
            << BytesToBinarySiUnits(speed) << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_Benchmark64kBytes) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  SelfEncryptor selfenc(data_map, chunk_store);
  const uint32_t kTestDataSize(1024 * 1024 * 20);
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] = 'a';
  }
  // Write in 16kB byte chunks
  uint32_t sixtyfourkB(65536);
  bptime::ptime time = bptime::microsec_clock::universal_time();
  for (uint32_t i = 0; i < kTestDataSize; i += sixtyfourkB)
    ASSERT_TRUE(selfenc.Write(&plain_data[i], sixtyfourkB, i));
  // TODO(dirvine) FIXME - wont work till destructor called
  //   ASSERT_TRUE(selfenc.FinaliseWrite());
  uint64_t duration =
      (bptime::microsec_clock::universal_time() - time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(kTestDataSize)
            << " in " << (duration / 1000000.0) << " seconds at a speed of "
            << BytesToBinarySiUnits(speed) << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadIncompressible) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const uint32_t kTestDataSize((1024 * 1024 * 20) + 4);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
//    plain_data[i] = 'a';
    plain_data[i] = plain_text[i];
  }
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    bptime::ptime time =
          bptime::microsec_clock::universal_time();
    ASSERT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize));
    uint64_t duration =
        (bptime::microsec_clock::universal_time() - time).total_microseconds();
    if (duration == 0)
      duration = 1;
    uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
    std::cout << "Self-encrypted " << BytesToBinarySiUnits(kTestDataSize)
              << " in " << (duration / 1000000.0) << " seconds at a speed of "
              << BytesToBinarySiUnits(speed) << "/s" << std::endl;
    boost::scoped_array<char> some_chunks_some_q(new char[kTestDataSize]);
    ASSERT_TRUE(selfenc.Read(some_chunks_some_q.get(), kTestDataSize, 0));
    for (uint32_t  i = 0; i < kTestDataSize; ++i)
      ASSERT_EQ(plain_text[i], some_chunks_some_q[i]) << "failed @ count " << i;
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  bptime::ptime time =
        bptime::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
  uint64_t duration =
      (bptime::microsec_clock::universal_time() - time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
  std::cout << "Self-decrypted " << BytesToBinarySiUnits(kTestDataSize)
            << " in " << (duration / 1000000.0) << " seconds at a speed of "
            << BytesToBinarySiUnits(speed) << "/s" << std::endl;

  for (uint32_t  i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_text[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadCompressible) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const uint32_t kTestDataSize((1024 * 1024 * 20) + 36);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] = 'a';
  }
  {
    SelfEncryptor selfenc(data_map, chunk_store);
  //   EXPECT_TRUE(selfenc.ReInitialise());
    bptime::ptime time = bptime::microsec_clock::universal_time();
    ASSERT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize));
    // TODO(dirvine) FIXME - wont work till destructor called
    //   ASSERT_TRUE(selfenc.FinaliseWrite());
    uint64_t duration =
        (bptime::microsec_clock::universal_time() - time).total_microseconds();
    if (duration == 0)
      duration = 1;
    uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
    std::cout << "Self-encrypted " << BytesToBinarySiUnits(kTestDataSize)
              << " in " << (duration / 1000000.0) << " seconds at a speed of "
              << BytesToBinarySiUnits(speed) << "/s" << std::endl;
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  bptime::ptime time =  bptime::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
  uint64_t duration =
      (bptime::microsec_clock::universal_time() - time).total_microseconds();
  if (duration == 0)
    duration = 1;
  uint64_t speed((static_cast<uint64_t>(kTestDataSize) * 1000000) / duration);
  std::cout << "Self-decrypted " << BytesToBinarySiUnits(kTestDataSize)
            << " in " << (duration / 1000000.0) << " seconds at a speed of "
            << BytesToBinarySiUnits(speed) << "/s" << std::endl;
  for (uint32_t i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}


TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATime) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // less than 2 MB fails due to test
  const uint32_t kTestDataSize(1024 * 1024 * 2);
  std::string plain_text(SRandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 1; ++i) {
    plain_data[i] = 'a';  // plain_text[i];
  }
  plain_data[kTestDataSize - 1] = 'b';
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    // EXPECT_TRUE(selfenc.ReInitialise());
    // extra = sequencer_.Get(current_position_);
    for (uint32_t i = 0; i < kTestDataSize; ++i)  {
      selfenc.Write(&plain_data[i], 1, i);
    }
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(kTestDataSize, data_map->size);
  EXPECT_EQ(0, data_map->content_size);
  EXPECT_EQ(8, data_map->chunks.size());
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize));

//   // check chunks 1 and 2
  for (uint32_t i = 0; i < 524288; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "c0 or c1 failed at count " << i;
// check all other chunks
  for (uint32_t i = 524288; i < kTestDataSize - 1; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "normal chunks failed count :" << i;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATimeOutOfSequenceForward) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(1024 * 20);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 2; ++i) {
    plain_data[i] = plain_text[i];
  }
  plain_data[kTestDataSize - 2] = 'a';
  plain_data[kTestDataSize - 1] = 'b';

  uint32_t length = 1;
  {
    SelfEncryptor selfenc(data_map, chunk_store);
  bptime::ptime time = bptime::microsec_clock::universal_time();
  //   EXPECT_TRUE(selfenc.ReInitialise());
    for (uint32_t i = 0; i < kTestDataSize + 1; i += 2)  {
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    }
  uint64_t duration1 =
      (bptime::microsec_clock::universal_time() -
       time).total_microseconds();
  std::cout << "even byte_by_byte written taken : " << duration1
            << " microseconds" << std::endl;
    for (uint32_t i = 1; i < kTestDataSize + 1; i += 2)  {
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    }
  uint64_t duration2 =
      (bptime::microsec_clock::universal_time() -
       time).total_microseconds();
  std::cout << "odd byte_by_byte written taken : " << duration2 - duration1
            << " microseconds" << std::endl;
  // TODO(dirvine) FIXME - wont work till destructor called
  //   ASSERT_TRUE(selfenc.FinaliseWrite());
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize + 1]);

  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize + 1, 0));

  for (size_t  i = 0; i < kTestDataSize + 1; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, BEH_WriteOnceRead20) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(1024 * 1024);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  for (uint32_t i = 0; i < kTestDataSize - 1; ++i) {
//    plain_data[i] = 'a';
    plain_data[i] = plain_text[i];
  }
  plain_data[kTestDataSize - 1] = 'b';
  {
    SelfEncryptor selfenc(data_map, chunk_store);
//   EXPECT_TRUE(selfenc.ReInitialise());
    ASSERT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize));
    // TODO(dirvine) FIXME - wont work till destructor called
    //   ASSERT_TRUE(selfenc.FinaliseWrite());
    // check it works at least once
    boost::scoped_array<char> answer(new char[kTestDataSize]);
    ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
    // In process check !!
    for (int j = 0; j < 20; ++j) {
      boost::scoped_array<char> answer1(new char[kTestDataSize]);
      ASSERT_TRUE(selfenc.Read(answer1.get(), kTestDataSize, 0))
      << "failed at read attempt " << j;
      for (uint32_t  i = 0; i < kTestDataSize; ++i)
        ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
    }
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));

  for (int j = 0; j < 20; ++j) {
    boost::scoped_array<char> answer1(new char[kTestDataSize]);
    ASSERT_TRUE(selfenc.Read(answer1.get(), kTestDataSize, 0))
    << "failed at read attempt " << j;
    for (uint32_t  i = 0; i < kTestDataSize; ++i)
      ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
  }
}

TEST(SelfEncryptionTest, BEH_WriteRandomlyAllDirections) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const uint32_t kTestDataSize(1024 * 20);
//   std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);
  std::vector<size_t> vec_data(kTestDataSize);
  for (uint32_t i = 0; i < kTestDataSize; ++i) {
    plain_data[i] = 'a';  // plain_text[i];
  }
//   plain_data[kTestDataSize - 1] = 'b';
  for (uint32_t i = 0; i < kTestDataSize; ++i)
    vec_data[i] = i;  // vector of seq numbers

  std::random_shuffle(vec_data.begin(), vec_data.end());  // shuffle all about
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    boost::scoped_array<char> answer(new char[kTestDataSize]);
    for (uint32_t i = 0; i < kTestDataSize; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[vec_data[i]], 1, vec_data[i]));
      ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
      ASSERT_EQ(plain_data[i], answer[i]) << "failed in process at " << i;
    }
    // In process check

    ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
    for (uint32_t i = 0; i < kTestDataSize; ++i)
      ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
  }


//   EXPECT_EQ(8, selfenc.data_map()->chunks.size());
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[kTestDataSize]);
  ASSERT_TRUE(selfenc.Read(answer.get(), kTestDataSize, 0));
  for (uint32_t i = 0; i < kTestDataSize; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_RepeatedRandomCharReadInProcess) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t chunk_size(1024 * 256);
  const uint32_t kTestDataSize(chunk_size * 6);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);

  for (uint32_t i = 0; i < kTestDataSize - 1; ++i)
    plain_data[i] = plain_text[i];
  plain_data[kTestDataSize - 1] = 'b';
  SelfEncryptor selfenc(data_map, chunk_store);
  // check 2 chunk_size
    for (uint32_t i = 0; i < chunk_size * 2; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

    // read some data - should be in queue
    // Check read From Queue FIXME !!
//     boost::scoped_array<char> testq(new char[chunk_size]);
//     for (uint32_t i = 0; i < 10; ++i) {
// // TODO(dirvine) FIXME - this next line causes segfault (double free error
// //                       in checked delete)
// //      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
// //       EXPECT_EQ(plain_data[i], testq[i]) << "not read " << i << std::endl;
//     }

    // next 2
    for (uint32_t i = chunk_size * 2; i < chunk_size * 4; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

    // Check read from c0 and c1 buffer
    EXPECT_EQ(0, data_map->size);
    EXPECT_EQ(0, data_map->content_size);
    EXPECT_EQ(2, data_map->chunks.size());  // not really but pre_hash is set

    boost::scoped_array<char> testc0(new char[chunk_size]);
    for (uint32_t i = 0; i < 100; ++i) {
      EXPECT_TRUE(selfenc.Read(&testc0[i], 1, i));
      ASSERT_EQ(testc0[i], plain_data[i]) << "not read " << i << std::endl;
    }


    boost::scoped_array<char> testc1(new char[chunk_size]);
    for (uint32_t i = 0; i <  100; ++i) {
      EXPECT_TRUE(selfenc.Read(&testc1[i], 1, i +  chunk_size));
      ASSERT_EQ(testc1[i], plain_data[i  + chunk_size])
      << "not read " << i << std::endl;
    }




    // write  out of sequence (should be in sequencer now
    for (uint32_t i = chunk_size * 5; i < (chunk_size * 5) + 10; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }



    // Check read from Sequencer
    boost::scoped_array<char> testseq(new char[chunk_size]);
    for (uint32_t i = 0; i < 10; ++i) {
      EXPECT_TRUE(selfenc.Read(&testseq[i], 1, i));
      ASSERT_EQ(testseq[i], plain_data[i]) << "not read " << i << std::endl;
    }
    // write second last chunk

    for (uint32_t i = chunk_size * 4; i < chunk_size * 5; i += chunk_size) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

    for (uint32_t i = (chunk_size * 5) + 10; i < chunk_size * 6; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

  // TODO(dirvine) FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
//   // read some data - should be in chunks now
//   boost::scoped_array<char> testchunks(new char[10]);
//   for (uint32_t i = 0; i < 10; ++i) {
//     EXPECT_TRUE(selfenc.Read(testchunks.get(), 1, i));
//     ASSERT_EQ(testchunks.get()[i], plain_data[i]) << "not read " << i;
//   }
//
//   EXPECT_EQ(6,  selfenc.data_map()->chunks.size());
//   EXPECT_EQ(0,  selfenc.data_map()->content_size);
//   EXPECT_EQ(kTestDataSize + 1, selfenc.data_map()->size);

//   boost::scoped_array<char> answer(new char[kTestDataSize + 1]);
//   EXPECT_TRUE(selfenc.Read(answer.get(), kTestDataSize + 1, 0));
//   for (uint32_t i = 0; i < kTestDataSize + 1; ++i)
//     ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_ReadArbitaryPosition) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t chunk_size(1024 * 256);
  const uint32_t kTestDataSize(chunk_size * 6);
  std::string plain_text(RandomString(kTestDataSize));
  boost::scoped_array<char> plain_data(new char[kTestDataSize]);

  std::copy(plain_text.begin(), plain_text.end(), plain_data.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(plain_data.get(), kTestDataSize));
  }
  {
    // read some data
    SelfEncryptor selfenc(data_map, chunk_store);
    boost::scoped_array<char> testq(new char[chunk_size * 6]);
    for (size_t i = 0; i < 10; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i << std::endl;
    }
    for (size_t i = chunk_size - 1; i < chunk_size + 1; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i << std::endl;
    }
    for (size_t i = chunk_size * 3 - 1; i < chunk_size * 3 + 1; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i << std::endl;
    }
    for (size_t i = chunk_size * 6 - 1; i < chunk_size * 6; ++i) {
      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i))
          << "not read " << i << std::endl;
      ASSERT_EQ(plain_data[i], testq[0]) << "not match " << i << std::endl;
    }

    int position(0);
    int length(chunk_size + 2);
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i << std::endl;

    position = chunk_size - 1;
    length = chunk_size * 2 + 2;
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i << std::endl;

    position = chunk_size * 2 - 1;
    length = chunk_size * 3 + 2;
    EXPECT_TRUE(selfenc.Read(testq.get(), length, position));
    for (int i = 0; i < length; ++i)
      EXPECT_EQ(plain_data[position + i], testq[i])
          << "not match " << i << std::endl;
  }
}

// TEST(SelfEncryptionManualTest, BEH_RandomAccess) {
//   size_t chunk_size(1024 * 256);
//   std::vector<size_t> num_of_tries;
//   std::vector<size_t> max_variation;
//   max_variation.push_back(1024);
//   max_variation.push_back(3072);
//   max_variation.push_back(chunk_size);
//   max_variation.push_back(3 * chunk_size);
//   max_variation.push_back(6 * chunk_size);
//   num_of_tries.push_back(5);
//   num_of_tries.push_back(20);
//   num_of_tries.push_back(50);
//   num_of_tries.push_back(100);
//   num_of_tries.push_back(200);
//   // the longest length of data is writing to position 6 * chunk_size with
//   // a content length of 6 * chunk_size, make the total to be 12 * chunk_size
//   size_t kTestDataSize(chunk_size * 12);
//
//   {
//     // In Process random write/read access
//     MemoryChunkStore::HashFunc hash_func
//         (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
//     std::shared_ptr<MemoryChunkStore> chunk_store
//         (new MemoryChunkStore(false, hash_func));
//     DataMapPtr data_map(new DataMap);
//     SelfEncryptor selfenc(data_map, chunk_store);
//
//     boost::scoped_array<char>plain_data(new char[kTestDataSize]);
//     // The initialization value of truncated data shall be filled here
//     for (size_t i = 0; i < kTestDataSize; ++i)
//       plain_data[i] = '0';
//
//     for (size_t i = 0; i < max_variation.size(); ++i) {
//       size_t num_tries = num_of_tries[i];
//       size_t variation = max_variation[i];
//       for (size_t j = 0; j < num_tries; ++j) {
//         int op_code(RandomUint32() % 2);
//         DLOG(INFO) << " op code : " << op_code;
//
//         switch (op_code) {
//           case 0: // write
//             {
//               size_t write_position(RandomUint32() % variation);
//               size_t write_length(RandomUint32() % variation);
//               DLOG(INFO) << " write_position : " << write_position
//                          << " write_length : " << write_length;
//
//               std::string plain_text(RandomString(write_length));
//               boost::scoped_array<char>content_data(new char[write_length]);
//               for (size_t i = 0; i < write_length; ++i) {
//                 plain_data[i + write_position] = plain_text[i];
//                 content_data[i] = plain_text[i];
//               }
//
//               EXPECT_TRUE(selfenc.Write(content_data.get(),
//                                         write_length, write_position));
//               break;
//             }
//           case 1: // read
//             {
//               size_t read_position(RandomUint32() % variation);
//               size_t read_length(RandomUint32() % variation);
//               boost::scoped_array<char>answer(new char[read_length]);
//               DLOG(INFO) << " read_position : " << read_position
//                          << " read_length : " << read_length;
//
//               // The read method shall accept a reading request that exceeds
//               // the current data lenth of the encrypt stream.
//               // It shall return part of the content or false if the starting
//               // read position exceed the data size
//               if (read_position < data_map->size) {
//                 EXPECT_TRUE(selfenc.Read(answer.get(),
//                                          read_length, read_position));
//                 // A return value of num_of_bytes succeeded read is required
//                 for (size_t i = 0; i < read_length; ++i)
//                   ASSERT_EQ(plain_data[read_position + i], answer[i])
//                       << "not match " << i << " from " << read_position
//                     << " when total data is " << data_map->size << std::endl;
//               } else {
//                 EXPECT_FALSE(selfenc.Read(answer.get(),
//                                           read_length, read_position))
//                     << " when trying to read " << read_position
//                     << " from " << data_map->size << std::endl;
//               }
//               break;
//             }
//           default:
//             break;
//         }
//       }
//     }
//   }
//
//   {
//     // Out Process random write/read access
//     MemoryChunkStore::HashFunc hash_func
//         (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
//     std::shared_ptr<MemoryChunkStore> chunk_store
//         (new MemoryChunkStore(false, hash_func));
//     DataMapPtr data_map(new DataMap);
//
//     for (size_t i = 0; i < max_variation.size(); ++i) {
//       size_t num_tries = num_of_tries[i];
//       size_t variation = max_variation[i];
//       for (size_t j = 0; j < num_tries; ++j) {
//         size_t position(RandomUint32() % variation);
//         size_t length(RandomUint32() % variation);
//         DLOG(INFO) << " accesing at postion : " << position
//                    << " with data length : " << length;
//
//         std::string plain_text(RandomString(length));
//         boost::scoped_array<char>content_data(new char[length]);
//         for (size_t i = 0; i < length; ++i)
//           content_data[i] = plain_text[i];
//
//         {
//           SelfEncryptor selfenc(data_map, chunk_store);
//           EXPECT_TRUE(selfenc.Write(content_data.get(), length, position));
//         }
//
//         boost::scoped_array<char>answer(new char[length]);
//         {
//           SelfEncryptor selfenc(data_map, chunk_store);
//           EXPECT_TRUE(selfenc.Read(answer.get(), length, position));
//         }
//
//         for (size_t i = 0; i < length; ++i)
//           ASSERT_EQ(content_data[i], answer[i])
//               << "not match " << i << std::endl;
//       }
//     }
//   }
//
//   // The situation combining in-process and out-process access may need to
//   // be considered
// }

TEST(SelfEncryptionTest, BEH_NewRead) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  uint32_t size = 1024 * 256 * 10;    // 10 chunks
  uint64_t position = 0;
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff1(new char[size]);
  std::copy(content.c_str(), content.c_str() + size, stuff1.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff1.get(), size));
    EXPECT_EQ(10, selfenc.data_map()->chunks.size());
    EXPECT_EQ(size - (1024 * 256 * 2), selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  boost::scoped_array<char> answer(new char[size]);
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i) {
    if (stuff1[static_cast<size_t>(position + i)] != answer[i])
    DLOG(INFO) << "stuff1[" << i << "] = " << stuff1[i] << "   answer["
               << i << "] = " << answer[i];
  }
  // read next small part straight from cache
  position += 4096;
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i) {
    if (stuff1[static_cast<size_t>(position + i)] != answer[i])
    DLOG(INFO) << "stuff1[" << i << "] = " << stuff1[i] << "   answer["
               << i << "] = " << answer[i];
  }
  // try to read from end of cache, but request more data than remains
  // will result in cache being refreshed
  position += (1024 * 256 * 8 - 1000);
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i) {
    if (stuff1[static_cast<size_t>(position + i)] != answer[i])
    DLOG(INFO) << "stuff1[" << i << "] = " << stuff1[i] << "   answer["
               << i << "] = " << answer[i];
  }
  // try to read startish of file, no longer in cache
  position = 5;
  EXPECT_TRUE(selfenc.Read(answer.get(), 4096, position));
  for (int i = 0; i < 4096; ++i) {
    if (stuff1[static_cast<size_t>(position + i)] != answer[i])
    DLOG(INFO) << "stuff1[" << i << "] = " << stuff1[i] << "   answer["
               << i << "] = " << answer[i];
  }

  // use file smaller than the cache size
  MemoryChunkStorePtr chunk_store2(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map2(new DataMap);
  size = 1024 * 256 * 5;
  std::string content2(RandomString(size));
  boost::scoped_array<char> stuff2(new char[size]);
  std::copy(content2.c_str(), content2.c_str() + size, stuff2.get());
  {
    SelfEncryptor selfenc(data_map2, chunk_store2);
    EXPECT_TRUE(selfenc.Write(stuff2.get(), size));
    EXPECT_EQ(2, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  // try to read the entire file, will not cache.
  SelfEncryptor selfenc2(data_map2, chunk_store2);
  boost::scoped_array<char> answer2(new char[size]);
  EXPECT_TRUE(selfenc2.Read(answer2.get(), size, 0));
  for (uint32_t i = 0; i < size; ++i) {
    if (stuff2[i] != answer2[i])
    DLOG(INFO) << "stuff2[" << i << "] = " << stuff2[i] << "   answer2["
               << i << "] = " << answer2[i];
  }
  // same small file, many small reads, will cache and read from.
  for (int a = 0; a < 10; ++a) {
    EXPECT_TRUE(selfenc2.Read(answer2.get(), 4096, (4096 * a)));
    for (int i = 0; i < 4096; ++i) {
      if (stuff2[i + (4096 * a)] != answer2[i])
      DLOG(INFO) << "stuff2[" << i + (4096 * a) << "] = "
                 << stuff2[i+ (4096 * a)] << "   answer2["
                 << i << "] = " << answer2[i];
    }
  }
}

TEST(SelfEncryptionTest, BEH_1024x3Minus1Chars) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const size_t size(1024*3-1);
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff(new char[size]);
  std::copy(content.c_str(), content.c_str() + size, stuff.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff.get(), size, 0));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(0, selfenc.data_map()->chunks.size());
  EXPECT_EQ(size, selfenc.data_map()->size);
  EXPECT_EQ(size, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_1024x3Plus1Chars) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const size_t size(1024*3+1);
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff(new char[size]);
  std::copy(content.c_str(), content.c_str() + size, stuff.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff.get(), size, 0));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(3, selfenc.data_map()->chunks.size());
  for (size_t i = 0; i != 3; ++i)
    EXPECT_EQ(1024, selfenc.data_map()->chunks[i].size);
  EXPECT_EQ(size, selfenc.data_map()->size);
  EXPECT_EQ(1, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_1024x256x3Minus1Chars) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const size_t size(1024*256*3-1);
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff(new char[size]);
  std::copy(content.c_str(), content.c_str() + size, stuff.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff.get(), size, 0));
    EXPECT_EQ(0, selfenc.data_map()->chunks.size());
    EXPECT_EQ(0, selfenc.data_map()->size);
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(5, selfenc.data_map()->chunks.size());
  EXPECT_EQ(size, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_1024x256x3Plus1Chars) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);

  const size_t size(1024*256*3+1);
  size_t chunks((1 / omp_get_num_procs()) * omp_get_num_procs());
  std::string content(RandomString(size));
  boost::scoped_array<char> stuff(new char[size]);
  std::copy(content.c_str(), content.c_str() + size, stuff.get());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(stuff.get(), size, 0));
    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
    EXPECT_EQ(1024*256*chunks, selfenc.data_map()->size);
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(3, selfenc.data_map()->chunks.size());
  for (size_t i = 0; i != 3; ++i)
    EXPECT_EQ(1024*256, selfenc.data_map()->chunks[i].size);
  EXPECT_EQ(size, selfenc.data_map()->size);
  EXPECT_EQ(1, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_10Chunk4096ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 10 chunks, (1024*256*10+1)...
  // 640, 4096 byte parts...
  const size_t parts(640), size(4096);
  size_t chunks((8 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  char *content(new char[1]);
  content[0] = 'a';
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content, 1, 1024*256*10));
    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
    EXPECT_EQ(1024*256*chunks, selfenc.data_map()->size);
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10+1, selfenc.data_map()->size);
  EXPECT_EQ(1, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_12Chunk4096ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 639, 4096 byte parts...
  const size_t parts(639), size(4096);
  size_t chunks((10 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(4095));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.c_str(), content.size(), parts * size));
    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
    EXPECT_EQ(1024*256*chunks, selfenc.data_map()->size);
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(12, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_10Chunk65536ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 10 chunks, (1024*256*10+1)...
  // 40, 65536 byte parts...
  const size_t parts(40), size(65536);
  size_t chunks((8 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  char *content(new char[1]);
  content[0] = 'a';
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content, 1, 1024*256*10));
    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
    EXPECT_EQ(1024*256*chunks, selfenc.data_map()->size);
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(10, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10+1, selfenc.data_map()->size);
  EXPECT_EQ(1, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_12Chunk65536ByteOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 39, 65536 byte parts...
  const size_t parts(39), size(65536);
  size_t chunks((10 / omp_get_num_procs()) * omp_get_num_procs());
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(65535));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.c_str(), content.size(), parts * size));
    EXPECT_EQ(2 + chunks, selfenc.data_map()->chunks.size());
    EXPECT_EQ(1024*256*chunks, selfenc.data_map()->size);
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(12, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_12Chunk4096ByteOutOfSequenceWritesWithGap) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 639, 4096 byte parts...
  const size_t parts(639), size(4096);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(4095));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 300; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    for (size_t i = 301; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.c_str(), content.size(), parts * size));
    // Unknown number of chunks and data map size...
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(12, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_12Chunk65536ByteOutOfSequenceWritesWithGaps) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  // 12 chunks, (1024*256*10-1)...
  // 39, 65536 byte parts...
  const size_t parts(39), size(65536);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  std::string content(RandomString(65535));
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(size);
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 5; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    for (size_t i = 6; i != 34; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    for (size_t i = 35; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(), size,
                                index_array[i] * size));
    EXPECT_TRUE(selfenc.Write(content.c_str(), content.size(), parts * size));
    // Unknown number of chunks and data map size...
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  SelfEncryptor selfenc(data_map, chunk_store);
  // Check data_map values again after destruction...
  EXPECT_EQ(12, selfenc.data_map()->chunks.size());
  EXPECT_EQ(1024*256*10-1, selfenc.data_map()->size);
  EXPECT_EQ(0, selfenc.data_map()->content_size);
}

TEST(SelfEncryptionTest, BEH_RandomSizedOutOfSequenceWrites) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const size_t parts(500);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(RandomUint32() % ((1 << 18) + 1));
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(),
                        string_array[index_array[i]].size(),
                        index_array[i] * string_array[index_array[i]].size()));
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  // Unknown number of chunks and content details.
}

TEST(SelfEncryptionTest, BEH_RandomSizedOutOfSequenceWritesWithGaps) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  const size_t parts(500);
  std::array<std::string, parts> string_array;
  std::array<size_t, parts> index_array;
  for (size_t i = 0; i != parts; ++i) {
    string_array[i] = RandomString(RandomUint32() % ((1 << 18) + 1));
    index_array[i] = i;
  }
  std::random_shuffle(index_array.begin(), index_array.end());
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    for (size_t i = 0; i != 101; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(),
                        string_array[index_array[i]].size(),
                        index_array[i] * string_array[index_array[i]].size()));
    for (size_t i = 102; i != 233; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(),
                        string_array[index_array[i]].size(),
                        index_array[i] * string_array[index_array[i]].size()));
    for (size_t i = 234; i != parts; ++i)
      EXPECT_TRUE(selfenc.Write(string_array[index_array[i]].c_str(),
                        string_array[index_array[i]].size(),
                        index_array[i] * string_array[index_array[i]].size()));
    // No content yet...
    EXPECT_EQ(0, selfenc.data_map()->content_size);
  }
  // Unknown number of chunks and content details.
}

TEST(SelfEncryptionManualTest, BEH_manual_check_write) {
  MemoryChunkStorePtr chunk_store(new MemoryChunkStore(false, g_hash_func));
  DataMapPtr data_map(new DataMap);
  uint32_t chunk_size(1024 * 256);  // system default
  uint32_t num_chunks(10);
  boost::scoped_array<char> extra_content(new char[5]);
  for (char i = 0; i != 5; ++i)
    extra_content[i] = 49 + i;
  uint32_t expected_content_size(sizeof(extra_content));
  uint32_t file_size((chunk_size * num_chunks) + expected_content_size);
  boost::scoped_array<byte> pre_enc_chunk(new byte[chunk_size]);
  boost::scoped_array<byte>pad(new byte[(3 * crypto::SHA512::DIGESTSIZE) -
      crypto::AES256_KeySize - crypto::AES256_IVSize]);
  boost::scoped_array<byte>xor_res(new byte[chunk_size]);
  boost::scoped_array<byte>prehash(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::scoped_array<byte>posthashxor(new byte[crypto::SHA512::DIGESTSIZE]);
  boost::scoped_array<byte>postenc(new byte[chunk_size]);
  boost::scoped_array<byte>key(new byte[32]);
  boost::scoped_array<byte>iv(new byte[crypto::AES256_IVSize]);
  boost::scoped_array<char>pre_enc_file(new char[file_size]);

  for (size_t i = 0; i < chunk_size; ++i) {
    pre_enc_chunk[i] = 'a';
  }

  for (size_t i = 0; i < file_size; ++i) {
     pre_enc_file[i] = 'a';
  }
  {
    SelfEncryptor selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(pre_enc_file.get(), file_size));
  }
// Do some testing on results
  SelfEncryptor selfenc(data_map, chunk_store);
  EXPECT_EQ(num_chunks,  selfenc.data_map()->chunks.size());
  EXPECT_EQ(expected_content_size,  selfenc.data_map()->content_size);
  EXPECT_EQ(file_size, selfenc.data_map()->size);

  CryptoPP::SHA512().CalculateDigest(prehash.get(), pre_enc_chunk.get(),
                                     chunk_size);

  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    pad[i] = prehash[i];
    pad[i + crypto::SHA512::DIGESTSIZE] = prehash[i];
  }
  for (int i = 0; i != crypto::AES256_IVSize; ++i) {
    pad[i + (2 * crypto::SHA512::DIGESTSIZE)] =
        prehash[i + crypto::AES256_KeySize + crypto::AES256_IVSize];
  }

  std::copy(prehash.get(), prehash.get() + crypto::AES256_KeySize, key.get());
  std::copy(prehash.get() + crypto::AES256_KeySize,
            prehash.get() + crypto::AES256_KeySize + crypto::AES256_IVSize,
            iv.get());

  CryptoPP::Gzip compress(new CryptoPP::MessageQueue(), 6);
  compress.Put2(pre_enc_chunk.get(), chunk_size, -1, true);

  size_t compressed_size(static_cast<size_t>(compress.MaxRetrievable()));

  boost::shared_array<byte> comp_data(new byte[compressed_size]);
  compress.Get(comp_data.get(), compressed_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc(key.get(),
                                                    crypto::AES256_KeySize,
                                                    iv.get());
  enc.ProcessData(postenc.get(), comp_data.get(), compressed_size);

  for (size_t i = 0; i < compressed_size; ++i) {
    xor_res[i] =
        postenc[i] ^ pad[i % ((3 * crypto::SHA512::DIGESTSIZE) -
                              crypto::AES256_KeySize - crypto::AES256_IVSize)];
  }

  CryptoPP::SHA512().CalculateDigest(posthashxor.get(),
                                     xor_res.get(),
                                     compressed_size);

  for (int i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    ASSERT_EQ(prehash[i], selfenc.data_map()->chunks[0].pre_hash[i])
      << "failed at chunk 0 pre hash " << i;
    ASSERT_EQ(prehash[i], selfenc.data_map()->chunks[1].pre_hash[i])
      << "failed at chunk 1 pre hash " << i;
    ASSERT_EQ(prehash[i], selfenc.data_map()->chunks[2].pre_hash[i])
      << "failed at chunk 2 pre hash " << i;
      // TODO(dirvine) uncomment these and fix
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.data_map()->chunks[0].hash[i]))
      << "failed at chunk 0 post hash : " << i;
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.data_map()->chunks[1].hash[i]))
    << "failed at chunk 1 post hash : " << i;
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.data_map()->chunks[2].hash[i]))
    << "failed at chunk 2 post hash : " << i;
  }
  // check chunks' hashes - should be equal for repeated single character input
  bool match(true);
  for (size_t i = 0; i < selfenc.data_map()->chunks.size(); ++i) {
    for (size_t j = i; j < selfenc.data_map()->chunks.size(); ++j) {
      for (int k = 0; k < crypto::SHA512::DIGESTSIZE; ++k) {
        if (selfenc.data_map()->chunks[i].hash[k] !=
                selfenc.data_map()->chunks[j].hash[k])
          match = false;
      }
      EXPECT_TRUE(match);
      match = true;
    }
  }
}


}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe
