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
 *******************************************************************************
 * @file  test_utils.cc
 * @brief Tests for the self-encryption helper functions.
 * @date  2011-04-05
 */

#include <array>
#include <cstdint>
#include <vector>
#include <exception>
#include <algorithm>
#include <functional>
#ifdef WIN32
#  pragma warning(push)
#  pragma warning(disable: 4308)
#endif
#include "boost/archive/text_oarchive.hpp"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#ifdef WIN32
#  pragma warning(pop)
#endif
#include "boost/archive/text_iarchive.hpp"
#include "boost/timer.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encrypt.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/common/memory_chunk_store.h"


namespace maidsafe {

namespace encrypt {


namespace test {


TEST(SelfEncryptionTest, BEH_40Charsonly) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);

  
  std::string content(RandomString(40));
  boost::scoped_array<char>stuff(new char[40]);
  boost::scoped_array<char>answer(new char[40]);
  std::copy(content.data(), content.data() + 40, stuff.get());
{
  SE selfenc(data_map, chunk_store);
  EXPECT_TRUE(selfenc.Write(stuff.get(), 40));
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
  EXPECT_EQ(0, selfenc.getDataMap()->size);
  EXPECT_EQ(0, selfenc.getDataMap()->content_size);
  // read before write - all in queue
  EXPECT_TRUE(selfenc.Read(answer.get(),40));
  EXPECT_EQ(*stuff.get(), *answer.get());
}
  SE selfenc(data_map, chunk_store);
   EXPECT_EQ(40, data_map->size);
   EXPECT_EQ(40, data_map->content_size);
   EXPECT_EQ(0, data_map->chunks.size());
   EXPECT_EQ(*stuff.get(), *data_map->content.c_str());
   EXPECT_TRUE(selfenc.Read(answer.get(),40));
   EXPECT_EQ(*stuff.get(), *answer.get());

}
/*
// This test get passed in Debug mode,
// but will get segmentation fail in Release mode
// The breaking point is : CryptoPP::Put2 being called by SE::Write
//                         in SE::EnptySedquence during destruction
TEST(SelfEncryptionTest, BEH_40CharPlusPadding) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);

  
  std::string content(RandomString(40));
  boost::scoped_array<char>stuff(new char[40]);
  boost::scoped_array<char>answer(new char[80]);
  std::copy(content.data(), content.data() + 40, stuff.get());
{
  SE selfenc(data_map, chunk_store);
  EXPECT_TRUE(selfenc.Write(stuff.get(), 40, 40));
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
  EXPECT_EQ(0, selfenc.getDataMap()->size);
  EXPECT_EQ(0, selfenc.getDataMap()->content_size);
}

  SE selfenc(data_map, chunk_store);
  EXPECT_EQ(80, selfenc.getDataMap()->size);
  EXPECT_EQ(80, selfenc.getDataMap()->content_size);
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
  for( size_t i = 0; i < 40; ++i) {
    EXPECT_TRUE(selfenc.Read(&answer[i], 1, i));
  }
}*/




TEST(SelfEncryptionTest, BEH_1023Chars) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
      (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);


  
  std::string content(RandomString(1023));
  boost::scoped_array<char>stuff1 (new char[1023]);
  std::copy(content.c_str(), content.c_str() + 1023, stuff1.get());
{
  SE selfenc(data_map, chunk_store);
  EXPECT_TRUE(selfenc.Write(stuff1.get(), 1023));
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
  EXPECT_EQ(0, selfenc.getDataMap()->size);
  EXPECT_EQ(0, selfenc.getDataMap()->content_size);
}
  
  EXPECT_EQ(1023, data_map->size);
  EXPECT_EQ(1023, data_map->content_size);
  EXPECT_EQ(0, data_map->chunks.size());
}

TEST(SelfEncryptionTest, BEH_1025Chars3chunks) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);

  
  std::string content(RandomString(1025));
  boost::scoped_array<char>stuff1 (new char[1025]);
  std::copy(content.c_str(), content.c_str() + 1025, stuff1.get());
  {
  SE selfenc(data_map, chunk_store);  
  EXPECT_TRUE(selfenc.Write(stuff1.get(), 1025));
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
  EXPECT_EQ(0, selfenc.getDataMap()->size);
  EXPECT_EQ(0, selfenc.getDataMap()->content_size);
  }
  SE selfenc(data_map, chunk_store); 
  EXPECT_EQ(1025, selfenc.getDataMap()->size);
  EXPECT_EQ(1025, selfenc.getDataMap()->content_size);
  EXPECT_EQ(0, selfenc.getDataMap()->chunks.size());
}

TEST(SelfEncryptionTest, BEH_BenchmarkMemOnly) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  SE selfenc(data_map, chunk_store);
  
  size_t test_data_size(1024*1024*20);
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a';
  }
  // Memory chunkstore
  // Write as complete stream
  boost::posix_time::ptime time =
  boost::posix_time::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Write(plain_data.get(), test_data_size));
  // TODO FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
  std::uint64_t duration =
  (boost::posix_time::microsec_clock::universal_time() -
  time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
  << " in " << (duration / 1000000.0)
  << " seconds at a speed of "
  <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
  << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_Benchmark4kBytes) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  SE selfenc(data_map, chunk_store);
  
  size_t test_data_size(1024*1024*20);
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a';
  }
  // Write in 4kB byte chunks
  size_t fourkB(4096);
  boost::posix_time::ptime time = boost::posix_time::microsec_clock::universal_time();
  for (size_t i = 0; i < test_data_size; i += fourkB)
    ASSERT_TRUE(selfenc.Write(&plain_data[i], fourkB, i));
  // TODO FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
  std::uint64_t duration =  (boost::posix_time::microsec_clock::universal_time() -
  time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
  << " in " << (duration / 1000000.0)
  << " seconds at a speed of "
  <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
  << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_Benchmark64kBytes) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  SE selfenc(data_map, chunk_store);
  size_t test_data_size(1024*1024*20);
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a';
  }
  // Write in 16kB byte chunks
  size_t sixtyfourkB(65536);
  boost::posix_time::ptime time = boost::posix_time::microsec_clock::universal_time();
  for (size_t i = 0; i < test_data_size; i += sixtyfourkB)
    ASSERT_TRUE(selfenc.Write(&plain_data[i], sixtyfourkB, i));
  //   ASSERT_TRUE(selfenc.FinaliseWrite());  // TODO FIXME - wont work till destructor called
  std::uint64_t duration =  (boost::posix_time::microsec_clock::universal_time() -
  time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
  << " in " << (duration / 1000000.0)
  << " seconds at a speed of "
  <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
  << "/s" << std::endl;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadIncompressable) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);


  size_t test_data_size(1024*1024*20 + 4);
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size; ++i) {
    plain_data[i] =/* 'a'; //*/plain_text[i];
  }
{
  SE selfenc(data_map, chunk_store);
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Write(plain_data.get(), test_data_size));
  std::uint64_t duration =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
             << " in " << (duration / 1000000.0)
             << " seconds at a speed of "
             <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
             << "/s" << std::endl;
  boost::scoped_array<char>some_chunks_some_q (new char[test_data_size]);
  ASSERT_TRUE(selfenc.Read(some_chunks_some_q.get(), test_data_size, 0));
  for (size_t  i = 0; i < test_data_size ; ++i)
    ASSERT_EQ(plain_text[i], some_chunks_some_q[i]) << "failed at count " << i;
}
  SE selfenc(data_map, chunk_store);
  boost::scoped_array<char>answer (new char[test_data_size]);
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
  std::uint64_t duration = (boost::posix_time::microsec_clock::universal_time() -
              time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-decrypted " << BytesToBinarySiUnits(test_data_size)
             << " in " << (duration / 1000000.0)
             << " seconds at a speed of "
             <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
             << "/s" << std::endl;

  for (size_t  i = 0; i < test_data_size ; ++i)
    ASSERT_EQ(plain_text[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, BEH_WriteAndReadCompressable) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);

  size_t test_data_size(1024*1024*20 + 36);
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a';
  }
{
  SE selfenc(data_map, chunk_store);
//   EXPECT_TRUE(selfenc.ReInitialise());
  boost::posix_time::ptime time =
  boost::posix_time::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Write(plain_data.get(), test_data_size));
  //   ASSERT_TRUE(selfenc.FinaliseWrite());  // TODO FIXME - wont work till destructor called
  std::uint64_t duration =
  (boost::posix_time::microsec_clock::universal_time() -
  time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-encrypted " << BytesToBinarySiUnits(test_data_size)
  << " in " << (duration / 1000000.0)
  << " seconds at a speed of "
  <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
  << "/s" << std::endl;
}
  SE selfenc(data_map, chunk_store);
  boost::scoped_array<char>answer (new char[test_data_size]);
  boost::posix_time::ptime time =  boost::posix_time::microsec_clock::universal_time();
  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
  std::uint64_t duration = (boost::posix_time::microsec_clock::universal_time() -
  time).total_microseconds();
  if (duration == 0)
    duration = 1;
  std::cout << "Self-decrypted " << BytesToBinarySiUnits(test_data_size)
  << " in " << (duration / 1000000.0)
  << " seconds at a speed of "
  <<  BytesToBinarySiUnits(test_data_size / (duration / 1000000.0) )
  << "/s" << std::endl;
  for (size_t  i = 0; i < test_data_size ; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}


TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATime) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t test_data_size(1024*1024*2); // less than 2 mB fails due to test
  std::string plain_text(SRandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a'; //plain_text[i];
  }
  plain_data[test_data_size] = 'b';
  {
    SE selfenc(data_map, chunk_store);
    //   EXPECT_TRUE(selfenc.ReInitialise());extra = sequencer_.Get(current_position_);
    for (size_t i = 0; i < test_data_size ; ++i)  {
      selfenc.Write(&plain_data[i], 1, i);
    }
  }
  SE selfenc(data_map, chunk_store);
  EXPECT_EQ(test_data_size, data_map->size);
  EXPECT_EQ(0, data_map->content_size);
  EXPECT_EQ(8, data_map->chunks.size());
  boost::scoped_array<char>answer (new char[test_data_size]);
  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size));

//   // check chunks 1 and 2
  for (size_t  i = 0; i < 524288 ; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "c0 or c1 failed at count " << i;
// check all other chunks
  for (size_t  i = 524288; i < test_data_size -1 ; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "normal chunks failed count :" << i;  
}

TEST(SelfEncryptionTest, BEH_WriteAndReadByteAtATimeOutOfSequenceForward) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t test_data_size(1024*20); // less than 2 mB fails due to test
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data  (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = plain_text[i];
  }
  plain_data[test_data_size] = 'a';
  ++test_data_size;
  plain_data[test_data_size] = 'b';

  size_t length = 1;
  {
    SE selfenc(data_map, chunk_store);
  boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
  //   EXPECT_TRUE(selfenc.ReInitialise());
    for (size_t i = 0; i < test_data_size ; i += 2)  {
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    }
  std::uint64_t duration1 =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  std::cout << "even byte_by_byte written taken : " << duration1 << " microseconds" << std::endl;
    for (size_t i = 1; i < test_data_size ; i += 2 )  {
      ASSERT_TRUE(selfenc.Write(&plain_data.get()[i], length, i));
    }
  std::uint64_t duration2 =
      (boost::posix_time::microsec_clock::universal_time() -
       time).total_microseconds();
  std::cout << "odd byte_by_byte written taken : " << duration2 - duration1 << " microseconds" << std::endl;
    //   ASSERT_TRUE(selfenc.FinaliseWrite());  // TODO FIXME - wont work till destructor called
  }
  SE selfenc(data_map, chunk_store);
  boost::scoped_array<char>answer (new char[test_data_size]);

  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));

  for (size_t  i = 0; i < test_data_size ; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_WriteOnceRead20) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t test_data_size(1024*1024);
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = /*'a'; //*/plain_text[i];
  }
  plain_data[test_data_size] = 'b';
  {
    SE selfenc(data_map, chunk_store);
//   EXPECT_TRUE(selfenc.ReInitialise());
    ASSERT_TRUE(selfenc.Write(plain_data.get(), test_data_size));
    //   ASSERT_TRUE(selfenc.FinaliseWrite());  // TODO FIXME - wont work till destructor called
    // check it works at least once
    boost::scoped_array<char>answer (new char[test_data_size]);
    ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
    // In process check !!
    for (int j = 0; j < 20; ++j) {
      boost::scoped_array<char>answer1 (new char[test_data_size]);
      ASSERT_TRUE(selfenc.Read(answer1.get(), test_data_size, 0))
      << "failed at read attempt " << j;
      for (size_t  i = 0; i < test_data_size ; ++i)
        ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
    }
    
  }
  SE selfenc(data_map, chunk_store);
  boost::scoped_array<char>answer (new char[test_data_size]);
  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));

  for (int j = 0; j < 20; ++j) {
    boost::scoped_array<char>answer1 (new char[test_data_size]);
    ASSERT_TRUE(selfenc.Read(answer1.get(), test_data_size, 0))
    << "failed at read attempt " << j;
    for (size_t  i = 0; i < test_data_size ; ++i)
      ASSERT_EQ(plain_data[i], answer1[i]) << "failed at count " << i;
  }
}


TEST(SelfEncryptionTest, BEH_WriteRandomlyAllDirections) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t test_data_size(1024*20);
//   std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);
  std::vector<size_t> vec_data(test_data_size);
  for (size_t i = 0; i < test_data_size ; ++i) {
    plain_data[i] = 'a'; // plain_text[i];
  }
//   plain_data[test_data_size] = 'b';
  for (size_t i = 0; i < test_data_size; ++i) 
    vec_data[i] = i; // vector of seq numbers

  std::random_shuffle(vec_data.begin(), vec_data.end()); // shuffle all about
  {
    SE selfenc(data_map, chunk_store);
    boost::scoped_array<char>answer (new char[test_data_size]);
    for (size_t i = 0; i < test_data_size; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[vec_data[i]], 1, vec_data[i]));
      ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
      ASSERT_EQ(plain_data[i], answer[i]) << "failed in process ";
    }
    // In process check

    ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
    for (size_t  i = 0; i < test_data_size ; ++i)
      ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
  }


//   EXPECT_EQ(8, selfenc.getDataMap()->chunks.size());
  SE selfenc(data_map, chunk_store);
  boost::scoped_array<char>answer (new char[test_data_size]);
  ASSERT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
  for (size_t  i = 0; i < test_data_size ; ++i)
    ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_RepeatedRandomCharReadInProcess) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t chunk_size(1024*256);
  size_t test_data_size(chunk_size * 6);
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);

  for (size_t i = 0; i < test_data_size -1 ; ++i)
    plain_data[i] = plain_text[i];
  ++test_data_size;
  plain_data[test_data_size] = 'b';
  SE selfenc(data_map, chunk_store);
  //check 2 chunk_size
    for (size_t i = 0; i < chunk_size * 2; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }
 
    // read some data - should be in queue
    //Check read From Queue FIXME !!
//     boost::scoped_array<char> testq(new char[chunk_size]);
//     for (size_t i = 0; i < 10 ; ++i) {
// //TODO FIXME - this next line causes segfault (double free error in checked delete)
// //      EXPECT_TRUE(selfenc.Read(testq.get(), 1, i));
// //       EXPECT_EQ(plain_data[i], testq[i]) << "not read " << i << std::endl;
//     }
    
    // next 2
    for (size_t i = chunk_size * 2; i < chunk_size * 4; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

    // Check read from c0 and c1 buffer
    EXPECT_EQ(0, data_map->size);
    EXPECT_EQ(0, data_map->content_size);
    EXPECT_EQ(2, data_map->chunks.size()); // not really but pre_hash is set

    boost::scoped_array<char> testc0(new char[chunk_size]);
    for (size_t i = 0; i < 100 ; ++i) {
      EXPECT_TRUE(selfenc.Read(&testc0[i], 1, i));
      ASSERT_EQ(testc0[i], plain_data[i]) << "not read " << i << std::endl;
    }
 
    
    boost::scoped_array<char> testc1(new char[chunk_size]);
    for (size_t i = 0 ; i <  100 ; ++i) {
      EXPECT_TRUE(selfenc.Read(&testc1[i], 1, i +  chunk_size));
      ASSERT_EQ(testc1[i], plain_data[i  + chunk_size])
      << "not read " << i << std::endl;
    }




    // write  out of sequence (should be in sequencer now
    for (size_t i = chunk_size * 5; i < (chunk_size * 5) + 10; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }
  
  

    // Check read from Sequencer
    boost::scoped_array<char> testseq(new char[chunk_size]);
    for (size_t i = 0; i < 10 ; ++i) {
      EXPECT_TRUE(selfenc.Read(&testseq[i], 1, i));
      ASSERT_EQ(testseq[i], plain_data[i]) << "not read " << i << std::endl;
    }
    // write second last chunk
   
    for (size_t i = chunk_size * 4; i < chunk_size * 5; i += chunk_size) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }

    for (size_t i = (chunk_size * 5) + 10; i < chunk_size * 6; ++i) {
      EXPECT_TRUE(selfenc.Write(&plain_data[i], 1, i));
    }
  
  // TODO FIXME - wont work till destructor called
//   ASSERT_TRUE(selfenc.FinaliseWrite());
//   // read some data - should be in chunks now
//   boost::scoped_array<char> testchunks(new char[10]);
//   for (size_t i = 0; i < 10 ; ++i) {
//     EXPECT_TRUE(selfenc.Read(testchunks.get(), 1, i));
//     ASSERT_EQ(testchunks.get()[i], plain_data[i]) << "not read " << i << std::endl;
//   }
// 
//   EXPECT_EQ(6,  selfenc.getDataMap()->chunks.size());
//   EXPECT_EQ(0,  selfenc.getDataMap()->content_size);
//   EXPECT_EQ(test_data_size, selfenc.getDataMap()->size);

//   boost::scoped_array<char>answer (new char[test_data_size]);
//   EXPECT_TRUE(selfenc.Read(answer.get(), test_data_size, 0));
//   for (size_t  i = 0; i < test_data_size ; ++i)
//     ASSERT_EQ(plain_data[i], answer[i]) << "failed at count " << i;
}

TEST(SelfEncryptionTest, FUNC_ReadArbitaryPosition) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  size_t chunk_size(1024*256);
  size_t test_data_size(chunk_size * 6);
  std::string plain_text(RandomString(test_data_size));
  boost::scoped_array<char>plain_data (new char[test_data_size]);

  std::copy(plain_text.begin(), plain_text.end(), plain_data.get());
  {
    SE selfenc(data_map, chunk_store);
    EXPECT_TRUE(selfenc.Write(plain_data.get(), test_data_size));
  }
  {
    // read some data
    SE selfenc(data_map, chunk_store);
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

TEST(SelfEncryptionManualTest, BEH_RandomAccess) {
  size_t chunk_size(1024 * 256);
  std::vector<size_t> num_of_tries;
  std::vector<size_t> max_variation;
  max_variation.push_back(1024);
  max_variation.push_back(3072);
  max_variation.push_back(chunk_size);
  max_variation.push_back(3 * chunk_size);
  max_variation.push_back(6 * chunk_size);
  num_of_tries.push_back(5);
  num_of_tries.push_back(20);
  num_of_tries.push_back(50);
  num_of_tries.push_back(100);
  num_of_tries.push_back(200);
  // the longest length of data is writing to position 6 * chunk_size with
  // a content length of 6 * chunk_size, make the total to be 12 * chunk_size
  size_t test_data_size(chunk_size * 12);

  {
    // In Process random write/read access
    MemoryChunkStore::HashFunc hash_func
        (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
    std::shared_ptr<MemoryChunkStore> chunk_store
        (new MemoryChunkStore(false, hash_func));
    std::shared_ptr<DataMap> data_map(new DataMap);
    SE selfenc(data_map, chunk_store);

    boost::scoped_array<char>plain_data(new char[test_data_size]);
    // The initialization value of truncated data shall be filled here
    for (size_t i = 0; i < test_data_size; ++i)
      plain_data[i] = '0';

    for (size_t i = 0; i < max_variation.size(); ++i) {
      size_t num_tries = num_of_tries[i];
      size_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        int op_code(RandomUint32() % 2);
        DLOG(INFO) << " op code : " << op_code;

        switch (op_code) {
          case 0: // write
            {
              size_t write_position(RandomUint32() % variation);
              size_t write_length(RandomUint32() % variation);
              DLOG(INFO) << " write_position : " << write_position
                         << " write_length : " << write_length;

              std::string plain_text(RandomString(write_length));
              boost::scoped_array<char>content_data(new char[write_length]);
              for (size_t i = 0; i < write_length; ++i) {
                plain_data[i + write_position] = plain_text[i];
                content_data[i] = plain_text[i];
              }

              SE selfenc(data_map, chunk_store);
              EXPECT_TRUE(selfenc.Write(content_data.get(),
                                        write_length, write_position));
              break;
            }
          case 1: // read
            {
              size_t read_position(RandomUint32() % variation);
              size_t read_length(RandomUint32() % variation);
              boost::scoped_array<char>answer(new char[read_length]);
              DLOG(INFO) << " read_position : " << read_position
                         << " read_length : " << read_length;

              SE selfenc(data_map, chunk_store);
              // The read method shall accept a reading request that exceeds
              // the current data lenth of the encrypt stream.
              // It shall return part of the content or false if the starting
              // read position exceed the data size
              if (read_position < data_map->size) {
                EXPECT_TRUE(selfenc.Read(answer.get(),
                                         read_length, read_position));
                // A return value of num_of_bytes succeeded read is required
                for (size_t i = 0; i < read_length; ++i)
                  ASSERT_EQ(plain_data[read_position + i], answer[i])
                      << "not match " << i << " from " << read_position
                      << " when total data is " << data_map->size << std::endl;
              } else {
                EXPECT_FALSE(selfenc.Read(answer.get(),
                                          read_length, read_position))
                    << " when trying to read " << read_position
                    << " from " << data_map->size << std::endl;
              }
              break;
            }
          default:
            break;
        }
      }
    }
  }

  {
    // Out Process random write/read access
    MemoryChunkStore::HashFunc hash_func
        (std::bind(&crypto::Hash<crypto::SHA512>, std::placeholders::_1));
    std::shared_ptr<MemoryChunkStore> chunk_store
        (new MemoryChunkStore(false, hash_func));
    std::shared_ptr<DataMap> data_map(new DataMap);
    SE selfenc(data_map, chunk_store);

    for (size_t i = 0; i < max_variation.size(); ++i) {
      size_t num_tries = num_of_tries[i];
      size_t variation = max_variation[i];
      for (size_t j = 0; j < num_tries; ++j) {
        size_t position(RandomUint32() % variation);
        size_t length(RandomUint32() % variation);
        DLOG(INFO) << " accesing at postion : " << position
                   << " with data length : " << length;

        std::string plain_text(RandomString(length));
        boost::scoped_array<char>content_data(new char[length]);
        for (size_t i = 0; i < length; ++i)
          content_data[i] = plain_text[i];

        {
          SE selfenc(data_map, chunk_store);
          EXPECT_TRUE(selfenc.Write(content_data.get(), length, position));
        }

        boost::scoped_array<char>answer(new char[length]);
        {
          SE selfenc(data_map, chunk_store);
          EXPECT_TRUE(selfenc.Read(answer.get(), length, position));
        }

        for (size_t i = 0; i < length; ++i)
          ASSERT_EQ(content_data[i], answer[i])
              << "not match " << i << std::endl;
      }
    }
  }

  // The situation combining in-process and out-process access may need to
  // be considered
}

/*
TEST(SelfEncryptionManualTest, BEH_manual_check_write) {
  MemoryChunkStore::HashFunc hash_func(std::bind(&crypto::Hash<crypto::SHA512>,
                                                 std::placeholders::_1));
  std::shared_ptr<MemoryChunkStore> chunk_store
  (new MemoryChunkStore (false, hash_func));
  std::shared_ptr<DataMap> data_map(new DataMap);
  SE selfenc(data_map, chunk_store);
  size_t chunk_size(1024*256); // system default
  size_t num_chunks(10);
  boost::scoped_array<char>extra_content(new char[5]{'1','2','3','4','5'});
  size_t expected_content_size(sizeof(extra_content));
  size_t file_size(chunk_size*num_chunks + expected_content_size);
  boost::scoped_array<byte> pre_enc_chunk(new byte[chunk_size]);
  boost::scoped_array<byte>pad(new byte[144]);
  boost::scoped_array<byte>xor_res(new byte[chunk_size]);
  boost::scoped_array<byte>prehash(new byte[CryptoPP::SHA512::DIGESTSIZE]);
  boost::scoped_array<byte>posthashxor(new byte[CryptoPP::SHA512::DIGESTSIZE]);
  boost::scoped_array<byte>postenc(new byte[chunk_size]);
  boost::scoped_array<byte>key(new byte[32]);
  boost::scoped_array<byte>iv(new byte[16]);
  boost::scoped_array<char>pre_enc_file(new char[file_size]);

  for (size_t i = 0; i < chunk_size; ++i ) {
    pre_enc_chunk[i] = 'a';   
  }

  for (size_t i = 0; i < file_size; ++i) {
     pre_enc_file[i] = 'a';
  }

  EXPECT_TRUE(selfenc.Write(pre_enc_file.get(), file_size));
  
// Do some testing on results
  EXPECT_EQ(num_chunks,  selfenc.getDataMap()->chunks.size());
  EXPECT_EQ(expected_content_size,  selfenc.getDataMap()->content_size);
  EXPECT_EQ(file_size, selfenc.getDataMap()->size);

  CryptoPP::SHA512().CalculateDigest(prehash.get(), pre_enc_chunk.get(),
                                     chunk_size);

  for (int i = 0; i < 64; ++i) {
    pad[i] = prehash[i];
    pad[i+64] = prehash[i];
  }
  for (int i = 0; i < 16; ++i) {
    pad[i+128] = prehash[i+48];
  }
  
  std::copy(prehash.get(), prehash.get() + 32, key.get());
  std::copy(prehash.get() + 32, prehash.get() + 48, iv.get());

  CryptoPP::Gzip compress(new CryptoPP::MessageQueue(), 0);
  compress.Put2(pre_enc_chunk.get(), chunk_size, -1, true);
  
  size_t compressed_size(compress.MaxRetrievable());

  boost::shared_array<byte> comp_data (new byte[compressed_size]);
  compress.Get(comp_data.get(), compressed_size);
  
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc(key.get(), 32, iv.get());
  enc.ProcessData(postenc.get(), comp_data.get(), compressed_size);

  for (size_t i = 0; i < compressed_size; ++i) {
    xor_res[i] = postenc[i]^pad[i%144];
  }

  CryptoPP::SHA512().CalculateDigest(posthashxor.get(),
                                     xor_res.get(),
                                     compressed_size);
  
  for (int i = 0; i < 64; ++i) {
    
    ASSERT_EQ(prehash[i], selfenc.getDataMap()->chunks[0].pre_hash[i])
      << "failed at chunk 0 pre hash " << i;
    ASSERT_EQ(prehash[i], selfenc.getDataMap()->chunks[1].pre_hash[i])
      << "failed at chunk 1 pre hash " << i;
    ASSERT_EQ(prehash[i], selfenc.getDataMap()->chunks[2].pre_hash[i])
      << "failed at chunk 2 pre hash " << i;
      // TODO uncomment these and fix
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.getDataMap()->chunks[0].hash[i]))
      << "failed at chunk 0 post hash : " << i;
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.getDataMap()->chunks[1].hash[i]))
    << "failed at chunk 1 post hash : " << i;
    ASSERT_EQ(posthashxor[i], static_cast<byte>
      (selfenc.getDataMap()->chunks[2].hash[i]))
    << "failed at chunk 2 post hash : " << i;
  }
  // check chunks' hashes - should be equal for repeated single character input
  bool match(true);
  for (size_t i = 0; i < selfenc.getDataMap()->chunks.size(); ++i) {
    for (size_t j = i; j < selfenc.getDataMap()->chunks.size(); ++j) {
      for (int k = 0; k < CryptoPP::SHA512::DIGESTSIZE ; ++k) {
        if (selfenc.getDataMap()->chunks[i].hash[k] !=
                selfenc.getDataMap()->chunks[j].hash[k])
          match = false;
      }
      EXPECT_TRUE(match);
      match = true;
    }
  }
}
*/

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
