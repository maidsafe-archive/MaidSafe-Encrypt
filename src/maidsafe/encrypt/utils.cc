/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  utils.cc
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 */

#include "maidsafe/encrypt/utils.h"

#include <algorithm>
#include <set>
#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4702)
#endif

#include "cryptopp/gzip.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/channels.h"
#include "cryptopp/mqueue.h"

#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/filesystem/fstream.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {
/**
 * Implementation of XOR transformation filter to allow pipe-lining
 *
 */
size_t XORFilter::Put2(const byte* inString,
                      size_t length,
                      int messageEnd,
                      bool blocking) {
  // Anything to process for us? If not, we will pass it on
  // to the lower filter just in case
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);
//   if((pad_length_ == 0))
//     throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT,
//                               "XORFilter zero length PAD passed");

  size_t buffer_size(length);
  // Do XOR

  byte *buffer = new byte[length];

  for (size_t i = 0; i <= length; ++i) {
     buffer[i] = inString[i] ^ pad_[i%144]; // don't overrun the pad
   }

  return AttachedTransformation()->Put2(buffer,
                                        length,
                                        messageEnd,
                                        blocking );
}

/**
 * Implementation of an AES transformation filter to allow pipe-lining
 * This can be done with cfb - do not change cypher without reading a lot !
 */
size_t AESFilter::Put2(const byte* inString,
                      size_t length,
                      int messageEnd,
                      bool blocking) {
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);

    byte *out_string = new byte[length];
  if (encrypt_) {
  // Encryptor object
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key_,
    32, iv_);
    encryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  } else {
  //decryptor object
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(this->key_,
    32, this->iv_);
     decryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  }
  return AttachedTransformation()->Put2(out_string,
                                         length,
                                         messageEnd,
                                         blocking);
};

bool SE::FinaliseWrite()
{
  while (main_encrypt_queue_.TotalBytesRetrievable() < chunk_size_ * 3) {
    chunk_size_ = (main_encrypt_queue_.TotalBytesRetrievable()) / 3;
    // small files direct to data map
    if (chunk_size_ *3 < 1025) {
      size_t qlength = main_encrypt_queue_.TotalBytesRetrievable();     
      byte i[qlength];
      main_encrypt_queue_.Get(data_map_.content, sizeof(i));
      data_map_.content[qlength] = '\0';
      data_map_.content_size = qlength;
      data_map_.size += qlength;
      main_encrypt_queue_.SkipAll();
      return true;
    }
    Write();
  }

  
  return true;
}

bool SE::ReInitialise() {
    chunk_size_ = 1024*256;
    main_encrypt_queue_.SkipAll();
    data_map_.chunks.clear();
    data_map_.size = 0;
}



bool SE::QueueC1AndC2()
{
  // Chunk 1
  main_encrypt_queue_.TransferTo(chunk1_queue_, chunk_size_);
  chunk1_queue_.MessageEnd();
  ChunkDetails2 chunk_data;
  byte temp[chunk_size_];
  chunk1_queue_.Peek(temp, sizeof(temp));
  CryptoPP::SHA512().CalculateDigest(chunk_data.pre_hash,
                                     temp,
                                     sizeof(temp));
  chunk_data.pre_size = chunk_size_;
  data_map_.chunks.push_back(chunk_data);
  
  // Chunk 2
  main_encrypt_queue_.TransferTo(chunk2_queue_, chunk_size_);
  chunk2_queue_.MessageEnd();
  ChunkDetails2 chunk_data2;
  byte temp2[chunk_size_];
  chunk2_queue_.Peek(temp2, sizeof(temp2));
  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
                                     temp2 ,
                                     sizeof(temp2));
  chunk_data2.pre_size = chunk_size_;
  data_map_.chunks.push_back(chunk_data);
  chunk_one_two_q_full_ = true;
  return chunk_one_two_q_full_;
}

bool SE::Write (const char* data, size_t length) {
  if (length > 0)
    main_encrypt_queue_.Put2(const_cast<byte*>
                           (reinterpret_cast<const byte*>(data)),
                            length, -1, true);

    // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
  if (!chunk_one_two_q_full_) { // for speed 
    if (main_encrypt_queue_.MaxRetrievable() >= chunk_size_ * 3) 
      QueueC1AndC2();
    else
      return true; // not enough to process chunks yet 
  }

  while (main_encrypt_queue_.MaxRetrievable() > chunk_size_) {
    main_encrypt_queue_.TransferTo(chunk_current_queue_ , chunk_size_);
    EncryptChunkFromQueue(chunk_current_queue_);
  }
  return true;
}

bool SE::EncryptChunkFromQueue(CryptoPP::MessageQueue & queue) {
    std::string chunk_content;
//     byte obfuscation_pad[144] = {0};
    ChunkDetails2 chunk_details;
          
    auto itr = data_map_.chunks.end();
    --itr;
    byte *N_1_pre_hash = (*itr).pre_hash;
     --itr;
    byte *N_2_pre_hash = (*itr).pre_hash;

// No need to rehash chunks 1 and 2
    if ((&queue != &chunk1_queue_) && (&queue != &chunk2_queue_)) {
      byte temp[chunk_size_];
      chunk1_queue_.Peek(temp, sizeof(temp));
      CryptoPP::SHA512().CalculateDigest(chunk_details.pre_hash,
                                        temp,
                                        sizeof(temp));
      chunk_details.pre_size = chunk_size_;
    }
    // TODO FIXME relace these with CryptoPP::SecByteBlock
    // which guarantees they will be zero'd when freed
    byte *key = new byte[32];
    byte *iv = new byte[16];
    byte * obfuscation_pad = new byte[144];
    
    memset(key, 0 , 32);
    memset(iv, 0, 16);
    memset(obfuscation_pad, 0, 144);
    std::copy(N_1_pre_hash,
              N_1_pre_hash + 32,
              key);
    std::copy(N_1_pre_hash + 32,
              N_1_pre_hash + 48,
              iv);

   for(int i = 0; i < 64; ++i) {
      obfuscation_pad[i] = N_1_pre_hash[i];
    }
    for(int i = 0; i < 64; ++i) {     
      obfuscation_pad[i+64] = chunk_details.pre_hash[i];
    }
   
    for(int i = 0; i < 16; ++i) {
       obfuscation_pad[i+128] = N_2_pre_hash[i+48];
    }

   AESFilter aes_filter(
                     new XORFilter(
                        new CryptoPP::HashFilter(hash_,
                          new CryptoPP::StringSink(chunk_content)
                        , true)
                     , obfuscation_pad)
                 , key , iv, true);

      queue.TransferAllTo(aes_filter);
      aes_filter.MessageEnd();

      byte post_data[chunk_size_];
      // TODO fill in chunk details post_hash

      
      data_map_.chunks.push_back(chunk_details);
      //chunk_store_->Store(hash, post_data);

     delete key;
     delete iv;
     delete obfuscation_pad;

    return true;
}

bool SE::Read(char* data, std::shared_ptr<DataMap2> data_map)
{
  if (!data_map)
    data_map.reset(new DataMap2(data_map_));
  auto itr = data_map->chunks.end();
  --itr;
  byte *N_1_pre_hash = (*itr).pre_hash;
  --itr;
  byte *N_2_pre_hash = (*itr).pre_hash;


  for(auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it) {
    byte *pre_hash = (*it).pre_hash;
    byte obfuscation_pad[144];
    memcpy(obfuscation_pad, N_1_pre_hash, 64);
    memcpy(obfuscation_pad, N_2_pre_hash, 64);

    byte key[32];
    byte iv[16];
    std::copy(N_1_pre_hash, N_1_pre_hash + 32, key);
    std::copy(N_1_pre_hash + 32, N_1_pre_hash + 48, iv);

    XORFilter xor_filter(
            new AESFilter(
                new CryptoPP::ArraySink(reinterpret_cast< byte* >(data),
                                        data_map->size),
                key, iv, false),
            obfuscation_pad);

    std::string hash(reinterpret_cast< char const* >((*it).hash),
                     sizeof((*it).hash));
    std::string content(chunk_store_->Get(hash));
    byte content_bytes[content.size()];
    std::copy(content.begin(), content.end(), content_bytes);
    xor_filter.Put(content_bytes, content.size());

    N_2_pre_hash = N_1_pre_hash;
    N_1_pre_hash = pre_hash;
  }
}

bool SE::PartialRead(char * data, size_t position, size_t length,
                     std::shared_ptr<DataMap2> data_map) {
//   if (!data_map)
//     data_map.reset(new DataMap2(data_map_));
//   size_t itr_position(0);
//   size_t bytes_read(0);
//   size_t chunk_size(256 * 1024);
// 
//   auto itr = data_map->chunks.end();
//   --itr;
//   byte *N_1_pre_hash = (*itr).pre_hash;
//   --itr;
//   byte *N_2_pre_hash = (*itr).pre_hash;
// 
//   Anchor anchor;
//   bool start_read(false);
//   bool read_finished(false);
// 
//   auto it = data_map->chunks.begin();
//   auto it_end = data_map->chunks.end();
// 
//   while ((it != it_end) && (!read_finished)) {
//     byte *pre_hash = (*it).pre_hash;
// 
//     if (!start_read) {
//       if ((itr_position + chunk_size) >= position) {
//         start_read = true;
//       }
//     } else {
//       if (itr_position >= (position + length)) {
//         read_finished = true;
//       } else {
//         byte obfuscation_pad[128];
//         memcpy(obfuscation_pad, N_1_pre_hash, 64);
//         memcpy(obfuscation_pad, N_2_pre_hash, 64);
// 
//         byte key[32];
//         byte iv[16];
//         std::copy(N_1_pre_hash, N_1_pre_hash + 32, key);
//         std::copy(N_1_pre_hash + 32, N_1_pre_hash + 48, iv);
// 
//         anchor.Attach(new XORFilter(
//                 new AESFilter(
//                     new CryptoPP::ArraySink(reinterpret_cast< byte* >(data),
//                                             length),
//                     key, iv, false),
//                 obfuscation_pad));
// 
//         std::string hash(reinterpret_cast< char const* >((*it).hash),
//                         sizeof((*it).hash));
//         std::string content(chunk_store_->Get(hash));
//         byte content_bytes[content.size()];
//         std::copy(content.begin(), content.end(), content_bytes);
// 
//         size_t start = itr_position >= position ? 0 : itr_position - position;
//         start = start % chunk_size;
//         size_t end = (itr_position + (*it).pre_size) < (position + length) ?
//                         (*it).size : (position + length) - itr_position;
//         end = end % chunk_size;
//         size_t size = end - start + 1;
//         byte sub_content_bytes[size];
//         std::copy(content_bytes + start, content_bytes + end,
//                   sub_content_bytes);
// 
//         anchor.Put(sub_content_bytes, size);
// 
//         anchor.Detach();
//       }
//     }
// 
//     N_2_pre_hash = N_1_pre_hash;
//     N_1_pre_hash = pre_hash;
//     itr_position += (*it).pre_size;
//     ++it;
//   }
}



}  // namespace encrypt

}  // namespace maidsafe
