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
#include "boost/shared_array.hpp"
#include "boost/thread.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/scoped_array.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"

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
  if ((length == 0))
    return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);
  size_t buffer_size(length);
  byte buffer[length+1];

  for (size_t i = 0; i < length; ++i) {
    buffer[i] = inString[i] ^  pad_[count_%144];
    ++count_;
  }
  return AttachedTransformation()->Put2(buffer,
                                        length,
                                        messageEnd,
                                        blocking);
}

bool SE::FinaliseWrite() {
  while (main_encrypt_queue_.TotalBytesRetrievable() < chunk_size_ * 3) {
    chunk_size_ = (main_encrypt_queue_.TotalBytesRetrievable()) / 3;
    // small files direct to data map
    if ((chunk_size_ +1) *3 < 1025) {
      size_t qlength = main_encrypt_queue_.TotalBytesRetrievable();
      byte i[qlength];
      main_encrypt_queue_.Get(data_map_.content, sizeof(i));
      data_map_.content_size = qlength;
      data_map_.size += qlength;
      if (chunk0_queue_.AnyRetrievable()) {
        EncryptChunkFromQueue(chunk0_queue_);
        EncryptChunkFromQueue(chunk1_queue_);
        chunk_one_two_q_full_ = false;
      }
      main_encrypt_queue_.SkipAll();
      return true;
    }
    Write();
  }
      if (chunk0_queue_.AnyRetrievable()) {
        EncryptChunkFromQueue(chunk0_queue_);
        EncryptChunkFromQueue(chunk1_queue_);
        chunk_one_two_q_full_ = false;
      }
  return true;
}

bool SE::ReInitialise() {
    chunk_size_ = 1024*256;
    main_encrypt_queue_.SkipAll();
    chunk0_queue_.SkipAll();
    chunk1_queue_.SkipAll();
    chunk_one_two_q_full_ = false;
    data_map_.chunks.clear();
    data_map_.size = 0;
    data_map_.content = {0};
    data_map_.content_size = 0;
    return true;
}

bool SE::QueueC1AndC2() {
  c0_and_1_chunk_size_ = chunk_size_;
  // Chunk 1
  main_encrypt_queue_.TransferTo(chunk0_queue_, chunk_size_);
  chunk0_queue_.MessageEnd();
//   main_encrypt_queue_.MessageEnd();
  ChunkDetails2 chunk_data;
  byte temp[chunk_size_];
  chunk0_queue_.Peek(temp, sizeof(temp));
  CryptoPP::SHA512().CalculateDigest(chunk_data.pre_hash,
                                     temp,
                                     sizeof(temp));
  chunk_data.pre_size = chunk_size_;
  data_map_.chunks.push_back(chunk_data);

  // Chunk 2
  main_encrypt_queue_.TransferTo(chunk1_queue_, chunk_size_);
  chunk1_queue_.MessageEnd();
//   main_encrypt_queue_.MessageEnd();
  ChunkDetails2 chunk_data2;
  byte temp2[chunk_size_];
  chunk1_queue_.Peek(temp2, sizeof(temp2));
  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
                                     temp2 ,
                                     sizeof(temp2));
  chunk_data2.pre_size = chunk_size_;
  data_map_.chunks.push_back(chunk_data);
  chunk_one_two_q_full_ = true;
  return chunk_one_two_q_full_;
}

bool SE::Write(const char* data, size_t length) {

  if (length != 0)
    main_encrypt_queue_.Put2(const_cast<byte*>
                           (reinterpret_cast<const byte*>(data)),
                            length, -1, true);

    // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
  if (!chunk_one_two_q_full_) {  // for speed
    if (main_encrypt_queue_.MaxRetrievable() >= chunk_size_ * 3)
       QueueC1AndC2();
    else
      return true;  // not enough to process chunks yet
  }

  while (main_encrypt_queue_.MaxRetrievable() >= chunk_size_) {
    main_encrypt_queue_.TransferTo(chunk_current_queue_ , chunk_size_);
    EncryptChunkFromQueue(chunk_current_queue_);
  }
  return true;
}

void SE::HashMe(byte * digest, byte* data, size_t length) {
  CryptoPP::SHA512().CalculateDigest(digest, data, length);
}

bool SE::EncryptChunkFromQueue(CryptoPP::MessageQueue & queue) {
  ChunkDetails2 chunk_details;
  size_t num_chunks = data_map_.chunks.size();
  size_t this_chunk_num = num_chunks;
  size_t n_1_chunk = (this_chunk_num + num_chunks -1) % num_chunks;
  size_t n_2_chunk = (this_chunk_num + num_chunks -2) % num_chunks;
  boost::shared_array<byte> obfuscation_pad;
  obfuscation_pad = boost::shared_array<byte>(new byte[144]);
  byte key[32];
  byte iv[16];
  byte hash[CryptoPP::SHA512::DIGESTSIZE];
  
  if ((&queue != &chunk0_queue_) && (&queue != &chunk1_queue_)) {
    byte temp[chunk_size_];
    queue.Peek(temp, sizeof(temp));
    // FIXME thread this to half time taken for encrypt
    
    HashMe(chunk_details.pre_hash, temp, sizeof(temp));
    chunk_details.pre_size = chunk_size_;
    this_chunk_size_ = chunk_size_;
  } else {
    this_chunk_size_ = c0_and_1_chunk_size_;
    if (&queue == &chunk0_queue_)
    this_chunk_num = 0;
    if (&queue == &chunk1_queue_)
    this_chunk_num = 1;
  }
  
  for (int i = 0; i < 48; ++i) {
    if (i < 32)
      key[i] = data_map_.chunks[n_1_chunk].pre_hash[i];
    if (i > 31)
      iv[i - 32] = data_map_.chunks[n_1_chunk].pre_hash[i];
  }

  for (int i = 0; i < 64; ++i) {
    obfuscation_pad[i] =
        data_map_.chunks[n_1_chunk].pre_hash[i];
      if (&queue == &chunk0_queue_)
        obfuscation_pad[i+64] =  data_map_.chunks[0].pre_hash[i];
      else if (&queue == &chunk1_queue_)
        obfuscation_pad[i+64] =  data_map_.chunks[1].pre_hash[i];
      else
        obfuscation_pad[i+64] =  chunk_details.pre_hash[i];
    if (i < 16)
      obfuscation_pad[i+128] =
          data_map_.chunks[(this_chunk_num + num_chunks -2) % num_chunks].pre_hash[i+48];
  }

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key, 32, iv);
  
  CryptoPP::StreamTransformationFilter aes_filter(encryptor,
                  new XORFilter(
                    new CryptoPP::HashFilter(hash_,
                      new CryptoPP::MessageQueue()
                    , true)
                  , obfuscation_pad.get()));

  queue.TransferAllTo(aes_filter);
  aes_filter.MessageEnd(-1, true);

  // chunk = chunk content
  byte chunk[this_chunk_size_]; // do not move this !!
  aes_filter.Get(chunk, sizeof(chunk)); // get content
  
  if (&queue == &chunk0_queue_) {
      aes_filter.Get(data_map_.chunks[0].hash , sizeof(hash));
      data_map_.chunks[0].size = this_chunk_size_;
  } else if (&queue == &chunk1_queue_) {
      aes_filter.Get(data_map_.chunks[1].hash , sizeof(hash));
      data_map_.chunks[1].size = this_chunk_size_;
  } else {
    aes_filter.Get(chunk_details.hash, sizeof(hash));
    chunk_details.size = this_chunk_size_;
    data_map_.chunks.push_back(chunk_details);
  }
// alter data_store to store as bytes
  std::string content(reinterpret_cast<char const*>(chunk));
  std::string post_hash;
  
//   for (int i=0;i<64;++i)
//     post_hash += static_cast<char>(chunk_details.hash[i]);

//    std::cout << "post hash " << EncodeToHex(post_hash) << std::endl;
  chunk_store_->Store(post_hash, content);
  data_map_.size += this_chunk_size_;
  return true;
}

bool SE::Read(char* data) {

  auto itr = data_map_.chunks.end();
  byte *N_pre_hash = (*itr).pre_hash;
  --itr;
  byte *N_1_pre_hash = (*itr).pre_hash;
  --itr;
  byte *N_2_pre_hash = (*itr).pre_hash;

  for (auto it = data_map_.chunks.begin(); it != data_map_.chunks.end(); ++it) {
    byte *pre_hash = (*it).pre_hash;
    byte obfuscation_pad[144];
  for (int i = 0; i < 64; ++i) {
    obfuscation_pad[i] = N_pre_hash[i];
    obfuscation_pad[i+64] =  N_1_pre_hash[i];
    if (i < 16)
      obfuscation_pad[i+128] = N_2_pre_hash[i+48];
   }
 
    byte key[32];
    byte iv[16];
    std::copy(N_2_pre_hash, N_2_pre_hash + 32, key);
    std::copy(N_2_pre_hash + 32, N_2_pre_hash + 48, iv);
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key, 32, iv);
    XORFilter xor_filter(
              new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::MessageQueue),
              obfuscation_pad);

     std::string hash = reinterpret_cast<const char*>((*it).hash);


   if (!chunk_store_->Has(hash))
     return false;
    
    std::string content(chunk_store_->Get(hash));
    byte content_bytes[content.size()];
    byte answer_bytes[content.size()];
    std::copy(content.begin(), content.end(), content_bytes);
    xor_filter.Put(content_bytes, content.size());
    xor_filter.MessageEnd(-1, true);
    
    xor_filter.Get(answer_bytes, content.size());
    strcat(data, reinterpret_cast<const char*>(answer_bytes));

    
    N_2_pre_hash = N_1_pre_hash;
    N_1_pre_hash = pre_hash;
  }
//   if (data_map_.content_size > 0) {
//   strcat(data, reinterpret_cast<const char*>(data_map_.content));
//   }
  return true;
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
