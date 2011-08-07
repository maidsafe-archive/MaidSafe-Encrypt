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

#include <omp.h>
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
  byte buffer[length];
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
      main_encrypt_queue_.Get(i, sizeof(i));
      data_map_.content = reinterpret_cast<const char *>(i);
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
    data_map_.content = {};
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

bool SE::Write(const char* data, size_t length, size_t position) {

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
    if (!EncryptChunkFromQueue(chunk_current_queue_))
      return false;
  }
  return true;
}

void SE::HashMe(byte * digest, byte* data, size_t length) {
  CryptoPP::SHA512().CalculateDigest(digest, data, length);
}

void SE::getPad_Iv_Key(size_t chunk_num,
                       byte * key,
                       byte * iv,
                       byte * pad)
{
  size_t num_chunks = data_map_.chunks.size();
  size_t this_chunk_num = num_chunks;
  size_t n_1_chunk = (this_chunk_num + num_chunks -1) % num_chunks;
  size_t n_2_chunk = (this_chunk_num + num_chunks -2) % num_chunks;
  for (int i = 0; i < 48; ++i) {
    if (i < 32)
      key[i] = data_map_.chunks[n_1_chunk].pre_hash[i];
    if (i > 31)
      iv[i - 32] = data_map_.chunks[n_1_chunk].pre_hash[i];
  }

  for (int i = 0; i < 64; ++i) {
    pad[i] =  data_map_.chunks[n_1_chunk].pre_hash[i];
    pad[i+64] = data_map_.chunks[chunk_num].pre_hash[i];
    if (i < 16)
      pad[i+128] = data_map_.chunks[n_2_chunk].pre_hash[i+48];
  }
}

bool SE::EncryptChunkFromQueue(CryptoPP::MessageQueue & queue) {
  ChunkDetails2 chunk_details;
  size_t num_chunks = data_map_.chunks.size();
  size_t this_chunk_num = num_chunks;
//   boost::shared_array<byte> obfuscation_pad;
  byte * obfuscation_pad = new byte[144];
  byte *key = new byte[32];
  byte *iv = new byte[16];
  byte hash[CryptoPP::SHA512::DIGESTSIZE];
  if ((&queue != &chunk0_queue_) && (&queue != &chunk1_queue_)) {
    byte temp[chunk_size_];
    queue.Peek(temp, sizeof(temp)); // copy whole array
    HashMe(chunk_details.pre_hash, temp, sizeof(temp));
    chunk_details.pre_size = chunk_size_;
    this_chunk_size_ = chunk_size_;
    data_map_.chunks.push_back(chunk_details);
  } else {
    this_chunk_size_ = c0_and_1_chunk_size_;
    if (&queue == &chunk0_queue_)
    this_chunk_num = 0;
    if (&queue == &chunk1_queue_)
    this_chunk_num = 1;
  }

  getPad_Iv_Key(this_chunk_num, key, iv, obfuscation_pad);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key, 32, iv);
  CryptoPP::StreamTransformationFilter aes_filter(encryptor,
                  new XORFilter(
                    new CryptoPP::HashFilter(hash_,
                      new CryptoPP::MessageQueue()
                    , true)
                  , obfuscation_pad));

  queue.TransferAllTo(aes_filter);
  aes_filter.MessageEnd(-1, true);

  byte chunk_content[this_chunk_size_]; // do not move this !!
  aes_filter.Get(chunk_content, this_chunk_size_); // get content
  aes_filter.Get(data_map_.chunks[this_chunk_num].hash , 64);
  std::string post_hash = reinterpret_cast<char *>(data_map_.chunks[this_chunk_num].hash);
  std::string data(reinterpret_cast<char *>(chunk_content), this_chunk_size_);
  if (! chunk_store_->Store(post_hash, data))
    DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash)
                                      << std::endl;
  data_map_.chunks[this_chunk_num].size = this_chunk_size_;
  data_map_.size += this_chunk_size_;
  return true;
}

bool SE::Read(char* data, size_t length, size_t position) {

   if ((data_map_.size > (length + position)) && (length != 0))
     return false;

   // find start and and chunks
   size_t start_chunk(0), start_offset(0), end_chunk(0), run_total(0);
   
   for(size_t i = 0; i < data_map_.chunks.size(); ++i) {
     if ((data_map_.chunks[i].size + run_total >= position) &&
         (start_chunk = 0)) {
       start_chunk = i;
       start_offset = run_total + data_map_.chunks[i].size -
                      (position - run_total);
       run_total = data_map_.chunks[i].size - start_offset;
     }
     else 
       run_total += data_map_.chunks[i].size;
           // find end (offset handled by return truncated size
     if ((run_total <= length) || (length == 0))
       end_chunk = i;
   }
DLOG(INFO) << std::endl;
DLOG(INFO) << "num chunks " << data_map_.chunks.size()
           << " start chunk " << start_chunk
           << " start offset " << start_offset
           << " end chunk " << end_chunk << std::endl
           << "run total " << run_total
           << " Dm size " << data_map_.size
           << std::endl;
DLOG(INFO) << std::endl;

   size_t amount_of_extra_content(0);
   if (run_total <  length)
     amount_of_extra_content = length - run_total;
   else
     amount_of_extra_content = data_map_.content_size;
 
   if (end_chunk != 0)
     ++end_chunk;

   std::vector<std::string> plain_text_vec(end_chunk - start_chunk);
#pragma omp parallel for
  for (size_t i = start_chunk;i < end_chunk ; ++i) {
    ReadChunk(i, &plain_text_vec.at(i));
  }
 // build data
  std::string alldata;
  for (auto it = plain_text_vec.begin();it < plain_text_vec.end() ; ++it) {
    alldata += (*it).c_str() ;
  }

  strncpy(data, alldata.c_str(), alldata.size());
  if (data_map_.content_size > 0) {
   strncat(data, data_map_.content.c_str(), amount_of_extra_content);
  }
  return true;
}

bool SE::ReadChunk(size_t chunk_num, std::string *data) {
  if (data_map_.chunks.size() < chunk_num)
    return false;
   std::string hash = reinterpret_cast<char *>(data_map_.chunks[chunk_num].hash);
    if (!chunk_store_->Has(hash)) {
      DLOG(ERROR) << "Could not find chunk: " << EncodeToHex(hash) << std::endl;
      return false;
    }
    byte * pad = new byte[144];
    byte *key = new byte[32];
    byte *iv = new byte[16];
    getPad_Iv_Key(chunk_num, key, iv, pad);
    std::string content(chunk_store_->Get(hash));
    std::string answer;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key, 32, iv);
           CryptoPP::StringSource filter(content, true,
             new XORFilter(
              new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::StringSink(*data)),
              pad));
    delete[] pad; // these should be shared_arrays !!!
    delete[] key;
    delete[] iv;
  return true;
}

}  // namespace encrypt

}  // namespace maidsafe
