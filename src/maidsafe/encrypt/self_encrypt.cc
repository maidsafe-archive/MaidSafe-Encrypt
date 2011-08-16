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

#include "maidsafe/encrypt/self_encrypt.h"

#include <algorithm>
#include <set>
#include <tuple>
#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4702)
#endif

// #include <omp.h>
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
  boost::scoped_array<byte> buffer(new byte[length]);
// #pragme omp parallel for 
  for (size_t i = 0; i < length; ++i) {
    buffer[i] = inString[i] ^  pad_[count_%144];
    ++count_;
  }
  return AttachedTransformation()->Put2(buffer.get(),
                                       length,
                                        messageEnd,
                                        blocking);
}

bool SE::IncRepeat(const char* data, size_t length)
{
  data_map_->content=data[0];
  data_map_->content_repeat += length;
  data_map_->content_size += length;
  data_map_->size += length;
  return true;
}


bool SE::Write(const char* data, size_t length, size_t position) {

  if (length == 0)
    return true;
  // Repeated input logic FIXME TODO (dirvine)
  // if anything passed this then ignore this whole condition
//   if ((main_encrypt_queue_.MaxRetrievable() == 0) &&
//        (sequencer_.size() == 0) ) { //no data so far check for repeated input
// 
//     if ((length == 1) && (data_map_->content_repeat == 0)) {
//       return IncRepeat(data, length);
//     } // first bit of data captured
//     
//     if ((length == 1) && (data_map_->content_repeat > 0)
//                 && (data_map_->content[0] = data[0])) { // repeated bit
//       return IncRepeat(data, length);
//     } else {
//       main_encrypt_queue_.Put2(const_cast<byte*>
//       (reinterpret_cast<const byte*>(data_map_->content.c_str())),
//                                1, 0, true);
//       data_map_->content_repeat = 0;
//     }
//     // capture streams of repeating data here
//     if (length > 1) 
//       for(size_t i = 1; i < length; ++i) {
//         if (data[i] == data[i-1]) {
//           IncRepeat();
//         } else {
//           data_map_->content_repeat = 0;
//           break;
//         }
//         if ( i == length -1 )
//           return true;
//       }
//   }

    // TODO transmogrify 
//      if (data_map_->size > position)
//        std::cout << " would transmogrify I think size is "
//        << data_map_->size << std::endl;
//       return Transmogrify(data, length, position);
      
    CheckSequenceData();
    if (position == current_position_) {
      main_encrypt_queue_.Put2(const_cast<byte*>
                             (reinterpret_cast<const byte*>(data)),
                              length, 0, true);
    current_position_ += length;

    } else if (position > current_position_) { // we cannot have less !! 
      sequencer_.Add(position, const_cast<char *>(data), length);
    }



    // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
    if ((main_encrypt_queue_.MaxRetrievable() >= chunk_size_ * 3) &&
       (! chunk_one_two_q_full_)) {
       QueueC0AndC1();
    }
    if ((main_encrypt_queue_.MaxRetrievable() >= chunk_size_) &&
      (chunk_one_two_q_full_))
      ProcessMainQueue();
    return true;  
}

void SE::CheckSequenceData() {
 sequence_data extra(sequencer_.Get(current_position_));
  while (extra.second != 0) {
    main_encrypt_queue_.Put2(const_cast<byte*>
    (reinterpret_cast<const byte*>(extra.first)),
                             extra.second, 0, true);
    current_position_ += extra.second;
    extra = sequencer_.Get(current_position_);
  }
}

bool SE::Transmogrify(const char* data, size_t length, size_t position) {

// Transmogrifier will identify the appropriate chunk
// recover it and alter the data in place
// then re-encrypt it and store again, it will also re-encrypt
// the following two chunks.
// Check its a chunk.
  
  size_t start_chunk_num(0), end_chunk_num(0), total(0), start_position(0);
  bool got_it(false);
  for(size_t i =0; data_map_->chunks.size(); ++i) {
    total += data_map_->chunks[i].size;
    if (total >= position) {
      start_chunk_num = i;
      start_position = total - data_map_->chunks[i].size + position;
      got_it = true;
    }
    if (got_it && (total >= position+length)) 
      end_chunk_num = i;
  }
  // do the work now
  size_t count(0);
  std::string replace_string(data, length);
  if (got_it) {

    while(start_chunk_num <= end_chunk_num) { // single chunk
    std::string this_hash(reinterpret_cast<char *>
      (data_map_->chunks[start_chunk_num].hash), 64);
    std::string chunk_data(chunk_store_->Get(this_hash));
    size_t stop = std::min(length,
                           start_position -
                           data_map_->chunks[start_chunk_num].size);
    for (size_t i = start_position; stop; ++i) {
      chunk_data[i] = replace_string[count];
      ++count;
    }
    start_position = 0; // for more chunks
    EncryptAChunk(start_chunk_num,const_cast<byte *>
    (reinterpret_cast<const byte *>(chunk_data.c_str())),
                  chunk_data.size(),
                  true);
    ++start_chunk_num;
    }
    // do next two chunks
    size_t chunk_num(0);
    for (int i = 1; i <= 2; ++i) {
      chunk_num = (end_chunk_num + i + data_map_->chunks.size())
                       %  data_map_->chunks.size();
      std::string hash(reinterpret_cast<char *>
                       (data_map_->chunks[chunk_num].hash), 64);
      
      EncryptAChunk(chunk_num,const_cast<byte *>
                    (reinterpret_cast<const byte *>
                      (chunk_store_->Get(hash).c_str())),
                    data_map_->chunks[chunk_num].size,
                    true);
    }
  } else // might be in content !!! FIXME also check count >= length
    return false;
}


bool SE::FinaliseWrite() {
  if (data_map_->content_repeat > 0)
    return true;
  chunk_size_ = (main_encrypt_queue_.MaxRetrievable()) / 3 ;
  
  if ((chunk_size_) < 1025) {
    return ProcessLastData();
  }
   CheckSequenceData();
   ProcessMainQueue();
}

bool SE::ProcessLastData() {
  size_t qlength = main_encrypt_queue_.MaxRetrievable();
    boost::shared_array<byte> i(new byte[qlength]);
    main_encrypt_queue_.Get(i.get(), qlength);
    std::string extra(reinterpret_cast<char *>(i.get()), qlength);
    data_map_->content = extra;
    data_map_->content_size = qlength;
    data_map_->size += qlength;
    // when all that is done, encrypt chunks 0 and 1
    if (chunk_one_two_q_full_) {
      EncryptAChunk(0, chunk0_raw_.get(), c0_and_1_chunk_size_, false);
      EncryptAChunk(1, chunk1_raw_.get(), c0_and_1_chunk_size_, false);
      chunk0_raw_.reset();
      chunk1_raw_.reset();
      chunk_one_two_q_full_ = false;
    }
    main_encrypt_queue_.SkipAll();
    return true;
}

bool SE::DeleteAllChunks()
{
  for (size_t i =0; i < data_map_->chunks.size(); ++i)
    if (!chunk_store_->Delete(reinterpret_cast<char *>
      (data_map_->chunks[i].hash)))
      return false;
    return true;
}

bool SE::DeleteAChunk(size_t chunk_num)
{
  if (!chunk_store_->Delete(reinterpret_cast<char *>
    (data_map_->chunks[chunk_num].hash)))
    return false;
  return true;
}

bool SE::ReInitialise() {
    chunk_size_ = 1024*256;
    main_encrypt_queue_.SkipAll();
    chunk_one_two_q_full_ = false;
    data_map_.reset(new DataMap);
    return true;
}

bool SE::QueueC0AndC1() {
  c0_and_1_chunk_size_ = chunk_size_;
  // Chunk 0
  main_encrypt_queue_.Get(chunk0_raw_.get(), chunk_size_);
  ChunkDetails chunk_data;
  CryptoPP::SHA512().CalculateDigest(chunk_data.pre_hash,
                                     chunk0_raw_.get(),
                                     chunk_size_);
  chunk_data.pre_size = chunk_size_;
  data_map_->chunks.push_back(chunk_data);
  
  // Chunk 1
  main_encrypt_queue_.Get(chunk1_raw_.get(), chunk_size_);
  ChunkDetails chunk_data2;
  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
                                     chunk1_raw_.get() ,
                                     chunk_size_);
  chunk_data2.pre_size = chunk_size_;
  data_map_->chunks.push_back(chunk_data2);
  chunk_one_two_q_full_ = true;
  return true;
}

bool SE::ProcessMainQueue() {
  if (main_encrypt_queue_.MaxRetrievable()  < chunk_size_)
    return false;

  size_t chunks_to_process = (main_encrypt_queue_.MaxRetrievable() / chunk_size_);
  size_t old_dm_size = data_map_->chunks.size();
  data_map_->chunks.resize(chunks_to_process + old_dm_size);
  std::vector<boost::shared_array<byte>>chunk_vec(chunks_to_process,
                                               boost::shared_array<byte
                                               >(new byte[chunk_size_]));
  //get all hashes
   for(size_t i = 0; i < chunks_to_process; ++i) {
     boost::shared_array<byte> tempy(new byte[chunk_size_]);
     main_encrypt_queue_.Get(tempy.get(), chunk_size_);
     chunk_vec[i] = tempy;
   }
#pragma omp parallel for
   for(size_t i = 0; i < chunks_to_process; ++i) {
     CryptoPP::SHA512().CalculateDigest(data_map_->chunks[i + old_dm_size].pre_hash,
           chunk_vec[i].get(),
           chunk_size_);
    data_map_->chunks[i + old_dm_size].pre_size = chunk_size_;
    }

#pragma omp parallel for  // gives over 100Mb write speeds
  for(size_t j = 0; j < chunks_to_process; ++j) {
    EncryptAChunk(j + old_dm_size,
                  &chunk_vec[j][0],
                  chunk_size_,
                  false);
  }

  return true;
}

void SE::getPad_Iv_Key(size_t this_chunk_num,
                       boost::shared_array<byte> key,
                       boost::shared_array<byte> iv,
                       boost::shared_array<byte> pad) {
  size_t num_chunks = data_map_->chunks.size();
  size_t n_1_chunk = (this_chunk_num + num_chunks -1) % num_chunks;
  size_t n_2_chunk = (this_chunk_num + num_chunks -2) % num_chunks;

  for (int i = 0; i < 48; ++i) {
    if (i < 32)
      key[i] = data_map_->chunks[n_1_chunk].pre_hash[i];
    if (i > 31)
      iv[i - 32] = data_map_->chunks[n_1_chunk].pre_hash[i];
  }

  for (int i = 0; i < 64; ++i) {
    pad[i] =  data_map_->chunks[n_1_chunk].pre_hash[i];
    pad[i+64] = data_map_->chunks[this_chunk_num].pre_hash[i];
    if (i < 16)
      pad[i+128] = data_map_->chunks[n_2_chunk].pre_hash[i+48];
  }
}


void SE::EncryptAChunk(size_t chunk_num, byte* data,
                       size_t length, bool re_encrypt) {

   if (data_map_->chunks.size() < chunk_num)
    return;
   if (re_encrypt)  // fix pre enc hash and re-encrypt next 2
     CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].pre_hash,
                                        data,
                                        length);

  boost::shared_array<byte> pad(new byte[144]);
  boost::shared_array<byte> key(new byte[32]);
  boost::shared_array<byte> iv (new byte[16]);
  getPad_Iv_Key(chunk_num, key, iv, pad);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key.get(),
                                                          32,
                                                          iv.get());
  std::string chunk_content;
  CryptoPP::StreamTransformationFilter aes_filter(encryptor,
                  new XORFilter(
                    new CryptoPP::StringSink(chunk_content)
                  , pad.get()));
  aes_filter.Put2(data, length, -1, true);
  CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].hash,
                      const_cast<byte *>
                      (reinterpret_cast<const byte *>(chunk_content.c_str())),
                      length);
  std::string post_hash(reinterpret_cast<char *>
                          (data_map_->chunks[chunk_num].hash), 64);
#pragma omp critical
{
  if (!chunk_store_->Store(post_hash,  chunk_content))
    DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash)
                                        << std::endl;
}

   if (!re_encrypt) {
    data_map_->chunks[chunk_num].size = length;
#pragma omp atomic
    data_map_->size += length;
   }
}


bool SE::Read(char* data, size_t length, size_t position) {

   if ((data_map_->size > (length + position)) && (length != 0))
     return false;
   if (data_map_->content_repeat > 0) {
     for(size_t i = 0; i < length; ++i)
       data[i] = data_map_->content.c_str()[i];
     return true;
   }
   
   size_t start_chunk(0), start_offset(0), end_chunk(0), run_total(0);
   for(size_t i = 0; i < data_map_->chunks.size(); ++i) {
     if ((data_map_->chunks[i].size + run_total >= position) &&
         (start_chunk = 0)) {
       start_chunk = i;
       start_offset = run_total + data_map_->chunks[i].size -
                      (position - run_total);
       run_total = data_map_->chunks[i].size - start_offset;
     }
     else
#pragma omp atomic
       run_total += data_map_->chunks[i].size;
           // find end (offset handled by return truncated size
     if ((run_total <= length) || (length == 0))
       end_chunk = i;
   }

   if (end_chunk != 0)
     ++end_chunk;

#pragma omp parallel for shared(data)
  for (size_t i = start_chunk;i < end_chunk ; ++i) {
    size_t this_chunk_size(0);
    for (size_t j = start_chunk; j < i; ++j)
#pragma omp atomic
      this_chunk_size += data_map_->chunks[j].size;
    ReadChunk(i, reinterpret_cast<byte *>(&data[this_chunk_size])); 
  }
 
  for(size_t i = 0; i < data_map_->content_size; ++i) {
#pragma omp barrier
    data[length - data_map_->content_size + i] = data_map_->content[i];
  }
  return readok_;
}

void SE::ReadChunk(size_t chunk_num, byte *data) {
  if (data_map_->chunks.size() < chunk_num) {
    readok_ = false;
    return;
  }
   std::string hash(reinterpret_cast<char *>(data_map_->chunks[chunk_num].hash),
                    64);
  size_t length = data_map_->chunks[chunk_num].size;
  boost::shared_array<byte> pad(new byte[144]);
  boost::shared_array<byte> key(new byte[32]);
  boost::shared_array<byte> iv (new byte[16]);
  getPad_Iv_Key(chunk_num, key, iv, pad);
  std::string content("");
#pragma omp critical
{
  content = chunk_store_->Get(hash);
}
  if (content == ""){
    DLOG(ERROR) << "Could not find chunk: " << EncodeToHex(hash) << std::endl;
    readok_ = false;
    return;
  }
    
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(), 32, iv.get());
          CryptoPP::StringSource filter(content, true,
            new XORFilter(
            new CryptoPP::StreamTransformationFilter(decryptor,
              new CryptoPP::MessageQueue),
            pad.get()));
  filter.Get(data, length);
}

}  // namespace encrypt

}  // namespace maidsafe
