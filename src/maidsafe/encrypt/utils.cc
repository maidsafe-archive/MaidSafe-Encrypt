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
  boost::scoped_array<byte> buffer(new byte[length]);
  for (size_t i = 0; i < length; ++i) {
    buffer[i] = inString[i] ^  pad_[count_%144];
    ++count_;
  }
  return AttachedTransformation()->Put2(buffer.get(),
                                       length,
                                        messageEnd,
                                        blocking);
}

bool SE::Write(const char* data, size_t length, size_t position) {

  if (length == 0)
    return true;
  
  if (position == current_position_) {
    std::string extra(getFromSequencer(current_position_+length));
    main_encrypt_queue_.Put2(const_cast<byte*>
                           (reinterpret_cast<const byte*>(data)),
                            length, -1, true);
    if (extra != "") {
    main_encrypt_queue_.Put2(const_cast<byte*>
                           (reinterpret_cast<const byte*>(extra.data())),
                            extra.size(), -1, true);
    current_position_ += extra.size();
    }
    current_position_ += length;
    
  } else if (position < current_position_) {
    // TODO (dirvine) handle rewrites properly
    // need to grab data and rewrite it
    // check sequencer
  } else {
    std::string add_this(data, length);
    AddToSequencer(add_this, position);
  }
    // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
  if (!chunk_one_two_q_full_) {  // for speed
    if (main_encrypt_queue_.MaxRetrievable() >= chunk_size_ * 3) {
       QueueC1AndC2();
       return ProcessMainQueue();
    } else
      return true;  // not enough to process chunks yet
  }
  return ProcessMainQueue();
}

bool SE::AddToSequencer(std::string data, size_t position) {
  // TODO (dirvine) if a write happens half way through we count as 2 sets,
  // need to take
  // care of this in the getFromSequencer method.
  // ah no needs to be here, otherwise we lose timeline 
  for (auto it = sequence_map_.begin(); it != sequence_map_.end(); ++it) {
      auto iter = sequence_map_.find(position);
      if (iter == sequence_map_.end())
        sequence_map_.insert(std::pair<size_t, std::string>(position, data));
      else
        (*iter).second = data;
  }
}

std::string SE::getFromSequencer(size_t position) {
  if (sequence_map_.size() == 0)
    return "";
  for (auto it = sequence_map_.begin(); it != sequence_map_.end(); ++it) {
    if ((*it).first == position) {
      std::string result = (*it).second;
      sequence_map_.erase(it);
      return result;
    }
    if ((*it).first + (*it).second.size()  >= position) {
      std::string result = (*it).second.substr((*it).first +
                           (*it).second.size() - position);
      std::string keep_this = (*it).second.substr(0,(*it).first +
                                     (*it).second.size() - position);
      // hopefully this is empty !!
      std::string keep_this_to = (*it).second.substr((*it).first +
                                     (*it).second.size() - position);
      (*it).second = keep_this + keep_this_to;
      return result;                                           
    }
  }
  return "";  // nothing found
}

bool SE::FinaliseWrite() {
  chunk_size_ = (main_encrypt_queue_.TotalBytesRetrievable()) / 3 ;
  while (main_encrypt_queue_.TotalBytesRetrievable() < chunk_size_ * 3) {
    // small files direct to data map
    if ((chunk_size_) < 1025) {
       return ProcessLastData();
    }
    EncryptChunkFromQueue(main_encrypt_queue_);
  }
  
  if (chunk0_queue_.AnyRetrievable()) {
    EncryptChunkFromQueue(chunk0_queue_);
    EncryptChunkFromQueue(chunk1_queue_);
    chunk_one_two_q_full_ = false;
  }
  
  return ProcessLastData();
}

bool SE::ProcessLastData() {
  size_t qlength = main_encrypt_queue_.TotalBytesRetrievable();
    boost::scoped_array<byte> i(new byte[qlength]);
    main_encrypt_queue_.Get(i.get(), sizeof(i));
    data_map_->content = reinterpret_cast<const char *>(i.get());
    data_map_->content_size = qlength;
    data_map_->size += qlength;
    if (chunk0_queue_.AnyRetrievable()) {
      EncryptChunkFromQueue(chunk0_queue_);
      EncryptChunkFromQueue(chunk1_queue_);
      chunk_one_two_q_full_ = false;
    }
    main_encrypt_queue_.SkipAll();
    return true;
}

bool SE::ReInitialise() {
    chunk_size_ = 1024*256;
    main_encrypt_queue_.SkipAll();
    chunk0_queue_.SkipAll();
    chunk1_queue_.SkipAll();
    chunk_one_two_q_full_ = false;
    data_map_.reset(new DataMap2);
    return true;
}

bool SE::QueueC1AndC2() {
  c0_and_1_chunk_size_ = chunk_size_;
  // Chunk 1
  main_encrypt_queue_.TransferTo(chunk0_queue_, chunk_size_);
  chunk0_queue_.MessageEnd();
  ChunkDetails2 chunk_data;
  boost::scoped_array<byte> temp(new byte[chunk_size_]);
  chunk0_queue_.Peek(temp.get(), chunk_size_);
  CryptoPP::SHA512().CalculateDigest(chunk_data.pre_hash,
                                     temp.get(),
                                     chunk_size_);
  chunk_data.pre_size = chunk_size_;
  data_map_->chunks.push_back(chunk_data);
  // Chunk 2
  main_encrypt_queue_.TransferTo(chunk1_queue_, chunk_size_);
  chunk1_queue_.MessageEnd();
  ChunkDetails2 chunk_data2;
  boost::scoped_array<byte> temp2(new byte[chunk_size_]);
  chunk1_queue_.Peek(temp2.get(), chunk_size_);
  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
                                     temp2.get() ,
                                     chunk_size_);
  chunk_data2.pre_size = chunk_size_;
  data_map_->chunks.push_back(chunk_data);
  chunk_one_two_q_full_ = true;
  return chunk_one_two_q_full_;
}
/*
bool SE::ProcessMainQueue() {
  while (main_encrypt_queue_.MaxRetrievable()  >= chunk_size_) {
    main_encrypt_queue_.TransferTo(chunk_current_queue_ , chunk_size_);
    if (!EncryptChunkFromQueue(chunk_current_queue_))
      return false;
  }
  return true;
}*/

bool SE::ProcessMainQueue() {
  size_t chunks_to_process = main_encrypt_queue_.MaxRetrievable() / chunk_size_;
  size_t old_dm_size = data_map_->chunks.size();
  data_map_->chunks.resize(chunks_to_process + old_dm_size);
  std::vector<byte[chunk_size_]>chunks(chunks_to_process);
  boost::shared_array<byte> chunk_content(new byte [this_chunk_size_]);

  //get all hashes

  for(size_t i = 0; i < chunks_to_process; ++i) {
    main_encrypt_queue_.Get(chunk_content.get(), chunk_size_);

    for(size_t j = 0; j < chunk_size_; ++j)
      chunks[i][j] = chunk_content[j];
    
    HashMe(data_map_->chunks[i + old_dm_size].pre_hash,
          chunk_content.get(),
          chunk_size_);
    data_map_->chunks[i + old_dm_size].pre_size = chunk_size_;
   }
  // process chunks
//#pragma omp parallel for // gives over 100Mb write speeds
  for(size_t i = 0; i <  chunks_to_process; ++i) {
    EncryptAChunk(i + old_dm_size,
                  chunks[i],
                  chunk_size_,
                  false);
  }

  return true;
}

void SE::HashMe(byte * digest, byte* data, size_t length) {
  CryptoPP::SHA512().CalculateDigest(digest, data, length);
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

bool SE::EncryptChunkFromQueue(CryptoPP::MessageQueue & queue) {
  ChunkDetails2 chunk_details;
  size_t this_chunk_num(0);
  boost::shared_array<byte> pad(new byte[144]);
  boost::shared_array<byte> key(new byte[32]);
  boost::shared_array<byte> iv (new byte[16]);

  if ((&queue != &chunk0_queue_) && (&queue != &chunk1_queue_)) {
    boost::scoped_array<byte> temp(new byte [chunk_size_]);
    queue.Peek(temp.get(), chunk_size_); // copy whole array
    HashMe(chunk_details.pre_hash, temp.get(), chunk_size_);
    chunk_details.pre_size = chunk_size_;
    this_chunk_size_ = chunk_size_;
    data_map_->chunks.push_back(chunk_details);
    this_chunk_num = data_map_->chunks.size() -1;
  } else {
    this_chunk_size_ = c0_and_1_chunk_size_;
    if (&queue == &chunk0_queue_)
    this_chunk_num = 0;
    if (&queue == &chunk1_queue_)
    this_chunk_num = 1;
  }

  getPad_Iv_Key(this_chunk_num, key, iv, pad);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key.get(),
                                                          32,
                                                          iv.get());
  CryptoPP::StreamTransformationFilter aes_filter(encryptor,
                  new XORFilter(
                    new CryptoPP::HashFilter(hash_,
                      new CryptoPP::MessageQueue()
                    , true)
                  , pad.get()));

  queue.TransferAllTo(aes_filter);
  aes_filter.MessageEnd(-1, true);

  boost::scoped_array<byte> chunk_content(new byte [this_chunk_size_]); // do not move this !!
  aes_filter.Get(chunk_content.get(), this_chunk_size_); // get content
  aes_filter.Get(data_map_->chunks[this_chunk_num].hash , 64);

  std::string post_hash(reinterpret_cast<char *>
                          (data_map_->chunks[this_chunk_num].hash), 64);
  std::string data(reinterpret_cast<char *>(chunk_content.get()),
                   this_chunk_size_);
  // TODO FIME (dirvine) quick hack for retry
  if (! chunk_store_->Store(post_hash, data)) {
    if (! chunk_store_->Store(post_hash, data)) {
      DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash)
                                        << std::endl;
      return false;
    }
  }
  data_map_->chunks[this_chunk_num].size = this_chunk_size_;
  data_map_->size += this_chunk_size_;
  return true;
}

bool SE::EncryptAChunk(size_t chunk_num, byte* data,
                       size_t length, bool re_encrypt) {
  if (data_map_->chunks.size() < chunk_num)
    return false;
  if (re_encrypt)  // fix pre enc hash and re-encrypt next 2
    HashMe(data_map_->chunks[chunk_num].pre_hash, data, length);
    
  boost::shared_array<byte> pad(new byte[144]);
  boost::shared_array<byte> key(new byte[32]);
  boost::shared_array<byte> iv (new byte[16]);
  getPad_Iv_Key(chunk_num, key, iv, pad);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key.get(),
                                                          32,
                                                          iv.get());
  CryptoPP::StreamTransformationFilter aes_filter(encryptor,
                  new XORFilter(
                    new CryptoPP::HashFilter(hash_,
                      new CryptoPP::MessageQueue()
                    , true)
                  , pad.get()));

  aes_filter.Put2(data, length, -1, true);

  boost::scoped_array<byte> chunk_content(new byte [length]);
  aes_filter.Get(chunk_content.get(), length); // get content
  aes_filter.Get(data_map_->chunks[chunk_num].hash , 64);
  std::string post_hash(reinterpret_cast<char *>
                          (data_map_->chunks[chunk_num].hash), 64);
  std::string data_to_store(reinterpret_cast<char *>(chunk_content.get()),
                            length);
  // TODO FIME (dirvine) quick hack for retry
  if (! chunk_store_->Store(post_hash, data_to_store)) {
    if (! chunk_store_->Store(post_hash, data_to_store)) {
      DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash)
                                        << std::endl;
      return false;
    }
  }
  
  if (!re_encrypt) {
    data_map_->chunks[chunk_num].size = length;
    data_map_->size += length;
  }
  return true;
}


bool SE::Read(char* data, size_t length, size_t position) {

   if ((data_map_->size > (length + position)) && (length != 0))
     return false;

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
       run_total += data_map_->chunks[i].size;
           // find end (offset handled by return truncated size
     if ((run_total <= length) || (length == 0))
       end_chunk = i;
   }

   size_t amount_of_extra_content(0);
   if (run_total <  length)
     amount_of_extra_content = length - run_total;
   else
     amount_of_extra_content = data_map_->content_size;
 
   if (end_chunk != 0)
     ++end_chunk;

   std::vector<std::string> plain_text_vec(end_chunk - start_chunk);
#pragma omp parallel for 
  for (size_t i = start_chunk;i < end_chunk ; ++i) {
    ReadChunk(i, &plain_text_vec.at(i));
  }
 
  std::string alldata;
  for (size_t i = 0 ;i < plain_text_vec.size() ; ++i) {
    alldata += plain_text_vec[i];
  }
#pragma omp parallel for
  for(size_t i = 0; i < alldata.size(); ++i)
     data[i] = alldata[i];
#pragma omp parallel for
  for(size_t i = 0; i < amount_of_extra_content; ++i)
    data[i+alldata.size()] = data_map_->content[i];
  return true;
}

bool SE::ReadChunk(size_t chunk_num, std::string *data) {
  if (data_map_->chunks.size() < chunk_num)
    return false;
   std::string hash(reinterpret_cast<char *>(data_map_->chunks[chunk_num].hash),
                    64);
    if (!chunk_store_->Has(hash)) {
      DLOG(ERROR) << "Could not find chunk: " << EncodeToHex(hash) << std::endl;
      return false;
    }
  boost::shared_array<byte> pad(new byte[144]);
  boost::shared_array<byte> key(new byte[32]);
  boost::shared_array<byte> iv (new byte[16]);
  getPad_Iv_Key(chunk_num, key, iv, pad);
  std::string content(chunk_store_->Get(hash));
  std::string answer;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(), 32, iv.get());
          CryptoPP::StringSource filter(content, true,
            new XORFilter(
            new CryptoPP::StreamTransformationFilter(decryptor,
              new CryptoPP::StringSink(*data)),
            pad.get()));
  return true;
}

}  // namespace encrypt

}  // namespace maidsafe
