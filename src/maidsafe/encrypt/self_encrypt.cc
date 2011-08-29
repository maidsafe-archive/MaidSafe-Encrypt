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
 *******************************************************************************
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
  size_t i(0);
  
// #pragma omp parallel for shared(buffer, inString) private(i)
  for (i = 0; i < length; ++i) {
    buffer[i] = inString[i] ^  pad_[count_%144];
    ++count_;
  }

  return AttachedTransformation()->Put2(buffer.get(),
                                       length,
                                        messageEnd,
                                        blocking);
}

SE::~SE() {
  ProcessMainQueue(); // to pick up unprocessed whole chunks
  EmptySequencer();
  chunk_size_ = (main_encrypt_queue_.MaxRetrievable()) / 3 ;
  if ((chunk_size_) < 1025) {
    chunk_size_ = 1024*256;
    current_position_ = 0;
    q_position_ = 0;
    ProcessLastData();
    return;
  }
  CheckSequenceData();
  ProcessMainQueue();
  chunk_size_ = 1024*256;
  main_encrypt_queue_.SkipAll();
  chunk_one_two_q_full_ = false;
  current_position_ = 0;
  q_position_ = 0;
  return;
}

void SE::SequenceAllNonStandardChunksAndExtraContent() {
  size_t start_chunk(0), chunk_size(0), pos(0);
  for (size_t i = 0; i < data_map_->chunks.size(); ++i) {
    pos += data_map_->chunks[i].size;
    if ((data_map_->chunks[i].size >2) &&
      (data_map_->chunks[i].size != data_map_->chunks[i - 1].size)) {
      start_chunk = i - 2;
      chunk_size = data_map_->chunks[i].size;
      break;
    }
    if (start_chunk > 0) {
      for (size_t i = start_chunk; i < data_map_->chunks.size(); ++i) {
        // shove chunk data into sequencer (which will get overwritten anyway
        // as sequencer has ability to maintain timelines)
        boost::scoped_array<byte> data(new byte[chunk_size]);
        
        ReadChunk(i, data.get());
        sequencer_.Add(pos, reinterpret_cast<char *>(data.get()), chunk_size);
        DeleteAChunk(i);
        pos += data_map_->chunks[i].size;
      }
      if (data_map_->content_size > 0)
        sequencer_.Add(pos,
                       const_cast<char *>(data_map_->content.c_str()),
                       data_map_->content_size);
      data_map_->content = "";
      data_map_->content_size = 0;
    }
  }
}

bool SE::Write(const char* data, size_t length, size_t position) {

  if (length == 0)
    return true;
  if (complete_) {
    SequenceAllNonStandardChunksAndExtraContent();
  if (position != current_position_) 
      sequencer_.Add(position, const_cast<char *>(data), length);
  else
    // continue as usual we are rewriting data
    // assume we will rewrite everything TODO (DI) check assumption
    rewriting_ = true;
  }
  
  CheckSequenceData();
  if (position == current_position_) {
    main_encrypt_queue_.Put2(const_cast<byte*>
                            (reinterpret_cast<const byte*>(data)),
                            length, 0, true);
  current_position_ += length;

  } else if (position > current_position_) { !
    sequencer_.Add(position, const_cast<char *>(data), length);
  } /*else if (position < current_position_) {
    return Transmogrify(data, length, position);
  }*/
  // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
  if ((main_encrypt_queue_.MaxRetrievable() >= chunk_size_ * 3) &&
      (! chunk_one_two_q_full_)) {
      QueueC0AndC1();
      q_position_ = chunk_size_ * 2;
  }
  size_t num_chunks_to_process(0);

  if (!ignore_threads_)
    num_chunks_to_process = (num_procs_) * chunk_size_;
  else
    num_chunks_to_process = chunk_size_;

  if ((main_encrypt_queue_.MaxRetrievable() >= num_chunks_to_process) &&
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

void SE::EmptySequencer() {
  if (sequencer_.size() == 0)
    return;

  while (sequencer_.size() > 0) {
    char * data;
    size_t length(0);
    size_t seq_pos = sequencer_.GetFirst(data, &length);

    // need to pad and write data
    if (current_position_ < seq_pos) { // Nothing done - pad to this point
      boost::scoped_array<char> pad(new char[1]);
      pad[0] = 'a';
      for (size_t i = current_position_; i < seq_pos; ++i)
        Write(pad.get(),1, current_position_);
      Write(data, length, seq_pos);
      CheckSequenceData();
    } 
    size_t pos = sequencer_.GetFirst(data, &length);
    Transmogrify(data, length, pos);
  }

}

bool SE::Transmogrify(const char* data, size_t length, size_t position) {

// Transmogrifier will identify the appropriate chunk
// recover it and alter the data in place
// then re-encrypt it and store again, it will also re-encrypt
// the following two chunks.

  size_t start_chunk(0), start_offset(0), end_chunk(0), run_total(0),
  end_cut(0);
  bool found_start(false);
  bool found_end(false);
  size_t num_chunks = data_map_->chunks.size();
  size_t this_position(0);
  if (num_chunks > 0) {
    for(size_t i = 0; i < num_chunks;  ++i) {
      size_t this_chunk_size = data_map_->chunks[i].size;
      if ((this_chunk_size + run_total >= position)
        && (!found_start)) {
        start_chunk = i;
      start_offset =  position;
      run_total = this_chunk_size - start_offset;
      found_start = true;
      if (run_total >= length) {
        found_end = true;
        end_chunk = i;
        break;
      }
      continue;
        }

        if (found_start)
          #pragma omp atomic
        run_total += this_chunk_size - start_offset;

        if (run_total > length) {
          end_chunk = i;
          end_cut = length - run_total;
          found_end = true;
          break;
        }
    }
    if (!found_end)
      end_chunk = num_chunks;

    do {
      // get chunk
      boost::shared_array<byte> chunk_data
      (new byte[data_map_->chunks[start_chunk].size]);
      ReadChunk(start_chunk, chunk_data.get());
      for (size_t i = start_offset; i < length + start_offset; ++i)
        chunk_data[i] = static_cast<const char>(data[i]);
      DeleteAChunk(start_chunk);
      EncryptAChunk(start_chunk, chunk_data.get(), sizeof(chunk_data), true);
      ++start_offset;
      this_position += data_map_->chunks[start_chunk].size;
    } while (start_chunk < end_chunk);
    
    // encrypt next two chunks
    size_t chunk_num(0);
    for (int i = end_chunk; i <= 2; ++i) {
      chunk_num = (i + data_map_->chunks.size())
                       %  data_map_->chunks.size();
      std::string hash(reinterpret_cast<char *>
                       (data_map_->chunks[chunk_num].hash), 64);
      DeleteAChunk(i);
      EncryptAChunk(chunk_num,const_cast<byte *>
                    (reinterpret_cast<const byte *>
                      (chunk_store_->Get(hash).c_str())),
                    data_map_->chunks[chunk_num].size,
                    true);
      this_position += data_map_->chunks[chunk_num].size;
    }
    return true;
  }  // might be in content !!! FIXME make string
  if (this_position < (position + length)) {
    data_map_->content = (reinterpret_cast<char *>(data[this_position]),
                          (position + length) - this_position);
    data_map_->content_size = data_map_->content.size();
    return true;
  }
  return false;
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
    data_map_->chunks.clear();
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
    DeleteAllChunks();
    main_encrypt_queue_.SkipAll();
    chunk_one_two_q_full_ = false;
    current_position_ = 0;
    q_position_ = 0;
    data_map_.reset(new DataMap);
    complete_ = false;
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
  chunk_data.size = chunk_size_;
  data_map_->chunks.push_back(chunk_data);
  
  // Chunk 1
  main_encrypt_queue_.Get(chunk1_raw_.get(), chunk_size_);
  ChunkDetails chunk_data2;
  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
                                     chunk1_raw_.get() ,
                                     chunk_size_);
  chunk_data2.size = chunk_size_;
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
     q_position_ += chunk_size_;
     chunk_vec[i] = tempy;
   }
#pragma omp parallel for
   for(size_t i = 0; i < chunks_to_process; ++i) {
     CryptoPP::SHA512().CalculateDigest(
       data_map_->chunks[i + old_dm_size].pre_hash,
       chunk_vec[i].get(),
       chunk_size_);
    data_map_->chunks[i + old_dm_size].size = chunk_size_;
    }
// check for repeated content
// TODO FIXME ( needs tested )

//   for(size_t i = 0; i < chunks_to_process; ++i) {
//     if ((data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i + old_dm_size].pre_hash) &&
//       (data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i -1 + old_dm_size].pre_hash) &&
//       (data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i -2 + old_dm_size].pre_hash)) {
//       if (i == 2) { // only encrypt chunk 2
//         EncryptAChunk(i + old_dm_size, &chunk_vec[i][0], chunk_size_, false);
//       } else {
//         for (int j =0; j < 64; ++j)
//           data_map_->chunks[i + old_dm_size].hash[j] =
//           data_map_->chunks[i - 1 + old_dm_size].hash[j];
//       }
//     }
//   }


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
//   CryptoPP::StreamTransformationFilter aes_filter(encryptor,
//                   new XORFilter(
//                     new CryptoPP::StringSink(chunk_content)
//                   , pad.get()));
  // with compression speeds are min 10% slower mostly 25% slower
  CryptoPP::Gzip aes_filter(new CryptoPP::StreamTransformationFilter(encryptor,
                              new XORFilter(
                                new CryptoPP::StringSink(chunk_content)
                              , pad.get())), 0);

  
  aes_filter.Put2(data, length, -1, true);
  CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].hash,
                      const_cast<byte *>
                      (reinterpret_cast<const byte *>(chunk_content.c_str())),
                      chunk_content.size());
  std::string post_hash(reinterpret_cast<char *>
                          (data_map_->chunks[chunk_num].hash), 64);
#pragma omp critical
{
  if (!chunk_store_->Store(post_hash,  chunk_content))
    DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash)
                                        << std::endl;
}

   if (!re_encrypt) {
    data_map_->chunks[chunk_num].size = length; // keep pre-compressed length
#pragma omp atomic
    data_map_->size += length;
   }
}

bool SE::ReadInProcessData(char* data, size_t *length, size_t *position)
{
  // true == all data received, false means still work to do
  // pointer to length as it may be returned different size if not all found
  size_t q_size = main_encrypt_queue_.MaxRetrievable();
  size_t wanted_length = *length;
  size_t start_position = *position;

  // check c0 and c1
  if ((*position < c0_and_1_chunk_size_ * 2) && (chunk_one_two_q_full_)) {

    for (size_t i = start_position; i < c0_and_1_chunk_size_ * 2;
          ++i,--wanted_length ) {
      
      if (c0_and_1_chunk_size_ > i)
        data[i] = static_cast<char>(chunk0_raw_[i]);
      else if ((c0_and_1_chunk_size_ > i) && (i < (c0_and_1_chunk_size_ * 2)))
        data[i] = static_cast<char>(chunk1_raw_[i]);
      if (wanted_length == 1)
        return true;
    }
    *length = wanted_length;
    *position += wanted_length;
    start_position += wanted_length;
  }
  // check queue
  if ((q_size > 0) && (q_size + current_position_ > start_position)) {
    size_t to_get = (q_size - current_position_ + wanted_length);
    
    // grab all queue into new array
    boost::scoped_array<char>  temp(new char[q_size]);
    main_encrypt_queue_.Peek(reinterpret_cast<byte *>(temp.get()), q_size);
    size_t start(0);
    if (current_position_ == q_size)
      start = start_position;
    else
      start = current_position_ - q_size + start_position;
    
    for (size_t i = start; i < to_get + start;
                          ++i, --wanted_length) {
      data[i] = temp[i];
      if (wanted_length == 1) //  will be zero on next round
        return true;
    }
    *length = wanted_length;
    *position += wanted_length;
    start_position += wanted_length;
  }

  
  if (sequencer_.size() > 0) {
    sequence_data answer = sequencer_.Peek(start_position);
    for (size_t i = 0; i < answer.second, wanted_length > 0;
          ++i, --wanted_length) {
      data[i + start_position] = answer.first[i];
    }
    if (wanted_length == 0)
      return true;
    else {
      *length = wanted_length;
      *position = start_position;
    }
  }
  return false;
}

bool SE::ReadAhead(char* data, size_t length, size_t position) {
 size_t maxbuffersize(chunk_size_ * num_procs_);
 size_t buffersize = std::min(data_map_->size, maxbuffersize);
 // full file, just get it
 if (length >= data_map_->size) {
   ReadAhead(data, length, position);
   return true;
 }
 //quite big just get it direct
 if ((length + position) > (buffersize - read_ahead_buffer_start_pos_)) {
   ReadAhead(data, length, position);
   return true;
 }
// buffer bigger than filesize
  if(buffersize >= data_map_->size) {
    if (!read_ahead_initialised_) {
      ReadAhead(read_ahead_buffer_.get(), data_map_->size, 0);
      read_ahead_initialised_ = true;
      read_ahead_buffer_start_pos_ = 0;
    }
  } else if  ((read_ahead_buffer_start_pos_ + buffersize < position + length) ||
    (!read_ahead_initialised_)){ 
   size_t toread = std::min(data_map_->size - position, buffersize);
   ReadAhead(read_ahead_buffer_.get(), toread, position);
   read_ahead_initialised_ = true;
   read_ahead_buffer_start_pos_ = position;
 }
 // actually read from buffer
 for (size_t i = position - read_ahead_buffer_start_pos_; //FIXM
      i < length  ; ++i) {
   data[i] = read_ahead_buffer_[i];
 }
 return true;
}

bool SE::Read(char* data, size_t length, size_t position) {
   // this will get date in process including c0 and c1
   // so unless finalise write is given it will be here
   if (!complete_)
     if (ReadInProcessData(data, &length, &position))
       return true;
   // length and position may be adjusted now
   // --length and ++ position

    size_t start_chunk(0), start_offset(0), end_chunk(0), run_total(0),
            end_cut(0);
    bool found_start(false);
    bool found_end(false);
    size_t num_chunks = data_map_->chunks.size();
    size_t this_position(0);
  if (num_chunks > 0) {
    for(size_t i = 0; i < num_chunks;  ++i) {
      size_t this_chunk_size = data_map_->chunks[i].size;
      if ((this_chunk_size + run_total >= position)
           && (!found_start)) {
        start_chunk = i;
      start_offset =  position;
      run_total = this_chunk_size - start_offset;
        found_start = true;
        if (run_total >= length) {
          found_end = true;
          end_chunk = i;
          break;
        }
        continue;
      } 

     if (found_start) 
 #pragma omp atomic
       run_total += this_chunk_size - start_offset;

      if (run_total > length) {
        end_chunk = i;
        end_cut = length - run_total;
        found_end = true;
        break;
      }
    }
     if (!found_end)
      end_chunk = num_chunks;
// this is 2 for loops to allow openmp to thread properly.
// should be refactored to a do loop and openmp fixed
     if (start_chunk == end_chunk) {
       // get chunk
       boost::shared_array<byte> chunk_data
                   (new byte[data_map_->chunks[start_chunk].size]);
       ReadChunk(start_chunk, chunk_data.get());
       for (size_t i = start_offset; i < length + start_offset; ++i)
         data[i] = static_cast<char>(chunk_data[i]);
      return readok_;
     }

#pragma omp parallel for shared(data) 
    for (size_t i = start_chunk;i < end_chunk ; ++i) {
      size_t pos(0);
      size_t this_chunk_size(data_map_->chunks[i].size);

        if ((i == start_chunk) && (start_offset != 0)) {
          this_chunk_size -= start_offset;

          boost::shared_array<byte> chunk_data
                      (new byte[data_map_->chunks[start_chunk].size]);
          ReadChunk(start_chunk, chunk_data.get());

          for (size_t j = start_offset; j < this_chunk_size; ++j)
            data[j] = static_cast<char>(chunk_data[j]);


        } else if ((i == end_chunk) && (end_cut != 0)) {
          this_chunk_size -= end_cut;

          boost::shared_array<byte> chunk_data
          (new byte[data_map_->chunks[end_chunk].size]);
          ReadChunk(start_chunk, chunk_data.get());
          
          for (size_t j = start_chunk; j < i; ++j)
#pragma omp atomic
            pos += data_map_->chunks[j].size;

          for (size_t j = 0; j < this_chunk_size; ++j)
            data[j + pos] = static_cast<char>(chunk_data[j]);

        }else {
          for (size_t j = start_chunk; j < i; ++j)
#pragma omp atomic
            pos += data_map_->chunks[j].size;
          ReadChunk(i, reinterpret_cast<byte *>(&data[pos]));
       }
    }
  }

  
  #pragma omp barrier
  for(size_t i = 0; i < num_chunks;  ++i) 
    this_position += data_map_->chunks[i].size;
 // Extra data in data_map_->content
  //if ((data_map_->content_size > 0) && (this_position < length))
// #pragma omp parallel for shared(data)
  for(size_t i = 0; i < data_map_->content_size ; ++i) {
    if (this_position < (position + length))
      data[this_position] = data_map_->content.c_str()[i];
    ++this_position;
  }
  // pad rest with zero's just in case.
  for (size_t i = this_position; i < (position + length); ++i)
    data[i] = '0';
  return readok_;
}

void SE::ReadChunk(size_t chunk_num, byte *data) {
  if ((data_map_->chunks.size() < chunk_num) ||
    (data_map_->chunks.size() == 0)){
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
    DLOG(ERROR) << "Could not find chunk number : " << chunk_num
        << " which is " << EncodeToHex(hash) << std::endl;
    readok_ = false;
    return;
  }
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(), 32, iv.get());
//   CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(), 32, iv.get());
//           CryptoPP::StringSource filter(content, true,
//             new XORFilter(
//             new CryptoPP::StreamTransformationFilter(decryptor,
//               new CryptoPP::MessageQueue),
//             pad.get()));


  CryptoPP::StringSource filter(content, true,
           new XORFilter(
             new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::Gunzip(new CryptoPP::MessageQueue())),
            pad.get()));
  filter.Get(data, length);
}

}  // namespace encrypt

}  // namespace maidsafe
