
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

#include <omp.h>

#include <tuple>
#include <algorithm>
#include <limits>
#include <set>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
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

uint64_t TotalSize(DataMapPtr data_map) {
  uint64_t size(data_map->content.size());
  std::for_each(data_map->chunks.begin(), data_map->chunks.end(),
                [&size] (ChunkDetails chunk) { size += chunk.size; });
  return size;
}

/// Implementation of XOR transformation filter to allow pipe-lining
size_t XORFilter::Put2(const byte *in_string,
                       size_t length,
                       int message_end,
                       bool blocking) {
  if (length == 0) {
    return AttachedTransformation()->Put2(in_string, length, message_end,
                                          blocking);
  }
  boost::scoped_array<byte> buffer(new byte[length]);

  size_t i(0);
  size_t offset((3 * crypto::SHA512::DIGESTSIZE) - crypto::AES256_KeySize -
                crypto::AES256_IVSize);
// #pragma omp parallel for shared(buffer, in_string) private(i)
  for (; i != length; ++i) {
    buffer[i] = in_string[i] ^ pad_[count_ % offset];
    ++count_;
  }

  return AttachedTransformation()->Put2(buffer.get(), length, message_end,
                                        blocking);
}

SelfEncryptor::~SelfEncryptor() {
  Flush();
//  ProcessMainQueue();  // to pick up unprocessed whole chunks
//  EmptySequencer();
//  while (retrievable_from_queue_ > 0) {
//    uint32_t chunk_size = retrievable_from_queue_ / 3;
//    if (chunk_size < kMinChunkSize) {
//      WriteExtraAndEnc0and1();
//    }
//    AddReleventSeqDataToQueue();
//    ProcessMainQueue(chunk_size);
//  }
//  WriteExtraAndEnc0and1();
}

bool SelfEncryptor::Write(const char *data,
                          uint32_t length,
                          uint64_t position) {
  if (length == 0)
    return true;

  PrepareToWrite();

  uint32_t written = PutToInitialChunks(data, &length, &position);

  uint32_t data_offset(0), queue_offset(0);
  if (GetDataOffsetForEnqueuing(length, position, &data_offset,
                                &queue_offset)) {
    PutToEncryptQueue(data + written, length, data_offset, queue_offset);
  }

  if (GetLengthForSequencer(position, &length))
    sequencer_.Add(data + written, length, position);

  AddReleventSeqDataToQueue();  // gets any relevent data from sequencer
  return true;
}

void SelfEncryptor::PrepareToWrite() {
  if (prepared_for_writing_)
    return;

  if (!main_encrypt_queue_) {
    main_encrypt_queue_.reset(new byte[kQueueCapacity_]);
    memset(main_encrypt_queue_.get(), 0, kQueueCapacity_);
  }

  if (!chunk0_raw_) {
    chunk0_raw_.reset(new byte[kDefaultChunkSize]);
    memset(chunk0_raw_.get(), 0, kDefaultChunkSize);
  }

  if (!chunk1_raw_) {
    chunk1_raw_.reset(new byte[kDefaultChunkSize]);
    memset(chunk1_raw_.get(), 0, kDefaultChunkSize);
  }

  if (data_map_->content.empty()) {
    BOOST_ASSERT(data_map_->chunks.empty() || data_map_->chunks.size() >= 3);
    if (TotalSize(data_map_) >= 3 * kDefaultChunkSize) {
      // First 2 chunks must all be kDefaultChunkSize
      BOOST_ASSERT(data_map_->chunks[0].size == kDefaultChunkSize);
      BOOST_ASSERT(data_map_->chunks[1].size == kDefaultChunkSize);
      BOOST_ASSERT(current_position_ == 0);
      ByteArray temp(new byte[kDefaultChunkSize]);
      uint32_t length(kDefaultChunkSize);
      uint64_t position(0);
      ReadChunk(0, temp.get());
      PutToInitialChunks(reinterpret_cast<char*>(temp.get()), &length,  
                         &position);
      BOOST_ASSERT(current_position_ == kDefaultChunkSize);
      BOOST_ASSERT(length == 0);
      BOOST_ASSERT(current_position_ == kDefaultChunkSize);
      BOOST_ASSERT(current_position_ == kDefaultChunkSize);

      ReadChunk(1, temp.get());
      PutToInitialChunks(reinterpret_cast<char*>(temp.get()), &length,
                         &position);

      for (size_t i(0); i != 2; ++i) {
        uint32_t length(data_map_->chunks[i].size);
        uint64_t position(current_position_);
        PutToInitialChunks(reinterpret_cast<char*>(temp.get()), &length,
                           &position);

      }
      chunk0_modified_ = chunk1_modified_ = false;
    } else {
      uint32_t i(0);
      ByteArray temp(new byte[kDefaultChunkSize + kMinChunkSize - 1]);
      bool consumed_whole_chunk(true);
      while (i != static_cast<uint32_t>(data_map_->chunks.size()) &&
             consumed_whole_chunk) {
        ReadChunk(i, temp.get());
        uint32_t length(data_map_->chunks[i].size);
        uint64_t position(current_position_);
        uint32_t written =
            PutToInitialChunks(reinterpret_cast<char*>(temp.get()),
                               &length, &position);
        consumed_whole_chunk = (length == 0);
        if (!consumed_whole_chunk) {
          sequencer_.Add(reinterpret_cast<char*>(temp.get()) + written, length,
                         position);
        }
        chunk_store_->Delete(std::string(
            reinterpret_cast<char*>(data_map_->chunks[i].hash),
            crypto::SHA512::DIGESTSIZE));
        ++i;
      }
    }
  } else {
    uint32_t length(static_cast<uint32_t>(data_map_->content.size()));
    uint64_t position(0);
    PutToInitialChunks(data_map_->content.data(), &length, &position);
    data_map_->content.clear();
  }

  data_map_->complete = false;
}

uint32_t SelfEncryptor::PutToInitialChunks(const char *data,
                                           uint32_t *length,
                                           uint64_t *position) {
  uint32_t copy_length0(0);
  // Handle Chunk 0
  if (*position < kDefaultChunkSize) {
    copy_length0 =
        std::min(*length, kDefaultChunkSize - static_cast<uint32_t>(*position));
    memcpy(&chunk0_raw_[static_cast<uint32_t>(*position)], data, copy_length0);
    // Don't decrease current_position_ (could be a rewrite - this shouldn't
    // change current_position_).
    if (current_position_ < copy_length0)
      current_position_ = copy_length0;
    *length -= copy_length0;
    *position += copy_length0;
    chunk0_modified_ = true;
  }

  // Handle Chunk 1
  uint32_t copy_length1(0);
  if ((*position >= kDefaultChunkSize) && (*position < 2 * kDefaultChunkSize)) {
    copy_length1 = std::min(*length,
        (2 * kDefaultChunkSize) - static_cast<uint32_t>(*position));
    memcpy(&chunk1_raw_[static_cast<uint32_t>(*position - kDefaultChunkSize)],
           data + copy_length0, copy_length1);
    // Don't decrease current_position_ (could be a rewrite - this shouldn't
    // change current_position_).
    if (current_position_ < kDefaultChunkSize + copy_length1)
      current_position_ = kDefaultChunkSize + copy_length1;
    *length -= copy_length1;
    *position += copy_length1;
    chunk1_modified_ = true;
  }

  return copy_length0 + copy_length1;
}

bool SelfEncryptor::GetDataOffsetForEnqueuing(const uint32_t &length,
                                              const uint64_t &position,
                                              uint32_t *data_offset,
                                              uint32_t *queue_offset) {
  // Cover most common case first
  if (position == current_position_) {
    *data_offset = 0;
    *queue_offset =
        static_cast<uint32_t>(current_position_ - queue_start_position_);
    return true;
  }

  if (length == 0)
    return false;

  if (position < queue_start_position_) {
    // We don't care if this overflows as in this case we return false
    *data_offset = static_cast<uint32_t>(queue_start_position_ - position);
    *queue_offset = 0;
    return (position + length >= queue_start_position_);
  }

  *data_offset = 0;
  // We don't care if this overflows as in this case we return false
  *queue_offset = static_cast<uint32_t>(position - queue_start_position_);
  return (position <= queue_start_position_ + kQueueCapacity_);
}

void SelfEncryptor::PutToEncryptQueue(const char *data,
                                      uint32_t length,
                                      uint32_t data_offset,
                                      uint32_t queue_offset) {
  length -= data_offset;
  uint32_t copy_length =
      std::min(length, kQueueCapacity_ - retrievable_from_queue_);
  while (copy_length != 0) {
    memcpy(&main_encrypt_queue_[queue_offset], data + data_offset, copy_length);
    retrievable_from_queue_ += copy_length;
    current_position_ += copy_length;
    if (retrievable_from_queue_ == kQueueCapacity_)
      ProcessMainQueue(kDefaultChunkSize, 0);
    data_offset += copy_length;
    queue_offset = kDefaultChunkSize;
    length -= copy_length;
    copy_length = std::min(length, kDefaultByteArraySize_);
  }
}

bool SelfEncryptor::GetLengthForSequencer(const uint64_t &position,
                                          uint32_t *length) {
  if (*length == 0)
    return false;
  BOOST_ASSERT(position >= 2 * kDefaultChunkSize);
  if (position < queue_start_position_) {
    *length = static_cast<uint32_t>(std::min(static_cast<uint64_t>(*length),
                                             queue_start_position_ - position));
    return true;
  }
  return (position > queue_start_position_ + kQueueCapacity_);
}

void SelfEncryptor::AddReleventSeqDataToQueue() {
  SequenceData extra(sequencer_.Get(current_position_));
  if (extra.second != 0) {
    PutToEncryptQueue(reinterpret_cast<char*>(extra.first[0]), extra.second, 0,
                      static_cast<uint32_t>(current_position_ -
                                            queue_start_position_));
  }
}

void SelfEncryptor::ReadChunk(uint32_t chunk_num, byte *data) {
//  if ((data_map_->chunks.size() < chunk_num) ||
//      (data_map_->chunks.size() == 0)) {
  if (data_map_->chunks.size() < chunk_num) {
    read_ok_ = false;
    return;
  }

  // still in process of writing so read raw arrays
  if (chunk_one_two_q_full_ && (chunk_num < 2)) {
    if (chunk_num == 0) {
      for (uint32_t i = 0; i != c0_and_1_chunk_size_; ++i)
        data[i] = static_cast<byte>(chunk0_raw_[i]);
    } else {
      for (uint32_t i = 0; i != c0_and_1_chunk_size_; ++i)
        data[i] = static_cast<byte>(chunk1_raw_[i]);
    }
    return;
  }

  std::string hash(reinterpret_cast<char*>(data_map_->chunks[chunk_num].hash),
                   crypto::SHA512::DIGESTSIZE);
  uint32_t length = data_map_->chunks[chunk_num].size;
  ByteArray pad(new byte[(3 * crypto::SHA512::DIGESTSIZE) -
                         crypto::AES256_KeySize - crypto::AES256_IVSize]);
  ByteArray key(new byte[crypto::AES256_KeySize]);
  ByteArray iv(new byte[crypto::AES256_IVSize]);
  GetPadIvKey(chunk_num, key, iv, pad);
  std::string content;
#pragma omp critical
  {  // NOLINT (Fraser)
    content = chunk_store_->Get(hash);
  }

  if (content.empty()) {
    DLOG(ERROR) << "Could not find chunk number : " << chunk_num
                << " which is " << EncodeToHex(hash);
    read_ok_ = false;
    return;
  }

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(
      key.get(), crypto::AES256_KeySize, iv.get());
//   CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(),
//       crypto::AES256_KeySize, iv.get());
//           CryptoPP::StringSource filter(content, true,
//             new XORFilter(
//             new CryptoPP::StreamTransformationFilter(decryptor,
//               new CryptoPP::MessageQueue),
//             pad.get()));
  CryptoPP::StringSource filter(content, true,
      new XORFilter(
          new CryptoPP::StreamTransformationFilter(decryptor,
              new CryptoPP::Gunzip(new CryptoPP::MessageQueue())), pad.get()));
  filter.Get(data, length);
}

void SelfEncryptor::GetPadIvKey(uint32_t this_chunk_num,
                                ByteArray key,
                                ByteArray iv,
                                ByteArray pad) {
  uint32_t num_chunks = static_cast<uint32_t>(data_map_->chunks.size());
  uint32_t n_1_chunk = (this_chunk_num + num_chunks - 1) % num_chunks;
  uint32_t n_2_chunk = (this_chunk_num + num_chunks - 2) % num_chunks;

  for (uint32_t i = 0; i != crypto::AES256_KeySize; ++i)
    key[i] = data_map_->chunks[n_1_chunk].pre_hash[i];
  for (uint32_t i = 0; i != crypto::AES256_IVSize; ++i)
    iv[i] = data_map_->chunks[n_1_chunk].pre_hash[i + crypto::AES256_KeySize];

  for (uint32_t i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
    pad[i] = data_map_->chunks[n_1_chunk].pre_hash[i];
    pad[i + crypto::SHA512::DIGESTSIZE] =
        data_map_->chunks[this_chunk_num].pre_hash[i];
  }

  uint32_t pad_offset(2 * crypto::SHA512::DIGESTSIZE);
  uint32_t hash_offset(crypto::AES256_KeySize + crypto::AES256_IVSize);
  for (uint32_t i = 0; i != crypto::AES256_IVSize; ++i) {
    pad[i + pad_offset] =
        data_map_->chunks[n_2_chunk].pre_hash[i + hash_offset];
  }
}

//bool SelfEncryptor::AttemptProcessQueue() {
//  // Do not queue chunks 0 and 1 till we know we have enough for 3 chunks
//  if ((retrievable_from_queue_ >= chunk_size_ * 3) && !chunk_one_two_q_full_)
//    QueueC0AndC1();
//
//  uint32_t bytes_to_process(ignore_threads_ ? chunk_size_ :
//                            kDefaultByteArraySize_);
//
//  if ((retrievable_from_queue_ >= bytes_to_process) && chunk_one_two_q_full_)
//    ProcessMainQueue();
//
//  return true;
//}
//
//bool SelfEncryptor::QueueC0AndC1() {
//  c0_and_1_chunk_size_ = chunk_size_;
//  // Chunk 0
//  main_encrypt_queue_.Get(chunk0_raw_.get(), chunk_size_);
//  ChunkDetails chunk_data;
//  CryptoPP::SHA512().CalculateDigest(chunk_data.pre_hash,
//                                     chunk0_raw_.get(),
//                                     chunk_size_);
//  chunk_data.size = chunk_size_;
//  data_map_->chunks.push_back(chunk_data);
//
//  // Chunk 1
//  main_encrypt_queue_.Get(chunk1_raw_.get(), chunk_size_);
//  ChunkDetails chunk_data2;
//  CryptoPP::SHA512().CalculateDigest(chunk_data2.pre_hash,
//                                     chunk1_raw_.get() ,
//                                     chunk_size_);
//  chunk_data2.size = chunk_size_;
//  data_map_->chunks.push_back(chunk_data2);
//  chunk_one_two_q_full_ = true;
//  return true;
//}

bool SelfEncryptor::ProcessMainQueue(const uint32_t &chunk_size,
                                     const uint64_t &last_chunk_position) {
  if (retrievable_from_queue_ < chunk_size || chunk_size == 0)
    return false;

  uint32_t chunks_to_process(0);
  if (queue_start_position_ + retrievable_from_queue_ >= last_chunk_position) {
    chunks_to_process = static_cast<uint32_t>(
        (last_chunk_position - queue_start_position_) / chunk_size);
    BOOST_ASSERT((last_chunk_position-queue_start_position_) % chunk_size == 0);
  } else {
    chunks_to_process = (retrievable_from_queue_ / chunk_size) - 1;
  }

  uint32_t first_queue_chunk_index =
      static_cast<uint32_t>(queue_start_position_ / chunk_size);
  data_map_->chunks.resize(first_queue_chunk_index + chunks_to_process);

//#pragma omp parallel for
//  for (uint32_t i = 0; i < chunks_to_process; ++i) {
//    CryptoPP::SHA512().CalculateDigest(
//        data_map_->chunks[first_queue_chunk_index + i].pre_hash,
//        main_encrypt_queue_.get() + (i * chunk_size),
//        chunk_size);
//  }

// check for repeated content
// TODO(dirvine) FIXME ( needs tested )

//   for(uint32_t i = 0; i < chunks_to_process; ++i) {
//     if ((data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i + old_dm_size].pre_hash) &&
//       (data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i -1 + old_dm_size].pre_hash) &&
//       (data_map_->chunks[i + old_dm_size].pre_hash ==
//       data_map_->chunks[i -2 + old_dm_size].pre_hash)) {
//       if (i == 2) { // only encrypt chunk 2
//         EncryptAChunk(i + old_dm_size, &chunk_vec[i][0], chunk_size_, false);
//       } else {
//         for (int j =0; j != crypto::SHA512::DIGESTSIZE; ++j)
//           data_map_->chunks[i + old_dm_size].hash[j] =
//           data_map_->chunks[i - 1 + old_dm_size].hash[j];
//       }
//     }
//   }
#pragma omp parallel for
  for (uint32_t i = 0; i < chunks_to_process; ++i) {
    EncryptChunk(first_queue_chunk_index + i,
                 main_encrypt_queue_.get() + (i * chunk_size),
                 chunk_size);
  }
  memcpy(main_encrypt_queue_.get(),
         main_encrypt_queue_.get() + (chunks_to_process * chunk_size),
         chunk_size);
  queue_start_position_ += retrievable_from_queue_ - chunk_size;
  retrievable_from_queue_ = chunk_size;
  return true;
}

void SelfEncryptor::EncryptChunk(uint32_t chunk_num,
                                 byte *data,
                                 uint32_t length) {
  BOOST_ASSERT(data_map_->chunks.size() > chunk_num);
  bool re_encrypt(data_map_->chunks[chunk_num].size != 0);

  if (re_encrypt) {
#pragma omp critical
    {  // NOLINT (Fraser)
      std::string old_hash(reinterpret_cast<char*>(
              data_map_->chunks[chunk_num].hash), crypto::SHA512::DIGESTSIZE);
      if (!chunk_store_->Delete(old_hash))
        DLOG(ERROR) << "Failed to delete chunk " << EncodeToHex(old_hash);
    }
  }

  CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].pre_hash,
                                     data, length);

  ByteArray pad(new byte[(3 * crypto::SHA512::DIGESTSIZE) -
                         crypto::AES256_KeySize - crypto::AES256_IVSize]);
  ByteArray key(new byte[crypto::AES256_KeySize]);
  ByteArray iv(new byte[crypto::AES256_IVSize]);
  GetPadIvKey(chunk_num, key, iv, pad);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(
      key.get(), crypto::AES256_KeySize, iv.get());

  std::string chunk_content;
  CryptoPP::Gzip aes_filter(new CryptoPP::StreamTransformationFilter(encryptor,
                                new XORFilter(
                                    new CryptoPP::StringSink(chunk_content),
                                    pad.get())), 6);
  aes_filter.Put2(data, length, -1, true);

  CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].hash,
      const_cast<byte*>(reinterpret_cast<const byte*>(chunk_content.c_str())),
      chunk_content.size());

  std::string post_hash(reinterpret_cast<char*>(
      data_map_->chunks[chunk_num].hash), crypto::SHA512::DIGESTSIZE);
#pragma omp critical
  {  // NOLINT (Fraser)
    if (!chunk_store_->Store(post_hash, chunk_content))
      DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash);
  }

  data_map_->chunks[chunk_num].size = length;  // keep pre-compressed length
}

void SelfEncryptor::Flush() {
  if (!prepared_for_writing_)
    return;
  // TODO(dirvine)
    // check if chunks exists that the sequencer should write to
    // i.e. get data map parameters and keep these chunks.num current size etc.
    // as we empty sequencer we grab chunks worth at time and encrypt that chunk
    // we need to check whether we have data for next chunks to encrypt next2
    // so read->chunk / alter / encrypt chunk / enc next 2 (unless ...)
    // divide num chunks with / chunks_size to get current floor
    // floor + chunk_size_ is this range !!
//  uint32_t last_seq_length;
//  uint64_t last_seq_pos = sequencer_.PeekLast(&last_seq_length);

//  uint64_t total_size(last_seq_pos + last_seq_length);
//  uint32_t last_chunk_num(static_cast<uint32_t>(total_size / chunk_size_));
     // after this set current_position_ and q - process last

  uint64_t file_size, last_chunk_position;
  uint32_t normal_chunk_size;
  CalculateSizes(&file_size, &normal_chunk_size, &last_chunk_position);
  ProcessMainQueue(normal_chunk_size, last_chunk_position);  // Queue now only
                                                             // contains 1 chunk
  uint64_t flush_position(2 * normal_chunk_size);
  uint32_t chunk_index(2);
  bool pre_pre_chunk_modified(chunk0_modified_);
  bool pre_chunk_modified(chunk1_modified_);
  bool this_chunk_modified(false);
  bool this_chunk_has_data_in_sequencer(false);
  bool this_chunk_has_data_in_queue(false);

  std::pair<uint64_t, SequenceData> sequence_block(sequencer_.GetFirst());
  uint64_t sequence_block_position(sequence_block.first);
  ByteArray sequence_block_data(sequence_block.second.first);
  uint32_t sequence_block_size(sequence_block.second.second);
  uint32_t sequence_block_copied(0);

  ByteArray chunk_array(new byte[kDefaultChunkSize + kMinChunkSize]);

  while (flush_position <= last_chunk_position) {
    memset(chunk_array.get(), 0, kDefaultChunkSize + kMinChunkSize);
    if (sequence_block_position < flush_position + kDefaultChunkSize) {
      this_chunk_has_data_in_sequencer = true;
      this_chunk_modified = true;
    }

    if (flush_position == queue_start_position_) {
      this_chunk_has_data_in_queue = true;
      this_chunk_modified = true;
    }

    BOOST_ASSERT(!(this_chunk_has_data_in_sequencer &&
                 this_chunk_has_data_in_queue));

    // Read in any data from previously-encrypted chunk
    if (chunk_index < data_map_->chunks.size() &&
        (pre_pre_chunk_modified || pre_chunk_modified || this_chunk_modified)) {
      ReadChunk(chunk_index, chunk_array.get());
      chunk_store_->Delete(std::string(
          reinterpret_cast<char*>(data_map_->chunks[chunk_index].hash),
          crypto::SHA512::DIGESTSIZE));
    }

    // Overwrite with any data from sequencer
    if (this_chunk_has_data_in_sequencer) {
      while (sequence_block_position + sequence_block_copied <
             flush_position + kDefaultChunkSize) {
        uint32_t copy_size(std::min(sequence_block_size - sequence_block_copied,
            static_cast<uint32_t>(flush_position + kDefaultChunkSize -
                sequence_block_position + sequence_block_copied)));
        memcpy(chunk_array.get() + sequence_block_position - flush_position,
               sequence_block_data.get(), copy_size);
        if (copy_size == sequence_block_size) {
          sequence_block = sequencer_.GetFirst();
          sequence_block_position = sequence_block.first;
          sequence_block_data = sequence_block.second.first;
          sequence_block_size = sequence_block.second.second;
          sequence_block_copied = 0;
        } else {
          sequence_block_copied += copy_size;
        }
      }
    } else if (this_chunk_has_data_in_queue) {
      // Overwrite with any data in queue
      memcpy(chunk_array.get(), main_encrypt_queue_.get(),
             retrievable_from_queue_);
      queue_start_position_ += retrievable_from_queue_;
      retrievable_from_queue_ = 0;
    }

    if (pre_pre_chunk_modified || pre_chunk_modified || this_chunk_modified)
      EncryptChunk(chunk_index, chunk_array.get(), normal_chunk_size);

    flush_position += normal_chunk_size;
    ++chunk_index;
    pre_pre_chunk_modified = pre_chunk_modified;
    pre_chunk_modified = this_chunk_modified;
    this_chunk_modified = false;
  }

  BOOST_ASSERT(flush_position == file_size);

  if (pre_pre_chunk_modified || pre_chunk_modified || chunk0_modified_)
    EncryptChunk(0, chunk0_raw_.get(), normal_chunk_size);

  pre_pre_chunk_modified = pre_chunk_modified;
  pre_chunk_modified = chunk0_modified_;

  if (pre_pre_chunk_modified || pre_chunk_modified || chunk1_modified_)
    EncryptChunk(1, chunk1_raw_.get(), normal_chunk_size);
}

void SelfEncryptor::CalculateSizes(uint64_t *file_size,
                                   uint32_t *normal_chunk_size,
                                   uint64_t *last_chunk_position) {
  *file_size = std::max(sequencer_.GetEndPosition(),
                        std::max(current_position_, TotalSize(data_map_)));
  if (*file_size < kMinChunkSize) {
    *normal_chunk_size = 0;
    *last_chunk_position = std::numeric_limits<uint64_t>::max();
  } else {
    if (*file_size < 3 * kDefaultChunkSize) {
      *normal_chunk_size = static_cast<uint32_t>(*file_size) / 3;
      *last_chunk_position = 2 * *normal_chunk_size;
    } else {
      *normal_chunk_size = kDefaultChunkSize;
      uint32_t chunk_count_excluding_last =
          static_cast<uint32_t>(*file_size / kDefaultChunkSize);
      if (*file_size % kDefaultChunkSize < kMinChunkSize) {
        --chunk_count_excluding_last;
        *last_chunk_position = chunk_count_excluding_last * kDefaultChunkSize;
      }
    }
  }
}

//bool SelfEncryptor::WriteExtraAndEnc0and1() {
//  if (retrievable_from_queue_ != 0) {
//    ByteArray i(new byte[retrievable_from_queue_]);
////    main_encrypt_queue_.Get(i.get(), retrievable_from_queue_);
//    std::string extra(reinterpret_cast<char*>(i.get()),
//                      retrievable_from_queue_);
//    data_map_->content = extra;
//  }
//  // when all that is done, encrypt chunks 0 and 1
//  if (chunk_one_two_q_full_) {
//#pragma omp sections
//    {  // NOLINT (Fraser)
//#pragma omp section
//      {  // NOLINT (Fraser)
//        EncryptAChunk(0, chunk0_raw_.get(), c0_and_1_chunk_size_, false);
//      }
//#pragma omp section
//      {  // NOLINT (Fraser)
//        EncryptAChunk(1, chunk1_raw_.get(), c0_and_1_chunk_size_, false);
//      }
//    }
//
//    chunk0_raw_.reset();
//    chunk1_raw_.reset();
//    chunk_one_two_q_full_ = false;
//  }
////  main_encrypt_queue_.SkipAll();
//  data_map_->complete = true;
//  return true;
//}

bool SelfEncryptor::Read(char* data, uint32_t length, uint64_t position) {
  uint32_t maxbuffersize = kDefaultByteArraySize_;
  uint32_t cachesize =
      static_cast<uint32_t>(std::min(TotalSize(data_map_),
                                     static_cast<uint64_t>(maxbuffersize)));

  if (length < cachesize) {
    //  required -
    //  cache already populated and
    //  requested position not less than cache start and
    //  requested position not greater than cache end and
    //  enough info in cache to fulfil request
    if (cache_ &&
        (position > cache_initial_posn_) &&
        (cache_initial_posn_ + cachesize > position) &&
        ((cachesize - (position - cache_initial_posn_)) >= length)) {
      // read data_cache_
      for (uint32_t i = 0; i != length; ++i) {
        BOOST_ASSERT(position - cache_initial_posn_ + i <=
                     std::numeric_limits<uint32_t>::max());
        data[i] = data_cache_[static_cast<uint32_t>(position -
                              cache_initial_posn_) + i];
      }
    } else {
      // populate data_cache_ and read
      Transmogrify(data_cache_.get(), cachesize, position, false);
      cache_initial_posn_ = position;
      for (uint32_t i = 0; i != length; ++i)
        data[i] = data_cache_[i];
      cache_ = true;
    }
  } else {
    // length requested larger than cache size, just go ahead and read
    Transmogrify(data, length, position, false);
  }
  return true;
}

bool SelfEncryptor::Transmogrify(char *data,
                                 uint32_t length,
                                 uint64_t position,
                                 bool /*writing*/) {
  // TODO(JLB) :  ensure that on rewrite, if data is being written to area
  //              currently held in cache, then cache is refreshed after write.
  //              Transmogrify(data_cache_.get(), kDefaultByteArraySize_,
  //                           cache_initial_posn_, false)
  uint64_t run_total(0), all_run_total(0);
  uint32_t start_offset(0), end_cut(0), start_chunk(0), end_chunk(0);
  bool found_start(false);
  bool found_end(false);
  uint32_t num_chunks = static_cast<uint32_t>(data_map_->chunks.size());

  if (num_chunks != 0) {
    for (uint32_t i = 0; i != num_chunks; ++i) {
      if (found_start)
        run_total += data_map_->chunks[i].size;

      if (((all_run_total + data_map_->chunks[i].size) > position) &&
          !found_start) {
        start_chunk = i;
        start_offset = static_cast<uint32_t>(position - all_run_total);
        run_total = all_run_total + data_map_->chunks[i].size - position;
        found_start = true;
      }

      if (run_total >= length) {
        found_end = true;
        end_chunk = i;
        end_cut = length + static_cast<uint32_t>(position - all_run_total);
               // all_run_total - position - length
        break;
      }
      all_run_total += data_map_->chunks[i].size;
    }

    if (!found_end) {
      end_chunk = num_chunks - 1;
      end_cut = static_cast<uint32_t>(
          std::min(position + length -
                   (all_run_total - data_map_->chunks[end_chunk].size),
                   static_cast<uint64_t>(data_map_->chunks[end_chunk].size)));
    }
// this is 2 for loops to allow openmp to thread properly.
// should be refactored to a do loop and openmp fixed
//     if (chunk_one_two_q_full_) {
//      // don't try and get these chunks they're in a q
//      if ((start_chunk < 2) && (end_chunk < 2)) {
//       ReadInProcessData(data, length, position);
//       return true;
//      }
//     }

    if (start_chunk == end_chunk) {
      // get chunk
      ByteArray chunk_data(new byte[data_map_->chunks[start_chunk].size]);
      ReadChunk(start_chunk, chunk_data.get());
      for (uint32_t i = start_offset; i != length + start_offset; ++i)
        data[i - start_offset] = static_cast<char>(chunk_data[i]);
      return read_ok_;
    }

#pragma omp parallel for shared(data)
    for (uint32_t i = start_chunk; i <= end_chunk; ++i) {
      uint64_t pos(0);
      uint32_t this_chunk_size(data_map_->chunks[i].size);

      if (i == start_chunk) {
        if (start_offset != 0) {
          ByteArray chunk_data(new byte[data_map_->chunks[start_chunk].size]);
          ReadChunk(start_chunk, chunk_data.get());
          for (uint32_t j = start_offset; j != this_chunk_size; ++j)
            data[j - start_offset] = static_cast<char>(chunk_data[j]);
        } else {
          ReadChunk(i, reinterpret_cast<byte*>(&data[0]));
        }
      } else if (i == end_chunk) {
        ByteArray chunk_data(new byte[data_map_->chunks[end_chunk].size]);
        ReadChunk(end_chunk, chunk_data.get());

        for (uint32_t j = 0; j != i; ++j)
#pragma omp atomic
          pos += data_map_->chunks[j].size;

        for (uint32_t j = 0; j != end_cut; ++j)
          data[j + pos - position] = static_cast<char>(chunk_data[j]);

      } else {
        for (uint32_t j = 0; j != i; ++j)
#pragma omp atomic
          pos += data_map_->chunks[j].size;

        ReadChunk(i, reinterpret_cast<byte*>(&data[pos - position]));
      }
    }
  }

  uint64_t this_position(0);
#pragma omp barrier
  for (uint32_t i = 0; i != num_chunks; ++i)
    this_position += data_map_->chunks[i].size;

  for (size_t i = 0; i != data_map_->content.size(); ++i) {
    if ((this_position + i) < (position + length)) {
      data[static_cast<size_t>(this_position - position) + i] =
          data_map_->content.c_str()[i];
    }
  }
  // replace any chunk data with most recently written stuff
  ReadInProcessData(data, length, position);
  return read_ok_;
}

void SelfEncryptor::ReadInProcessData(char *data,
                                      uint32_t length,
                                      uint64_t position) {
                                                          // TODO(Fraser#5#): 2011-09-15 - check Chunks 0 and 1

  // check queue
  if (retrievable_from_queue_ != 0)  {
    uint32_t data_offset(0), queue_offset(0), copy_length(0);
    if ((position < queue_start_position_ + retrievable_from_queue_) &&
        (position + length > queue_start_position_)) {
      if (position < queue_start_position_)
        data_offset = static_cast<uint32_t>(queue_start_position_ - position);
      else
        queue_offset = static_cast<uint32_t>(position - queue_start_position_);
      copy_length = std::min(length - data_offset,
                             retrievable_from_queue_ - queue_offset);
    }
    memcpy(data + data_offset, &main_encrypt_queue_[queue_offset], copy_length);
  }

  if (!sequencer_.empty()) {
    SequenceData answer = sequencer_.Peek(position);
    for (uint32_t i = 0; i != answer.second; ++i) {
      data[i] = answer.first[i];
    }
  }
}

bool SelfEncryptor::DeleteAllChunks() {
  for (uint32_t i = 0; i != static_cast<uint32_t>(data_map_->chunks.size());
       ++i) {
    if (!chunk_store_->Delete(reinterpret_cast<char*>(
                              data_map_->chunks[i].hash)))
      return false;
  }
  data_map_->chunks.clear();
  return true;
}

bool SelfEncryptor::Truncate(uint64_t size) {
  uint64_t byte_count(0);
  uint32_t number_of_chunks(static_cast<uint32_t>(data_map_->chunks.size()));
//  bool delete_remainder(false), found_end(false);
  // if (data_map_->complete) {
    // Assume size < data_map.size
    for (uint32_t i = 0; i != number_of_chunks; ++i) {
      uint32_t chunk_size = data_map_->chunks[i].size;
      byte_count += chunk_size;
      if (byte_count > size) {
        // Found chunk with data at position 'size'.
        if (retrievable_from_queue_ != 0)
//          main_encrypt_queue_.SkipAll();
        sequencer_.Clear();
        for (uint32_t j = i + 1; j != number_of_chunks; ++j) {
          if (!chunk_store_->Delete(reinterpret_cast<char*>
                                      (data_map_->chunks[j].hash))) {
            DLOG(ERROR) << "Failed to delete chunk";
            return false;
          }
          data_map_->chunks.pop_back();
        }
        if (byte_count - size == chunk_size) {
          if (!chunk_store_->Delete(reinterpret_cast<char*>
                                      (data_map_->chunks[i].hash))) {
            DLOG(ERROR) << "Failed to delete chunk";
            return false;
          }
          data_map_->chunks.pop_back();
        } else {
          std::shared_ptr<byte> data(new byte[chunk_size]);
          ReadChunk(i, data.get());
          BOOST_ASSERT(byte_count - size <= chunk_size);
//          uint32_t bytes_to_queue(chunk_size -
//                                  static_cast<uint32_t>(byte_count - size));
//          main_encrypt_queue_.Put2(data.get(), bytes_to_queue, 0, true);
          if (!chunk_store_->Delete(reinterpret_cast<char*>
                                      (data_map_->chunks[i].hash))) {
            DLOG(ERROR) << "Failed to delete chunk";
            return false;
          }
          data_map_->chunks.pop_back();
        }
        current_position_ = size;
        data_map_->content.erase();
        data_map_->complete = false;
        return true;
      }
    }
    // Check data map content.

  // } else {
//    if (delete_remainder == true) {
//      sequencer_.EraseAll();
//      main_encrypt_queue_.SkipAll();
//    } else {
//      // check content
//    else
//      //check queue;
//    else
//      //check sequencer
//      if (size <= retrievable_from_queue_) {
//
//      }
//    }
  // }
  return true;
}

}  // namespace encrypt
}  // namespace maidsafe
