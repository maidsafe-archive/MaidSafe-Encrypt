
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
#include <utility>

#ifdef __MSVC__
#  pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
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

namespace {

uint64_t TotalSize(DataMapPtr data_map, const uint32_t &normal_chunk_size) {
  if (!data_map->content.empty())
    return data_map->content.size();

  if (data_map->chunks.empty())
    return 0;

  return ((data_map->chunks.size() - 1) * normal_chunk_size) +
          (*data_map->chunks.rbegin()).size;
}

class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *pad = NULL)
      : pad_(pad), count_(0) { CryptoPP::Filter::Detach(attachment); }
  size_t Put2(const byte* in_string,
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
  bool IsolatedFlush(bool, bool) { return false; }
 private:
  XORFilter &operator = (const XORFilter&);
  XORFilter(const XORFilter&);
  byte *pad_;
  size_t count_;
};

}  // unnamed namespace


SelfEncryptor::SelfEncryptor(DataMapPtr data_map,
                             std::shared_ptr<ChunkStore> chunk_store,
                             int num_procs)
    : data_map_(data_map ? data_map : DataMapPtr(new DataMap)),
      sequencer_(),
      kDefaultByteArraySize_(num_procs == 0 ?
                             kDefaultChunkSize * omp_get_num_procs() :
                             kDefaultChunkSize * num_procs),
      file_size_(0),
      last_chunk_position_(0),
      normal_chunk_size_(0),
      main_encrypt_queue_(),
      queue_start_position_(2 * kDefaultChunkSize),
      kQueueCapacity_(kDefaultByteArraySize_ + kDefaultChunkSize),
      retrievable_from_queue_(0),
      chunk0_raw_(),
      chunk1_raw_(),
      chunk_store_(chunk_store),
      current_position_(0),
      prepared_for_writing_(false),
      chunk0_modified_(true),
      chunk1_modified_(true),
      read_ok_(true),
      read_cache_(),
      cache_start_position_(0),
      prepared_for_reading_() {
  if (data_map) {
    if (data_map->chunks.empty()) {
      file_size_ = data_map->content.size();
      last_chunk_position_ = std::numeric_limits<uint64_t>::max();
      normal_chunk_size_ = 0;
    } else {
      file_size_ = (data_map->chunks.empty() ? data_map->content.size() : 0);
      std::for_each(data_map->chunks.begin(), --data_map->chunks.end(),
                    [=] (ChunkDetails chunk) { file_size_ += chunk.size; });
      last_chunk_position_ = file_size_;
      file_size_ += (*data_map->chunks.rbegin()).size;
      normal_chunk_size_ = (*data_map->chunks.begin()).size;
    }
  }
}

SelfEncryptor::~SelfEncryptor() {
  Flush();
}

bool SelfEncryptor::Write(const char *data,
                          uint32_t length,
                          uint64_t position) {
  if (length == 0)
    return true;

  PrepareToWrite();
  PutToReadCache(data, length, position);

  if (position + length > file_size_) {
    file_size_ = position + length;
    CalculateSizes(false);
  }

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

  normal_chunk_size_ = kDefaultChunkSize;
  if (data_map_->content.empty()) {
    BOOST_ASSERT(data_map_->chunks.empty() || data_map_->chunks.size() >= 3);
    if (TotalSize(data_map_, normal_chunk_size_) >= 3 * kDefaultChunkSize) {
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
        data_map_->chunks[i].size = 0;
        ++i;
      }
    }
  } else {
    uint32_t length(static_cast<uint32_t>(data_map_->content.size()));
    uint64_t position(0);
    PutToInitialChunks(data_map_->content.data(), &length, &position);
    data_map_->content.clear();
  }

  prepared_for_writing_ = true;
}

void SelfEncryptor::PutToReadCache(const char *data,
                                   const uint32_t &length,
                                   const uint64_t &position) {
  if (!prepared_for_reading_)
    return;
  if (position < cache_start_position_ + kDefaultByteArraySize_ &&
      position + length >= cache_start_position_) {
    uint32_t data_offset(0), cache_offset(0);
    uint32_t copy_size(length);
    if (position < cache_start_position_) {
      data_offset = static_cast<uint32_t>(cache_start_position_ - position);
      copy_size -= data_offset;
    } else {
      cache_offset = static_cast<uint32_t>(position - cache_start_position_);
    }
    copy_size = std::min(copy_size, kDefaultByteArraySize_ - cache_offset);
    memcpy(read_cache_.get() + cache_offset, data + data_offset, copy_size);
  }
}

void SelfEncryptor::CalculateSizes(bool force) {
  if (normal_chunk_size_ != kDefaultChunkSize || force) {
    if (file_size_ < 3 * kMinChunkSize) {
      normal_chunk_size_ = 0;
      last_chunk_position_ = std::numeric_limits<uint64_t>::max();
      return;
    } else if (file_size_ < 3 * kDefaultChunkSize) {
      normal_chunk_size_ = static_cast<uint32_t>(file_size_) / 3;
      last_chunk_position_ = 2 * normal_chunk_size_;
      return;
    }
    normal_chunk_size_ = kDefaultChunkSize;
  }
  uint32_t chunk_count_excluding_last =
      static_cast<uint32_t>(file_size_ / kDefaultChunkSize);
  if (file_size_ % kDefaultChunkSize < kMinChunkSize)
    --chunk_count_excluding_last;
  last_chunk_position_ = chunk_count_excluding_last * kDefaultChunkSize;
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
    if (current_position_ < *position + copy_length0)
      current_position_ = *position + copy_length0;
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
    if (current_position_ < *position + copy_length1)
      current_position_ = *position + copy_length1;
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
    return current_position_ >= queue_start_position_;
  }

  if (length == 0)
    return false;

  if (position < queue_start_position_) {
    // We don't care if this overflows as in this case we return false
    *data_offset = static_cast<uint32_t>(queue_start_position_ - position);
    *queue_offset = 0;
    return (position + length >= queue_start_position_);
  }
  return false;
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
      ProcessMainQueue();
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
  if (position + *length < queue_start_position_) {
    *length = static_cast<uint32_t>(std::min(static_cast<uint64_t>(*length),
                                             queue_start_position_ - position));
    return true;
  }
  return (position > queue_start_position_ + retrievable_from_queue_);
}

void SelfEncryptor::AddReleventSeqDataToQueue() {
  SequenceData extra(sequencer_.Get(current_position_));
  if (extra.second != 0) {
    PutToEncryptQueue(reinterpret_cast<char*>(extra.first.get()), extra.second,
                      0, static_cast<uint32_t>(current_position_ -
                                               queue_start_position_));
  }
}

void SelfEncryptor::ReadChunk(uint32_t chunk_num, byte *data) {
  if (data_map_->chunks.size() <= chunk_num) {
    read_ok_ = false;
    return;
  }

  // still in process of writing so read raw arrays
//   if (chunk_num < 2) {
//     if (chunk_num == 0) {
//       for (uint32_t i = 0; i != kDefaultChunkSize; ++i)
//         data[i] = static_cast<byte>(chunk0_raw_[i]);
//     } else {
//       for (uint32_t i = 0; i != kDefaultChunkSize; ++i)
//         data[i] = static_cast<byte>(chunk1_raw_[i]);
//     }
//     return;
//   }

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

  try {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(
        key.get(), crypto::AES256_KeySize, iv.get());
    CryptoPP::StringSource filter(content, true,
        new XORFilter(
            new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::Gunzip(new CryptoPP::MessageQueue)), pad.get()));
    filter.Get(data, length);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << e.what();
    read_ok_ = false;
  }
}

void SelfEncryptor::GetPadIvKey(uint32_t this_chunk_num,
                                ByteArray key,
                                ByteArray iv,
                                ByteArray pad) {
  uint32_t num_chunks = static_cast<uint32_t>(data_map_->chunks.size());
  uint32_t n_1_chunk = (this_chunk_num + num_chunks - 1) % num_chunks;
  uint32_t n_2_chunk = (this_chunk_num + num_chunks - 2) % num_chunks;
  // Chunks 0 and 1 aren't encrypted until all others are done - we need to get
  // their pre-encryption hashes here if required.
  if (prepared_for_writing_) {
    if (n_1_chunk == 0 || n_2_chunk == 0) {
      CryptoPP::SHA512().CalculateDigest(data_map_->chunks[0].pre_hash,
                                         chunk0_raw_.get(), normal_chunk_size_);
    }
    if (n_1_chunk == 1 || n_2_chunk == 1) {
      if (normal_chunk_size_ == kDefaultChunkSize) {
        CryptoPP::SHA512().CalculateDigest(data_map_->chunks[1].pre_hash,
                                           chunk1_raw_.get(),
                                           kDefaultChunkSize);
      } else if (normal_chunk_size_ * 2 <= kDefaultChunkSize) {
        // All of chunk 0 and chunk 1 data in chunk0_raw_.
        CryptoPP::SHA512().CalculateDigest(data_map_->chunks[1].pre_hash,
            chunk0_raw_.get() + normal_chunk_size_, normal_chunk_size_);
      } else {
        // Some at end of chunk0_raw_ and rest in start of chunk1_raw_.
        ByteArray temp(new byte[normal_chunk_size_]);
        uint32_t size_chunk0(kDefaultChunkSize - normal_chunk_size_);
        uint32_t size_chunk1(kDefaultChunkSize - size_chunk0);
        memcpy(temp.get(), chunk0_raw_.get() + normal_chunk_size_, size_chunk0);
        memcpy(temp.get() + size_chunk0, chunk1_raw_.get(), size_chunk1);
          CryptoPP::SHA512().CalculateDigest(data_map_->chunks[1].pre_hash,
                                             temp.get(), normal_chunk_size_);
      }
    }
  }

  memcpy(key.get(), &data_map_->chunks[n_2_chunk].pre_hash[0],
         crypto::AES256_KeySize);
  memcpy(iv.get(),
         &data_map_->chunks[n_2_chunk].pre_hash[crypto::AES256_KeySize],
         crypto::AES256_IVSize);
  memcpy(pad.get(), &data_map_->chunks[n_1_chunk].pre_hash[0],
         crypto::SHA512::DIGESTSIZE);
  memcpy(pad.get() + crypto::SHA512::DIGESTSIZE,
         &data_map_->chunks[this_chunk_num].pre_hash[0],
         crypto::SHA512::DIGESTSIZE);
  uint32_t hash_offset(crypto::AES256_KeySize + crypto::AES256_IVSize);
  memcpy(pad.get() + (2 * crypto::SHA512::DIGESTSIZE),
         &data_map_->chunks[n_2_chunk].pre_hash[hash_offset],
         crypto::SHA512::DIGESTSIZE - hash_offset);

//  for (uint32_t i = 0; i != crypto::AES256_KeySize; ++i)
//    key[i] = data_map_->chunks[n_2_chunk].pre_hash[i];
//  for (uint32_t i = 0; i != crypto::AES256_IVSize; ++i)
//    iv[i] = data_map_->chunks[n_2_chunk].pre_hash[i + crypto::AES256_KeySize];
//
//  for (uint32_t i = 0; i != crypto::SHA512::DIGESTSIZE; ++i) {
//    pad[i] = data_map_->chunks[n_1_chunk].pre_hash[i];
//    pad[i + crypto::SHA512::DIGESTSIZE] =
//        data_map_->chunks[this_chunk_num].pre_hash[i];
//  }
//
//  uint32_t pad_offset(2 * crypto::SHA512::DIGESTSIZE);
//  uint32_t hash_offset(crypto::AES256_KeySize + crypto::AES256_IVSize);
//  for (uint32_t i = 0; i != crypto::AES256_IVSize; ++i) {
//    pad[i + pad_offset] =
//        data_map_->chunks[n_2_chunk].pre_hash[i + hash_offset];
//  }
}

bool SelfEncryptor::ProcessMainQueue() {
  if (retrievable_from_queue_ < kDefaultChunkSize)
    return false;

  uint32_t chunks_to_process(0);
  if (queue_start_position_ + retrievable_from_queue_ > last_chunk_position_) {
    chunks_to_process = static_cast<uint32_t>(
        (last_chunk_position_ - queue_start_position_) / kDefaultChunkSize);
  } else {
    chunks_to_process = (retrievable_from_queue_ / kDefaultChunkSize) - 1;
  }
  BOOST_ASSERT((last_chunk_position_ - queue_start_position_) %
               kDefaultChunkSize == 0);

  uint32_t first_queue_chunk_index =
      static_cast<uint32_t>(queue_start_position_ / kDefaultChunkSize);
  data_map_->chunks.resize(first_queue_chunk_index + chunks_to_process);

// #pragma omp parallel for
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
// #pragma omp parallel for
  for (uint32_t i = 0; i < chunks_to_process; ++i) {
    EncryptChunk(first_queue_chunk_index + i,
                 main_encrypt_queue_.get() + (i * kDefaultChunkSize),
                 kDefaultChunkSize);
  }

  if (chunks_to_process != 0) {
    uint32_t move_size(retrievable_from_queue_ -
                       (chunks_to_process * kDefaultChunkSize));
    memcpy(main_encrypt_queue_.get(),
           main_encrypt_queue_.get() + (chunks_to_process * kDefaultChunkSize),
           move_size);
    queue_start_position_ += (chunks_to_process * kDefaultChunkSize);
    retrievable_from_queue_ -= (chunks_to_process * kDefaultChunkSize);
  }
  return true;
}

void SelfEncryptor::EncryptChunk(uint32_t chunk_num,
                                 byte *data,
                                 uint32_t length) {
  BOOST_ASSERT(data_map_->chunks.size() > chunk_num);

  if (data_map_->chunks[chunk_num].size != 0) {
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
  try {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(
        key.get(), crypto::AES256_KeySize, iv.get());

    std::string chunk_content;
    chunk_content.reserve(length);
    CryptoPP::Gzip aes_filter(
        new CryptoPP::StreamTransformationFilter(encryptor,
            new XORFilter(
              new CryptoPP::StringSink(chunk_content), pad.get())), 6);
    aes_filter.Put2(data, length, -1, true);

    CryptoPP::SHA512().CalculateDigest(data_map_->chunks[chunk_num].hash,
        const_cast<byte*>(reinterpret_cast<const byte*>(chunk_content.data())),
        chunk_content.size());

    std::string post_hash(reinterpret_cast<char*>(
        data_map_->chunks[chunk_num].hash), crypto::SHA512::DIGESTSIZE);
#pragma omp critical
    {  // NOLINT (Fraser)
      if (!chunk_store_->Store(post_hash, chunk_content))
        DLOG(ERROR) << "Could not store " << EncodeToHex(post_hash);
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << e.what();
  }

  data_map_->chunks[chunk_num].size = length;  // keep pre-compressed length
}

void SelfEncryptor::Flush() {
  if (!prepared_for_writing_)
    return;

  if (file_size_ < 3 * kMinChunkSize) {
    data_map_->content.assign(reinterpret_cast<char*>(chunk0_raw_.get()),
                              static_cast<size_t>(file_size_));
    return;
  }

  // Re-calculate normal_chunk_size_ and last_chunk_position_
  uint32_t normal_chunk_size_before_flush(normal_chunk_size_);
  uint64_t last_chunk_position_before_flush(last_chunk_position_);
  CalculateSizes(true);

  // Empty queue (after this call it will contain 0 or 1 chunks).
  ProcessMainQueue();

  uint64_t flush_position(2 * normal_chunk_size_);
  uint32_t chunk_index(2);
  bool pre_pre_chunk_modified(chunk0_modified_);
  bool pre_chunk_modified(chunk1_modified_);
  bool this_chunk_modified(false);
  bool this_chunk_has_data_in_sequencer(false);
  bool this_chunk_has_data_in_queue(false);
  bool this_chunk_has_data_in_c0_or_c1(false);

  std::pair<uint64_t, SequenceData> sequence_block(sequencer_.GetFirst());
  uint64_t sequence_block_position(sequence_block.first);
  ByteArray sequence_block_data(sequence_block.second.first);
  uint32_t sequence_block_size(sequence_block.second.second);
  uint32_t sequence_block_copied(0);

  ByteArray chunk_array(new byte[kDefaultChunkSize + kMinChunkSize]);
  const uint32_t kOldChunkCount(
      static_cast<uint32_t>(data_map_->chunks.size()));
  data_map_->chunks.resize(
      static_cast<uint32_t>(last_chunk_position_ / normal_chunk_size_) + 1);

  uint32_t this_chunk_size(normal_chunk_size_);
  while (flush_position <= last_chunk_position_) {
    if (chunk_index == data_map_->chunks.size() - 1) {  // on last chunk
      this_chunk_size =
          static_cast<uint32_t>(file_size_ - last_chunk_position_);
    }

    memset(chunk_array.get(), 0, kDefaultChunkSize + kMinChunkSize);
    if (sequence_block_position < flush_position + kDefaultChunkSize) {
      this_chunk_has_data_in_sequencer = true;
      this_chunk_modified = true;
    }

    if (flush_position == queue_start_position_) {
      this_chunk_has_data_in_queue = true;
      this_chunk_modified = true;
    } else if (flush_position < 2 * kDefaultChunkSize) {
      this_chunk_has_data_in_c0_or_c1 = true;
      this_chunk_modified = true;
    }

    // Read in any data from previously-encrypted chunk
    if (chunk_index < kOldChunkCount &&
        (pre_pre_chunk_modified || pre_chunk_modified || this_chunk_modified)) {
      ReadChunk(chunk_index, chunk_array.get());
      chunk_store_->Delete(std::string(
          reinterpret_cast<char*>(data_map_->chunks[chunk_index].hash),
          crypto::SHA512::DIGESTSIZE));
    }

    // Overwrite with any data in chunk0_raw_ and/or chunk1_raw_
    if (this_chunk_has_data_in_c0_or_c1) {
      uint32_t offset(static_cast<uint32_t>(flush_position));
      uint32_t size_in_chunk0(0);
      if (offset < kDefaultChunkSize) {  // in chunk 0
        size_in_chunk0 = std::min(kDefaultChunkSize - offset, this_chunk_size);
        memcpy(chunk_array.get(), chunk0_raw_.get() + offset, size_in_chunk0);
      }
      uint32_t size_in_chunk1(this_chunk_size - size_in_chunk0);
      if (size_in_chunk1 != 0) {  // in chunk 1
        memcpy(chunk_array.get() + size_in_chunk0, chunk1_raw_.get(),
               size_in_chunk1);
      }
    } else if (this_chunk_has_data_in_queue) {
      // Overwrite with any data in queue
      memcpy(chunk_array.get(), main_encrypt_queue_.get(),
             retrievable_from_queue_);
    }

    // Overwrite with any data from sequencer
    if (this_chunk_has_data_in_sequencer) {
      while (sequence_block_position + sequence_block_copied <
             flush_position + kDefaultChunkSize) {
        uint32_t copy_size(std::min(sequence_block_size - sequence_block_copied,
            static_cast<uint32_t>(flush_position + kDefaultChunkSize - (
                sequence_block_position + sequence_block_copied))));
        uint32_t copy_offset = kDefaultChunkSize - copy_size;
        memcpy(chunk_array.get() + copy_offset,
               sequence_block_data.get() + sequence_block_copied, copy_size);
        if (sequence_block_copied + copy_size == sequence_block_size) {
          sequence_block = sequencer_.GetFirst();
          sequence_block_position = sequence_block.first;
          sequence_block_data = sequence_block.second.first;
          sequence_block_size = sequence_block.second.second;
          sequence_block_copied = 0;
        } else {
          sequence_block_copied += copy_size;
        }
      }
    }

    if (pre_pre_chunk_modified || pre_chunk_modified || this_chunk_modified)
      EncryptChunk(chunk_index, chunk_array.get(), this_chunk_size);

    flush_position += this_chunk_size;
    ++chunk_index;
    pre_pre_chunk_modified = pre_chunk_modified;
    pre_chunk_modified = this_chunk_modified;
    this_chunk_modified = false;
  }

  BOOST_ASSERT(flush_position == file_size_);

  if (pre_pre_chunk_modified || pre_chunk_modified || chunk0_modified_)
    EncryptChunk(0, chunk0_raw_.get(), normal_chunk_size_);

  pre_pre_chunk_modified = pre_chunk_modified;
  pre_chunk_modified = chunk0_modified_;

  if (pre_pre_chunk_modified || pre_chunk_modified || chunk1_modified_) {
    if (normal_chunk_size_ == kDefaultChunkSize) {
      EncryptChunk(1, chunk1_raw_.get(), normal_chunk_size_);
    } else if (normal_chunk_size_ * 2 <= kDefaultChunkSize) {
      // All of chunk 0 and chunk 1 data in chunk0_raw_
      EncryptChunk(1, chunk0_raw_.get() + normal_chunk_size_,
                   normal_chunk_size_);
    } else {
      // Some at end of chunk0_raw_ and rest in start of chunk1_raw_
      ByteArray temp(new byte[normal_chunk_size_]);
      uint32_t size_chunk0(kDefaultChunkSize - normal_chunk_size_);
      uint32_t size_chunk1(kDefaultChunkSize - size_chunk0);
      memcpy(temp.get(), chunk0_raw_.get() + normal_chunk_size_, size_chunk0);
      memcpy(temp.get() + size_chunk0, chunk1_raw_.get(), size_chunk1);
      EncryptChunk(1, temp.get(), normal_chunk_size_);
    }
  }

  // Restore sizes, in case of further writes.
  normal_chunk_size_ = normal_chunk_size_before_flush;
  last_chunk_position_ = last_chunk_position_before_flush;
}

bool SelfEncryptor::Read(char* data,
                         const uint32_t &length,
                         const uint64_t &position) {
  if (length == 0)
    return true;

  PrepareToRead();

  if (length < kDefaultByteArraySize_) {
    //  required -
    //  requested position not less than cache start and
    //  requested position + length not greater than cache end
    if (position < cache_start_position_ ||
        position + length > cache_start_position_ + kDefaultByteArraySize_) {
      // populate read_cache_.
      Transmogrify(read_cache_.get(), kDefaultByteArraySize_, position);
      cache_start_position_ = position;
    }
    memcpy(data, read_cache_.get() + static_cast<uint32_t>(position -
           cache_start_position_), length);
  } else {
    // length requested larger than cache size, just go ahead and read
    Transmogrify(data, length, position);
  }
  return true;
}

void SelfEncryptor::PrepareToRead() {
  if (prepared_for_reading_)
    return;

  read_cache_.reset(new char[kDefaultByteArraySize_]);
  cache_start_position_ = std::numeric_limits<uint64_t>::max();
  prepared_for_reading_ = true;
}

bool SelfEncryptor::Transmogrify(char *data,
                                 const uint32_t &length,
                                 const uint64_t &position) {
  memset(data, 0, length);

  // For tiny files, all data is in data_map_->content or chunk0_raw_.
  uint32_t copy_size(length);
  if (file_size_ < 3 * kMinChunkSize) {
    if (position >= 3 * kMinChunkSize)
      return false;
    copy_size =
        std::min(length, (3 * kMinChunkSize) - static_cast<uint32_t>(position));
    if (prepared_for_writing_) {
      memcpy(data, chunk0_raw_.get() + position, copy_size);
    } else {
      memcpy(data, data_map_->content.data() + position, copy_size);
    }
    return true;
  }

  ReadDataMapChunks(data, length, position);

  if (!prepared_for_writing_)
    return true;

  ReadInProcessData(data, length, position);

  return true;
}

bool SelfEncryptor::ReadDataMapChunks(char *data,
                                      const uint32_t &length,
                                      const uint64_t &position) {
  if (data_map_->chunks.empty())
    return false;

  uint32_t num_chunks = static_cast<uint32_t>(data_map_->chunks.size());
  uint32_t start_chunk = static_cast<uint32_t>(position / normal_chunk_size_);
  uint32_t end_chunk = std::min(num_chunks - 1, static_cast<uint32_t>(
                                (position + length - 1) / normal_chunk_size_));
  BOOST_ASSERT(start_chunk < num_chunks);
  BOOST_ASSERT(end_chunk < num_chunks);
  uint32_t start_offset(position % normal_chunk_size_);
  uint32_t end_cut(0);
  uint64_t total_data_map_size(TotalSize(data_map_, normal_chunk_size_));
  if (position + length >= total_data_map_size) {
    end_cut = (*data_map_->chunks.rbegin()).size;
  } else {
    end_cut = static_cast<uint32_t>(position + length -
                                    (normal_chunk_size_ * end_chunk));
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

  if (start_chunk == end_chunk && data_map_->chunks[start_chunk].size != 0) {
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

    if (this_chunk_size != 0) {
      if (i == start_chunk) {
        if (start_offset != 0) {
          ByteArray chunk_data(new byte[data_map_->chunks[start_chunk].size]);
          ReadChunk(start_chunk, chunk_data.get());
          for (uint32_t j = start_offset; j != this_chunk_size; ++j)
            data[j - start_offset] = static_cast<char>(chunk_data[j]);
        } else {
          ReadChunk(i, reinterpret_cast<byte*>(&data[0]));
        }
      } else {
        pos = i * normal_chunk_size_;
        ReadChunk(i, reinterpret_cast<byte*>(&data[pos - position]));
      }
    }
  }

//    uint64_t this_position(0);
//  #pragma omp barrier
//    for (uint32_t i = 0; i != num_chunks; ++i)
//      this_position += data_map_->chunks[i].size;

  return read_ok_;
//  uint64_t data_map_offset(0), read_position(position);
//  uint32_t bytes_read(0), chunk_index(0), copy_size(0);
//  ByteArray chunk_array(new byte[kDefaultChunkSize + kMinChunkSize]);
//  while (bytes_read != length && chunk_index != data_map_->chunks.size()) {
// if (read_position < data_map_offset + data_map_->chunks[chunk_index].size &&
//        read_position + length - bytes_read >= data_map_offset) {
//      // This chunk is needed
//      uint32_t chunk_offset(0);
//      BOOST_ASSERT(read_position >= data_map_offset);
//      chunk_offset = static_cast<uint32_t>(read_position - data_map_offset);
//      copy_size = std::min(length - bytes_read, static_cast<uint32_t>(
//                           data_map_offset +
//                           data_map_->chunks[chunk_index].size -
//                           read_position));
//      ReadChunk(chunk_index, chunk_array.get());
//      memcpy(data + bytes_read, chunk_array.get() + chunk_offset, copy_size);
//      bytes_read += copy_size;
//      read_position += copy_size;
//    }
//    data_map_offset += data_map_->chunks[chunk_index].size;
//    ++chunk_index;
//  }
//  return true;
}

void SelfEncryptor::ReadInProcessData(char *data,
                                      uint32_t length,
                                      uint64_t position) {
  uint32_t copy_size(0), bytes_read(0);
  uint64_t read_position(position);
  // Get data from chunk 0 if required.
  if (read_position < kDefaultChunkSize) {
    copy_size = std::min(length, kDefaultChunkSize -
                         static_cast<uint32_t>(read_position));
    memcpy(data, chunk0_raw_.get() + read_position, copy_size);
    bytes_read += copy_size;
    read_position += copy_size;
    if (bytes_read == length)
      return;
  }
  // Get data from chunk 1 if required.
  if (read_position < 2 * kDefaultChunkSize) {
    copy_size = std::min(length - bytes_read, (2 * kDefaultChunkSize) -
                         static_cast<uint32_t>(read_position));
    memcpy(data + bytes_read,
           chunk1_raw_.get() + read_position - kDefaultChunkSize,
           copy_size);
    bytes_read += copy_size;
    read_position += copy_size;
    if (bytes_read == length)
      return;
  }

  // Get data from queue if required.
  uint32_t data_offset(0), queue_offset(0), copy_length(0);
  if (retrievable_from_queue_ != 0)  {
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

  // Get data from sequencer if required.
  std::pair<uint64_t, SequenceData> sequence_block(sequencer_.Peek(position));
  uint64_t sequence_block_position(sequence_block.first);
  ByteArray sequence_block_data(sequence_block.second.first);
  uint32_t sequence_block_size(sequence_block.second.second);
  uint64_t seq_position(position);
  uint32_t sequence_block_offset(0);

  while (position < sequence_block_position + sequence_block_size &&
         position + length >= sequence_block_position) {
    if (position < sequence_block_position) {
      data_offset = static_cast<uint32_t>(sequence_block_position - position);
      sequence_block_offset = 0;
    } else {
      data_offset = 0;
      sequence_block_offset =
          static_cast<uint32_t>(position - sequence_block_position);
    }
    copy_length = std::min(length - data_offset, static_cast<uint32_t>(
                           sequence_block_position + sequence_block_size -
                           queue_offset));

    memcpy(data + data_offset,
           sequence_block_data.get() + sequence_block_offset, copy_length);

    seq_position = sequence_block_position + sequence_block_size;
    sequence_block = sequencer_.Peek(seq_position);
    sequence_block_position = sequence_block.first;
    sequence_block_data = sequence_block.second.first;
    sequence_block_size = sequence_block.second.second;
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
        sequencer_.clear();
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
//      // check queue;
//    else
//      // check sequencer
//      if (size <= retrievable_from_queue_) {
//
//      }
//    }
  // }
  return true;
}

}  // namespace encrypt
}  // namespace maidsafe
