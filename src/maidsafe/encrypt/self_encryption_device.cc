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
 ***************************************************************************//**
 * @file  self_encryption_device.cc
 * @brief Provides self-en/decryption functionality through a iostream device.
 * @date  2011-02-18
 * @todo  The stream device should be using exceptions.
 */

#include "maidsafe/encrypt/self_encryption_device.h"

#include <algorithm>
#include <iosfwd>
#include <map>
#include <string>

#include "boost/filesystem/fstream.hpp"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/encrypt/utils.h"

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

SelfEncryptionDevice::SelfEncryptionDevice(
    std::shared_ptr<DataMap> data_map,
    std::shared_ptr<ChunkStore> chunk_store,
    SelfEncryptionParams self_encryption_params)
        : self_encryption_params_(self_encryption_params),
          default_self_encryption_type_(kHashingSha512 | kCompressionGzip |
                                        kObfuscationRepeated | kCryptoAes256),
          data_map_(data_map),
          chunk_store_(chunk_store),
          data_size_(data_map_->size),
          offset_(0),
          current_chunk_offset_(0),
          current_chunk_index_(0),
          chunk_buffers_(),
          crypto_hashes_(),
          pending_chunks_(),
          deletable_chunks_(),
          write_mode_(false) {}

std::streamsize SelfEncryptionDevice::read(char *s, std::streamsize n) {
  // DLOG(INFO) << "read " << n;

  if (!s || n < 0)
    return -1;

  // switch to read mode
  if (write_mode_ && !flush())
    return -1;

  if (n == 0)
    return 0;

  if (static_cast<uint64_t>(offset_) == data_map_->size ||
      !UpdateCurrentChunkDetails())
    return -1;

  std::streamsize remaining(n);
  size_t chunk_index(current_chunk_index_);
  io::stream_offset chunk_offset(current_chunk_offset_);

  while (remaining > 0 && LoadChunkIntoBuffer(chunk_index, NULL)) {
    const std::string &current_chunk_content =
        chunk_buffers_[chunk_index % kMinChunks].content;
    io::stream_offset this_offset(0);
    if (offset_ > chunk_offset)
      this_offset = offset_ - chunk_offset;
    io::stream_offset size(std::min(remaining, static_cast<std::streamsize>(
        current_chunk_content.size() - this_offset)));
    memcpy(s, &(current_chunk_content[static_cast<size_t>(this_offset)]),
           static_cast<size_t>(size));

    current_chunk_index_ = chunk_index;
    current_chunk_offset_ = chunk_offset;

    s += size;
    offset_ += size;
    remaining -= size;
    ++chunk_index;
    chunk_offset += current_chunk_content.size();
  }

  return n - remaining;
}

std::streamsize SelfEncryptionDevice::write(const char *s, std::streamsize n) {
//   DLOG(INFO) << "write " << n;

  if (!s || n <= 0)
    return -1;

  if (write_mode_) {
    // check if a seek happened that left the currently buffered chunks
    size_t new_chunk_index(current_chunk_index_);
    io::stream_offset new_chunk_offset(current_chunk_offset_);
    bool looking(true);
    while (looking && chunk_buffers_[new_chunk_index % kMinChunks].index ==
           new_chunk_index) {
      if (new_chunk_index > 0 && offset_ < new_chunk_offset) {
        --new_chunk_index;
        new_chunk_offset -=
            chunk_buffers_[new_chunk_index % kMinChunks].content.size();
      } else if (offset_ > new_chunk_offset + static_cast<io::stream_offset>(
                 chunk_buffers_[new_chunk_index % kMinChunks].content.size())) {
        new_chunk_offset +=
            chunk_buffers_[new_chunk_index % kMinChunks].content.size();
        ++new_chunk_index;
      } else {
        // found!
        looking = false;
      }
    }

    if (looking) {
      DLOG(INFO) << "write: Left buffered chunks, flushing...";
      if (!flush())
        return -1;
    } else if (new_chunk_index != current_chunk_index_) {
      if (new_chunk_index < current_chunk_index_) {
        // don't finalise, since we might be overwriting it again soon
        pending_chunks_.insert(current_chunk_index_);
      } else if (!FinaliseWriting(current_chunk_index_)) {
        DLOG(ERROR) << "write: Could not finalise previous chunk.";
        return -1;
      }
      current_chunk_index_ = new_chunk_index;
      current_chunk_offset_ = new_chunk_offset;
    }
  }

  if (!write_mode_) {  // [sic] checking again, in case we did a flush above
    if (!UpdateCurrentChunkDetails())
      return -1;

    // rearrange buffers in case of 3 small chunks
    if (data_map_->chunks.size() == kMinChunks && data_map_->content.empty()) {
      bool error(false);
      for (size_t i = 0; i < kMinChunks; ++i)
        error = error || !LoadChunkIntoBuffer(i, NULL);
      if (error) {
        DLOG(ERROR) << "write: Could not fill buffers for all " << kMinChunks
                    << " chunks.";
        return -1;
      }

      for (size_t src(1), snk(0); src < kMinChunks && snk < kMinChunks;) {
        size_t diff(self_encryption_params_.max_chunk_size -
                    chunk_buffers_[snk].content.size());
        if (diff > 0) {
          // space in sink buffer available
          if (src == 1 && snk == 0) {
            for (auto it = data_map_->chunks.begin();
                 it != data_map_->chunks.end(); ++it)
              deletable_chunks_.push_back(it->hash);
            data_map_->chunks.clear();
          }
          chunk_buffers_[snk].content.append(
              chunk_buffers_[src].content.substr(0, diff));
          chunk_buffers_[snk].hash.clear();
          chunk_buffers_[src].content.erase(0, diff);
          chunk_buffers_[src].hash.clear();
        }

        if (chunk_buffers_[snk].content.size() ==
                  self_encryption_params_.max_chunk_size) {
          // continue with next buffer
          FinaliseWriting(snk);
          ++snk;
          if (src == snk)
            ++src;
        } else if (chunk_buffers_[src].content.empty()) {
          ++src;
        }
      }

      current_chunk_index_ = static_cast<size_t>(offset_ /
                             self_encryption_params_.max_chunk_size);
      current_chunk_offset_ = current_chunk_index_ *
                              self_encryption_params_.max_chunk_size;
    }
    write_mode_ = true;
  }

  std::streamsize remaining(n);
  while (remaining > 0) {
    ChunkBuffer &chunk_buffer =
        chunk_buffers_[current_chunk_index_ % kMinChunks];
    if ((offset_ == 0 && current_chunk_index_ == 0) ||
        chunk_buffer.index != current_chunk_index_ ||
        (chunk_buffer.content.empty() && !data_map_->content.empty())) {
      if (current_chunk_index_ >= data_map_->chunks.size() &&
          data_map_->content.empty() &&
          static_cast<uintmax_t>(offset_) == data_size_) {
        chunk_buffer.index = current_chunk_index_;
        chunk_buffer.content.clear();
        chunk_buffer.hash.clear();
      } else if (!LoadChunkIntoBuffer(current_chunk_index_, NULL)) {
        DLOG(ERROR) << "write: Could not load contents of required buffer.";
        return -1;
      }
    }
    if (!data_map_->content.empty() &&
        current_chunk_index_ == data_map_->chunks.size()) {
      data_map_->size -= data_map_->content.size();
      data_map_->content.clear();
    }

    io::stream_offset this_offset(0);
    if (offset_ > current_chunk_offset_)
      this_offset = offset_ - current_chunk_offset_;
    io::stream_offset size(std::min(remaining, static_cast<std::streamsize>(
        self_encryption_params_.max_chunk_size - this_offset)));

    if (size > 0) {
      if (this_offset + size >
          static_cast<io::stream_offset>(chunk_buffer.content.size())) {
        chunk_buffer.content.resize(static_cast<size_t>(this_offset + size));
      }
      memcpy(&(chunk_buffer.content[static_cast<size_t>(this_offset)]), s,
             static_cast<size_t>(size));
      chunk_buffer.hash.clear();
      s += size;
      offset_ += size;
      if (static_cast<uintmax_t>(offset_) > data_size_)
        data_size_ = offset_;
      remaining -= size;
    } else {
      // buffer is full, continue with the next one
      if (!FinaliseWriting(current_chunk_index_)) {
        DLOG(ERROR) << "write: Could not finalise current chunk.";
        return -1;
      }
      ++current_chunk_index_;
      current_chunk_offset_ += chunk_buffer.content.size();
    }
  }

  return n;
}

io::stream_offset SelfEncryptionDevice::seek(io::stream_offset offset,
                                             std::ios_base::seekdir way) {
  io::stream_offset new_offset;
  switch (way) {
    case std::ios_base::beg:
      new_offset = offset;
      break;
    case std::ios_base::cur:
      new_offset = offset_ + offset;
      break;
    case std::ios_base::end:
      new_offset = data_size_ + offset;
      break;
    default:
      DLOG(ERROR) << "seek: Invalid seek direction passed.";
      return -1;
  }

  if (new_offset < 0 || static_cast<uintmax_t>(new_offset) > data_size_) {
    DLOG(ERROR) << "seek: Invalid offset passed.";
    return -1;
  }

  offset_ = new_offset;
  return offset_;
}

bool SelfEncryptionDevice::flush() {
  if (!write_mode_)
    return true;
  // DLOG(INFO) << "flush";

  if (data_map_->content.empty() && data_map_->chunks.empty()) {
    // only have data in buffers
    size_t i(0), size(0);
    for (; i < kMinChunks; ++i)
      if (chunk_buffers_[i].index == i) {
        size += chunk_buffers_[i].content.size();
      } else {
        chunk_buffers_[i].index = i;
        chunk_buffers_[i].content.clear();
      }

    if (size <= self_encryption_params_.max_includable_data_size) {
      // include everything in DataMap
      for (i = 0; i < kMinChunks; ++i)
        data_map_->content.append(chunk_buffers_[i].content);
      data_map_->self_encryption_type = 0;
      data_map_->size = data_map_->content.size();
    } else {
      // equally distribute contents and re-calculate hashes
      InitialiseDataMap(
          chunk_buffers_[size / self_encryption_params_.max_chunk_size / 2]);
      size /= kMinChunks;

      for (i = 0; i < kMinChunks; ++i) {
        if (i < kMinChunks - 1 && chunk_buffers_[i].content.size() > size) {
          chunk_buffers_[i + 1].content =
              chunk_buffers_[i].content.substr(size) +
              chunk_buffers_[i + 1].content;
          chunk_buffers_[i].content.erase(size);
        }
        chunk_buffers_[i].hash = utils::Hash(chunk_buffers_[i].content,
                                            data_map_->self_encryption_type);
      }

      for (i = 0; i < kMinChunks; ++i) {
        crypto_hashes_[i] = std::make_tuple(
            chunk_buffers_[i].hash,
            chunk_buffers_[(i + 1) % kMinChunks].hash,
            chunk_buffers_[(i + 2) % kMinChunks].hash);
        if (!StoreChunkFromBuffer(&(chunk_buffers_[i]),
                                  std::get<0>(crypto_hashes_[i]),
                                  std::get<1>(crypto_hashes_[i]),
                                  std::get<2>(crypto_hashes_[i]))) {
          DLOG(ERROR) << "flush: Could not store chunk " << i;
          return false;
        }
      }
    }
  } else {
    size_t highest_index(0);
    for (size_t i = 0; i < kMinChunks; ++i)
      if (chunk_buffers_[i].index > highest_index &&
          !chunk_buffers_[i].content.empty())
        highest_index = chunk_buffers_[i].index;

    if (data_map_->chunks.size() <= highest_index &&
        chunk_buffers_[highest_index % kMinChunks].content.size() <=
            self_encryption_params_.max_includable_chunk_size) {
      // store last chunk in DataMap
      if (!StoreChunkFromBuffer(&(chunk_buffers_[highest_index % kMinChunks]),
                                "", "", "")) {
        DLOG(ERROR) << "flush: Could not store chunk " << highest_index
                    << " in DataMap.";
        return false;
      }
    }

    // try finalising all the buffers
    for (size_t i = current_chunk_index_; i < current_chunk_index_ + kMinChunks;
         ++i) {
      const size_t idx(chunk_buffers_[i % kMinChunks].index);
      if (!chunk_buffers_[i % kMinChunks].content.empty() &&
          !FinaliseWriting(idx)) {
        DLOG(ERROR) << "flush: Could not finalise chunk " << idx;
        return false;
      }
    }

    // load all unbuffered remaining chunks first
    std::map<size_t, ChunkBuffer> temp_buffers;
    for (auto it = pending_chunks_.begin(); it != pending_chunks_.end(); ++it)
      if (chunk_buffers_[*it % kMinChunks].index != *it)
        if (!LoadChunkIntoBuffer(*it, &(temp_buffers[*it]))) {
          DLOG(ERROR) << "flush: Could not load unbuffered chunk " << *it;
          return false;
        }

    // (re-)encrypt all the remaining chunks
    while (!pending_chunks_.empty()) {
      const size_t idx(*(pending_chunks_.begin()));
      bool this_buf(chunk_buffers_[idx % kMinChunks].index == idx &&
                    !chunk_buffers_[idx % kMinChunks].hash.empty());
      bool next_buf(chunk_buffers_[(idx + 1) % kMinChunks].index == idx + 1 &&
                    !chunk_buffers_[(idx + 1) % kMinChunks].hash.empty());
      bool next2_buf(chunk_buffers_[(idx + 2) % kMinChunks].index == idx + 2 &&
                     !chunk_buffers_[(idx + 2) % kMinChunks].hash.empty());
      std::string this_hash, encryption_hash, obfuscation_hash;
      if (this_buf)
        this_hash = chunk_buffers_[idx % kMinChunks].hash;
      else
        this_hash = data_map_->chunks[idx % data_map_->chunks.size()].pre_hash;

      if (next_buf)
        encryption_hash = chunk_buffers_[(idx + 1) % kMinChunks].hash;
      else if (idx == data_map_->chunks.size())
        encryption_hash = data_map_->chunks[0].pre_hash;
      else
        encryption_hash =
            data_map_->chunks[(idx + 1) % data_map_->chunks.size()].pre_hash;

      if (next2_buf) {
        obfuscation_hash = chunk_buffers_[(idx + 2) % kMinChunks].hash;
      } else if (idx == data_map_->chunks.size()) {
        if (next_buf)
          obfuscation_hash = data_map_->chunks[0].pre_hash;
        else
          obfuscation_hash = data_map_->chunks[1].pre_hash;
      } else if (next_buf && idx + 1 == data_map_->chunks.size()) {
        obfuscation_hash = data_map_->chunks[0].pre_hash;
      } else {
        obfuscation_hash =
          data_map_->chunks[(idx + 2) % data_map_->chunks.size()].pre_hash;
      }

      crypto_hashes_[idx] = std::make_tuple(this_hash, encryption_hash,
                                            obfuscation_hash);

      if ((chunk_buffers_[idx % kMinChunks].index == idx &&
             !StoreChunkFromBuffer(&(chunk_buffers_[idx % kMinChunks]),
                                   this_hash, encryption_hash,
                                   obfuscation_hash)) ||
          (temp_buffers.count(idx) > 0 &&
             !StoreChunkFromBuffer(&(temp_buffers[idx]), this_hash,
                                   encryption_hash, obfuscation_hash))) {
        DLOG(ERROR) << "flush: Could not store chunk " << idx;
        return false;
      }
      // NOTE StoreChunkFromBuffer removes entry from pending_chunks_
    }
  }

  while (!deletable_chunks_.empty()) {
    if (chunk_store_->Delete(deletable_chunks_.back())) {
      DLOG(INFO) << "flush: Deleted old chunk "
                 << EncodeToHex(deletable_chunks_.back()).substr(0, 8) << "..";
    } else {
      DLOG(WARNING) << "flush: Could not delete old chunk "
                    << EncodeToHex(deletable_chunks_.back()).substr(0, 8)
                    << "..";
    }
    deletable_chunks_.pop_back();
  }

  write_mode_ = false;
  return true;
}

void SelfEncryptionDevice::InitialiseDataMap(const ChunkBuffer &chunk_buffer) {
  DataMap dm;
  (*data_map_) = dm;  // full reset

  size_t offset(0);
  if (chunk_buffer.content.size() > kCompressionSampleSize)
    offset = (chunk_buffer.content.size() - kCompressionSampleSize) / 2;
  if (utils::CheckCompressibility(
          chunk_buffer.content.substr(offset, kCompressionSampleSize),
          default_self_encryption_type_))
    data_map_->self_encryption_type = default_self_encryption_type_;
  else
    data_map_->self_encryption_type = kCompressionNone |
        (default_self_encryption_type_ &
            (kHashingMask | kObfuscationMask | kCryptoMask));
}

bool SelfEncryptionDevice::UpdateCurrentChunkDetails() {
  if (static_cast<uint64_t>(offset_) > data_map_->size)
    return false;

  if (offset_ < current_chunk_offset_) {
    current_chunk_index_ = 0;
    current_chunk_offset_ = 0;
  }

  while (current_chunk_index_ < data_map_->chunks.size() &&
         current_chunk_offset_ +
             data_map_->chunks[current_chunk_index_].pre_size < offset_) {
    current_chunk_offset_ += data_map_->chunks[current_chunk_index_].pre_size;
    ++current_chunk_index_;
  }

  return true;
}

bool SelfEncryptionDevice::FinaliseWriting(const size_t &index) {
  ChunkBuffer &chunk_buffer = chunk_buffers_[index % kMinChunks];
  if (chunk_buffer.content.empty() ||
      chunk_buffer.index != index) {
    DLOG(ERROR) << "FinaliseWriting: Invalid chunk buffer.";
    return false;
  }

  if (!chunk_buffer.hash.empty()) {
//     DLOG(INFO) << "FinaliseWriting: Already hashed chunk " << index;
    return true;
  }

  if (index == 0 && data_map_->chunks.empty())
    InitialiseDataMap(chunk_buffer);

  chunk_buffer.hash = utils::Hash(chunk_buffer.content,
                                  data_map_->self_encryption_type);

//   if (index < data_map_->chunks.size() &&
//       data_map_->chunks[index].pre_hash == chunk_buffer.hash) {
//     // but the chunk previous to it need to be stored
//     // TODO(qima): any work can be saved by skipping ?
//     std::cout << "FinaliseWriting: Skipping unchanged chunk "
//                << index << std::endl;
//     return true;  // nothing actually changed
//   }

  if (index < kMinChunks - 1) {
    // we are near beginning of stream, just queue dependent chunks
    for (size_t i = 0; i < kMinChunks; ++i)
      if (i <= index)
        pending_chunks_.insert(i);
      else if (data_map_->chunks.size() > index + i)
        pending_chunks_.insert(data_map_->chunks.size() - kMinChunks + i);
    return true;
  }

  // we need to update pre-predecessor
  size_t prepred(index + 1 - kMinChunks), pred(prepred + 1);
  std::string prepred_hash;
  if (chunk_buffers_[prepred % kMinChunks].index == prepred)
    prepred_hash = chunk_buffers_[prepred % kMinChunks].hash;
  else if (prepred < data_map_->chunks.size())
    prepred_hash = data_map_->chunks[prepred].pre_hash;

  if (prepred_hash.empty()) {
    DLOG(ERROR) << "FinaliseWriting: Could not get own hash for " << prepred
                << ".";
    return false;
  }

  std::string encryption_hash;
  if (chunk_buffers_[pred % kMinChunks].index == pred)
    encryption_hash = chunk_buffers_[pred % kMinChunks].hash;
  else if (pred < data_map_->chunks.size())
    encryption_hash = data_map_->chunks[pred].pre_hash;

  if (encryption_hash.empty()) {
    DLOG(ERROR) << "FinaliseWriting: Could not get encryption hash for "
                << prepred << ".";
    return false;
  }

  // only use existing buffer if we don't need to load the chunk
  ChunkBuffer temp_chunk_buffer, *prepred_chunk_buffer;
  if (chunk_buffers_[prepred % kMinChunks].index == prepred)
    prepred_chunk_buffer = &(chunk_buffers_[prepred % kMinChunks]);
  else
    prepred_chunk_buffer = &temp_chunk_buffer;

  if (!LoadChunkIntoBuffer(prepred, prepred_chunk_buffer)) {
    DLOG(ERROR) << "FinaliseWriting: Could not load pre-predecessor of "
                << index << ".";
    return false;
  }

  crypto_hashes_[prepred] = std::make_tuple(prepred_hash, encryption_hash,
                                            chunk_buffer.hash);
  if (!StoreChunkFromBuffer(prepred_chunk_buffer, prepred_hash, encryption_hash,
                            chunk_buffer.hash)) {
    DLOG(ERROR) << "FinaliseWriting: Could not store pre-predecessor of "
                << index << ".";
    return false;
  }

  pending_chunks_.insert(pred);
  pending_chunks_.insert(index);
  return true;
}

bool SelfEncryptionDevice::LoadChunkIntoBuffer(const size_t &index,
                                               ChunkBuffer *chunk_buffer) {
  if (!chunk_buffer)
    chunk_buffer = &(chunk_buffers_[index % kMinChunks]);

  // already loaded
  if (chunk_buffer->index == index && !chunk_buffer->content.empty())
    return true;

  const size_t chunk_count(data_map_->chunks.size());
  if (index > chunk_count)
    return false;

  // contents in DataMap
  if (index == chunk_count) {
    if (index > 0) {
      // tail chunk
      chunk_buffer->index = index;
      chunk_buffer->hash.clear();
      chunk_buffer->content = data_map_->content;
    } else {
      for (size_t i = 0;
           i < kMinChunks && data_map_->content.size() >
              i * self_encryption_params_.max_chunk_size;
           ++i) {
        // fill buffers from DM, might span more than just 1
        chunk_buffers_[i].index = i;
        chunk_buffers_[i].hash.clear();
        chunk_buffers_[i].content = data_map_->content.substr(
            i * self_encryption_params_.max_chunk_size,
            self_encryption_params_.max_chunk_size);
      }
    }
    return !data_map_->content.empty();
  }

  const ChunkDetails &chunk = data_map_->chunks[index];
  if (chunk_buffer->content.empty() || chunk_buffer->hash != chunk.pre_hash) {
    std::string own_hash, encryption_hash, obfuscation_hash;
    if (crypto_hashes_.count(index) > 0) {
      own_hash = std::get<0>(crypto_hashes_[index]);
      encryption_hash = std::get<1>(crypto_hashes_[index]);
      obfuscation_hash = std::get<2>(crypto_hashes_[index]);
    } else {
      own_hash = chunk.pre_hash;
      encryption_hash = data_map_->chunks[(index + 1) % chunk_count].pre_hash;
      obfuscation_hash = data_map_->chunks[(index + 2) % chunk_count].pre_hash;
    }

    DLOG(INFO) << "LoadChunkIntoBuffer: Self-decrypting chunk " << index
               << " using hashes " << EncodeToHex(own_hash).substr(0, 8)
               << ".. | " << EncodeToHex(encryption_hash).substr(0, 8)
               << ".. | " << EncodeToHex(obfuscation_hash).substr(0, 8) << "..";

    chunk_buffer->content = utils::SelfDecryptChunk(
        chunk_store_->Get(chunk.hash), own_hash, encryption_hash,
        obfuscation_hash, data_map_->self_encryption_type);
    chunk_buffer->hash = chunk.pre_hash;
  }
  chunk_buffer->index = index;

  if (chunk_buffer->content.size() != chunk.pre_size) {
    DLOG(ERROR) << "LoadChunkIntoBuffer: Failed restoring chunk " << index
                << ", size differs.";
    chunk_buffer->content = std::string(chunk.pre_size, 0);
    return false;
  }

  if (utils::Hash(chunk_buffer->content, data_map_->self_encryption_type) !=
          chunk.pre_hash) {
    DLOG(ERROR) << "LoadChunkIntoBuffer: Failed restoring chunk " << index
                << ", does not validate.";
    chunk_buffer->content = std::string(chunk.pre_size, 0);
    return false;
  }

  return true;
}

bool SelfEncryptionDevice::StoreChunkFromBuffer(
    ChunkBuffer *chunk_buffer,
    const std::string &own_hash,
    const std::string &encryption_hash,
    const std::string &obfuscation_hash) {
  if (chunk_buffer->content.empty()) {
    DLOG(ERROR) << "StoreChunkFromBuffer: Can't store empty chunk.";
    return false;
  }

  if (own_hash.empty() && encryption_hash.empty() && obfuscation_hash.empty()) {
    data_map_->content = chunk_buffer->content;
    data_map_->size += chunk_buffer->content.size();
    pending_chunks_.erase(chunk_buffer->index);
    chunk_buffer->content.clear();
    chunk_buffer->hash.clear();
    DLOG(INFO) << "StoreChunkFromBuffer: Stored chunk " << chunk_buffer->index
               << " (" << data_map_->content.size() << " Bytes) to DataMap.";
    return true;
  }

  // TODO(Steve) optimisation: check cache for existing hash triple

  std::string encrypted_content(utils::SelfEncryptChunk(
      chunk_buffer->content, own_hash, encryption_hash, obfuscation_hash,
      data_map_->self_encryption_type));

  if (encrypted_content.empty()) {
    DLOG(ERROR) << "StoreChunkFromBuffer: Could not self-encrypt chunk "
                << chunk_buffer->index;
    return false;
  }

  std::string hash(utils::Hash(encrypted_content,
                               data_map_->self_encryption_type));

  bool do_store(false), added_chunk(false);

  if (chunk_buffer->index >= data_map_->chunks.size()) {
    // new chunk
    ChunkDetails chunk;
    chunk.pre_hash = chunk_buffer->hash;
    chunk.pre_size = static_cast<uint32_t>(chunk_buffer->content.size());
    chunk.hash = hash;
    chunk.size = static_cast<uint32_t>(encrypted_content.size());
    do_store = true;
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
    added_chunk = true;
  } else {
    // modified chunk
    ChunkDetails &chunk = data_map_->chunks[chunk_buffer->index];
    if (chunk.hash != hash) {
      deletable_chunks_.push_back(chunk.hash);
      data_map_->size -= chunk.pre_size;
      chunk.pre_hash = chunk_buffer->hash;
      chunk.pre_size = static_cast<uint32_t>(chunk_buffer->content.size());
      chunk.hash = hash;
      chunk.size = static_cast<uint32_t>(encrypted_content.size());
      do_store = true;
      data_map_->size += chunk.pre_size;
    }
  }

  if (do_store) {
    if (chunk_store_->Store(hash, encrypted_content)) {
      DLOG(INFO) << "StoreChunkFromBuffer: Stored chunk " << chunk_buffer->index
                 << " (" << EncodeToHex(hash).substr(0, 8)
                 << ".., " << chunk_buffer->content.size() << " | "
                 << encrypted_content.size() << " Bytes, ref #"
                 << chunk_store_->Count(hash) << ") with hashes "
                 << EncodeToHex(chunk_buffer->hash).substr(0, 8) << ".. | "
                 << EncodeToHex(encryption_hash).substr(0, 8) << ".. | "
                 << EncodeToHex(obfuscation_hash).substr(0, 8) << "..";
    } else {
      if (added_chunk) {  // revert addition
        data_map_->size -= chunk_buffer->content.size();
        data_map_->chunks.pop_back();
      }
      DLOG(ERROR) << "StoreChunkFromBuffer: Could not store chunk "
                  << chunk_buffer->index;
      return false;
    }
  } else {
    DLOG(INFO) << "StoreChunkFromBuffer: Not going to store chunk "
               << chunk_buffer->index;
  }

  pending_chunks_.erase(chunk_buffer->index);
  return true;
}

io::stream_offset SelfEncryptionDevice::InitialAllZero(io::stream_offset size) {
  // the encryption_type shall be reset when later on data is received
  data_map_->self_encryption_type = kCompressionNone |
        (default_self_encryption_type_ &
            (kHashingMask | kObfuscationMask | kCryptoMask));

  encrypt::SelfEncryptionParams self_encryption_params;
  std::string zeros(self_encryption_params.max_chunk_size, 0);
  io::stream_offset chunk_num = size / self_encryption_params.max_chunk_size;
  std::string pre_hash = utils::Hash(zeros,
                                     data_map_->self_encryption_type);
  std::string encrypted_content(utils::SelfEncryptChunk(
      zeros, pre_hash, pre_hash, pre_hash, data_map_->self_encryption_type));
  std::string post_hash = utils::Hash(encrypted_content,
                                      data_map_->self_encryption_type);
  io::stream_offset chunk_index(0);
  while (chunk_index < (chunk_num - 2)) {
    chunk_store_->Store(post_hash, encrypted_content);
    crypto_hashes_[chunk_index] = std::make_tuple(pre_hash, pre_hash, pre_hash);
    ChunkDetails chunk;
    chunk.pre_hash = pre_hash;
    chunk.pre_size = self_encryption_params.max_chunk_size;
    chunk.hash = post_hash;
    chunk.size = encrypted_content.size();
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
    ++chunk_index;
  }

  io::stream_offset remain = size % self_encryption_params.max_chunk_size;
  std::string remain_zeros(remain, 0);
  std::string pre_hash_remain = utils::Hash(remain_zeros,
                                     data_map_->self_encryption_type);
  std::string encrypted_content_n_2(utils::SelfEncryptChunk(
      zeros, pre_hash, pre_hash, pre_hash_remain,
      data_map_->self_encryption_type));
  std::string encrypted_content_n_1(utils::SelfEncryptChunk(
      zeros, pre_hash, pre_hash_remain, pre_hash,
      data_map_->self_encryption_type));
  std::string encrypted_content_n(utils::SelfEncryptChunk(
      remain_zeros, pre_hash_remain, pre_hash, pre_hash,
      data_map_->self_encryption_type));
  std::string post_hash_n_2 = utils::Hash(encrypted_content_n_2,
                                      data_map_->self_encryption_type);
  std::string post_hash_n_1 = utils::Hash(encrypted_content_n_1,
                                      data_map_->self_encryption_type);
  std::string post_hash_n = utils::Hash(encrypted_content_n,
                                      data_map_->self_encryption_type);

  chunk_store_->Store(post_hash_n_2, encrypted_content_n_2);
  {
    crypto_hashes_[chunk_index] = std::make_tuple(pre_hash, pre_hash,
                                                  pre_hash_remain);
    ChunkDetails chunk;
    chunk.pre_hash = pre_hash;
    chunk.pre_size = self_encryption_params.max_chunk_size;
    chunk.hash = post_hash_n_2;
    chunk.size = encrypted_content_n_2.size();
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
  }
  ++chunk_index;
  chunk_store_->Store(post_hash_n_1, encrypted_content_n_1);
  {
    crypto_hashes_[chunk_index] = std::make_tuple(pre_hash, pre_hash_remain,
                                                  pre_hash);
    ChunkDetails chunk;
    chunk.pre_hash = pre_hash;
    chunk.pre_size = self_encryption_params.max_chunk_size;
    chunk.hash = post_hash_n_1;
    chunk.size = encrypted_content_n_1.size();
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
  }
  ++chunk_index;
  chunk_store_->Store(post_hash_n, encrypted_content_n);
  {
    crypto_hashes_[chunk_index] = std::make_tuple(pre_hash_remain, pre_hash,
                                                  pre_hash);
    ChunkDetails chunk;
    chunk.pre_hash = pre_hash_remain;
    chunk.pre_size = remain;
    chunk.hash = post_hash_n;
    chunk.size = encrypted_content_n.size();
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
  }
  data_size_ = data_map_->size;
  return data_map_->size;
}

}  // namespace encrypt

}  // namespace maidsafe
