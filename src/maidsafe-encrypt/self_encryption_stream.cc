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
 * @file  self_encryption_stream.cc
 * @brief Provides self-en/decryption functionality through a stream interface.
 * @date  2011-02-18
 * @todo  The stream device should be using exceptions.
 */

#include "maidsafe-encrypt/self_encryption_stream.h"

#include <algorithm>
#include <iosfwd>
#include <string>

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/utils.h"
#include "boost/filesystem/fstream.hpp"

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

SelfEncryptionDevice::SelfEncryptionDevice(
    std::shared_ptr<DataMap> data_map,
    std::shared_ptr<ChunkStore> chunk_store,
    SelfEncryptionParams self_encryption_params)
    : self_encryption_params_(self_encryption_params),
      default_self_encryption_type_(kHashingSha512 | kCompressionNone |
                                    kObfuscationRepeated | kCryptoAes256),
      data_map_(data_map),
      chunk_store_(chunk_store),
      offset_(0),
      current_chunk_offset_(0),
      current_chunk_index_(0),
      chunk_buffers_(),
      pending_chunks_(),
      write_mode_(false) {}

std::streamsize SelfEncryptionDevice::read(char *s, std::streamsize n) {
  // DLOG(INFO) << "read " << n << std::endl;

  if (!s || n < 0)
    return -1;

  // switch to read mode
  if (write_mode_ && !flush())
    return -1;

  if (!UpdateCurrentChunkDetails())
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
    size_t size(std::min(remaining, static_cast<std::streamsize>(
        current_chunk_content.size() - this_offset)));
    memcpy(s, &(current_chunk_content[this_offset]), size);

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
  DLOG(INFO) << "write " << n << std::endl;

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
      } else if (offset_ > new_chunk_offset +
                 chunk_buffers_[new_chunk_index % kMinChunks].content.size()) {
        new_chunk_offset +=
            chunk_buffers_[new_chunk_index % kMinChunks].content.size();
        ++new_chunk_index;
      } else {
        // found!
        looking = false;
      }
    }

    if (looking) {
      DLOG(INFO) << "write: Left buffered chunks, flushing..." << std::endl;
      if (!flush())
        return -1;
    } else if (new_chunk_index != current_chunk_index_) {
      if (new_chunk_index < current_chunk_index_) {
        // don't finalise, since we might be overwriting it again soon
        pending_chunks_.insert(current_chunk_index_);
      } else if (!FinaliseWriting()) {
        DLOG(ERROR) << "write: Could not finalise previous chunk." << std::endl;
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
                    << " chunks." << std::endl;
        return -1;
      }

      bool reset(false);
      for (size_t i = 0; i < kMinChunks - 1; ++i) {
        size_t diff(self_encryption_params_.max_chunk_size -
                    chunk_buffers_[i].content.size());
        if (diff > 0) {
          chunk_buffers_[i].content.append(
              chunk_buffers_[i + 1].content.substr(0, diff));
          chunk_buffers_[i].hash.clear();
          chunk_buffers_[i + 1].content.erase(0, diff);
          chunk_buffers_[i + 1].hash.clear();
          reset = true;
        }
      }

      if (reset) {
        DataMap dm;
        (*data_map_) = dm;  // full reset
        current_chunk_index_ = offset_ / self_encryption_params_.max_chunk_size;
        current_chunk_offset_ = current_chunk_index_ *
                                self_encryption_params_.max_chunk_size;
      }
    }
    write_mode_ = true;
  }

  std::streamsize remaining(n);
  while (remaining > 0) {
    ChunkBuffer &chunk_buffer =
        chunk_buffers_[current_chunk_index_ % kMinChunks];
    if (chunk_buffer.index != current_chunk_index_) {
      if (current_chunk_index_ >= data_map_->chunks.size() &&
          data_map_->content.empty()) {
        chunk_buffer.index = current_chunk_index_;
        chunk_buffer.content.clear();
        chunk_buffer.hash.clear();
      } else if (LoadChunkIntoBuffer(current_chunk_index_, NULL)) {
        if (current_chunk_index_ == data_map_->chunks.size())
          data_map_->content.clear();
      } else {
        DLOG(ERROR) << "write: Could not load contents of required buffer."
                    << std::endl;
        return -1;
      }
    }

    io::stream_offset this_offset(0);
    if (offset_ > current_chunk_offset_)
      this_offset = offset_ - current_chunk_offset_;
    size_t size(std::min(remaining, static_cast<std::streamsize>(
        self_encryption_params_.max_chunk_size - this_offset)));

    if (size > 0) {
      if (this_offset + size < chunk_buffer.content.size())
        chunk_buffer.content.resize(this_offset + size);
      memcpy(&(chunk_buffer.content[this_offset]), s, size);
      chunk_buffer.hash.clear();
      s += size;
      offset_ += size;
      remaining -= size;
    } else {
      // buffer is full, continue with the next one
      if (!FinaliseWriting()) {
        DLOG(ERROR) << "write: Could not finalise current chunk." << std::endl;
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
      new_offset = data_map_->size + offset;
      break;
    default:
      DLOG(ERROR) << "seek: Invalid seek direction passed." << std::endl;
      return -1;
  }

  if (new_offset < 0 || new_offset > data_map_->size) {
    DLOG(ERROR) << "seek: Invalid offset passed." << std::endl;
    return -1;
  }

  offset_ = new_offset;
  return offset_;
}

bool SelfEncryptionDevice::flush() {
  if (!write_mode_)
    return true;
  DLOG(INFO) << "flush" << std::endl;

  if (data_map_->chunks.empty()) {
    // TODO(Steve) rearrange buffers in case of 3 small chunks
    return false;
  } else {
    const size_t prev_idx(current_chunk_index_);
    for (; current_chunk_index_ < prev_idx + kMinChunks; ++current_chunk_index_)
      if (!FinaliseWriting()) {
        DLOG(ERROR) << "flush: Could not finalise chunk" << current_chunk_index_
                    << std::endl;
        return false;
      }
    while (!pending_chunks_.empty()) {
      size_t idx(*(pending_chunks_.begin()));
      std::string encryption_hash, obfuscation_hash;
      if (chunk_buffers_[(idx + 1) % kMinChunks].index == idx + 1)
        encryption_hash = chunk_buffers_[(idx + 1) % kMinChunks].hash;
      else
        encryption_hash =
            data_map_->chunks[(idx + 1) % data_map_->chunks.size()].pre_hash;
      if (chunk_buffers_[(idx + 2) % kMinChunks].index == idx + 2)
        obfuscation_hash = chunk_buffers_[(idx + 2) % kMinChunks].hash;
      else
        obfuscation_hash =
            data_map_->chunks[(idx + 2) % data_map_->chunks.size()].pre_hash;

      if (chunk_buffers_[idx % kMinChunks].index == idx) {
        if (!StoreChunkFromBuffer(chunk_buffers_[idx % kMinChunks],
                                  encryption_hash, obfuscation_hash)) {
          DLOG(ERROR) << "flush: Could not store chunk " << idx << std::endl;
          return false;
        }
      } else {
        // need to re-encrypt a chunk we don't have buffered
        ChunkBuffer chunk_buffer;
        if (!LoadChunkIntoBuffer(idx, &chunk_buffer) ||
            !StoreChunkFromBuffer(chunk_buffer, encryption_hash,
                                  obfuscation_hash)) {
          DLOG(ERROR) << "flush: Could not load and re-store chunk " << idx
                      << std::endl;
          return false;
        }
      }
      // NOTE StoreChunkFromBuffer removes entry from pending_chunks_
    }
  }

  write_mode_ = false;
  return UpdateCurrentChunkDetails();
}

bool SelfEncryptionDevice::UpdateCurrentChunkDetails() {
  if (offset_ >= data_map_->size)
    return false;

  if (offset_ < current_chunk_offset_) {
    current_chunk_index_ = 0;
    current_chunk_offset_ = 0;
  }

  while (current_chunk_index_ < data_map_->chunks.size() &&
         current_chunk_offset_ +
             data_map_->chunks[current_chunk_index_].pre_size <= offset_) {
    current_chunk_offset_ += data_map_->chunks[current_chunk_index_].pre_size;
    ++current_chunk_index_;
  }

  return true;
}

bool SelfEncryptionDevice::FinaliseWriting() {
  ChunkBuffer &chunk_buffer = chunk_buffers_[current_chunk_index_ % kMinChunks];
  if (chunk_buffer.content.empty() ||
      chunk_buffer.index != current_chunk_index_) {
    DLOG(ERROR) << "FinaliseWriting: Invalid chunk buffer." << std::endl;
    return false;
  }

  if (!chunk_buffer.hash.empty())
    return true;

  chunk_buffer.hash = utils::Hash(chunk_buffer.content,
                                  data_map_->self_encryption_type);

  if (current_chunk_index_ < data_map_->chunks.size() &&
      data_map_->chunks[current_chunk_index_].pre_hash == chunk_buffer.hash)
    return true;  // nothing actually changed

  if (current_chunk_index_ < kMinChunks - 1) {
    // we are near beginning of stream, just queue dependent chunks
    for (size_t i = 0; i < kMinChunks; ++i)
      if (i <= current_chunk_index_)
        pending_chunks_.insert(i);
      else if (data_map_->chunks.size() > current_chunk_index_ + i)
        pending_chunks_.insert(data_map_->chunks.size() - i);
    return true;
  }

  // we need to update pre-predecessor
  size_t prepred(current_chunk_index_ + 1 - kMinChunks), pred(prepred + 1);
  std::string encryption_hash;
  if (chunk_buffers_[pred % kMinChunks].index == pred)
    encryption_hash = chunk_buffers_[pred % kMinChunks].hash;
  else if (pred < data_map_->chunks.size())
    encryption_hash = data_map_->chunks[pred].pre_hash;

  if (encryption_hash.empty()) {
    DLOG(ERROR) << "FinaliseWriting: Could not get encryption hash."
                << std::endl;
    return false;
  }

  if (!LoadChunkIntoBuffer(prepred, &(chunk_buffers_[prepred % kMinChunks]))) {
    DLOG(ERROR) << "FinaliseWriting: Could not load pre-predecessor of "
                << current_chunk_index_ << "." << std::endl;
    return false;
  }

  if (!StoreChunkFromBuffer(chunk_buffers_[prepred % kMinChunks],
                            encryption_hash, chunk_buffer.hash)) {
    DLOG(ERROR) << "FinaliseWriting: Could not store pre-predecessor of "
                << current_chunk_index_ << "." << std::endl;
    return false;
  }

  pending_chunks_.insert(pred);
  pending_chunks_.insert(current_chunk_index_);
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
    chunk_buffer->index = index;
    chunk_buffer->hash.clear();
    chunk_buffer->content = data_map_->content;
    return !chunk_buffer->content.empty();
  }

  const ChunkDetails &chunk = data_map_->chunks[index];
  if (chunk_buffer->content.empty() || chunk_buffer->hash != chunk.pre_hash) {
    chunk_buffer->content = utils::SelfDecryptChunk(
        chunk_store_->Get(chunk.hash),
        data_map_->chunks[(index + 1) % chunk_count].pre_hash,
        data_map_->chunks[(index + 2) % chunk_count].pre_hash,
        data_map_->self_encryption_type);
    chunk_buffer->hash = chunk.pre_hash;
  }
  chunk_buffer->index = index;

  if (chunk_buffer->content.size() != chunk.pre_size) {
    DLOG(ERROR) << "LoadChunkIntoBuffer: Failed restoring chunk " << index
                << ", size differs." << std::endl;
    chunk_buffer->content = std::string(chunk.pre_size, 0);
    return false;
  }

  if (utils::Hash(chunk_buffer->content, data_map_->self_encryption_type) !=
          chunk.pre_hash) {
    DLOG(ERROR) << "LoadChunkIntoBuffer: Failed restoring chunk " << index
                << ", does not validate." << std::endl;
    chunk_buffer->content = std::string(chunk.pre_size, 0);
    return false;
  }

  return true;
}

bool SelfEncryptionDevice::StoreChunkFromBuffer(
    const ChunkBuffer &chunk_buffer,
    const std::string &encryption_hash,
    const std::string &obfuscation_hash) {
  if (chunk_buffer.hash.empty() || chunk_buffer.content.empty() ||
      encryption_hash.empty() || obfuscation_hash.empty()) {
    DLOG(ERROR) << "StoreChunkFromBuffer: Invalid input." << std::endl;
    return false;
  }

  if (data_map_->chunks.empty()) {
    // TODO(Steve) determine compressibility
    data_map_->self_encryption_type = default_self_encryption_type_;
  }

  if ((data_map_->chunks.empty() && chunk_buffer.content.size() <=
           self_encryption_params_.max_includable_data_size) ||
      (data_map_->chunks.size() <= chunk_buffer.index &&
       chunk_buffer.content.size() <=
           self_encryption_params_.max_includable_chunk_size)) {
    data_map_->content = chunk_buffer.content;
    data_map_->size += chunk_buffer.content.size();
    pending_chunks_.erase(chunk_buffer.index);
    return true;
  }

  // TODO(Steve) look for existing chunk with same two successors

  std::string encrypted_content(utils::SelfEncryptChunk(
      chunk_buffer.content, encryption_hash, obfuscation_hash,
      data_map_->self_encryption_type));

  if (encrypted_content.empty()) {
    DLOG(ERROR) << "StoreChunkFromBuffer: Could not self-encrypt chunk."
                << std::endl;
    return false;
  }

  std::string hash(utils::Hash(encrypted_content,
                               data_map_->self_encryption_type));

  bool do_store(false);

  if (chunk_buffer.index >= data_map_->chunks.size()) {
    // new chunk
    ChunkDetails chunk;
    chunk.pre_hash = chunk_buffer.hash;
    chunk.pre_size = chunk_buffer.content.size();
    chunk.hash = hash;
    chunk.size = encrypted_content.size();
    do_store = true;
    data_map_->chunks.push_back(chunk);
    data_map_->size += chunk.pre_size;
  } else {
    // modified chunk
    ChunkDetails &chunk = data_map_->chunks[chunk_buffer.index];
    if (chunk.hash != hash) {
      if (!chunk_store_->Delete(chunk.hash)) {
        DLOG(WARNING) << "StoreChunkFromBuffer: Could not delete old chunk."
                      << std::endl;
      }
      data_map_->size -= chunk.pre_size;
      chunk.pre_hash = chunk_buffer.hash;
      chunk.pre_size = chunk_buffer.content.size();
      chunk.hash = hash;
      chunk.size = encrypted_content.size();
      do_store = true;
      data_map_->size += chunk.pre_size;
    }
  }

  if (do_store && !chunk_store_->Store(hash, encrypted_content)) {
    DLOG(ERROR) << "StoreChunkFromBuffer: Could not store chunk."
                << std::endl;
    return false;
  }

  pending_chunks_.erase(chunk_buffer.index);
  return true;
}

}  // namespace encrypt

}  // namespace maidsafe
