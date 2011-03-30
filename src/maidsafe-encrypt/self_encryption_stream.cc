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
  // DLOG(INFO) << "write " << n << std::endl;

  if (!s || n <= 0)
    return -1;

  return -1;
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
  return true;
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

}  // namespace encrypt

}  // namespace maidsafe
