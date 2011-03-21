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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/utils.h"
#include "boost/filesystem/fstream.hpp"

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

std::streamsize SelfEncryptionDevice::read(char *s, std::streamsize n) {
  std::streamsize remaining(n);
  size_t chunk_count(data_map_.chunks.size());

  if (offset_ >= data_map_.size)
    return -1;
  if (n <= 0)
    return 0;

  // check for whole content in DataMap
  if (chunk_count == 0) {
    std::string content;
    if (!data_map_.content.empty()) {
      if (data_map_.compression_type == kNoCompression)
        content = data_map_.content;
      else if (data_map_.compression_type == kGzipCompression)
        content = crypto::Uncompress(data_map_.content);
    }
    size_t size(std::min(n, static_cast<std::streamsize>(
        content.size() - offset_)));
    static_cast<char*>(memcpy(s, &(content[offset_]), size));
    offset_ += size;
    return static_cast<std::streamsize>(size);
  }

  // determine the first chunk in the range
  size_t start_chunk_index(0);
  io::stream_offset start_chunk_offset(0);
  if (offset_ >= current_chunk_offset_) {
    start_chunk_index = current_chunk_index_;
    start_chunk_offset = current_chunk_offset_;
  }
  while (start_chunk_index < chunk_count &&
         start_chunk_offset + data_map_.chunks[start_chunk_index].pre_size <=
             offset_) {
    start_chunk_offset += data_map_.chunks[start_chunk_index].pre_size;
    ++start_chunk_index;
  }
  if (start_chunk_index >= chunk_count ||
      start_chunk_offset >= data_map_.size) {
    DLOG(ERROR) << "read: Could not determine first chunk." << std::endl;
    return -1;
  }

  // determine the last chunk in the range
  size_t end_chunk_index(start_chunk_index);
  io::stream_offset end_chunk_offset(start_chunk_offset);
  while (end_chunk_index < chunk_count - 1 &&
         end_chunk_offset + data_map_.chunks[end_chunk_index].pre_size <
             offset_ + n) {
    end_chunk_offset += data_map_.chunks[end_chunk_index].pre_size;
    ++end_chunk_index;
  }

  io::stream_offset chunk_offset(start_chunk_offset);
  for (size_t chunk_index = start_chunk_index; chunk_index <= end_chunk_index;
       chunk_offset += data_map_.chunks[chunk_index].pre_size, ++chunk_index) {
    const ChunkDetails &chunk = data_map_.chunks[chunk_index];
    if (current_chunk_content_.empty() || chunk_index != current_chunk_index_) {
      if (current_chunk_content_.empty() ||
          chunk.pre_hash != data_map_.chunks[current_chunk_index_].pre_hash) {
        if (chunk.content.empty()) {
          fs::path chunk_path(chunk_dir_ / EncodeToHex(chunk.hash));
          if (!ReadFile(chunk_path, &current_chunk_content_)) {
            DLOG(ERROR) << "read: Can't read chunk data from "
                        << chunk_path.c_str() << std::endl;
            return -1;
          }

          if (current_chunk_content_.size() != chunk.size) {
            DLOG(ERROR) << "read: Wrong chunk size (actual "
                        << current_chunk_content_.size() << ", expected "
                        << chunk.size << ") - " << chunk_path.c_str()
                        << std::endl;
            return -1;
          }

          current_chunk_content_ = utils::SelfDecryptChunk(
              current_chunk_content_,
              data_map_.chunks[(chunk_index + 1) % chunk_count].pre_hash,
              data_map_.chunks[(chunk_index + 2) % chunk_count].pre_hash);
        } else {
          current_chunk_content_ = data_map_.chunks[chunk_index].content;
        }

        if (data_map_.compression_type == kGzipCompression)
          current_chunk_content_ = crypto::Uncompress(current_chunk_content_);

        if (current_chunk_content_.size() != chunk.pre_size ||
            crypto::Hash<crypto::SHA512>(current_chunk_content_) !=
                chunk.pre_hash) {
          DLOG(ERROR) << "read: Failed restoring chunk data." << std::endl;
          return -1;
        }
      } else {
        // we have a chunk cached with the same contents, no need to reload
        // DLOG(INFO) << "read: chunk cache hit" << std::endl;
      }

      current_chunk_index_ = chunk_index;
      current_chunk_offset_ = chunk_offset;
    }

    io::stream_offset this_offset(0);
    if (offset_ > chunk_offset)
      this_offset = offset_ - chunk_offset;
    size_t size(std::min(remaining, static_cast<std::streamsize>(
        current_chunk_content_.size() - this_offset)));
    static_cast<char*>(memcpy(s, &(current_chunk_content_[this_offset]), size));

    s += size;
    offset_ += size;
    remaining -= size;
  }

  return n - remaining;
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
      new_offset = data_map_.size + offset;
      break;
    default:
      DLOG(ERROR) << "seek: Invalid seek direction passed." << std::endl;
      return -1;
  }

  if (new_offset < 0 || new_offset > data_map_.size) {
    DLOG(ERROR) << "seek: Invalid offset passed." << std::endl;
    return -1;
  }

  offset_ = new_offset;
  return offset_;
}

}  // namespace encrypt

}  // namespace maidsafe
