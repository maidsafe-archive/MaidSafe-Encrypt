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
 */

#include "maidsafe-encrypt/self_encryption_stream.h"

#include <iosfwd>
#include <string>

#include "maidsafe-encrypt/utils.h"
#include "boost/filesystem/fstream.hpp"

namespace fs = boost::filesystem3;
namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

SelfEncryptionDevice::SelfEncryptionDevice(const DataMap &data_map,
                                           const fs::path &chunk_dir)
    : data_map_(data_map),
      chunk_dir_(chunk_dir),
      total_size_(0),
      offset_(0),
      current_chunk_index_(0),
      current_chunk_offset_(0),
      current_chunk_content_() {
  for (auto it = data_map_.chunks.begin(); it != data_map_.chunks.end(); ++it)
    total_size_ += it->pre_size;
}

std::streamsize SelfEncryptionDevice::read(char* s, std::streamsize n) {
  /* - determine which chunks the offset_ and offset_ + n locations translate to
   * - iterate over all relevant chunks
   *   - load chunk, if not already in memory
   *   - self-decrypt content
   *   - write to output buffer and increment pointer
   * - update relevant member vars
   */
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
      new_offset = offset_ + offset_;
      break;
    case std::ios_base::end:
      new_offset = total_size_ + offset;
      break;
    default:
      return -1;
  }

  if (new_offset < 0 || new_offset > total_size_)
    return -1;

  offset_ = new_offset;
  return offset_;
}

}  // namespace encrypt

}  // namespace maidsafe