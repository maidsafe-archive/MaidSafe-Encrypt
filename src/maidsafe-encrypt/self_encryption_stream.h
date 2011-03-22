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
 * @file  self_encryption_stream.h
 * @brief Provides self-en/decryption functionality through a stream interface.
 * @date  2011-02-18
 */

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_

#include <iosfwd>
#include <memory>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/iostreams/concepts.hpp"
#include "boost/iostreams/positioning.hpp"
#include "boost/iostreams/stream.hpp"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 4
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace maidsafe {

class ChunkStore;

namespace encrypt {

class DataMap;

namespace test {
class SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceSeek_Test;
}

/// Device implementing basic streaming functionality for self-encryption
class SelfEncryptionDevice {
 public:
  typedef char char_type;
  typedef io::seekable_device_tag category;
  SelfEncryptionDevice(std::shared_ptr<DataMap> data_map,
                       std::shared_ptr<ChunkStore> chunk_store)
      : data_map_(data_map),
        chunk_store_(chunk_store),
        offset_(0),
        current_chunk_index_(0),
        current_chunk_offset_(0),
        current_chunk_content_() {}
  virtual ~SelfEncryptionDevice() {}
  std::streamsize read(char *s, std::streamsize n);
  std::streamsize write(const char *s, std::streamsize n);
  io::stream_offset seek(io::stream_offset offset, std::ios_base::seekdir way);
 private:
  friend class test::SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceSeek_Test;
  std::shared_ptr<DataMap> data_map_;
  std::shared_ptr<ChunkStore> chunk_store_;
  io::stream_offset offset_;
  size_t current_chunk_index_;
  io::stream_offset current_chunk_offset_;
  std::string current_chunk_content_;
};

/// Stream wrapper for SelfEncryptionDevice
typedef io::stream<SelfEncryptionDevice> SelfEncryptionStream;

/// StreamBuffer wrapper for SelfEncryptionDevice
typedef io::stream_buffer<SelfEncryptionDevice> SelfEncryptionStreamBuffer;

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_
