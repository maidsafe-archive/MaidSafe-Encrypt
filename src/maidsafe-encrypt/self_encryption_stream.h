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
#include <string>

#include "boost/filesystem.hpp"
#include "boost/iostreams/concepts.hpp"
#include "boost/iostreams/positioning.hpp"
#include "boost/iostreams/stream.hpp"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 3
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace boost {
namespace iostreams {
struct input_seekable_device_tag
    : virtual device_tag, input_seekable, detail::one_head { };  // NOLINT
}  // namespace iostreams
}  // namespace boost

namespace maidsafe {

namespace encrypt {

namespace test {
class SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceInit_Test;
class SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceSeek_Test;
}

class SelfEncryptionDevice : public io::device<io::input_seekable_device_tag> {
 public:
  SelfEncryptionDevice(const DataMap &data_map, const fs::path &chunk_dir);
  virtual ~SelfEncryptionDevice() {}
  std::streamsize read(char* s, std::streamsize n);
  // std::streamsize write(const char_type* s, std::streamsize n);
  io::stream_offset seek(io::stream_offset offset, std::ios_base::seekdir way);
 private:
  friend class test::SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceInit_Test;
  friend class test::SelfEncryptionStreamTest_BEH_ENCRYPT_DeviceSeek_Test;
  DataMap data_map_;
  fs::path chunk_dir_;
  std::streamsize total_size_;
  io::stream_offset offset_;
  size_t current_chunk_index_;
  io::stream_offset current_chunk_offset_;
  std::string current_chunk_content_;
};

typedef io::stream<SelfEncryptionDevice> SelfEncryptionStream;

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_
