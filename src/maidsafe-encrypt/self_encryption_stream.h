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

#include <array>
#include <iosfwd>
#include <memory>
#include <set>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/iostreams/concepts.hpp"
#include "boost/iostreams/positioning.hpp"
#include "boost/iostreams/stream.hpp"
#include "maidsafe-encrypt/config.h"
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

struct DataMap;

namespace test {
class SelfEncryptionDeviceTest_BEH_Seek_Test;
class SelfEncryptionDeviceTest_BEH_InitialiseDataMap_Test;
class SelfEncryptionDeviceTest_BEH_UpdateCurrentChunkDetails_Test;
class SelfEncryptionDeviceTest_BEH_FinaliseWriting_Test;
class SelfEncryptionDeviceTest_BEH_LoadChunkIntoBuffer_Test;
class SelfEncryptionDeviceTest_BEH_StoreChunkFromBuffer_Test;
}

/// Device implementing basic streaming functionality for self-encryption
class SelfEncryptionDevice {
 public:
  typedef char char_type;
  struct category : io::seekable_device_tag, io::flushable_tag {};
  struct ChunkBuffer {  // NOTE this should be private, if MSVC were so kind...
    ChunkBuffer() : hash(), content(), index(0) {}
    std::string hash, content;
    size_t index;
  };
  SelfEncryptionDevice(std::shared_ptr<DataMap> data_map,
                       std::shared_ptr<ChunkStore> chunk_store,
                       SelfEncryptionParams self_encryption_params =
                           SelfEncryptionParams());
  virtual ~SelfEncryptionDevice() {}
  std::streamsize read(char *s, std::streamsize n);
  std::streamsize write(const char *s, std::streamsize n);
  io::stream_offset seek(io::stream_offset offset, std::ios_base::seekdir way);
  bool flush();
 private:
  friend class test::SelfEncryptionDeviceTest_BEH_Seek_Test;
  friend class test::SelfEncryptionDeviceTest_BEH_InitialiseDataMap_Test;
  friend class
      test::SelfEncryptionDeviceTest_BEH_UpdateCurrentChunkDetails_Test;
  friend class test::SelfEncryptionDeviceTest_BEH_FinaliseWriting_Test;
  friend class test::SelfEncryptionDeviceTest_BEH_LoadChunkIntoBuffer_Test;
  friend class test::SelfEncryptionDeviceTest_BEH_StoreChunkFromBuffer_Test;
  void InitialiseDataMap(const ChunkBuffer &chunk_buffer);
  bool UpdateCurrentChunkDetails();
  bool FinaliseWriting();
  bool LoadChunkIntoBuffer(const size_t &index, ChunkBuffer *chunk_buffer);
  bool StoreChunkFromBuffer(ChunkBuffer *chunk_buffer,
                            const std::string &encryption_hash,
                            const std::string &obfuscation_hash);
  SelfEncryptionParams self_encryption_params_;
  uint32_t default_self_encryption_type_;
  std::shared_ptr<DataMap> data_map_;
  std::shared_ptr<ChunkStore> chunk_store_;
  io::stream_offset offset_, current_chunk_offset_;
  size_t current_chunk_index_;
  std::array<ChunkBuffer, kMinChunks> chunk_buffers_;
  std::set<size_t> pending_chunks_;
  bool write_mode_;
};

/// Stream wrapper for SelfEncryptionDevice
typedef io::stream<SelfEncryptionDevice> SelfEncryptionStream;

/// StreamBuffer wrapper for SelfEncryptionDevice
typedef io::stream_buffer<SelfEncryptionDevice> SelfEncryptionStreamBuffer;

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_
