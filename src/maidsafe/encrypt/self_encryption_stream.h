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

#include <memory>
#include <vector>
#include <string>

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryption_device.h"
#include "maidsafe/encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION != 903
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-encrypt library.
#endif

namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

/// Stream wrapper for SelfEncryptionDevice
typedef io::stream<SelfEncryptionDevice> SelfEncryptionStream;

/// StreamBuffer wrapper for SelfEncryptionDevice
typedef io::stream_buffer<SelfEncryptionDevice> SelfEncryptionStreamBuffer;

/// Checks for existance of each chunk referred to by the DataMap.
bool ChunksExist(std::shared_ptr<DataMap> data_map,
                 std::shared_ptr<ChunkStore> chunk_store,
                 std::vector<std::string> *missing_chunks);

/// Deletes each chunk referred to by the DataMap.
bool DeleteChunks(std::shared_ptr<DataMap> data_map,
                  std::shared_ptr<ChunkStore> chunk_store);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_STREAM_H_
