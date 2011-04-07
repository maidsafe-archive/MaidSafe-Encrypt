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

namespace io = boost::iostreams;

namespace maidsafe {

namespace encrypt {

/**
 * Looks through the DataMap and checks if each required chunk exists in the
 * given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param missing_chunks Pointer to vector to receive list of unavailable
 *                       chunks' names, or NULL if not needed.
 * @return True if all chunks exist, otherwise false.
 */
bool ChunksExist(std::shared_ptr<DataMap> data_map,
                 std::shared_ptr<ChunkStore> chunk_store,
                 std::vector<std::string> *missing_chunks) {
  if (!data_map || !chunk_store)
    return false;
  bool result(true);
  if (missing_chunks)
    missing_chunks->clear();
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it) {
    if (!chunk_store->Has(it->hash)) {
      if (missing_chunks)
        missing_chunks->push_back(it->hash);
      result = false;
    }
  }
  return result;
}

/**
 * Looks through the DataMap and decreases the reference count for each chunk in
 * the given ChunkStore. The DataMap will be cleared, even if not all chunks
 * could be deleted.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore holding the chunks to be deleted.
 * @return True if all chunks could be deleted, otherwise false.
 */
bool DeleteChunks(std::shared_ptr<DataMap> data_map,
                  std::shared_ptr<ChunkStore> chunk_store) {
  if (!data_map || !chunk_store)
    return false;
  bool result(true);
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it)
    result = chunk_store->Delete(it->hash) && result;
  DataMap dm;
  (*data_map) = dm;
  return result;
}

}  // namespace encrypt

}  // namespace maidsafe
