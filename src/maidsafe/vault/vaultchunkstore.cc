/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */

#include "maidsafe/vault/vaultchunkstore.h"

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_array.hpp>
#include <boost/thread/mutex.hpp>

namespace maidsafe_vault {

bool VaultChunkStore::UpdateChunk(const std::string &key,
                                  const std::string &value) {
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::UpdateChunk.\n");
#endif
    return false;
  }
  if (key.size() != kKeySize) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, incorrect key size.\n");
#endif
    return false;
  }
  // check we have the chunk already
  maidsafe::ChunkType type = 0;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<maidsafe::non_hex_name>().find(key);
    if (itr != chunkstore_set_.end())
      type = (*itr).type_;
  }
  if (type == 0) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, don't currently have chunk.\n");
#endif
    return false;
  }
  fs::path chunk_path(GetChunkPath(key, type, false));
  if (!DeleteChunkFunction(key, chunk_path))
    return false;
  return StoreChunkFunction(key, value, chunk_path, type);
}

maidsafe::ChunkInfo VaultChunkStore::GetOldestChecked() {
  maidsafe::ChunkInfo chunk;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_last_checked::iterator itr =
        chunkstore_set_.get<1>().begin();
    chunk = *itr;
  }
  return chunk;
}

bool VaultChunkStore::LoadRandomChunk(std::string *key, std::string *value) {
  key->clear();
  value->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::LoadRandomChunk.\n");
#endif
    return false;
  }
  bool result(false);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    if (chunkstore_set_.size() != 0)
      result = true;
  }
  if (!result) {
#ifdef DEBUG
    printf("In ChunkStore::LoadRandomChunk: there are no chunks stored.\n");
#endif
    return false;
  }
  maidsafe::ChunkType type = (maidsafe::kHashable | maidsafe::kNormal);
  boost::uint64_t hashable_count(0);
  {
    maidsafe::chunk_set_by_chunk_type &sorted_index =
        chunkstore_set_.get<maidsafe::chunk_type>();
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    hashable_count = sorted_index.count(type);
  }
  if (!hashable_count)  // i.e. there are no chunks available
    return false;
  int randindex = static_cast<int>(base::random_32bit_uinteger()
      % hashable_count);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_chunk_type::iterator itr =
         chunkstore_set_.get<maidsafe::chunk_type>().begin();
    for (int i = 0; i < randindex; ++i, ++itr) {}
    *key = (*itr).non_hex_name_;
    // check we've got the correct type
    result = ((*itr).type_ == type);
  }
  if (result)
    return LoadChunk(*key, value);
  else
    return false;
}

void VaultChunkStore::GetAllChunks(std::list<std::string> *chunk_names) {
  chunk_names->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::GetAllChunks.\n");
#endif
    return;
  }
  boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
  for (maidsafe::chunk_set_by_non_hex_name::iterator itr =
       chunkstore_set_.get<maidsafe::non_hex_name>().begin();
       itr != chunkstore_set_.get<maidsafe::non_hex_name>().end(); ++itr) {
    chunk_names->push_back((*itr).non_hex_name_);
  }
}

int VaultChunkStore::HashCheckAllChunks(bool delete_failures,
                                        std::list<std::string> *failed_keys) {
  failed_keys->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::HashCheckAllChunks.\n");
#endif
    return -1;
  }
  boost::uint64_t filecount;
  bool result(true);
  for (maidsafe::path_map_iterator path_map_itr = path_map_.begin();
       path_map_itr != path_map_.end(); ++path_map_itr) {
    maidsafe::ChunkType type = path_map_itr->first;
    if (type & maidsafe::kHashable) {
      FindFiles(path_map_itr->second, type, true, delete_failures, &filecount,
                failed_keys);
    }
  }
  if (delete_failures) {
    std::list<std::string>::iterator itr;
    for (itr = failed_keys->begin(); itr != failed_keys->end(); ++itr) {
      if (DeleteChunk((*itr))) {
        --filecount;
      } else {
        result = false;
      }
    }
  }
  if (!result)
    return -1;
  return 0;
}

}  // namespace maidsafe_vault
