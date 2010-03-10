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

#include <set>

namespace maidsafe_vault {

int VaultChunkStore::UpdateChunk(const std::string &key,
                                 const std::string &value) {
  int valid = InitialOperationVerification(key);
  if (valid != kSuccess)
    return valid;

  // check we have the chunk already
  maidsafe::ChunkType type = kInvalidChunkType;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr =
        chunkstore_set_.get<maidsafe::non_hex_name>().find(key);
    if (itr != chunkstore_set_.end())
      type = (*itr).type_;
  }
  if (type == kInvalidChunkType) {
#ifdef DEBUG
    printf("In ChunkStore::UpdateChunk, don't currently have chunk.\n");
#endif
    return kInvalidChunkType;
  }
  fs::path chunk_path(GetChunkPath(key, type, false));
  if (DeleteChunkFunction(key, chunk_path) != kSuccess)
    return kChunkstoreUpdateFailure;
  return (StoreChunkFunction(key, value, chunk_path, type) == kSuccess) ?
      kSuccess : kChunkstoreUpdateFailure;
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

int VaultChunkStore::LoadRandomChunk(std::string *key, std::string *value) {
  key->clear();
  value->clear();
  if (!is_initialised()) {
#ifdef DEBUG
    printf("Not initialised in ChunkStore::LoadRandomChunk.\n");
#endif
    return kChunkstoreUninitialised;
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
    return kChunkstoreError;
  }
  maidsafe::ChunkType type = (maidsafe::kHashable | maidsafe::kNormal);
  boost::uint64_t hashable_count(0);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::chunk_set_by_chunk_type &sorted_index =
        chunkstore_set_.get<maidsafe::chunk_type>();
    hashable_count = sorted_index.count(type);
  }
  if (!hashable_count)  // i.e. there are no chunks available
    return kChunkstoreError;
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
    return Load(*key, value);
  else
    return kChunkstoreError;
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
    return kChunkstoreUninitialised;
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
      if (DeleteChunk((*itr)) == kSuccess) {
        --filecount;
      } else {
        result = false;
      }
    }
  }
  return result ? kSuccess : kHashCheckFailure;
}

int VaultChunkStore::CacheChunk(const std::string &key,
                                const std::string &value) {
  if (Has(key))
    return kSuccess;

  if (!EnoughSpace(value.size()))
    return kNoSpaceForCaching;

  maidsafe::ChunkType ct(maidsafe::kHashable | maidsafe::kCache);
  fs::path store_path = GetChunkPath(key, ct, true);
  int n = StoreChunkFunction(key, value, store_path, ct);
  if (n != kSuccess)
    return n;

  space_used_by_cache_ += value.size();
  return kSuccess;
}

int VaultChunkStore::FreeCacheSpace(const boost::uint64_t &space_to_clear) {
  if (space_used_by_cache() == 0)
    return kNoCacheSpaceToClear;

  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    maidsafe::ChunkInfo chunk;
    boost::uint64_t cleared_so_far(0);
    maidsafe::chunk_set_by_last_checked::iterator itr =
        chunkstore_set_.get<1>().begin();
    while (cleared_so_far < space_to_clear &&
        itr != chunkstore_set_.get<1>().end()) {
      chunk = *itr;
      if (chunk.type_ & maidsafe::kCache) {
        fs::path p(GetChunkPath(chunk.non_hex_name_, chunk.type_, false));
        try {
          fs::remove_all(p);
        }
        catch(const std::exception &e) {}
        maidsafe::chunk_set_by_non_hex_name::iterator name_itr =
            chunkstore_set_.get<0>().find(chunk.non_hex_name_);
        chunkstore_set_.erase(name_itr);
        space_used_by_cache_ -= chunk.size_;
        cleared_so_far += chunk.size_;
      } else {
        ++itr;
      }
    }
  }
  return kSuccess;
}

bool VaultChunkStore::EnoughSpace(const boost::uint64_t &length) {
  if (FreeSpace() < length)
    return false;
  return true;
}

}  // namespace maidsafe_vault
