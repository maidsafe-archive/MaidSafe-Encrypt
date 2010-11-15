/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Derived chunk store class.
* Version:      1.0
* Created:      2009-02-21-23.55.54
* Revision:     none
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/vault/vaultchunkstore.h"
#include <maidsafe/base/utils.h>
#include "maidsafe/common/returncodes.h"
#include "maidsafe/vault/vaultconfig.h"

namespace maidsafe {

namespace vault {

ChunkInfo VaultChunkStore::GetOldestChecked() {
  ChunkInfo chunk;
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_last_checked::iterator itr = chunkstore_set_.get<1>().begin();
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
  ChunkType type = (kHashable | kNormal);
  boost::uint64_t hashable_count(0);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_chunk_type &sorted_index =
        chunkstore_set_.get<maidsafe::chunk_type>();
    hashable_count = sorted_index.count(type);
  }
  if (!hashable_count)  // i.e. there are no chunks available
    return kChunkstoreError;
  int randindex = static_cast<int>(base::RandomUint32()
      % hashable_count);
  {
    boost::mutex::scoped_lock lock(chunkstore_set_mutex_);
    chunk_set_by_chunk_type::iterator itr =
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
  for (chunk_set_by_non_hex_name::iterator itr =
       chunkstore_set_.get<non_hex_name>().begin();
       itr != chunkstore_set_.get<non_hex_name>().end(); ++itr) {
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
  for (path_map_iterator path_map_itr = path_map_.begin();
       path_map_itr != path_map_.end(); ++path_map_itr) {
    ChunkType type = path_map_itr->first;
    if (type & kHashable) {
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

  ChunkType ct(kHashable | kCache);
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
    ChunkInfo chunk;
    boost::uint64_t cleared_so_far(0);
    chunk_set_by_last_checked::iterator itr = chunkstore_set_.get<1>().begin();
    while (cleared_so_far < space_to_clear &&
        itr != chunkstore_set_.get<1>().end()) {
      chunk = *itr;
      if (chunk.type_ & kCache) {
        fs::path p(GetChunkPath(chunk.non_hex_name_, chunk.type_, false));
        try {
          fs::remove_all(p);
        }
        catch(const std::exception&) {}
        chunkstore_set_.get<1>().erase(itr);
        itr = chunkstore_set_.get<1>().begin();
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

}  // namespace vault

}  // namespace maidsafe
