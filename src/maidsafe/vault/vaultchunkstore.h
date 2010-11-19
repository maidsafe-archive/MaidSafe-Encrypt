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

#ifndef MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_
#define MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_

#include <list>
#include <string>

#include "maidsafe/common/chunkstore.h"

namespace maidsafe {

namespace vault {

namespace test { class VaultChunkstoreTest_BEH_MAID_Space_Test; }

class VaultChunkStore : public ChunkStore {
 public:
  VaultChunkStore(const std::string &chunkstore_dir,
                  const boost::uint64_t &available_space,
                  const boost::uint64_t &used_space)
      : ChunkStore(chunkstore_dir, available_space, used_space),
        space_used_by_cache_(0) {}
  // Loads a chunk chosen at random from hashable normal (ie not cached) chunks
  int LoadRandomChunk(std::string *key, std::string *value);
  void GetAllChunks(std::list<std::string> *chunk_names);
  // Hash check all local chunks and add to list those that fail.  Bool set to
  // true causes failed chunks to be deleted.
  int HashCheckAllChunks(bool delete_failures,
                         std::list<std::string> *failed_keys);
  // Cache chunk procedure
  int CacheChunk(const std::string &key, const std::string &value);
  // Delete oldest cached chunks to make room
  int FreeCacheSpace(const boost::uint64_t &space_to_clear);
  inline boost::uint64_t available_space() { return available_space_; }
  inline boost::uint64_t used_space() { return used_space_; }
  inline boost::uint64_t space_used_by_cache() { return space_used_by_cache_; }
  inline boost::uint64_t FreeSpace() {
    return available_space_ - used_space_ - space_used_by_cache_;
  }
 private:
  friend class test::VaultChunkstoreTest_BEH_MAID_Space_Test;
  // Returns ChunkInfo for the chunk which was checked the longest time ago.  If
  // several chunks qualify, only the first one is returned.
  ChunkInfo GetOldestChecked();
  inline void set_available_space(boost::uint64_t avail) {
    available_space_ = avail;
  }
  bool EnoughSpace(const boost::uint64_t &length);
  boost::uint64_t space_used_by_cache_;
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_
