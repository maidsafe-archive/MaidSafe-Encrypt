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
 *      Author: Team
 */

#ifndef MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_
#define MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_

#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <list>
#include <map>
#include <string>

#include "maidsafe/chunkstore.h"
#include "maidsafe/maidsafe.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

class VaultChunkStore : public maidsafe::ChunkStore {
 public:
  VaultChunkStore(const std::string &chunkstore_dir,
                  const boost::uint64_t &available_space,
                  const boost::uint64_t &used_space)
      : ChunkStore(chunkstore_dir, available_space, used_space) {}
  // This replaces the existing value - it doesn't append to the existing value
  int UpdateChunk(const std::string &key, const std::string &value);
  // Loads a chunk chosen at random from hashable normal (ie not cached) chunks
  int LoadRandomChunk(std::string *key, std::string *value);
  void GetAllChunks(std::list<std::string> *chunk_names);
  // Hash check all local chunks and add to list those that fail.  Bool set to
  // true causes failed chunks to be deleted.
  int HashCheckAllChunks(bool delete_failures,
                         std::list<std::string> *failed_keys);
  inline boost::uint64_t available_space() { return available_space_; }
  inline boost::uint64_t used_space() { return used_space_; }
  inline boost::uint64_t FreeSpace() { return available_space_ - used_space_; }
 private:
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreInit);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreInvalidKeySize);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreStore);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreAddChunkToOutgoing);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreDeleteChunk);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreLoadRandomChunk);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreReuseDirectory);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreHashCheckChunk);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreChangeChunkType);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreChunkType);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreSpace);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreCheckAllChunks);
  FRIEND_TEST(TestChunkstore, BEH_MAID_ChunkstoreThreadedChangeType);
  // Returns ChunkInfo for the chunk which was checked the longest time ago.  If
  // several chunks qualify, only the first one is returned.
  maidsafe::ChunkInfo GetOldestChecked();
  inline void set_available_space(boost::uint64_t avail) {
    available_space_ = avail;
  }
};
}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_
