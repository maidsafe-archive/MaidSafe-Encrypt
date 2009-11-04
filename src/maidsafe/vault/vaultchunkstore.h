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
#include <functional>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "maidsafe/chunkstore.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

struct PacketStoreRow {
  PacketStoreRow(const std::string &packet_name,
                 const std::string &data,
                 const std::string &signature,
                 const int &index)
                     : packet_name_(packet_name),
                       data_(data),
                       signature_(signature),
                       index_(index) {}
  std::string packet_name_;
  std::string data_;
  std::string signature_;
  int index_;
};

/* Tags */
struct store_packet_unique_key {};
struct store_packet_index {};

typedef boost::multi_index_container<
  PacketStoreRow,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<store_packet_unique_key>,
      boost::multi_index::composite_key<
        PacketStoreRow,
        BOOST_MULTI_INDEX_MEMBER(PacketStoreRow, std::string, packet_name_),
        BOOST_MULTI_INDEX_MEMBER(PacketStoreRow, std::string, data_)
      >
    >,
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<store_packet_index>,
      boost::multi_index::composite_key<
        PacketStoreRow,
        BOOST_MULTI_INDEX_MEMBER(PacketStoreRow, std::string, packet_name_),
        BOOST_MULTI_INDEX_MEMBER(PacketStoreRow, int, index_)
      >,
      boost::multi_index::composite_key_compare<
        std::less<std::string>,
        std::greater<int>
      >
    >
  >
> packet_store_set;

class VaultChunkStore : public maidsafe::ChunkStore {
 public:
  VaultChunkStore(const std::string &chunkstore_dir,
                  const boost::uint64_t &available_space,
                  const boost::uint64_t &used_space)
      : ChunkStore(chunkstore_dir, available_space, used_space), pss_(),
        packetstore_set_mutex_() {}
  // This replaces the existing value - it doesn't append to the existing value
  int UpdateChunk(const std::string &key, const std::string &value);
  // Loads a chunk chosen at random from hashable normal (ie not cached) chunks
  int LoadRandomChunk(std::string *key, std::string *value);
  void GetAllChunks(std::list<std::string> *chunk_names);
  // Hash check all local chunks and add to list those that fail.  Bool set to
  // true causes failed chunks to be deleted.
  int HashCheckAllChunks(bool delete_failures,
                         std::list<std::string> *failed_keys);
  // Fails if packet_name is already an entry in the packet_store_set.
  int StorePacket(const std::string &packet_name,
                  const maidsafe::GenericPacket &gp);
  // Assumes that gp has already been validated against public_key, but checks
  // that the last value stored under packet_name was signed with the same
  // key as for this gp.  Method fails if packet_name is not already an entry in
  // the packet_store_set.
  int AppendToPacket(const std::string &packet_name,
                     const maidsafe::GenericPacket &gp,
                     const std::string &public_key);
  // Assumes that gp has already been validated against public_key, but checks
  // that the last value stored under packet_name was signed with the same
  // key as for this gp.  Method fails if packet_name is not already an entry in
  // the packet_store_set.
  int OverwritePacket(const std::string &packet_name,
                      const std::vector<maidsafe::GenericPacket> &gps,
                      const std::string &public_key);
  // If gps is empty, all values stored under packet_name are removed.
  int DeletePacket(const std::string &packet_name,
                   const std::vector<maidsafe::GenericPacket> &gps,
                   const std::string &public_key);
  int LoadPacket(const std::string &packet_name,
                 std::vector<maidsafe::GenericPacket> *gps);
  bool HasPacket(const std::string &packet_name);
  inline boost::uint64_t available_space() { return available_space_; }
  inline boost::uint64_t used_space() { return used_space_; }
  inline boost::uint64_t FreeSpace() { return available_space_ - used_space_; }
 private:
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreInit);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreInvalidKeySize);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreStoreChunk);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreAddChunkToOutgoing);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreDeleteChunk);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreLoadRandomChunk);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreReuseDirectory);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreHashCheckChunk);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreChangeChunkType);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreChunkType);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreSpace);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreCheckAllChunks);
  FRIEND_TEST(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedChangeType);
  FRIEND_TEST(ChunkstoreTest, FUNC_MAID_ChunkstoreStorePackets);
  FRIEND_TEST(ChunkstoreTest, FUNC_MAID_ChunkstoreAppendToPackets);
  FRIEND_TEST(ChunkstoreTest, FUNC_MAID_ChunkstoreOverwritePackets);
  FRIEND_TEST(ChunkstoreTest, FUNC_MAID_ChunkstoreDeletePackets);
  // Returns ChunkInfo for the chunk which was checked the longest time ago.  If
  // several chunks qualify, only the first one is returned.
  maidsafe::ChunkInfo GetOldestChecked();
  inline void set_available_space(boost::uint64_t avail) {
    available_space_ = avail;
  }
  packet_store_set pss_;
  boost::mutex packetstore_set_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_VAULTCHUNKSTORE_H_
