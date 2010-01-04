/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages watch lists and reference lists on a vault
* Version:      1.0
* Created:      2009-12-22
* Revision:     none
* Compiler:     gcc
* Author:       Team maidsafe.net
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

#ifndef MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_
#define MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_

#include <gtest/gtest_prod.h>
#include <maidsafe/maidsafe-dht.h>

#include <string>
#include <list>
#include <map>

#include "maidsafe/maidsafe.h"

namespace maidsafe_vault {

struct WatchListEntry {
  std::string pmid_;
  bool can_delete_;
};

struct ReferenceListEntry {
  std::string pmid_;
  // time stamp
  // rank?
};

struct ChunkInfo {
  ChunkInfo() : watchers_(), references_(), watcher_count_(0),
                watcher_checksum_(0), chunk_size_(0) {}
  std::list<WatchListEntry> watchers_;
  std::list<ReferenceListEntry> references_;
  boost::uint64_t watcher_count_;
  boost::uint64_t watcher_checksum_;
  boost::uint64_t chunk_size_;
  // TODO(Team#) stats?
};

class ChunkInfoHandler {
 public:
  ChunkInfoHandler() : chunk_infos_(), chunk_info_mutex_() {}
  ~ChunkInfoHandler() {}

  bool HasWatchers(const std::string &chunk_name);
  int AddToWatchList(const std::string &chunk_name,
                     const std::string &pmid,
                     const boost::uint64_t &chunk_size,
                     std::string *creditor,
                     bool *payment_required);
  int RemoveFromWatchList(const std::string &chunk_name,
                          const std::string &pmid,
                          const boost::uint64_t &chunk_size,
                          std::list<std::string> *creditors);
  void RevertAddToWatchList(const std::string &chunk_name,
                            const std::string &pmid,
                            const std::string &creditor);
  // TODO(Steve#) ref list methods
  void Lock();
  void Unlock();
 private:
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerInit);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerWlAddRemove);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerWlFailsafe);
  boost::uint64_t GetChecksum(const std::string &id);
  std::map<std::string, ChunkInfo> chunk_infos_;
  boost::mutex chunk_info_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_
