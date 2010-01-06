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

enum ResetReason {kReasonStoringFailed, kReasonPaymentFailed};

struct WatchListEntry {
  std::string pmid_;
  bool can_delete_;
};

struct ReferenceListEntry {
  std::string pmid_;
  // time stamp
  // rank?
};

struct WaitingListEntry {
  std::string pmid_;
  // time stamp
  bool storing_done_;
  bool payments_done_;
  int requested_payments_;
};

struct ChunkInfo {
  ChunkInfo() : waiting_list_(), watch_list_(), reference_list_(),
                watcher_count_(0), watcher_checksum_(0), chunk_size_(0) {}
  std::list<WaitingListEntry> waiting_list_;
  std::list<WatchListEntry> watch_list_;
  std::list<ReferenceListEntry> reference_list_;
  boost::uint64_t watcher_count_;
  boost::uint64_t watcher_checksum_;
  boost::uint64_t chunk_size_;
  // TODO(Team#) stats?
};

class ChunkInfoHandler {
 public:
  ChunkInfoHandler() : chunk_infos_(), chunk_info_mutex_() {}
  ~ChunkInfoHandler() {}

  int PrepareAddToWatchList(const std::string &chunk_name,
                            const std::string &pmid,
                            const boost::uint64_t &chunk_size,
                            int *required_references,
                            int *required_payments);
  bool TryCommitToWatchList(const std::string &chunk_name,
                            const std::string &pmid,
                            std::string *creditor,
                            int *refunds);
  void ResetAddToWatchList(const std::string &chunk_name,
                           const std::string &pmid,
                           const ResetReason &reason);
  int RemoveFromWatchList(const std::string &chunk_name,
                          const std::string &pmid,
                          const boost::uint64_t &chunk_size,
                          std::list<std::string> *creditors);
  int AddToReferenceList(const std::string &chunk_name,
                         const std::string &pmid,
                         const boost::uint64_t &chunk_size);
  int RemoveFromReferenceList(const std::string &chunk_name,
                              const std::string &pmid);
  void SetStoringDone(const std::string &chunk_name);
  void SetPaymentsDone(const std::string &chunk_name, const std::string &pmid);
  void PruneWaitingLists();
 private:
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerInit);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerWlAddRemove);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerFailsafe);
  bool HasWatchers(const std::string &chunk_name);
  int ActiveReferences(const std::string &chunk_name);
  boost::uint64_t GetChecksum(const std::string &id);
  std::map<std::string, ChunkInfo> chunk_infos_;
  boost::mutex chunk_info_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_
