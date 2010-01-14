/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Manages watch lists and reference lists on a vault
* Version:      1.0
* Created:      2009-12-22
* Revision:     none
* Compiler:     gcc
* Author:       Steve Muecklisch
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

enum ResetReason {kReasonStoringFailed, kReasonPaymentFailed, kReasonStale};

struct WatchListEntry {
  std::string pmid;
  bool can_delete;
};

struct ReferenceListEntry {
  std::string pmid;
  boost::uint32_t last_seen;
  // TODO(Team#) ranked chunk holders?
};

struct WaitingListEntry {
  std::string pmid;
  boost::uint32_t creation_time;
  bool storing_done;
  bool payments_done;
  int requested_payments;
};

struct ChunkInfo {
  ChunkInfo() : waiting_list(), watch_list(), reference_list(),
                watcher_count(0), watcher_checksum(0), chunk_size(0) {}
  std::list<WaitingListEntry> waiting_list;
  std::list<WatchListEntry> watch_list;
  std::list<ReferenceListEntry> reference_list;
  boost::uint64_t watcher_count;
  boost::uint64_t watcher_checksum;
  boost::uint64_t chunk_size;
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
                           const ResetReason &reason,
                           std::list<std::string> *creditors,
                           std::list<std::string> *references);
  int RemoveFromWatchList(const std::string &chunk_name,
                          const std::string &pmid,
                          int *chunk_size,
                          std::list<std::string> *creditors,
                          std::list<std::string> *references);
  int AddToReferenceList(const std::string &chunk_name,
                         const std::string &pmid,
                         const boost::uint64_t &chunk_size);
  int RemoveFromReferenceList(const std::string &chunk_name,
                              const std::string &pmid,
                              int *chunk_size);
  void SetStoringDone(const std::string &chunk_name);
  void SetPaymentsDone(const std::string &chunk_name, const std::string &pmid);
  void GetStaleWaitingListEntries(std::list< std::pair<std::string,
                                                       std::string> > *entries);
 private:
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerInit);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerAdd);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRefund);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRemove);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerReset);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerFailsafe);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerPruning);
  bool HasWatchers(const std::string &chunk_name);
  int ActiveReferences(const std::string &chunk_name);
  void ClearReferenceList(const std::string &chunk_name,
                          std::list<std::string> *references);
  boost::uint64_t GetChecksum(const std::string &id);
  std::map<std::string, ChunkInfo> chunk_infos_;
  boost::mutex chunk_info_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_
