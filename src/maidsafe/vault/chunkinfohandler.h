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

#include <algorithm>
#include <list>
#include <map>
#include <string>
#include <utility>

#include "maidsafe/maidsafe.h"
#include "protobuf/sync_data.pb.h"

namespace maidsafe_vault {

enum ResetReason {kReasonStoringFailed, kReasonPaymentFailed, kReasonStale};

struct WaitingListEntry {
  WaitingListEntry() : pmid(),
                       creation_time(0),
                       storing_done(false),
                       payments_done(false),
                       requested_payments(0) {}
  explicit WaitingListEntry(
      const ChunkInfoMap::VaultChunkInfo::WaitingListEntry &waiting_list_entry)
          : pmid(waiting_list_entry.pmid()),
            creation_time(waiting_list_entry.creation_time()),
            storing_done(waiting_list_entry.storing_done()),
            payments_done(waiting_list_entry.payments_done()),
            requested_payments(waiting_list_entry.requested_payments()) {}
  std::string pmid;
  boost::uint32_t creation_time;
  bool storing_done;
  bool payments_done;
  int requested_payments;
  void PutToPb(ChunkInfoMap::VaultChunkInfo *vault_chunk_info) {
    ChunkInfoMap::VaultChunkInfo::WaitingListEntry *waiting_list_entry =
        vault_chunk_info->add_waiting_list_entry();
    waiting_list_entry->set_pmid(pmid);
    waiting_list_entry->set_creation_time(creation_time);
    waiting_list_entry->set_storing_done(storing_done);
    waiting_list_entry->set_payments_done(payments_done);
    waiting_list_entry->set_requested_payments(requested_payments);
  }
};

struct WatchListEntry {
  WatchListEntry() : pmid(), can_delete(false) {}
  explicit WatchListEntry(
      const ChunkInfoMap::VaultChunkInfo::WatchListEntry &watch_list_entry)
          : pmid(watch_list_entry.pmid()),
            can_delete(watch_list_entry.can_delete()) {}
  std::string pmid;
  bool can_delete;
  void PutToPb(ChunkInfoMap::VaultChunkInfo *vault_chunk_info) {
    ChunkInfoMap::VaultChunkInfo::WatchListEntry *watch_list_entry =
        vault_chunk_info->add_watch_list_entry();
    watch_list_entry->set_pmid(pmid);
    watch_list_entry->set_can_delete(can_delete);
  }
};

struct ReferenceListEntry {
  ReferenceListEntry() : pmid(), last_seen(0) {}
  explicit ReferenceListEntry(
      const ChunkInfoMap::VaultChunkInfo::ReferenceListEntry &ref_list_entry)
          : pmid(ref_list_entry.pmid()),
            last_seen(ref_list_entry.last_seen()) {}
  std::string pmid;
  boost::uint32_t last_seen;
  // TODO(Team#) ranked chunk holders?
  void PutToPb(ChunkInfoMap::VaultChunkInfo *vault_chunk_info) {
    ChunkInfoMap::VaultChunkInfo::ReferenceListEntry *reference_list_entry =
        vault_chunk_info->add_reference_list_entry();
    reference_list_entry->set_pmid(pmid);
    reference_list_entry->set_last_seen(last_seen);
  }
};

struct ChunkInfo {
  ChunkInfo() : waiting_list(),
                watch_list(),
                reference_list(),
                watcher_count(0),
                watcher_checksum(0),
                chunk_size(0) {}
  explicit ChunkInfo(const ChunkInfoMap::VaultChunkInfo &vault_chunk_info)
      : waiting_list(),
        watch_list(),
        reference_list(),
        watcher_count(vault_chunk_info.watcher_count()),
        watcher_checksum(vault_chunk_info.watcher_checksum()),
        chunk_size(vault_chunk_info.chunk_size()) {
    for (int i = 0; i < vault_chunk_info.waiting_list_entry_size(); ++i) {
      waiting_list.push_back(WaitingListEntry(
          vault_chunk_info.waiting_list_entry(i)));
    }
    for (int i = 0; i < vault_chunk_info.watch_list_entry_size(); ++i) {
      watch_list.push_back(WatchListEntry(
          vault_chunk_info.watch_list_entry(i)));
    }
    for (int i = 0; i < vault_chunk_info.reference_list_entry_size(); ++i) {
      reference_list.push_back(ReferenceListEntry(
          vault_chunk_info.reference_list_entry(i)));
    }
  }
  std::list<WaitingListEntry> waiting_list;
  std::list<WatchListEntry> watch_list;
  std::list<ReferenceListEntry> reference_list;
  boost::uint64_t watcher_count;
  boost::uint64_t watcher_checksum;
  boost::uint64_t chunk_size;
  // TODO(Team#) stats?
  void PutToPb(const std::string &chunk_name,
               ChunkInfoMap::VaultChunkInfo *vault_chunk_info) {
    vault_chunk_info->set_chunk_name(chunk_name);
    std::for_each(waiting_list.begin(), waiting_list.end(),
        boost::bind(&WaitingListEntry::PutToPb, _1, vault_chunk_info));
    std::for_each(watch_list.begin(), watch_list.end(),
        boost::bind(&WatchListEntry::PutToPb, _1, vault_chunk_info));
    std::for_each(reference_list.begin(), reference_list.end(),
        boost::bind(&ReferenceListEntry::PutToPb, _1, vault_chunk_info));
    vault_chunk_info->set_watcher_count(watcher_count);
    vault_chunk_info->set_watcher_checksum(watcher_checksum);
    vault_chunk_info->set_chunk_size(chunk_size);
  }
};

class ChunkInfoHandler {
 public:
  typedef std::map<std::string, ChunkInfo> CIMap;
  explicit ChunkInfoHandler(bool start_immediately)
      : chunk_infos_(), chunk_info_mutex_(), started_(start_immediately) {}
  ~ChunkInfoHandler() {}
  void set_started(bool started);
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
  void SetStoringDone(const std::string &chunk_name, const std::string &pmid);
  void SetPaymentsDone(const std::string &chunk_name, const std::string &pmid);
  void GetStaleWaitingListEntries(std::list< std::pair<std::string,
                                                       std::string> > *entries);
  ChunkInfoMap PutMapToPb();
  void GetMapFromPb(const ChunkInfoMap &chunk_info_map);
  int GetChunkInfo(const std::string &chunk_name, ChunkInfo *chunk_info);
  int InsertChunkInfoFromPb(
      const ChunkInfoMap::VaultChunkInfo &vault_chunk_info);
 private:
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerInit);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerAdd);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRefund);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRemove);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerReset);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerFailsafe);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerPruning);
  FRIEND_TEST(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerPutGetPb);
  FRIEND_TEST(MockVaultServicesTest, BEH_MAID_ServicesStoreChunk);
  bool HasWatchers(const std::string &chunk_name);
  int ActiveReferences(const std::string &chunk_name);
  void ClearReferenceList(const std::string &chunk_name,
                          std::list<std::string> *references);
  boost::uint64_t GetChecksum(const std::string &id);
  void AddChunkInfoToPbSet(const CIMap::value_type &ci_pair,
                           ChunkInfoMap *chunk_info_map);
  CIMap chunk_infos_;
  boost::mutex chunk_info_mutex_;
  bool started_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_CHUNKINFOHANDLER_H_
