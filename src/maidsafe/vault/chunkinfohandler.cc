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

#include "maidsafe/vault/chunkinfohandler.h"
#include <algorithm>

namespace maidsafe_vault {

void ChunkInfoHandler::set_started(bool started) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  started_ = started;
}

int ChunkInfoHandler::PrepareAddToWatchList(const std::string &chunk_name,
                                            const std::string &pmid,
                                            const boost::uint64_t &chunk_size,
                                            int *required_references,
                                            int *required_payments) {
  *required_references = 0;
  *required_payments = 0;
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  // check chunk size
  if (chunk_size == 0) {
    return kChunkInfoInvalidSize;
  } else if (ci.chunk_size == 0) {
    ci.chunk_size = chunk_size;
  } else if (ci.chunk_size != chunk_size) {
    return kChunkInfoInvalidSize;
  }

  WaitingListEntry entry;
  entry.pmid = pmid;
  entry.storing_done = false;
  entry.payments_done = false;
  entry.requested_payments = 0;
  entry.creation_time = base::get_epoch_time();

  // only request uploads if not already waiting
  std::list<WaitingListEntry>::iterator it = ci.waiting_list.begin();
  while (it->pmid != pmid && it != ci.waiting_list.end()) {
    ++it;
  }
  if (it == ci.waiting_list.end()) {
    *required_references = std::max(0, static_cast<int>
        (std::ceil(.5 * (kMinChunkCopies - ActiveReferences(chunk_name)))));
  } else {
    entry.storing_done = true;
  }

  // count occupied slots in watch list
  int n = 0;
  for (std::list<WatchListEntry>::iterator it = ci.watch_list.begin();
       it != ci.watch_list.end(); ++it) {
    if (!it->can_delete)
      ++n;
  }

  if (n == 0)
    entry.requested_payments = kMinChunkCopies;
  else if (n < kMinChunkCopies + kMaxReserveWatchListEntries)
    entry.requested_payments = 1;
  else
    entry.payments_done = true;

  *required_payments = entry.requested_payments;

  ci.waiting_list.push_back(entry);

  return 0;
}

bool ChunkInfoHandler::TryCommitToWatchList(const std::string &chunk_name,
                                            const std::string &pmid,
                                            std::string *creditor,
                                            int *refunds) {
  creditor->clear();
  *refunds = 0;
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return false;
  if (chunk_infos_.count(chunk_name) == 0)
    return false;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching, completed waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list.begin();
  while (wait_it != ci.waiting_list.end() && !(wait_it->pmid == pmid &&
         wait_it->storing_done && wait_it->payments_done)) {
    ++wait_it;
  }

  if (wait_it == ci.waiting_list.end())
    return false;

  WatchListEntry entry;
  entry.pmid = pmid;
  entry.can_delete = false;

  // find a replacable entry within the first 4
  std::list<WatchListEntry>::iterator watch_it;
  int i = 1;
  watch_it = ci.watch_list.begin();
  while (watch_it != ci.watch_list.end() && !watch_it->can_delete &&
         i < kMinChunkCopies) {
    ++watch_it;
    ++i;
  }

  if (wait_it->requested_payments > 0) {
    int required_payments = 0;
    if (watch_it != ci.watch_list.end() && watch_it->can_delete) {
      // replace this pmid and pay them directly
      *creditor = watch_it->pmid;
      *watch_it = entry;
      required_payments = 1;
    } else if (ci.watch_list.size() < (kMinChunkCopies +
                                       kMaxReserveWatchListEntries)) {
      // add to watch list
      ci.watch_list.push_back(entry);
      if (ci.watch_list.size() == 1) {
        // we are first, so add 3 more deletable entries
        entry.can_delete = true;
        required_payments = kMinChunkCopies;
        for (i = 0; i < kMinChunkCopies - 1; ++i)
          ci.watch_list.push_back(entry);
      } else {
        required_payments = 1;
      }
    }
    *refunds = wait_it->requested_payments - required_payments;
  }

  // in any case, add as watcher
  ++ci.watcher_count;
  ci.watcher_checksum += GetChecksum(pmid);

  ci.waiting_list.erase(wait_it);

  return true;
}

void ChunkInfoHandler::ResetAddToWatchList(const std::string &chunk_name,
                                           const std::string &pmid,
                                           const ResetReason &reason,
                                           std::list<std::string> *creditors,
                                           std::list<std::string> *references) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return;
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list.begin();
  while (wait_it != ci.waiting_list.end() && !(wait_it->pmid == pmid && (
         (reason == kReasonPaymentFailed && !wait_it->payments_done) ||
         (reason == kReasonStoringFailed && !wait_it->storing_done) ||
         reason == kReasonStale))) {
    ++wait_it;
  }

  if (wait_it != ci.waiting_list.end())
    ci.waiting_list.erase(wait_it);

  if (HasWatchers(chunk_name))
    return;

  // no one is watching anymore, recompense everyone and implode
  for (std::list<WatchListEntry>::iterator
       it = ci.watch_list.begin();
       it != ci.watch_list.end(); ++it) {
    creditors->push_back(it->pmid);
  }
  ClearReferenceList(chunk_name, references);
}

int ChunkInfoHandler::RemoveFromWatchList(const std::string &chunk_name,
                                          const std::string &pmid,
                                          int *chunk_size,
                                          std::list<std::string> *creditors,
                                          std::list<std::string> *references) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;

  if (!HasWatchers(chunk_name))
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];
  *chunk_size = ci.chunk_size;

  // find the watcher and the first reserve
  std::list<WatchListEntry>::iterator it, watch_it, reserve_it;
  watch_it = reserve_it = ci.watch_list.end();
  int i = 1, watcher_index = 0, remaining_entry_count = 0;
  for (it = ci.watch_list.begin(); it != ci.watch_list.end(); ++it, ++i) {
    if (!it->can_delete) {
      ++remaining_entry_count;
      if (watch_it == ci.watch_list.end() && it->pmid == pmid) {
        watch_it = it;
        watcher_index = i;
      } else if (reserve_it == ci.watch_list.end() && i > kMinChunkCopies) {
        reserve_it = it;
      }
    }
  }

  /*
  if (remaining_entry_count >= ci.watcher_count &&
      watch_it == ci.watch_list.end()) {
    // we've been tricked at some point, but for now do nothing about it
  }
  */

  // remove watcher
  if (ci.watcher_count > boost::uint64_t(remaining_entry_count))
    --ci.watcher_count;
  ci.watcher_checksum -= GetChecksum(pmid);

  if (watch_it != ci.watch_list.end()) {
    if (watcher_index <= kMinChunkCopies) {
      // we are one of the first four
      if (reserve_it != ci.watch_list.end()) {
        // replace by reserve and recompense
        creditors->push_back(pmid);
        (*watch_it) = (*reserve_it);
        ci.watch_list.erase(reserve_it);
      } else {
        // no reserve, flag deletable
        watch_it->can_delete = true;
        if (remaining_entry_count == 1) {
          ci.watcher_count = 0;
          if (!HasWatchers(chunk_name)) {
            // no one is watching anymore, recompense everyone and implode
            for (std::list<WatchListEntry>::iterator
                 it = ci.watch_list.begin();
                 it != ci.watch_list.end(); ++it) {
              creditors->push_back(it->pmid);
            }
            ClearReferenceList(chunk_name, references);
          } else {
            // watch list has been tampered with
            // TODO(Team#) set timestamp and delete after a long time
          }
        }
      }
    } else {
      // just delete from the reserve
      creditors->push_back(pmid);
      ci.watch_list.erase(watch_it);
    }
  }  // don't recompense if not listed

  return 0;
}

int ChunkInfoHandler::AddToReferenceList(const std::string &chunk_name,
                                         const std::string &pmid,
                                         const boost::uint64_t &chunk_size) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;
  if (!HasWatchers(chunk_name))
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  if (ci.chunk_size != chunk_size)
    return kChunkInfoInvalidSize;

  // find existing entry
  std::list<ReferenceListEntry>::iterator it = ci.reference_list.begin();
  while (it != ci.reference_list.end() && it->pmid != pmid) {
    ++it;
  }

  if (it != ci.reference_list.end()) {
    it->last_seen = base::get_epoch_time();
  } else {
    ReferenceListEntry entry;
    entry.pmid = pmid;
    entry.last_seen = base::get_epoch_time();
    ci.reference_list.push_back(entry);
  }

  return 0;
}

int ChunkInfoHandler::RemoveFromReferenceList(const std::string &chunk_name,
                                              const std::string &pmid,
                                              int *chunk_size) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;
  if (chunk_infos_.count(chunk_name) == 0)
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];
  *chunk_size = ci.chunk_size;

  if (ci.reference_list.size() == 1 && HasWatchers(chunk_name))
    return kChunkInfoCannotDelete;

  // find existing entry
  std::list<ReferenceListEntry>::iterator it = ci.reference_list.begin();
  while (it != ci.reference_list.end() && it->pmid != pmid) {
    ++it;
  }

  if (it == ci.reference_list.end())
    return kChunkInfoCannotDelete;

  ci.reference_list.erase(it);

  return 0;
}

int ChunkInfoHandler::GetActiveReferences(const std::string chunk_name,
                                          std::list<std::string> *references) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;
  if (chunk_infos_.count(chunk_name) == 0)
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  if (ci.watcher_count == 0 && ci.watcher_checksum == 0)
    return kChunkInfoNoActiveWatchers;

  boost::uint32_t now = base::get_epoch_time();

  for (std::list<ReferenceListEntry>::iterator it = ci.reference_list.begin();
       it != ci.reference_list.end(); ++it) {
    if (it->last_seen + kChunkInfoRefActiveTimeout >= now)
      references->push_back(it->pmid);
  }

  return kSuccess;
}

void ChunkInfoHandler::SetStoringDone(const std::string &chunk_name,
                                      const std::string &pmid) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return;
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list.begin();
  while (wait_it != ci.waiting_list.end() && !(wait_it->pmid == pmid &&
         !wait_it->storing_done)) {
    ++wait_it;
  }

  if (wait_it != ci.waiting_list.end())
    wait_it->storing_done = true;
}

void ChunkInfoHandler::SetPaymentsDone(const std::string &chunk_name,
                                       const std::string &pmid) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return;
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list.begin();
  while (wait_it != ci.waiting_list.end() && !(wait_it->pmid == pmid &&
         !wait_it->payments_done)) {
    ++wait_it;
  }

  if (wait_it != ci.waiting_list.end())
    wait_it->payments_done = true;
}

void ChunkInfoHandler::GetStaleWaitingListEntries(
    std::list< std::pair<std::string, std::string> > *entries) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return;
  boost::uint32_t now = base::get_epoch_time();
  for (std::map<std::string, ChunkInfo>::iterator ci_it = chunk_infos_.begin();
       ci_it != chunk_infos_.end(); ++ci_it) {
    for (std::list<WaitingListEntry>::iterator wait_it =
         ci_it->second.waiting_list.begin();
         wait_it != ci_it->second.waiting_list.end(); ++wait_it) {
      if (wait_it->creation_time + kChunkInfoWatcherPendingTimeout < now)
        entries->push_back(std::pair<std::string, std::string>(ci_it->first,
                                                               wait_it->pmid));
    }
  }
}

bool ChunkInfoHandler::HasWatchers(const std::string &chunk_name) {
  if (chunk_infos_.count(chunk_name) == 0)
    return false;
  ChunkInfo &ci = chunk_infos_[chunk_name];
  return /* ci.watch_list.size() != 0 || */ !ci.waiting_list.empty() ||
         ci.watcher_count != 0 || ci.watcher_checksum != 0;
}

int ChunkInfoHandler::ActiveReferences(const std::string &chunk_name) {
  if (chunk_infos_.count(chunk_name) == 0)
    return 0;
  ChunkInfo &ci = chunk_infos_[chunk_name];
  int n = 0;
  boost::uint32_t now = base::get_epoch_time();

  for (std::list<ReferenceListEntry>::iterator it = ci.reference_list.begin();
       it != ci.reference_list.end(); ++it) {
    if (it->last_seen + kChunkInfoRefActiveTimeout >= now)
      ++n;
  }
  return n;
  // TODO(Steve#) add method to update time stamp externally (validity check)
}

void ChunkInfoHandler::ClearReferenceList(const std::string &chunk_name,
                                          std::list<std::string> *references) {
  if (chunk_infos_.count(chunk_name) == 0)
    return;

  ChunkInfo &ci = chunk_infos_[chunk_name];
  for (std::list<ReferenceListEntry>::iterator it = ci.reference_list.begin();
       it != ci.reference_list.end(); ++it) {
    references->push_back(it->pmid);
  }

  // delete whole chunk info
  chunk_infos_.erase(chunk_name);
}

boost::uint64_t ChunkInfoHandler::GetChecksum(const std::string &id) {
  // return last 8 bytes of the ID as number
  return *reinterpret_cast<boost::uint64_t*>(
            const_cast<char*>(id.substr(kKeySize - 8).data()));
}

ChunkInfoMap ChunkInfoHandler::PutMapToPb() {
  ChunkInfoMap chunk_info_map;
  {
    boost::mutex::scoped_lock loch(chunk_info_mutex_);
    std::for_each(chunk_infos_.begin(), chunk_infos_.end(), boost::bind(
        &ChunkInfoHandler::AddChunkInfoToPbSet, this, _1, &chunk_info_map));
  }
  return chunk_info_map;
}

void ChunkInfoHandler::AddChunkInfoToPbSet(
    const std::pair<const std::string, ChunkInfo> &pr,
    ChunkInfoMap *chunk_info_map) {
  ChunkInfoMap::VaultChunkInfo *vault_chunk_info =
      chunk_info_map->add_vault_chunk_info();
  ChunkInfo chunk_info(pr.second);
  chunk_info.PutToPb(pr.first, vault_chunk_info);
}

void ChunkInfoHandler::GetMapFromPb(const ChunkInfoMap &chunk_info_map) {
  ChunkInfoMap::VaultChunkInfo vault_chunk_info;
  boost::mutex::scoped_lock loch(chunk_info_mutex_);
  bool use_max_efficiency = chunk_infos_.empty();
  std::map<std::string, ChunkInfo>::iterator it = chunk_infos_.begin();
  for (int i = 0; i < chunk_info_map.vault_chunk_info_size(); ++i) {
    vault_chunk_info.Clear();
    vault_chunk_info = chunk_info_map.vault_chunk_info(i);
    ChunkInfo chunk_info(vault_chunk_info);
    if (use_max_efficiency)
      it = chunk_infos_.insert(it, std::pair<std::string, ChunkInfo>(
          vault_chunk_info.chunk_name(), chunk_info));
    else
      chunk_infos_.insert(std::pair<std::string, ChunkInfo>(
          vault_chunk_info.chunk_name(), chunk_info));
  }
  started_ = true;
}

int ChunkInfoHandler::GetChunkInfo(const std::string &chunk_name,
                                   ChunkInfo *chunk_info) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_) {
    *chunk_info = ChunkInfo();
    return kChunkInfoHandlerNotStarted;
  }
  std::map<std::string, ChunkInfo>::iterator it = chunk_infos_.find(chunk_name);

  if (it == chunk_infos_.end()) {
    *chunk_info = ChunkInfo();
    return kChunkInfoInvalidName;
  } else {
    *chunk_info = (*it).second;
    return kSuccess;
  }
}

int ChunkInfoHandler::InsertChunkInfoFromPb(
    const ChunkInfoMap::VaultChunkInfo &vault_chunk_info) {
  ChunkInfo chunk_info(vault_chunk_info);
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!started_)
    return kChunkInfoHandlerNotStarted;
  std::pair<std::map<std::string, ChunkInfo>::iterator, bool> sp =
      chunk_infos_.insert(std::pair<std::string, ChunkInfo>
          (vault_chunk_info.chunk_name(), chunk_info));
  if (!sp.second)
    return kChunkInfoExists;
  return kSuccess;
}


}  // namespace maidsafe_vault
