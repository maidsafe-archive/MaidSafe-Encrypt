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

#include "maidsafe/vault/chunkinfohandler.h"
#include <algorithm>

namespace maidsafe_vault {

int ChunkInfoHandler::PrepareAddToWatchList(const std::string &chunk_name,
                                            const std::string &pmid,
                                            const boost::uint64_t &chunk_size,
                                            int *required_references,
                                            int *required_payments) {
  *required_references = 0;
  *required_payments = 0;
  boost::mutex::scoped_lock lock(chunk_info_mutex_);

  ChunkInfo &ci = chunk_infos_[chunk_name];

  // check chunk size
  if (chunk_size == 0) {
    return kChunkInfoInvalidSize;
  } else if (ci.chunk_size_ == 0) {
    ci.chunk_size_ = chunk_size;
  } else if (ci.chunk_size_ != chunk_size) {
    return kChunkInfoInvalidSize;
  }

  WaitingListEntry entry;
  entry.pmid_ = pmid;
  entry.storing_done_ = false;
  entry.payments_done_ = false;
  entry.requested_payments_ = 0;

  // only request uploads if not already waiting
  std::list<WaitingListEntry>::iterator it = ci.waiting_list_.begin();
  while (it->pmid_ != pmid && it != ci.waiting_list_.end()) {
    it++;
  }
  if (it == ci.waiting_list_.end()) {
    *required_references = std::max(0, static_cast<int>
        (std::ceil(.5 * (kMinChunkCopies - ActiveReferences(chunk_name)))));
  } else {
    entry.storing_done_ = true;
  }

  // count occupied slots in watch list
  int n = 0;
  for (std::list<WatchListEntry>::iterator it = ci.watch_list_.begin();
       it != ci.watch_list_.end(); it++) {
    if (!it->can_delete_)
      n++;
  }

  if (n == 0)
    entry.requested_payments_ = kMinChunkCopies;
  else if (n < kMinChunkCopies + kMaxReserveWatchListEntries)
    entry.requested_payments_ = 1;
  else
    entry.payments_done_ = true;

  *required_payments = entry.requested_payments_;

  ci.waiting_list_.push_back(entry);

  return 0;
}

bool ChunkInfoHandler::TryCommitToWatchList(const std::string &chunk_name,
                                            const std::string &pmid,
                                            std::string *creditor,
                                            int *refunds) {
  *creditor = "";
  *refunds = 0;
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return false;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching, completed waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list_.begin();
  while (wait_it != ci.waiting_list_.end() && !(wait_it->pmid_ == pmid &&
         wait_it->storing_done_ && wait_it->payments_done_)) {
    wait_it++;
  }

  if (wait_it == ci.waiting_list_.end())
    return false;

  WatchListEntry entry;
  entry.pmid_ = pmid;
  entry.can_delete_ = false;

  // find a replacable entry within the first 4
  std::list<WatchListEntry>::iterator watch_it;
  int i = 1;
  watch_it = ci.watch_list_.begin();
  while (watch_it != ci.watch_list_.end() && !watch_it->can_delete_ &&
         i < kMinChunkCopies) {
    watch_it++;
    i++;
  }

  if (wait_it->requested_payments_ > 0) {
    int required_payments = 0;
    if (watch_it != ci.watch_list_.end() && watch_it->can_delete_) {
      // replace this pmid and pay them directly
      *creditor = watch_it->pmid_;
      *watch_it = entry;
      required_payments = 1;
    } else if (ci.watch_list_.size() < (kMinChunkCopies +
                                      kMaxReserveWatchListEntries)) {
      // add to watch list
      ci.watch_list_.push_back(entry);
      if (ci.watch_list_.size() == 1) {
        // we are first, so add 3 more deletable entries
        entry.can_delete_ = true;
        required_payments = kMinChunkCopies;
        for (i = 0; i < kMinChunkCopies - 1; i++)
          ci.watch_list_.push_back(entry);
      } else {
        required_payments = 1;
      }
    }
    *refunds = wait_it->requested_payments_ - required_payments;
  }

  // in any case, add as watcher
  ci.watcher_count_++;
  ci.watcher_checksum_ += GetChecksum(pmid);

  ci.waiting_list_.erase(wait_it);

  return true;
}

void ChunkInfoHandler::ResetAddToWatchList(const std::string &chunk_name,
                                           const std::string &pmid,
                                           const ResetReason &reason,
                                           std::list<std::string> *creditors,
                                           std::list<std::string> *references) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list_.begin();
  while (wait_it != ci.waiting_list_.end() && (
         wait_it->pmid_ != pmid ||
         (wait_it->payments_done_ && reason == kReasonPaymentFailed) ||
         (wait_it->storing_done_ && reason == kReasonStoringFailed))) {
    wait_it++;
  }

  if (wait_it != ci.waiting_list_.end())
    ci.waiting_list_.erase(wait_it);

  if (HasWatchers(chunk_name))
    return;

  // no one is watching anymore, recompense everyone and implode
  for (std::list<WatchListEntry>::iterator
       it = ci.watch_list_.begin();
       it != ci.watch_list_.end(); it++) {
    creditors->push_back(it->pmid_);
  }
  ClearReferenceList(chunk_name, references);
}

int ChunkInfoHandler::RemoveFromWatchList(const std::string &chunk_name,
                                          const std::string &pmid,
                                          std::list<std::string> *creditors,
                                          std::list<std::string> *references) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);

  if (!HasWatchers(chunk_name))
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find the watcher and the first reserve
  std::list<WatchListEntry>::iterator it, watch_it, reserve_it;
  watch_it = reserve_it = ci.watch_list_.end();
  int i, watcher_index, remaining_entry_count = 0;
  for (it = ci.watch_list_.begin(), i = 1; it != ci.watch_list_.end();
       it++, i++) {
    if (!it->can_delete_) {
      remaining_entry_count++;
      if (watch_it == ci.watch_list_.end() && it->pmid_ == pmid) {
        watch_it = it;
        watcher_index = i;
      } else if (reserve_it == ci.watch_list_.end() && i > kMinChunkCopies) {
        reserve_it = it;
      }
    }
  }

  /*
  if (remaining_entry_count >= ci.watcher_count_ &&
      watch_it == ci.watch_list_.end()) {
    // we've been tricked at some point, but for now do nothing about it
  }
  */

  // remove watcher
  if (ci.watcher_count_ > boost::uint64_t(remaining_entry_count))
    ci.watcher_count_--;
  ci.watcher_checksum_ -= GetChecksum(pmid);

  if (watch_it != ci.watch_list_.end()) {
    if (watcher_index <= kMinChunkCopies) {
      // we are one of the first four
      if (reserve_it != ci.watch_list_.end()) {
        // replace by reserve and recompense
        creditors->push_back(pmid);
        (*watch_it) = (*reserve_it);
        ci.watch_list_.erase(reserve_it);
      } else {
        // no reserve, flag deletable
        watch_it->can_delete_ = true;
        if (remaining_entry_count == 1) {
          ci.watcher_count_ = 0;
          if (!HasWatchers(chunk_name)) {
            // no one is watching anymore, recompense everyone and implode
            for (std::list<WatchListEntry>::iterator
                 it = ci.watch_list_.begin();
                 it != ci.watch_list_.end(); it++) {
              creditors->push_back(it->pmid_);
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
      ci.watch_list_.erase(watch_it);
    }
  }  // don't recompense if not listed

  return 0;
}

int ChunkInfoHandler::AddToReferenceList(const std::string &chunk_name,
                                         const std::string &pmid,
                                         const boost::uint64_t &chunk_size) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (!HasWatchers(chunk_name))
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  if (ci.chunk_size_ != chunk_size)
    return kChunkInfoInvalidSize;

  // find existing entry
  std::list<ReferenceListEntry>::iterator it = ci.reference_list_.begin();
  while (it != ci.reference_list_.end() && it->pmid_ != pmid) {
    it++;
  }

  if (it != ci.reference_list_.end()) {
    // TODO(Steve#) update time stamp
  } else {
    ReferenceListEntry entry;
    entry.pmid_ = pmid;
    ci.reference_list_.push_back(entry);
  }

  return 0;
}

int ChunkInfoHandler::RemoveFromReferenceList(const std::string &chunk_name,
                                              const std::string &pmid) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  if (ci.reference_list_.size() == 1 && HasWatchers(chunk_name))
    return kChunkInfoCannotDelete;

  // find existing entry
  std::list<ReferenceListEntry>::iterator it = ci.reference_list_.begin();
  while (it != ci.reference_list_.end() && it->pmid_ != pmid) {
    it++;
  }

  if (it == ci.reference_list_.end())
    return kChunkInfoCannotDelete;

  ci.reference_list_.erase(it);

  return 0;
}

void ChunkInfoHandler::SetStoringDone(const std::string &chunk_name) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list_.begin();
  while (wait_it != ci.waiting_list_.end() && wait_it->storing_done_) {
    wait_it++;
  }

  if (wait_it != ci.waiting_list_.end())
    wait_it->storing_done_ = true;
}

void ChunkInfoHandler::SetPaymentsDone(const std::string &chunk_name,
                                       const std::string &pmid) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return;
  ChunkInfo &ci = chunk_infos_[chunk_name];

  // find first matching waiting list entry
  std::list<WaitingListEntry>::iterator wait_it = ci.waiting_list_.begin();
  while (wait_it != ci.waiting_list_.end() && !(wait_it->pmid_ == pmid &&
         !wait_it->payments_done_)) {
    wait_it++;
  }

  if (wait_it != ci.waiting_list_.end())
    wait_it->payments_done_ = true;
}

void ChunkInfoHandler::PruneWaitingLists() {
  // TODO(Steve#) remove old entries from waiting list
  // boost::mutex::scoped_lock lock(chunk_info_mutex_);
}

bool ChunkInfoHandler::HasWatchers(const std::string &chunk_name) {
  if (chunk_infos_.count(chunk_name) == 0)
    return false;
  ChunkInfo &ci = chunk_infos_[chunk_name];
  return /* ci.watch_list_.size() != 0 || */ ci.waiting_list_.size() != 0 ||
         ci.watcher_count_ != 0 || ci.watcher_checksum_ != 0;
}

int ChunkInfoHandler::ActiveReferences(const std::string &chunk_name) {
  // TODO(Steve#) count active references based on time stamp
  if (chunk_infos_.count(chunk_name) == 0)
    return 0;
  return chunk_infos_[chunk_name].reference_list_.size();
}

void ChunkInfoHandler::ClearReferenceList(const std::string &chunk_name,
                                          std::list<std::string> *references) {
  if (chunk_infos_.count(chunk_name) == 0)
    return;

  ChunkInfo &ci = chunk_infos_[chunk_name];
  for (std::list<ReferenceListEntry>::iterator it = ci.reference_list_.begin();
       it != ci.reference_list_.end(); it++) {
    references->push_back(it->pmid_);
  }

  // delete whole chunk info
  chunk_infos_.erase(chunk_name);
}

boost::uint64_t ChunkInfoHandler::GetChecksum(const std::string &id) {
  // return last 8 bytes of the ID as number
  return *reinterpret_cast<boost::uint64_t*>(
            const_cast<char*>(id.substr(kKeySize - 8).data()));
}

}  // namespace maidsafe_vault
