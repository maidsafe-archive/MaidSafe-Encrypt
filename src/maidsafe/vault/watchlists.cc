/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages watchlists on a vault
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

#include "maidsafe/vault/watchlists.h"

namespace maidsafe_vault {

bool WatchListHandler::HasWatchers(const std::string &watch_list_name) {
  boost::mutex::scoped_lock lock(watch_list_mutex_);
  if (watch_lists_.count(watch_list_name) == 0)
    return false;
  if (watch_lists_[watch_list_name].entries_.size() == 0)
    return false;
  if (watch_lists_[watch_list_name].watcher_count_ == 0 &&
      watch_lists_[watch_list_name].watcher_checksum_ == 0)
    return false;
  return true;
}

int WatchListHandler::AddToWatchList(const std::string &watch_list_name,
                                     const std::string &pmid,
                                     const boost::uint64_t &chunk_size,
                                     std::string *creditor,
                                     int *required_payments) {
  *creditor = "";
  *required_payments = 0;
  boost::mutex::scoped_lock lock(watch_list_mutex_);

  WatchList &wl = watch_lists_[watch_list_name];

  // check chunk size
  if (chunk_size == 0) {
    return kWatchListInvalidChunkSize;
  } else if (wl.chunk_size_ == 0) {
    wl.chunk_size_ = chunk_size;
  } else if (wl.chunk_size_ != chunk_size) {
    return kWatchListInvalidChunkSize;
  }

  WatchListEntry entry;
  entry.pmid_ = pmid;
  entry.can_delete_ = false;

  // find a replacable entry within the first 4
  std::list<WatchListEntry>::iterator it;
  int i = 1;
  it = wl.entries_.begin();
  while (it != wl.entries_.end() && !it->can_delete_ && i < kMinChunkCopies) {
    it++;
    i++;
  }

  if (it != wl.entries_.end() && it->can_delete_) {
    // replace this pmid and pay them directly
    *creditor = it->pmid_;
    *it = entry;
    *required_payments = 1;
  } else if (wl.entries_.size() < (kMinChunkCopies +
                                    kMaxReserveWatchListEntries)) {
    // add to watch list
    wl.entries_.push_back(entry);
    *required_payments = 1;
    if (wl.entries_.size() == 1) {
      // we are first, so add 3 more deletable entries
      entry.can_delete_ = true;
      for (i = 0; i < kMinChunkCopies - 1; i++)
        wl.entries_.push_back(entry);
      *required_payments = kMinChunkCopies;
    }
  }

  // in all cases, add as watcher
  wl.watcher_count_++;
  wl.watcher_checksum_ += GetChecksum(pmid);

  return 0;
}

int WatchListHandler::RemoveFromWatchList(const std::string &watch_list_name,
                                          const std::string &pmid,
                                          const boost::uint64_t &chunk_size,
                                          std::list<std::string> *creditors) {
  boost::mutex::scoped_lock lock(watch_list_mutex_);

  if (watch_lists_.count(watch_list_name) == 0)
    return kWatchListInvalidName;

  WatchList &wl = watch_lists_[watch_list_name];

  if (wl.chunk_size_ != chunk_size)
    return kWatchListInvalidChunkSize;

  // find the watcher and the first reserve
  std::list<WatchListEntry>::iterator it, watcher_it, reserve_it;
  watcher_it = reserve_it = wl.entries_.end();
  int i, watcher_index, remaining_entry_count = 0;
  for (it = wl.entries_.begin(), i = 1; it != wl.entries_.end(); it++, i++) {
    if (!it->can_delete_) {
      remaining_entry_count++;
      if (watcher_it == wl.entries_.end() && it->pmid_ == pmid) {
        watcher_it = it;
        watcher_index = i;
      } else if (reserve_it == wl.entries_.end() && i > kMinChunkCopies) {
        reserve_it = it;
      }
    }
  }

  /*
  if (remaining_entry_count >= wl.watcher_count_ &&
      watcher_it == wl.entries_.end()) {
    // we've been tricked at some point, but for now do nothing about it
  }
  */

  // remove watcher
  if (wl.watcher_count_ > boost::uint64_t(remaining_entry_count))
    wl.watcher_count_--;
  wl.watcher_checksum_ -= GetChecksum(pmid);

  if (watcher_it != wl.entries_.end()) {
    if (watcher_index <= kMinChunkCopies) {
      // we are one of the first four
      if (reserve_it != wl.entries_.end()) {
        // replace by reserve and recompense
        creditors->push_back(pmid);
        (*watcher_it) = (*reserve_it);
        wl.entries_.erase(reserve_it);
      } else {
        // no reserve, flag deletable
        watcher_it->can_delete_ = true;
        if (remaining_entry_count == 1) {
          if (wl.watcher_count_ == 1 && wl.watcher_checksum_ == 0) {
            // no one is watching anymore, recompense everyone and implode
            for (std::list<WatchListEntry>::iterator it = wl.entries_.begin();
                 it != wl.entries_.end(); it++) {
              creditors->push_back(it->pmid_);
            }
            watch_lists_.erase(watch_list_name);
          } else {
            // watch list has been tampered with
            // TODO(anyone) set timestamp and delete after a long time
          }
        }
      }
    } else {
      // just delete from the reserve
      creditors->push_back(pmid);
      wl.entries_.erase(watcher_it);
    }
  } else {
    // recompense, even if not listed
    // creditors->push_back(pmid);
    // big problem if multiple removal requests by same pmid!
  }

  return 0;
}

boost::uint64_t WatchListHandler::GetChecksum(const std::string &id) {
  // return last 8 bytes of the ID as number
  return *reinterpret_cast<boost::uint64_t*>(
            const_cast<char*>(id.substr(kKeySize - 8).data()));
}

}  // namespace maidsafe_vault
