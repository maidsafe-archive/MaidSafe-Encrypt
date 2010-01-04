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

namespace maidsafe_vault {

bool ChunkInfoHandler::HasWatchers(const std::string &chunk_name) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);
  if (chunk_infos_.count(chunk_name) == 0)
    return false;
  if (chunk_infos_[chunk_name].watchers_.size() == 0)
    return false;
  if (chunk_infos_[chunk_name].watcher_count_ == 0 &&
      chunk_infos_[chunk_name].watcher_checksum_ == 0)
    return false;
  return true;
}

int ChunkInfoHandler::AddToWatchList(const std::string &chunk_name,
                                     const std::string &pmid,
                                     const boost::uint64_t &chunk_size,
                                     std::string *creditor,
                                     bool *payment_required) {
  *creditor = "";
  *payment_required = false;
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

  WatchListEntry entry;
  entry.pmid_ = pmid;
  entry.can_delete_ = false;

  // find a replacable entry within the first 4
  std::list<WatchListEntry>::iterator it;
  int i = 1;
  it = ci.watchers_.begin();
  while (it != ci.watchers_.end() && !it->can_delete_ && i < kMinChunkCopies) {
    it++;
    i++;
  }

  if (it != ci.watchers_.end() && it->can_delete_) {
    // replace this pmid and pay them directly
    *creditor = it->pmid_;
    *it = entry;
    *payment_required = true;
  } else if (ci.watchers_.size() < (kMinChunkCopies +
                                    kMaxReserveWatchListEntries)) {
    // add to watch list
    ci.watchers_.push_back(entry);
    *payment_required = true;
    if (ci.watchers_.size() == 1) {
      // we are first, so add 3 more deletable entries
      entry.can_delete_ = true;
      for (i = 0; i < kMinChunkCopies - 1; i++)
        ci.watchers_.push_back(entry);
    }
  }

  // in all cases, add as watcher
  ci.watcher_count_++;
  ci.watcher_checksum_ += GetChecksum(pmid);

  return 0;
}

int ChunkInfoHandler::RemoveFromWatchList(const std::string &chunk_name,
                                          const std::string &pmid,
                                          const boost::uint64_t &chunk_size,
                                          std::list<std::string> *creditors) {
  boost::mutex::scoped_lock lock(chunk_info_mutex_);

  if (chunk_infos_.count(chunk_name) == 0)
    return kChunkInfoInvalidName;

  ChunkInfo &ci = chunk_infos_[chunk_name];

  if (ci.chunk_size_ != chunk_size)
    return kChunkInfoInvalidSize;

  // find the watcher and the first reserve
  std::list<WatchListEntry>::iterator it, watcher_it, reserve_it;
  watcher_it = reserve_it = ci.watchers_.end();
  int i, watcher_index, remaining_entry_count = 0;
  for (it = ci.watchers_.begin(), i = 1; it != ci.watchers_.end(); it++, i++) {
    if (!it->can_delete_) {
      remaining_entry_count++;
      if (watcher_it == ci.watchers_.end() && it->pmid_ == pmid) {
        watcher_it = it;
        watcher_index = i;
      } else if (reserve_it == ci.watchers_.end() && i > kMinChunkCopies) {
        reserve_it = it;
      }
    }
  }

  /*
  if (remaining_entry_count >= ci.watcher_count_ &&
      watcher_it == ci.watchers_.end()) {
    // we've been tricked at some point, but for now do nothing about it
  }
  */

  // remove watcher
  if (ci.watcher_count_ > boost::uint64_t(remaining_entry_count))
    ci.watcher_count_--;
  ci.watcher_checksum_ -= GetChecksum(pmid);

  if (watcher_it != ci.watchers_.end()) {
    if (watcher_index <= kMinChunkCopies) {
      // we are one of the first four
      if (reserve_it != ci.watchers_.end()) {
        // replace by reserve and recompense
        creditors->push_back(pmid);
        (*watcher_it) = (*reserve_it);
        ci.watchers_.erase(reserve_it);
      } else {
        // no reserve, flag deletable
        watcher_it->can_delete_ = true;
        if (remaining_entry_count == 1) {
          if (ci.watcher_count_ == 1 && ci.watcher_checksum_ == 0) {
            // no one is watching anymore, recompense everyone and implode
            for (std::list<WatchListEntry>::iterator it = ci.watchers_.begin();
                 it != ci.watchers_.end(); it++) {
              creditors->push_back(it->pmid_);
            }
            // TODO(Steve) properly delete references and chunks in vaults
            chunk_infos_.erase(chunk_name);
          } else {
            // watch list has been tampered with
            // TODO(Team#) set timestamp and delete after a long time
          }
        }
      }
    } else {
      // just delete from the reserve
      creditors->push_back(pmid);
      ci.watchers_.erase(watcher_it);
    }
  } else {
    // recompense, even if not listed
    // creditors->push_back(pmid);
    // big problem if multiple removal requests by same pmid!
  }

  return 0;
}

void ChunkInfoHandler::RevertAddToWatchList(const std::string &chunk_name,
                                            const std::string &pmid,
                                            const std::string &creditor) {
  // TODO(Steve#) implement revert add to watch list
}

void ChunkInfoHandler::Lock() {
  // TODO(Steve#) lock chunk_info_mutex_
}

void ChunkInfoHandler::Unlock() {
  // TODO(Steve#) unlock chunk_info_mutex_
}

boost::uint64_t ChunkInfoHandler::GetChecksum(const std::string &id) {
  // return last 8 bytes of the ID as number
  return *reinterpret_cast<boost::uint64_t*>(
            const_cast<char*>(id.substr(kKeySize - 8).data()));
}

}  // namespace maidsafe_vault
