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

#ifndef MAIDSAFE_VAULT_WATCHLISTS_H_
#define MAIDSAFE_VAULT_WATCHLISTS_H_

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

struct WatchList {
  WatchList() : entries_(), watcher_count_(0), watcher_checksum_(0),
                chunk_size_(0) {}
  std::list<WatchListEntry> entries_;
  boost::uint64_t watcher_count_;
  boost::uint64_t watcher_checksum_;
  boost::uint64_t chunk_size_;
  // TODO(anyone) minimum rank
};

class WatchListHandler {
 public:
  WatchListHandler() : watch_lists_(), watch_list_mutex_() {}
  ~WatchListHandler() {}

  bool HasWatchers(const std::string &watch_list_name);
  int AddToWatchList(const std::string &watch_list_name,
                     const std::string &pmid,
                     const boost::uint64_t &chunk_size,
                     std::string *creditor);
  int RemoveFromWatchList(const std::string &watch_list_name,
                          const std::string &pmid,
                          const boost::uint64_t &chunk_size,
                          std::list<std::string> *creditors);
 private:
  FRIEND_TEST(WatchListHandlerTest, BEH_VAULT_WatchListHandlerInit);
  FRIEND_TEST(WatchListHandlerTest, BEH_VAULT_WatchListHandlerChecksum);
  FRIEND_TEST(WatchListHandlerTest, BEH_VAULT_WatchListHandlerAddRemove);
  FRIEND_TEST(WatchListHandlerTest, BEH_VAULT_WatchListHandlerFailsafe);
  boost::uint64_t GetChecksum(const std::string &id);
  std::map<std::string, WatchList> watch_lists_;
  boost::mutex watch_list_mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_WATCHLISTS_H_
