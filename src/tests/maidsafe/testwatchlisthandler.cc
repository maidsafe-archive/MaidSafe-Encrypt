/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Tests the watch list handler
* Version:      1.0
* Created:      2009-12-23
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

#include <gtest/gtest.h>
#include <boost/lexical_cast.hpp>
#include "maidsafe/vault/watchlists.h"

namespace maidsafe_vault {

class WatchListHandlerTest : public testing::Test {
 public:
  WatchListHandlerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(WatchListHandlerTest, BEH_VAULT_WatchListHandlerInit) {
  WatchListHandler wlh;
  ASSERT_EQ(0, wlh.watch_lists_.size());
  ASSERT_FALSE(wlh.HasWatchers("some list name"));
}

TEST_F(WatchListHandlerTest, BEH_VAULT_WatchListHandlerChecksum) {
  WatchListHandler wlh;
  boost::uint64_t checksum = wlh.GetChecksum(base::DecodeFromHex(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1234567890ABCDEF"));
  ASSERT_EQ(boost::uint64_t(0xEFCDAB9078563412ll), checksum);
}

TEST_F(WatchListHandlerTest, BEH_VAULT_WatchListHandlerAddRemove) {
  WatchListHandler wlh;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string watch_list_name(co.Hash("wl", "", crypto::STRING_STRING, false));
  std::string client[kNumClients], creditor;
  for (int i = 0; i < kNumClients; i++) {
    client[i] = co.Hash("id" + boost::lexical_cast<std::string>(i), "",
                        crypto::STRING_STRING, false);
  }

  ASSERT_EQ(kWatchListInvalidChunkSize, wlh.AddToWatchList(watch_list_name,
                                                           client[0], 0,
                                                           &creditor));
  ASSERT_FALSE(wlh.HasWatchers(watch_list_name));

  ASSERT_EQ(0, wlh.AddToWatchList(watch_list_name, client[0], 123, &creditor));
  ASSERT_EQ("", creditor);
  ASSERT_TRUE(wlh.HasWatchers(watch_list_name));
  ASSERT_EQ(1, wlh.watch_lists_.count(watch_list_name));
  ASSERT_EQ(1, wlh.watch_lists_[watch_list_name].watcher_count_);
  ASSERT_EQ(123, wlh.watch_lists_[watch_list_name].chunk_size_);
  ASSERT_EQ(kMinChunkCopies, wlh.watch_lists_[watch_list_name].entries_.size());

  ASSERT_EQ(kWatchListInvalidChunkSize, wlh.AddToWatchList(watch_list_name,
                                                           client[1], 321,
                                                           &creditor));

  for (int i = 1; i < kNumClients; i++) {
    ASSERT_EQ(0, wlh.AddToWatchList(watch_list_name, client[i], 123,
                                    &creditor));
    if (i < kMinChunkCopies)
      ASSERT_EQ(client[0], creditor);
    else
      ASSERT_EQ("", creditor);
    ASSERT_EQ(1, wlh.watch_lists_.count(watch_list_name));
    ASSERT_EQ(i + 1, wlh.watch_lists_[watch_list_name].watcher_count_);
    if (i < kMinChunkCopies)
      ASSERT_EQ(kMinChunkCopies,
                wlh.watch_lists_[watch_list_name].entries_.size());
    else if (i < kMinChunkCopies + kMaxReserveWatchListEntries)
      ASSERT_EQ(i + 1, wlh.watch_lists_[watch_list_name].entries_.size());
    else
      ASSERT_EQ(kMinChunkCopies + kMaxReserveWatchListEntries,
                wlh.watch_lists_[watch_list_name].entries_.size());
  }

  std::list<std::string> creditors;

  ASSERT_EQ(kWatchListInvalidName, wlh.RemoveFromWatchList("fail", client[0],
                                                           123, &creditors));
  ASSERT_EQ(kWatchListInvalidChunkSize, wlh.RemoveFromWatchList(watch_list_name,
                                                                client[0], 321,
                                                                &creditors));

  ASSERT_EQ(0, wlh.RemoveFromWatchList(watch_list_name, client[0], 123,
                                       &creditors));
  ASSERT_EQ(1, creditors.size());
  ASSERT_EQ(client[0], creditors.front());
  ASSERT_EQ(kNumClients - 1, wlh.watch_lists_[watch_list_name].watcher_count_);
  ASSERT_EQ(kNumClients - 2, wlh.watch_lists_[watch_list_name].entries_.size());

  for (int i = kNumClients - 1; i >= 1; i--) {
    creditors.clear();
    ASSERT_EQ(0, wlh.RemoveFromWatchList(watch_list_name, client[i], 123,
                                         &creditors));
    if (i > kMinChunkCopies) {
      if (i == kNumClients - 1) {
        ASSERT_EQ(i - 1, wlh.watch_lists_[watch_list_name].watcher_count_);
      } else {
        ASSERT_EQ(i, wlh.watch_lists_[watch_list_name].watcher_count_);
      }
      ASSERT_EQ(1, creditors.size());
      ASSERT_EQ(client[i], creditors.front());
      ASSERT_EQ(i - 1, wlh.watch_lists_[watch_list_name].entries_.size());
    } else if (i == 1) {  // last entry
      ASSERT_EQ(4, creditors.size());
      ASSERT_EQ(0, wlh.watch_lists_.count(watch_list_name));
    } else {
      ASSERT_EQ(0, creditors.size());
      ASSERT_EQ(kMinChunkCopies,
                wlh.watch_lists_[watch_list_name].entries_.size());
      ASSERT_EQ(i, wlh.watch_lists_[watch_list_name].watcher_count_);
    }
  }

  ASSERT_FALSE(wlh.HasWatchers(watch_list_name));
}

TEST_F(WatchListHandlerTest, BEH_VAULT_WatchListHandlerFailsafe) {
  WatchListHandler wlh;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string watch_list_name(co.Hash("wl", "", crypto::STRING_STRING, false));
  std::string client1(co.Hash("client1", "", crypto::STRING_STRING, false));
  std::string client2(co.Hash("client2", "", crypto::STRING_STRING, false));

  ASSERT_FALSE(wlh.HasWatchers(watch_list_name));

  std::string creditor;
  std::list<std::string> creditors;
  ASSERT_EQ(0, wlh.AddToWatchList(watch_list_name, client1, 123, &creditor));
  ASSERT_EQ(0, wlh.RemoveFromWatchList(watch_list_name, client2, 123,
                                       &creditors));
  ASSERT_EQ(1, wlh.watch_lists_[watch_list_name].watcher_count_);
  ASSERT_EQ(kMinChunkCopies, wlh.watch_lists_[watch_list_name].entries_.size());
  ASSERT_EQ(0, wlh.RemoveFromWatchList(watch_list_name, client1, 123,
                                       &creditors));
  ASSERT_EQ(1, wlh.watch_lists_[watch_list_name].watcher_count_);
  ASSERT_EQ(kMinChunkCopies, wlh.watch_lists_[watch_list_name].entries_.size());

  ASSERT_TRUE(wlh.HasWatchers(watch_list_name));
}

}  // namespace maidsafe_vault
