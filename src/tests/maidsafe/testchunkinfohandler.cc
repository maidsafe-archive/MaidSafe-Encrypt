/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Tests the chunk info handler
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
#include "maidsafe/vault/chunkinfohandler.h"

namespace maidsafe_vault {

class ChunkInfoHandlerTest : public testing::Test {
 public:
  ChunkInfoHandlerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerInit) {
  ChunkInfoHandler cih;
  ASSERT_EQ(size_t(0), cih.chunk_infos_.size());
  ASSERT_FALSE(cih.HasWatchers("some chunk name"));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum) {
  ChunkInfoHandler cih;
  boost::uint64_t checksum = cih.GetChecksum(base::DecodeFromHex(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1234567890ABCDEF"));
  ASSERT_EQ(boost::uint64_t(0xEFCDAB9078563412ll), checksum);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerWlAddRemove) {
  ChunkInfoHandler cih;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client[kNumClients], creditor;
  bool payment_required = false;

  for (int i = 0; i < kNumClients; i++) {
    client[i] = co.Hash("id" + boost::lexical_cast<std::string>(i), "",
                        crypto::STRING_STRING, false);
  }

  ASSERT_EQ(kChunkInfoInvalidSize, cih.AddToWatchList(chunk_name, client[0], 0,
                                                      &creditor,
                                                      &payment_required));
  ASSERT_FALSE(cih.HasWatchers(chunk_name));

  ASSERT_EQ(0, cih.AddToWatchList(chunk_name, client[0], 123, &creditor,
                                  &payment_required));
  ASSERT_EQ("", creditor);
  ASSERT_TRUE(payment_required);
  ASSERT_TRUE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count_);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size_);
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watchers_.size());

  ASSERT_EQ(kChunkInfoInvalidSize, cih.AddToWatchList(chunk_name, client[1],
                                                      321, &creditor,
                                                      &payment_required));

  for (int i = 1; i < kNumClients; i++) {
    ASSERT_EQ(0, cih.AddToWatchList(chunk_name, client[i], 123, &creditor,
                                    &payment_required));
    ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
    ASSERT_EQ(size_t(i) + 1, cih.chunk_infos_[chunk_name].watcher_count_);
    if (i < kMinChunkCopies) {
      ASSERT_EQ(kMinChunkCopies,
                cih.chunk_infos_[chunk_name].watchers_.size());
      ASSERT_TRUE(payment_required);
      ASSERT_EQ(client[0], creditor);
    } else if (i < kMinChunkCopies + kMaxReserveWatchListEntries) {
      ASSERT_EQ(size_t(i) + 1,
                cih.chunk_infos_[chunk_name].watchers_.size());
      ASSERT_TRUE(payment_required);
      ASSERT_EQ("", creditor);
    } else {
      ASSERT_EQ(kMinChunkCopies + size_t(kMaxReserveWatchListEntries),
                cih.chunk_infos_[chunk_name].watchers_.size());
      ASSERT_FALSE(payment_required);
      ASSERT_EQ("", creditor);
    }
  }

  std::list<std::string> creditors;

  ASSERT_EQ(kChunkInfoInvalidName, cih.RemoveFromWatchList("fail", client[0],
                                                           123, &creditors));
  ASSERT_EQ(kChunkInfoInvalidSize, cih.RemoveFromWatchList(chunk_name,
                                                           client[0], 321,
                                                           &creditors));

  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[0], 123, &creditors));
  ASSERT_EQ(size_t(1), creditors.size());
  ASSERT_EQ(client[0], creditors.front());
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watcher_count_);
  ASSERT_EQ(size_t(kNumClients) - 2,
            cih.chunk_infos_[chunk_name].watchers_.size());

  for (int i = kNumClients - 1; i >= 1; i--) {
    creditors.clear();
    ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[i], 123,
                                         &creditors));
    if (i > kMinChunkCopies) {
      if (i == kNumClients - 1) {
        ASSERT_EQ(size_t(i) - 1,
                  cih.chunk_infos_[chunk_name].watcher_count_);
        ASSERT_EQ(size_t(0), creditors.size());
      } else {
        ASSERT_EQ(size_t(i), cih.chunk_infos_[chunk_name].watcher_count_);
        ASSERT_EQ(size_t(1), creditors.size());
        ASSERT_EQ(client[i], creditors.front());
      }
      ASSERT_EQ(size_t(i) - 1,
          cih.chunk_infos_[chunk_name].watchers_.size());
    } else if (i == 1) {  // last entry
      ASSERT_EQ(size_t(4), creditors.size());
      ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));
    } else {
      ASSERT_EQ(size_t(0), creditors.size());
      ASSERT_EQ(kMinChunkCopies,
                cih.chunk_infos_[chunk_name].watchers_.size());
      ASSERT_EQ(size_t(i), cih.chunk_infos_[chunk_name].watcher_count_);
    }
  }

  ASSERT_FALSE(cih.HasWatchers(chunk_name));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerWlFailsafe) {
  ChunkInfoHandler cih;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client1(co.Hash("client1", "", crypto::STRING_STRING, false));
  std::string client2(co.Hash("client2", "", crypto::STRING_STRING, false));

  ASSERT_FALSE(cih.HasWatchers(chunk_name));

  std::string creditor;
  std::list<std::string> creditors;
  bool payment_required = false;

  ASSERT_EQ(0, cih.AddToWatchList(chunk_name, client1, 123, &creditor,
                                  &payment_required));
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client2, 123,
                                       &creditors));
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count_);
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watchers_.size());
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client1, 123,
                                       &creditors));
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count_);
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watchers_.size());

  ASSERT_TRUE(cih.HasWatchers(chunk_name));
}

}  // namespace maidsafe_vault
