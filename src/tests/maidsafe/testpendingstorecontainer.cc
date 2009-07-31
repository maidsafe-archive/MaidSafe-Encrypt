/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe contacts
* Version:      1.0
* Created:      2009-01-28-23.19.56
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

#include <boost/filesystem.hpp>
#include <boost/scoped_ptr.hpp>

#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>
#include "maidsafe/vault/pendingstores.h"

namespace fs = boost::filesystem;

class PendingStoreContainerTest : public testing::Test {
 public:
  PendingStoreContainerTest() : psh_() {}
 protected:
  void SetUp() {
    psh_.ClearPendingStores();
  }
  void TearDown() {}
  maidsafe_vault::PendingStoreHandler psh_;
};

TEST_F(PendingStoreContainerTest, BEH_VAULT_PendingStoreInit) {
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());

  // Getting next on all phases returns the empty result
  maidsafe_vault::PendingStoreRow psr;
  ASSERT_EQ(-2703, psh_.NextPendingStore(0, &psr));
  ASSERT_EQ(-2703, psh_.NextPendingStore(1, &psr));
  ASSERT_EQ(-2703, psh_.NextPendingStore(2, &psr));
  ASSERT_EQ(-2703, psh_.NextPendingStore(3, &psr));
}

TEST_F(PendingStoreContainerTest, BEH_VAULT_AddPendingStore) {
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());

  // Add a pending store
  ASSERT_EQ(0, psh_.AddPendingStore("abc", "def", 123456789));
  ASSERT_EQ(1, psh_.PendingStoresCount());
  ASSERT_EQ(123456789, psh_.QueuedSpace());
  maidsafe_vault::PendingStoreRow psr;
  ASSERT_EQ(-2703, psh_.NextPendingStore(1, &psr));
  ASSERT_EQ(-2703, psh_.NextPendingStore(2, &psr));
  ASSERT_EQ(-2703, psh_.NextPendingStore(3, &psr));

  ASSERT_EQ(0, psh_.NextPendingStore(0, &psr));
  ASSERT_EQ("abc", psr.pmid_);
  ASSERT_EQ("def", psr.chunk_name_);
  ASSERT_EQ(0, psr.contacts_.size());
  ASSERT_EQ(123456789, psr.chunk_size_);
  ASSERT_EQ(0, psr.phase_);
  ASSERT_NE(0, psr.timestamp_);

  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());
  ASSERT_EQ(-2703, psh_.NextPendingStore(0, &psr));
}

TEST_F(PendingStoreContainerTest, BEH_VAULT_AddInvalidPendingStore) {
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());

  // Add a pending store
  ASSERT_EQ(-2700, psh_.AddPendingStore("", "def", 123456789));
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(-2700, psh_.AddPendingStore("abc", "", 123456789));
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(-2700, psh_.AddPendingStore("abc", "def", 0));
  ASSERT_EQ(0, psh_.PendingStoresCount());
}

TEST_F(PendingStoreContainerTest, BEH_VAULT_AddMultiplePendingStores) {
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());

  // Add cycle
  std::string pmid("abc");
  std::string chunkname("def");
  boost::uint64_t chunk_size(1234567);
  for (int n = 0; n < 22; ++n) {
    ASSERT_EQ(0, psh_.AddPendingStore(pmid + base::itos(n),
              chunkname + base::itos(n), chunk_size + n));
  }
  ASSERT_EQ(22, psh_.PendingStoresCount());
  ASSERT_EQ((chunk_size * 22) + (21 * 11), psh_.QueuedSpace());

  for (int n = 0; n < 22; ++n) {
    maidsafe_vault::PendingStoreRow psr;
    ASSERT_EQ(0, psh_.NextPendingStore(0, &psr));
    ASSERT_EQ(pmid + base::itos(n), psr.pmid_);
    ASSERT_EQ(chunkname + base::itos(n), psr.chunk_name_);
    ASSERT_EQ(0, psr.contacts_.size());
    ASSERT_EQ(chunk_size + n, psr.chunk_size_);
    ASSERT_EQ(0, psr.phase_);
    ASSERT_NE(0, psr.timestamp_);
    ASSERT_EQ(21 - n, psh_.PendingStoresCount());
  }
}

TEST_F(PendingStoreContainerTest, BEH_VAULT_ClearPendingStores) {
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());

  // Add cycle
  std::string pmid("abc");
  std::string chunkname("def");
  boost::uint64_t chunk_size(1234567);
  for (int n = 0; n < 22; ++n) {
    ASSERT_EQ(0, psh_.AddPendingStore(pmid + base::itos(n),
              chunkname + base::itos(n), chunk_size + n));
  }
  ASSERT_EQ(22, psh_.PendingStoresCount());
  ASSERT_EQ((chunk_size * 22) + (21 * 11), psh_.QueuedSpace());

  psh_.ClearPendingStores();
  ASSERT_EQ(0, psh_.PendingStoresCount());
  ASSERT_EQ(0, psh_.QueuedSpace());
}
