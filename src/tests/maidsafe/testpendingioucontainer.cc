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
#include "maidsafe/vault/pendingious.h"

namespace fs = boost::filesystem;

class PendingIOUContainerTest : public testing::Test {
 public:
  PendingIOUContainerTest() : pih_() {}
 protected:
  void SetUp() {
    pih_.ClearPendingIOUs();
  }
  void TearDown() {}
  maidsafe_vault::PendingIOUHandler pih_;
};

TEST_F(PendingIOUContainerTest, BEH_VAULT_PendingIOUInit) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(0, pih_.PrunableIOUsCount(0));
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_AddPendingIOU) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  // Add a pending store
  ASSERT_EQ(0, pih_.AddPendingIOU("abc", 123456789, "maidsafe", 0));
  ASSERT_EQ(1, pih_.PendingIOUsCount());
  ASSERT_TRUE(pih_.IOUExists("abc", 123456789, "maidsafe"));
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_AddInvalidPendingIOU) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  // Add a pending store
  std::string authority = base::RandomString(64);
  ASSERT_EQ(-2700, pih_.AddPendingIOU("", 123456789, authority, 0));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(-2700, pih_.AddPendingIOU("abc", 123456789, "", 0));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(-2700, pih_.AddPendingIOU("abc", 0, authority, 0));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(-2700, pih_.AddPendingIOU("abc", 123456789, "lalalala", 0));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_AddMultiplePendingStores) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  // Add cycle
  unsigned int cycles = 22;
  std::string authority[22];
  for (unsigned int n = 0; n < cycles; ++n)
    authority[n] = base::RandomString(64);
  boost::uint64_t chunk_size(1234567);
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority[a], 0));
  }
  ASSERT_EQ(22, pih_.PendingIOUsCount());
}


TEST_F(PendingIOUContainerTest, BEH_VAULT_ClearPendingIOUs) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(0, pih_.PrunableIOUsCount(0));

  // Add cycle
  unsigned int cycles = 22;
  std::string authority[22];
  for (unsigned int n = 0; n < cycles; ++n)
    authority[n] = base::RandomString(64);
  boost::uint64_t chunk_size(1234567);
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority[a], 0));
  }
  ASSERT_EQ(22, pih_.PendingIOUsCount());

  pih_.ClearPendingIOUs();
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(0, pih_.PrunableIOUsCount(0));
  ASSERT_FALSE(pih_.IOUExists("abc", chunk_size, authority[cycles - 1]));
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_DeletePendingIOUs) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  // Add cycle
  unsigned int cycles = 5;
  std::string authority = base::RandomString(64);
  boost::uint64_t chunk_size(1234567);
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, 0));
  }
  ASSERT_EQ(cycles, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("def", chunk_size, authority, 0));
  }
  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PendingIOUsCount()));

  ASSERT_EQ(0, pih_.DeletePendingIOU("abc", chunk_size, authority));
  ASSERT_EQ((cycles * 2) - 1,
      static_cast<unsigned int>(pih_.PendingIOUsCount()));
  ASSERT_TRUE(pih_.IOUExists("abc", chunk_size, authority));

  unsigned int y = cycles - 1;
  while (0 == pih_.DeletePendingIOU("abc", chunk_size, authority))
    --y;

  ASSERT_EQ(static_cast<unsigned int>(0), y);
  ASSERT_FALSE(pih_.IOUExists("abc", chunk_size, authority));
  ASSERT_TRUE(pih_.IOUExists("def", chunk_size, authority));
  ASSERT_EQ(cycles, static_cast<unsigned int>(pih_.PendingIOUsCount()));

  y = cycles;
  while (0 == pih_.DeletePendingIOU("def", chunk_size, authority))
    --y;
  ASSERT_FALSE(pih_.IOUExists("def", chunk_size, authority));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_PrunableIOUCount) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  unsigned int cycles = 5;
  std::string authority = base::RandomString(64);
  boost::uint64_t chunk_size(1234567);
  for (unsigned int a = 0; a < 2 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, 1));
  }
  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < 3 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, 10));
  }
  ASSERT_EQ(cycles * 5, static_cast<unsigned int>(pih_.PendingIOUsCount()));

  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PrunableIOUsCount(5)));

  pih_.ClearPendingIOUs();
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(0, pih_.PrunableIOUsCount(11));

  boost::uint32_t now = base::get_epoch_time() - 86400;
  for (unsigned int a = 0; a < 2 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, now));
  }
  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < 3 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, now + 10));
  }
  ASSERT_EQ(cycles * 5, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  printf("Before 5 sec sleep.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("After 5 sec sleep.\n");

  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PrunableIOUsCount(0)));
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_DeletePrunableIOUs) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  unsigned int cycles = 5;
  std::string authority = base::RandomString(64);
  boost::uint64_t chunk_size(1234567);
  for (unsigned int a = 0; a < 2 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, 1));
  }
  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < 3 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, 10));
  }
  ASSERT_EQ(cycles * 5, static_cast<unsigned int>(pih_.PendingIOUsCount()));

  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PrunableIOUsCount(5)));
  ASSERT_EQ(0, pih_.PrunePendingIOUs(5));
  ASSERT_EQ(0, pih_.PrunableIOUsCount(5));
  ASSERT_EQ(cycles * 3, static_cast<unsigned int>(pih_.PendingIOUsCount()));

  pih_.ClearPendingIOUs();
  ASSERT_EQ(0, pih_.PendingIOUsCount());
  ASSERT_EQ(0, pih_.PrunableIOUsCount(11));

  boost::uint32_t now = base::get_epoch_time() - 86400;
  for (unsigned int a = 0; a < 2 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, now));
  }
  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < 3 * cycles; ++a) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc", chunk_size, authority, now + 10));
  }
  ASSERT_EQ(cycles * 5, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  printf("Before 5 sec sleep.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  printf("After 5 sec sleep.\n");

  ASSERT_EQ(cycles * 2, static_cast<unsigned int>(pih_.PrunableIOUsCount(0)));
  ASSERT_EQ(0, pih_.PrunePendingIOUs(0));
  ASSERT_EQ(0, pih_.PrunableIOUsCount(0));
  ASSERT_EQ(cycles * 3, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  while (pih_.PrunableIOUsCount(0) == 0)
    boost::this_thread::sleep(boost::posix_time::seconds(1));

  ASSERT_EQ(cycles * 3, static_cast<unsigned int>(pih_.PrunableIOUsCount(0)));
  ASSERT_EQ(0, pih_.PrunePendingIOUs(0));
  ASSERT_EQ(0, pih_.PrunableIOUsCount(0));
  ASSERT_EQ(0, pih_.PendingIOUsCount());
}

TEST_F(PendingIOUContainerTest, BEH_VAULT_FindIOUs) {
  ASSERT_EQ(0, pih_.PendingIOUsCount());

  unsigned int cycles = 10;
  std::string authority(63, 'N');
  boost::uint64_t chunk_size(1234567);
  for (unsigned int n = 0; n < cycles; ++n) {
    ASSERT_EQ(0, pih_.AddPendingIOU("abc" + base::itos(n), chunk_size + n,
              authority + base::itos(n), n));
  }
  ASSERT_EQ(cycles, static_cast<unsigned int>(pih_.PendingIOUsCount()));
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(authority + base::itos(a), pih_.GetIOU("abc" + base::itos(a),
              chunk_size + a));
  }
  ASSERT_EQ("", pih_.GetIOU("abcd", chunk_size + 22));
  ASSERT_EQ(cycles, static_cast<unsigned int>(pih_.PendingIOUsCount()));
}
