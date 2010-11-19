/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Created:      2010-04-08
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
#include "maidsafe/vault/bufferpacketstore.h"

namespace maidsafe_vault {

class BufferPacketStoreTest : public testing::Test {
 public:
  BufferPacketStoreTest() : bps_() {}
 protected:
  BufferPacketStore bps_;
};

TEST_F(BufferPacketStoreTest, BEH_MAID_BPStorage) {
  std::string bp_name("Buffer packet name"), bp_data("Buffer packet contents");
  std::string temp;
  EXPECT_FALSE(bps_.HasBP(bp_name));
  EXPECT_FALSE(bps_.LoadBP(bp_name, &temp));
  EXPECT_FALSE(bps_.UpdateBP(bp_name, bp_data));
  EXPECT_FALSE(bps_.DeleteBP(bp_name));

  EXPECT_TRUE(bps_.StoreBP(bp_name, bp_data));
  EXPECT_TRUE(bps_.HasBP(bp_name));
  EXPECT_TRUE(bps_.LoadBP(bp_name, &temp));
  EXPECT_EQ(bp_data, temp);

  bp_data = "New BP contents";
  EXPECT_TRUE(bps_.UpdateBP(bp_name, bp_data));
  EXPECT_TRUE(bps_.LoadBP(bp_name, &temp));
  EXPECT_EQ(bp_data, temp);

  EXPECT_TRUE(bps_.DeleteBP(bp_name));
  EXPECT_FALSE(bps_.HasBP(bp_name));
}

TEST_F(BufferPacketStoreTest, DISABLED_BEH_MAID_BPImportMapFromPb) {
  // TODO(Team#) test ImportMapFromPb
}

TEST_F(BufferPacketStoreTest, DISABLED_BEH_MAID_BPExportMapToPb) {
  // TODO(Team#) test ExportMapToPb
}

TEST_F(BufferPacketStoreTest, BEH_MAID_BPStoreClean) {
  ASSERT_EQ(size_t(0), bps_.buffer_packets_.size());
  boost::uint32_t n(base::RandomUint32() % 50 + 50);
  for (boost::uint32_t i = 0; i < n; ++i)
    EXPECT_TRUE(bps_.StoreBP("bp" + base::IntToString(i), "bp data"));
  ASSERT_EQ(size_t(n), bps_.buffer_packets_.size());
  bps_.Clear();
  ASSERT_EQ(size_t(0), bps_.buffer_packets_.size());
}

}  // namespace maidsafe_vault
