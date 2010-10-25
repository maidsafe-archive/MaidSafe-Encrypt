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
  BufferPacketStoreTest() : bps() {}
 protected:
  BufferPacketStore bps;
};

TEST_F(BufferPacketStoreTest, BEH_MAID_BPStorage) {
  std::string bp_name("Buffer packet name"), bp_data("Buffer packet contents");
  std::string temp;
  EXPECT_FALSE(bps.HasBP(bp_name));
  EXPECT_FALSE(bps.LoadBP(bp_name, &temp));
  EXPECT_FALSE(bps.UpdateBP(bp_name, bp_data));
  EXPECT_FALSE(bps.DeleteBP(bp_name));

  EXPECT_TRUE(bps.StoreBP(bp_name, bp_data));
  EXPECT_TRUE(bps.HasBP(bp_name));
  EXPECT_TRUE(bps.LoadBP(bp_name, &temp));
  EXPECT_EQ(bp_data, temp);

  bp_data = "New BP contents";
  EXPECT_TRUE(bps.UpdateBP(bp_name, bp_data));
  EXPECT_TRUE(bps.LoadBP(bp_name, &temp));
  EXPECT_EQ(bp_data, temp);

  EXPECT_TRUE(bps.DeleteBP(bp_name));
  EXPECT_FALSE(bps.HasBP(bp_name));
}

TEST_F(BufferPacketStoreTest, DISABLED_BEH_MAID_BPImportMapFromPb) {
  // TODO(Steve#) test ImportMapFromPb
}

TEST_F(BufferPacketStoreTest, DISABLED_BEH_MAID_BPExportMapToPb) {
  // TODO(Steve#) test ExportMapToPb
}

}  // namespace maidsafe_vault
