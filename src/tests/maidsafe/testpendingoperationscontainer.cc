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
#include "maidsafe/vault/pendingoperations.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

class PendingOperationContainerTest : public testing::Test {
 public:
  PendingOperationContainerTest() : poh_() {}
 protected:
  void SetUp() {
    poh_.ClearPendingOperations();
  }
  void TearDown() {}
  PendingOperationsHandler poh_;
};


TEST_F(PendingOperationContainerTest, BEH_VAULT_PendingOpsInit) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_AddPendingOp) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // Add a pending operation
  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "", "", 0,
                                        "public_key", STORE_ACCEPTED));
  ASSERT_EQ(1, poh_.PendingOperationsCount());
  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "iou", "",
                                        0, "", IOU_RECEIVED));
  ASSERT_EQ(2, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_ParameterAnalysis) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());
  printf("\nThe following messages are appropriate debug output.\n\n");

  // STORE_ACCEPTED
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "chunkname", 123456, "", "",
                                          "public_key", STORE_ACCEPTED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "", 123456, "", "",
                                          "public_key", STORE_ACCEPTED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "chunkname", 123456, "", "",
                                          "", STORE_ACCEPTED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "chunkname", 0, "", "",
                                          "public_key", STORE_ACCEPTED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "chunkname", 1234, "a", "b",
                                          "public_key", STORE_ACCEPTED));
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // STORE_DONE
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "chunkname", 123456, "", "",
                                          "", STORE_DONE));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "", 123456, "", "",
                                          "", STORE_DONE));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "chunkname", 0, "", "",
                                          "", STORE_DONE));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("pmid", "chunkname", 1234, "a", "b",
                                          "public_key", STORE_ACCEPTED));
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // IOU_READY/AWAITING_IOU
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "", 123456, "", "",
                                          "public_key", IOU_READY));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "", 123456, "", "",
                                          "public_key", AWAITING_IOU));
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // IOU_RANK_RETREIVED
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "", 123456, "iou", "rank",
                                          "", IOU_RANK_RETREIVED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "chunkname", 123456, "", "rank",
                                          "", IOU_RANK_RETREIVED));
  ASSERT_EQ(-1496, poh_.AnalyseParameters("", "chunkname", 123456, "iou", "",
                                        "", IOU_RANK_RETREIVED));
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // IOU_RECEIVED
  ASSERT_EQ(-1497, poh_.AnalyseParameters("", "chunkname", 123456, "iou", "",
                                          "", IOU_RECEIVED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "", 123456, "iou", "",
                                          "", IOU_RECEIVED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 0, "iou", "",
                                          "", IOU_RECEIVED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 0, "", "",
                                          "", IOU_RECEIVED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 0, "", "rank",
                                          "", IOU_RECEIVED));
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // IOU_COLLECTED
  ASSERT_EQ(-1497, poh_.AnalyseParameters("", "chunkname", 0, "", "",
                                          "", IOU_COLLECTED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "", 0, "", "",
                                          "", IOU_COLLECTED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 123456, "", "",
                                          "", IOU_COLLECTED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 0, "iou", "",
                                          "", IOU_COLLECTED));
  ASSERT_EQ(-1497, poh_.AnalyseParameters("pmid", "chunkname", 0, "", "rank",
                                          "", IOU_COLLECTED));
  ASSERT_EQ(0, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest,
       BEH_VAULT_AddAndClearMultiplePendingStores) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // Add cycle
  unsigned int cycles = 22;
  for (unsigned int n = 0; n < cycles; ++n) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(n),
              "chunkname" + base::itos(n), 123456 + n, "", "", 0, "public_key",
              STORE_ACCEPTED));
    ASSERT_EQ(n + 1, poh_.PendingOperationsCount());
  }
  poh_.ClearPendingOperations();
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(a),
              "chunkname" + base::itos(a), 123456 + a, "iou", "", 0, "",
              IOU_RECEIVED));
    ASSERT_EQ(a + 1, poh_.PendingOperationsCount());
  }
  poh_.ClearPendingOperations();
  ASSERT_EQ(0, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_AddInvalidPendingStores) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "", "",
            0, "public_key", STORE_ACCEPTED));
  ASSERT_EQ(1, poh_.PendingOperationsCount());
  ASSERT_EQ(-1492, poh_.AddPendingOperation("pmid", "chunkname", 123456, "", "",
            0, "public_key", STORE_ACCEPTED));
  ASSERT_EQ(1, poh_.PendingOperationsCount());

  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "iou", "",
            0, "", IOU_RECEIVED));
  ASSERT_EQ(2, poh_.PendingOperationsCount());
  ASSERT_EQ(-1492, poh_.AddPendingOperation("pmid", "chunkname", 123456, "iou",
            "", 0, "", IOU_RECEIVED));
  ASSERT_EQ(2, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_FindPendingStores) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // Add cycle
  unsigned int cycles = 22;
  for (unsigned int n = 0; n < cycles; ++n) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(n),
              "chunkname" + base::itos(n), 123456 + n, "", "", 0, "public_key",
              STORE_ACCEPTED));
    ASSERT_EQ(n + 1, poh_.PendingOperationsCount());
  }

  // Check size
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, poh_.FindOperation("pmid" + base::itos(a),
              "chunkname" + base::itos(a), 123456 + a, "", "", STORE_ACCEPTED));
  }
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_AdvanceStatus) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "", "", 0,
            "public_key", STORE_ACCEPTED));
  ASSERT_EQ(0, poh_.AdvanceStatus("pmid", "chunkname", 123456, "", "", "",
            STORE_DONE));
  ASSERT_EQ(-1493, poh_.AdvanceStatus("pmid", "chunkname", 123456, "", "", "",
            STORE_DONE));
  ASSERT_EQ(0, poh_.AdvanceStatus("pmid", "chunkname", 123456, "", "", "",
            AWAITING_IOU));
  ASSERT_EQ(-1493, poh_.AdvanceStatus("pmid", "chunkname", 123456, "", "", "",
            AWAITING_IOU));
  ASSERT_EQ(0, poh_.AdvanceStatus("", "chunkname", 0, "", "", "",
            IOU_READY));
  ASSERT_EQ(-1493, poh_.AdvanceStatus("", "chunkname", 0, "", "", "",
            IOU_READY));
  ASSERT_EQ(1, poh_.PendingOperationsCount());

  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "", "", 0,
            "public_key", STORE_ACCEPTED));
  ASSERT_EQ(2, poh_.PendingOperationsCount());

  // Add advance of status for chunk ref holder
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_GetSizeAndIOU) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  ASSERT_EQ(0, poh_.AddPendingOperation("pmid", "chunkname", 123456, "iou", "",
                                        0, "", IOU_RECEIVED));

  boost::uint64_t chunk_size = 0;
  std::string iou;
  ASSERT_EQ(0, poh_.GetSizeAndIOU("pmid", "chunkname", &chunk_size, &iou));
  ASSERT_EQ(123456, chunk_size);
  ASSERT_EQ("iou", iou);
  ASSERT_EQ(1, poh_.PendingOperationsCount());

  ASSERT_EQ(-1495, poh_.GetSizeAndIOU("pmid", "chunk", &chunk_size, &iou));
  ASSERT_EQ(0, chunk_size);
  ASSERT_EQ("", iou);
  ASSERT_EQ(1, poh_.PendingOperationsCount());
}

TEST_F(PendingOperationContainerTest, BEH_VAULT_PrunePendingOps) {
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  // Add cycle
  unsigned int cycles = 22;
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(a),
              "chunkname" + base::itos(a), 123456 + a, "iou", "", 0, "",
              IOU_RECEIVED));
    ASSERT_EQ(a + 1, poh_.PendingOperationsCount());
  }
  ASSERT_EQ(0, poh_.PrunePendingOps());

  printf("Before 15 sec sleep.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(15));
  printf("After 15 sec sleep.\n");
  ASSERT_EQ(cycles, poh_.PrunePendingOps());
  ASSERT_EQ(0, poh_.PendingOperationsCount());

  for (unsigned int n = 0; n < cycles; ++n) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(n),
              "chunkname" + base::itos(n), 123456 + n, "", "", 0, "public_key",
              STORE_ACCEPTED));
    ASSERT_EQ(n + 1, poh_.PendingOperationsCount());
  }
  for (unsigned int a = 0; a < cycles; ++a) {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid" + base::itos(a),
              "chunkname" + base::itos(a), 123456 + a, "iou", "", 0, "",
              IOU_RECEIVED));
    ASSERT_EQ(a + cycles + 1, poh_.PendingOperationsCount());
  }

  printf("Before 15 sec sleep.\n");
  boost::this_thread::sleep(boost::posix_time::seconds(15));
  printf("After 15 sec sleep.\n");
  ASSERT_EQ(cycles, poh_.PrunePendingOps());
  ASSERT_EQ(cycles, poh_.PendingOperationsCount());
}

}  // namespace maidsafe_vault
