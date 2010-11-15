/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Tests the chunk info handler
* Version:      1.0
* Created:      2009-12-23
* Revision:     none
* Compiler:     gcc
* Author:       Steve Muecklisch
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
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/maidsafe.h"
#include "maidsafe/vault/vaultconfig.h"
#include "maidsafe/vault/chunkinfohandler.h"

namespace maidsafe {

namespace vault {

namespace test {

class ChunkInfoHandlerTest : public testing::Test {
 public:
  ChunkInfoHandlerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Init) {
  ChunkInfoHandler cih(true);
  ASSERT_TRUE(cih.chunk_infos_.empty());
  ASSERT_FALSE(cih.HasWatchers("some chunk name"));
  ASSERT_EQ(0, cih.ActiveReferences("some chunk name"));
  std::list<std::string> references;
  ASSERT_EQ(kChunkInfoInvalidName,
            cih.GetActiveReferences("some chunk name", &references));
  ASSERT_TRUE(references.empty());
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Checksum) {
  ChunkInfoHandler cih(true);
  boost::uint64_t checksum = cih.GetChecksum(base::DecodeFromHex(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1234567890ABCDEF"));
  ASSERT_EQ(boost::uint64_t(0xEFCDAB9078563412ll), checksum);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Add) {
  ChunkInfoHandler cih(true);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string chunk_name(SHA512String("chunk"));
  std::string client[kNumClients], creditor;
  int required_references, required_payments, refunds;
  std::list<std::string> references;

  for (int i = 0; i < kNumClients; ++i) {
    client[i] = SHA512String("id" + boost::lexical_cast<std::string>(i));
  }

  ASSERT_EQ(kChunkInfoInvalidName,
            cih.GetActiveReferences(chunk_name, &references));
  ASSERT_TRUE(references.empty());

  ASSERT_EQ(kChunkInfoInvalidSize, cih.PrepareAddToWatchList(
            chunk_name, client[0], 0, &required_references,
            &required_payments));
  ASSERT_FALSE(cih.HasWatchers(chunk_name));

  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[0], 123,
                                         &required_references,
                                         &required_payments));

  ASSERT_FLOAT_EQ(std::ceil(kMinChunkCopies / 2.0), required_references);
  ASSERT_EQ(kMinChunkCopies, required_payments);

  ASSERT_TRUE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_TRUE(cih.chunk_infos_[chunk_name].watch_list.empty());
  ASSERT_TRUE(cih.chunk_infos_[chunk_name].reference_list.empty());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);
  ASSERT_EQ(kChunkInfoNoActiveWatchers,
            cih.GetActiveReferences(chunk_name, &references));
  ASSERT_TRUE(references.empty());

  cih.SetStoringDone(chunk_name, client[0]);
  cih.SetPaymentsDone(chunk_name, client[0]);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[0], &creditor,
                                       &refunds));

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_TRUE(cih.chunk_infos_[chunk_name].waiting_list.empty());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_TRUE(cih.chunk_infos_[chunk_name].reference_list.empty());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);
  ASSERT_EQ(kSuccess, cih.GetActiveReferences(chunk_name, &references));
  ASSERT_TRUE(references.empty());

  ASSERT_EQ(kChunkInfoInvalidSize, cih.PrepareAddToWatchList(
            chunk_name, client[1], 321, &required_references,
            &required_payments));
  ASSERT_EQ(kSuccess, cih.PrepareAddToWatchList(chunk_name, client[1], 123,
                                                &required_references,
                                                &required_payments));

  ASSERT_FLOAT_EQ(std::ceil(.5 * kMinChunkCopies), required_references);
  ASSERT_EQ(1, required_payments);

  cih.SetPaymentsDone(chunk_name, client[1]);
  ASSERT_FALSE(cih.TryCommitToWatchList(chunk_name, client[1], &creditor,
                                        &refunds));

  ASSERT_EQ(kChunkInfoInvalidName, cih.AddToReferenceList("some chunk", "ref",
                                                          123));
  ASSERT_EQ(kChunkInfoInvalidSize, cih.AddToReferenceList(chunk_name, "ref",
                                                          321));

  cih.SetStoringDone(chunk_name, client[1]);
  ASSERT_EQ(0, cih.ActiveReferences(chunk_name));
  for (int i = 0; i < required_references; ++i) {
    ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf" + base::IntToString(i),
                                        123));
  }
  ASSERT_EQ(required_references, cih.ActiveReferences(chunk_name));

  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[1], &creditor,
                                       &refunds));

  ASSERT_EQ(client[0], creditor);
  ASSERT_EQ(0, refunds);

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_TRUE(cih.chunk_infos_[chunk_name].waiting_list.empty());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(required_references),
            cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);

  if (required_references > 0)
    ASSERT_EQ(kChunkInfoRefExists,
              cih.AddToReferenceList(chunk_name, "rf0", 123));
  ASSERT_EQ(size_t(required_references),
            cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(kSuccess, cih.GetActiveReferences(chunk_name, &references));
  ASSERT_EQ(size_t(required_references), references.size());

  for (int i = 2; i < kNumClients - 2; ++i) {
    ASSERT_EQ(kSuccess, cih.PrepareAddToWatchList(chunk_name, client[i], 123,
                                                  &required_references,
                                                  &required_payments));
    ASSERT_FLOAT_EQ(std::ceil(.25 * kMinChunkCopies), required_references);
    ASSERT_EQ(1, required_payments);

    cih.SetStoringDone(chunk_name, client[i]);
    cih.SetPaymentsDone(chunk_name, client[i]);

    ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[i], &creditor,
                                         &refunds));

    ASSERT_EQ(0, refunds);
    ASSERT_TRUE(cih.chunk_infos_[chunk_name].waiting_list.empty());

    ASSERT_EQ(size_t(i) + 1, cih.chunk_infos_[chunk_name].watcher_count);
    if (i < kMinChunkCopies) {
      ASSERT_EQ(client[0], creditor);
      ASSERT_EQ(kMinChunkCopies,
                cih.chunk_infos_[chunk_name].watch_list.size());
    } else {
      ASSERT_EQ("", creditor);
      ASSERT_EQ(size_t(i) + 1, cih.chunk_infos_[chunk_name].watch_list.size());
    }
  }

  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[kNumClients - 2],
                                         123, &required_references,
                                         &required_payments));
  ASSERT_EQ(1, required_payments);
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[kNumClients - 1],
                                         123, &required_references,
                                         &required_payments));
  ASSERT_EQ(1, required_payments);

  cih.SetStoringDone(chunk_name, client[kNumClients - 2]);
  cih.SetPaymentsDone(chunk_name, client[kNumClients - 2]);
  cih.SetStoringDone(chunk_name, client[kNumClients - 1]);
  cih.SetPaymentsDone(chunk_name, client[kNumClients - 1]);

  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[kNumClients - 2],
                                       &creditor, &refunds));
  ASSERT_EQ(0, refunds);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[kNumClients - 1],
                                       &creditor, &refunds));
  ASSERT_EQ(1, refunds);

  ASSERT_TRUE(cih.chunk_infos_[chunk_name].waiting_list.empty());
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(kNumClients), cih.chunk_infos_[chunk_name].watcher_count);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Refund) {
  ChunkInfoHandler cih(true);

  std::string chunk_name(SHA512String("chunk"));
  std::string client[2], creditor;
  int required_references, required_payments, refunds;

  client[0] = SHA512String("id0");
  client[1] = SHA512String("id1");

  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[0], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(kMinChunkCopies, required_payments);
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[1], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(kMinChunkCopies, required_payments);

  cih.SetStoringDone(chunk_name, client[0]);
  cih.SetPaymentsDone(chunk_name, client[0]);
  cih.SetStoringDone(chunk_name, client[1]);
  cih.SetPaymentsDone(chunk_name, client[1]);

  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[0], &creditor,
                                       &refunds));
  ASSERT_EQ(0, refunds);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[1], &creditor,
                                       &refunds));
  ASSERT_EQ(kMinChunkCopies - 1, refunds);

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].watcher_count);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Remove) {
  ChunkInfoHandler cih(true);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string chunk_name(SHA512String("chunk"));
  std::string client[kNumClients], creditor;
  std::list<std::string> creditors, references;
  int required_references, required_payments, refunds;
  boost::uint64_t chunk_size;

  for (int i = 0; i < kNumClients; ++i) {
    client[i] = SHA512String("id" + boost::lexical_cast<std::string>(i));
  }

  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[0], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  cih.SetStoringDone(chunk_name, client[0]);
  cih.SetPaymentsDone(chunk_name, client[0]);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[0], &creditor,
                                       &refunds));

  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf0", 123));
  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf1", 123));

  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[1], 123,
                                         &required_references,
                                         &required_payments));

  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count);

  ASSERT_EQ(kSuccess, cih.GetActiveReferences(chunk_name, &references));
  ASSERT_EQ(size_t(2), references.size());
  ASSERT_EQ("rf0", references.front());

  references.clear();
  ASSERT_EQ(kChunkInfoInvalidName, cih.RemoveFromWatchList("fail", client[0],
            &chunk_size, &creditors, &references));

  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[0], &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_TRUE(creditors.empty());
  ASSERT_TRUE(references.empty());

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].watcher_count);

  cih.ResetAddToWatchList(chunk_name, client[1], kReasonPaymentFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(kMinChunkCopies), creditors.size());
  ASSERT_EQ(size_t(2), references.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));

  for (int i = 0; i < kNumClients; ++i) {
    ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[i], 123,
                                           &required_references,
                                           &required_payments));
    if (required_references > 0)
      cih.SetStoringDone(chunk_name, client[i]);
    if (required_payments > 0)
      cih.SetPaymentsDone(chunk_name, client[i]);
    ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[i], &creditor,
                                         &refunds));
  }

  ASSERT_EQ(size_t(kNumClients), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watch_list.size());

  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf0", 123));
  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf1", 123));

  creditors.clear();
  references.clear();
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[0], &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(1), creditors.size());
  ASSERT_EQ(client[0], creditors.front());
  ASSERT_TRUE(references.empty());
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(kNumClients) - 2,
            cih.chunk_infos_[chunk_name].watch_list.size());

  for (int i = kNumClients - 1; i >= 2; --i) {
    creditors.clear();
    ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[i], &chunk_size,
                                         &creditors, &references));
    ASSERT_EQ(123, chunk_size);
    ASSERT_TRUE(references.empty());
    if (i > kMinChunkCopies) {
      if (i == kNumClients - 1) {
        ASSERT_EQ(size_t(i) - 1,
                  cih.chunk_infos_[chunk_name].watcher_count);
        ASSERT_TRUE(creditors.empty());
      } else {
        ASSERT_EQ(size_t(i), cih.chunk_infos_[chunk_name].watcher_count);
        ASSERT_EQ(size_t(1), creditors.size());
        ASSERT_EQ(client[i], creditors.front());
      }
      ASSERT_EQ(size_t(i) - 1,
          cih.chunk_infos_[chunk_name].watch_list.size());
    } else {
      ASSERT_TRUE(creditors.empty());
      ASSERT_EQ(kMinChunkCopies,
                cih.chunk_infos_[chunk_name].watch_list.size());
      ASSERT_EQ(size_t(i), cih.chunk_infos_[chunk_name].watcher_count);
    }
  }

  ASSERT_EQ(kChunkInfoInvalidName, cih.RemoveFromReferenceList("fail", "rf1",
                                                               &chunk_size));
  ASSERT_EQ(kChunkInfoCannotDelete, cih.RemoveFromReferenceList(chunk_name,
                                                                "fail",
                                                                &chunk_size));
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(0, cih.RemoveFromReferenceList(chunk_name, "rf1", &chunk_size));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(kSuccess, cih.GetActiveReferences(chunk_name, &references));
  ASSERT_EQ(size_t(1), references.size());
  ASSERT_EQ("rf0", references.front());

  ASSERT_EQ(kChunkInfoCannotDelete, cih.RemoveFromReferenceList(chunk_name,
                                                                "rf0",
                                                                &chunk_size));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(1, cih.ActiveReferences(chunk_name));

  references.clear();
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[1], &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(kMinChunkCopies, creditors.size());
  ASSERT_EQ(size_t(1), references.size());
  ASSERT_EQ("rf0", references.front());
  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));

  ASSERT_FALSE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(0, cih.ActiveReferences(chunk_name));
  references.clear();
  ASSERT_EQ(kChunkInfoInvalidName,
            cih.GetActiveReferences(chunk_name, &references));
  ASSERT_TRUE(references.empty());
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Reset) {
  ChunkInfoHandler cih(true);

  std::string chunk_name(SHA512String("chunk"));
  std::string client[3];
  std::list<std::string> creditors, references;
  int required_references, required_payments;

  client[0] = SHA512String("id0");
  client[1] = SHA512String("id1");
  client[2] = SHA512String("id2");

  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[0], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[1], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[2], 123,
                                         &required_references,
                                         &required_payments));
  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(3), cih.chunk_infos_[chunk_name].waiting_list.size());

  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "ref", 123));
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].reference_list.size());

  ASSERT_TRUE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(1, cih.ActiveReferences(chunk_name));

  cih.SetPaymentsDone(chunk_name, client[0]);

  cih.ResetAddToWatchList(chunk_name, "fail", kReasonPaymentFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(3), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

  cih.ResetAddToWatchList(chunk_name, client[0], kReasonPaymentFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(3), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

  cih.ResetAddToWatchList(chunk_name, client[0], kReasonStoringFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

  cih.SetStoringDone(chunk_name, client[0]);
  cih.SetStoringDone(chunk_name, client[1]);
  cih.ResetAddToWatchList(chunk_name, client[1], kReasonStoringFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

  cih.ResetAddToWatchList(chunk_name, client[1], kReasonPaymentFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

  cih.ResetAddToWatchList(chunk_name, client[2], kReasonPaymentFailed,
                          &creditors, &references);
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(1), references.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ("ref", references.front());

  ASSERT_FALSE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(0, cih.ActiveReferences(chunk_name));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Failsafe) {
  ChunkInfoHandler cih(true);

  std::string chunk_name(SHA512String("chunk"));
  std::string client1(SHA512String("client1"));
  std::string client2(SHA512String("client2"));

  ASSERT_FALSE(cih.HasWatchers(chunk_name));

  std::string creditor;
  std::list<std::string> creditors, references;
  int required_references, required_payments, refunds;
  boost::uint64_t chunk_size;

  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client1, 123,
                                         &required_references,
                                         &required_payments));
  cih.SetStoringDone(chunk_name, client1);
  cih.SetPaymentsDone(chunk_name, client1);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client1, &creditor,
                                       &refunds));
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client2, &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client1, &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());

  ASSERT_TRUE(cih.HasWatchers(chunk_name));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_Pruning) {
  ChunkInfoHandler cih(true);

  std::string chunk_name(SHA512String("chunk"));
  std::string client(SHA512String("client"));
  std::list< std::pair<std::string, std::string> > entries;
  int required_references, required_payments;

  cih.GetStaleWaitingListEntries(&entries);
  ASSERT_EQ(size_t(0), entries.size());
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client, 123,
                                         &required_references,
                                         &required_payments));
  cih.GetStaleWaitingListEntries(&entries);
  ASSERT_EQ(size_t(0), entries.size());
  cih.chunk_infos_[chunk_name].waiting_list.front().creation_time -=
      (kChunkInfoWatcherPendingTimeout + 1);
  cih.GetStaleWaitingListEntries(&entries);
  ASSERT_EQ(size_t(1), entries.size());
  ASSERT_EQ(chunk_name, entries.front().first);
  ASSERT_EQ(client, entries.front().second);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_PutGetPb) {
  ChunkInfoHandler chunk_info_handler1(true), chunk_info_handler2(true);
  std::pair<std::map<std::string, ChunkInfo>::iterator, bool> result;
  const int kNumEntries(749);
  for (int i = 0; i < kNumEntries; ++i) {
    ChunkInfo chunk_info;
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      WaitingListEntry waiting_list_entry;
      waiting_list_entry.pmid = base::RandomAlphaNumericString(64);
      waiting_list_entry.creation_time = base::RandomUint32();
      waiting_list_entry.storing_done = waiting_list_entry.creation_time % 2;
      waiting_list_entry.payments_done = waiting_list_entry.creation_time % 3;
      waiting_list_entry.requested_payments = base::RandomInt32();
      chunk_info.waiting_list.push_back(waiting_list_entry);
    }
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      WatchListEntry watch_list_entry;
      watch_list_entry.pmid = base::RandomAlphaNumericString(64);
      watch_list_entry.can_delete =
          watch_list_entry.pmid.at(0) < watch_list_entry.pmid.at(1);
      chunk_info.watch_list.push_back(watch_list_entry);
    }
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      ReferenceListEntry reference_list_entry;
      reference_list_entry.pmid = base::RandomAlphaNumericString(64);
      reference_list_entry.last_seen = base::RandomUint32();
      chunk_info.reference_list.push_back(reference_list_entry);
    }
    chunk_info.watcher_count = base::RandomUint32();
    chunk_info.watcher_checksum = base::RandomUint32();
    chunk_info.chunk_size = base::RandomUint32();
    result = chunk_info_handler1.chunk_infos_.insert(
        std::pair<std::string, ChunkInfo>(base::RandomAlphaNumericString(64),
                                          chunk_info));
    ASSERT_TRUE(result.second);
  }
  ChunkInfoMap chunk_info_map = chunk_info_handler1.PutMapToPb();
  std::string serialised_chunk_info_map1;
  ASSERT_TRUE(chunk_info_map.SerializeToString(&serialised_chunk_info_map1));
  chunk_info_map.Clear();
  ASSERT_TRUE(chunk_info_map.ParseFromString(serialised_chunk_info_map1));
  chunk_info_handler2.GetMapFromPb(chunk_info_map);
  ASSERT_EQ(chunk_info_handler1.chunk_infos_.size(),
            chunk_info_handler2.chunk_infos_.size());
  std::map<std::string, ChunkInfo>::iterator it1 =
      chunk_info_handler1.chunk_infos_.begin();
  std::map<std::string, ChunkInfo>::iterator it2 =
      chunk_info_handler2.chunk_infos_.begin();
  for (; it1 != chunk_info_handler1.chunk_infos_.end(); ++it1, ++it2) {
    std::string chunk_name1((*it1).first), chunk_name2((*it2).first);
    ASSERT_EQ(chunk_name1, chunk_name2);
    ChunkInfo chunk_info1((*it1).second), chunk_info2((*it2).second);
    ASSERT_EQ(chunk_info1.waiting_list.size(), chunk_info2.waiting_list.size());
    std::list<WaitingListEntry>::iterator waiting_list_it1 =
        chunk_info1.waiting_list.begin();
    std::list<WaitingListEntry>::iterator waiting_list_it2 =
        chunk_info2.waiting_list.begin();
    for (; waiting_list_it1 != chunk_info1.waiting_list.end();
        ++waiting_list_it1, ++waiting_list_it2) {
      ASSERT_EQ((*waiting_list_it1).pmid, (*waiting_list_it2).pmid);
      ASSERT_EQ((*waiting_list_it1).creation_time,
                (*waiting_list_it2).creation_time);
      ASSERT_EQ((*waiting_list_it1).storing_done,
                (*waiting_list_it2).storing_done);
      ASSERT_EQ((*waiting_list_it1).payments_done,
                (*waiting_list_it2).payments_done);
      ASSERT_EQ((*waiting_list_it1).requested_payments,
                (*waiting_list_it2).requested_payments);
    }
    std::list<WatchListEntry>::iterator watch_list_it1 =
        chunk_info1.watch_list.begin();
    std::list<WatchListEntry>::iterator watch_list_it2 =
        chunk_info2.watch_list.begin();
    for (; watch_list_it1 != chunk_info1.watch_list.end();
        ++watch_list_it1, ++watch_list_it2) {
      ASSERT_EQ((*watch_list_it1).pmid, (*watch_list_it2).pmid);
      ASSERT_EQ((*watch_list_it1).can_delete, (*watch_list_it2).can_delete);
    }
    std::list<ReferenceListEntry>::iterator reference_list_it1 =
        chunk_info1.reference_list.begin();
    std::list<ReferenceListEntry>::iterator reference_list_it2 =
        chunk_info2.reference_list.begin();
    for (; reference_list_it1 != chunk_info1.reference_list.end();
        ++reference_list_it1, ++reference_list_it2) {
      ASSERT_EQ((*reference_list_it1).pmid, (*reference_list_it2).pmid);
      ASSERT_EQ((*reference_list_it1).last_seen,
                (*reference_list_it2).last_seen);
    }
    ASSERT_EQ(chunk_info1.watcher_count, chunk_info2.watcher_count);
    ASSERT_EQ(chunk_info1.watcher_checksum, chunk_info2.watcher_checksum);
    ASSERT_EQ(chunk_info1.chunk_size, chunk_info2.chunk_size);
  }
  chunk_info_map.Clear();
  chunk_info_map = chunk_info_handler2.PutMapToPb();
  std::string serialised_chunk_info_map2;
  ASSERT_TRUE(chunk_info_map.SerializeToString(&serialised_chunk_info_map2));
  ASSERT_EQ(serialised_chunk_info_map1, serialised_chunk_info_map2);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_PutGetChunkInfo) {
  // Test with chunk info handler not started
  ChunkInfoHandler chunk_info_handler(false);
  ChunkInfoMap::VaultChunkInfo vault_chunk_info_put;
  vault_chunk_info_put.set_chunk_name(base::RandomAlphaNumericString(64));
  ChunkInfoMap::VaultChunkInfo::WaitingListEntry *waiting_list_entry;
  ChunkInfoMap::VaultChunkInfo::WatchListEntry *watch_list_entry;
  ChunkInfoMap::VaultChunkInfo::ReferenceListEntry *reference_list_entry;
  for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
    waiting_list_entry = vault_chunk_info_put.add_waiting_list_entry();
    waiting_list_entry->set_pmid(base::RandomAlphaNumericString(64));
    waiting_list_entry->set_creation_time(base::RandomUint32());
    waiting_list_entry->set_storing_done(
        waiting_list_entry->creation_time() % 2);
    waiting_list_entry->set_payments_done(
        waiting_list_entry->creation_time() % 3);
    waiting_list_entry->set_requested_payments(base::RandomInt32());
  }
  for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
    watch_list_entry = vault_chunk_info_put.add_watch_list_entry();
    watch_list_entry->set_pmid(base::RandomAlphaNumericString(64));
    watch_list_entry->set_can_delete(
        base::RandomUint32() < base::RandomUint32());
  }
  for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
    reference_list_entry = vault_chunk_info_put.add_reference_list_entry();
    reference_list_entry->set_pmid(base::RandomAlphaNumericString(64));
    reference_list_entry->set_last_seen(base::RandomUint32());
  }
  vault_chunk_info_put.set_watcher_count(base::RandomUint32());
  vault_chunk_info_put.set_watcher_checksum(base::RandomUint32());
  vault_chunk_info_put.set_chunk_size(base::RandomUint32());
  ASSERT_EQ(kChunkInfoHandlerNotStarted,
            chunk_info_handler.InsertChunkInfoFromPb(vault_chunk_info_put));

  ChunkInfo dummy_chunk_info;
  dummy_chunk_info.waiting_list.push_back(WaitingListEntry());
  dummy_chunk_info.watch_list.push_back(WatchListEntry());
  dummy_chunk_info.reference_list.push_back(ReferenceListEntry());
  dummy_chunk_info.watcher_count = base::RandomUint32();
  dummy_chunk_info.watcher_checksum = base::RandomUint32();
  dummy_chunk_info.chunk_size = base::RandomUint32();
  ChunkInfo chunk_info = dummy_chunk_info;
  ASSERT_EQ(kChunkInfoHandlerNotStarted, chunk_info_handler.GetChunkInfo(
      vault_chunk_info_put.chunk_name(), &chunk_info));
  ASSERT_TRUE(chunk_info.waiting_list.empty());
  ASSERT_TRUE(chunk_info.watch_list.empty());
  ASSERT_TRUE(chunk_info.reference_list.empty());
  ASSERT_EQ(boost::uint64_t(0), chunk_info.watcher_count);
  ASSERT_EQ(boost::uint64_t(0), chunk_info.watcher_checksum);
  ASSERT_EQ(boost::uint64_t(0), chunk_info.chunk_size);
  chunk_info_handler.set_started(true);
  bool success = chunk_info_handler.chunk_infos_.end() ==
      chunk_info_handler.chunk_infos_.find(vault_chunk_info_put.chunk_name());
  ASSERT_TRUE(success);

  // Try before adding ChunkInfo
  chunk_info = dummy_chunk_info;
  ASSERT_EQ(kChunkInfoInvalidName, chunk_info_handler.GetChunkInfo(
      vault_chunk_info_put.chunk_name(), &chunk_info));
  ASSERT_TRUE(chunk_info.waiting_list.empty());
  ASSERT_TRUE(chunk_info.watch_list.empty());
  ASSERT_TRUE(chunk_info.reference_list.empty());
  ASSERT_EQ(boost::uint64_t(0), chunk_info.watcher_count);
  ASSERT_EQ(boost::uint64_t(0), chunk_info.watcher_checksum);
  ASSERT_EQ(boost::uint64_t(0), chunk_info.chunk_size);

  // Add ChunkInfos
  std::pair<ChunkInfoHandler::CIMap::iterator, bool> result;
  const size_t kNumEntries(583);
  for (size_t i = 0; i < kNumEntries; ++i) {
    chunk_info.waiting_list.clear();
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      WaitingListEntry waiting_list_ent;
      waiting_list_ent.pmid = base::RandomAlphaNumericString(64);
      waiting_list_ent.creation_time = base::RandomUint32();
      waiting_list_ent.storing_done = waiting_list_ent.creation_time % 2;
      waiting_list_ent.payments_done = waiting_list_ent.creation_time % 3;
      waiting_list_ent.requested_payments = base::RandomInt32();
      chunk_info.waiting_list.push_back(waiting_list_ent);
    }
    chunk_info.watch_list.clear();
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      WatchListEntry watch_list_ent;
      watch_list_ent.pmid = base::RandomAlphaNumericString(64);
      watch_list_ent.can_delete =
          watch_list_ent.pmid.at(0) < watch_list_ent.pmid.at(1);
      chunk_info.watch_list.push_back(watch_list_ent);
    }
    chunk_info.reference_list.clear();
    for (boost::uint16_t j = 0; j < (base::RandomUint32() % 16); ++j) {
      ReferenceListEntry reference_list_ent;
      reference_list_ent.pmid = base::RandomAlphaNumericString(64);
      reference_list_ent.last_seen = base::RandomUint32();
      chunk_info.reference_list.push_back(reference_list_ent);
    }
    chunk_info.watcher_count = base::RandomUint32();
    chunk_info.watcher_checksum = base::RandomUint32();
    chunk_info.chunk_size = base::RandomUint32();
    result = chunk_info_handler.chunk_infos_.insert(
        std::pair<std::string, ChunkInfo>(base::RandomAlphaNumericString(64),
                                          chunk_info));
    ASSERT_TRUE(result.second);
  }

  // Insert and retrieve chunk_info
  ASSERT_EQ(kSuccess,
            chunk_info_handler.InsertChunkInfoFromPb(vault_chunk_info_put));
  ASSERT_EQ(kNumEntries + 1, chunk_info_handler.chunk_infos_.size());
  success = chunk_info_handler.chunk_infos_.end() !=
      chunk_info_handler.chunk_infos_.find(vault_chunk_info_put.chunk_name());
  ASSERT_TRUE(success);
  chunk_info = dummy_chunk_info;
  ASSERT_EQ(kSuccess, chunk_info_handler.GetChunkInfo(
      vault_chunk_info_put.chunk_name(), &chunk_info));
  ASSERT_EQ(static_cast<size_t>(vault_chunk_info_put.waiting_list_entry_size()),
            chunk_info.waiting_list.size());
  std::list<WaitingListEntry>::iterator wait_it =
      chunk_info.waiting_list.begin();
  for (int i = 0; wait_it != chunk_info.waiting_list.end(); ++wait_it, ++i) {
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).pmid(), wait_it->pmid);
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).creation_time(),
              wait_it->creation_time);
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).storing_done(),
              wait_it->storing_done);
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).payments_done(),
              wait_it->payments_done);
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).requested_payments(),
              wait_it->requested_payments);
  }
  ASSERT_EQ(static_cast<size_t>(vault_chunk_info_put.watch_list_entry_size()),
            chunk_info.watch_list.size());
  std::list<WatchListEntry>::iterator watch_it = chunk_info.watch_list.begin();
  for (int i = 0; watch_it != chunk_info.watch_list.end(); ++watch_it, ++i) {
    ASSERT_EQ(vault_chunk_info_put.watch_list_entry(i).pmid(), watch_it->pmid);
    ASSERT_EQ(vault_chunk_info_put.watch_list_entry(i).can_delete(),
              watch_it->can_delete);
  }
  ASSERT_EQ(
      static_cast<size_t>(vault_chunk_info_put.reference_list_entry_size()),
      chunk_info.reference_list.size());
  std::list<ReferenceListEntry>::iterator ref_it =
      chunk_info.reference_list.begin();
  for (int i = 0; ref_it != chunk_info.reference_list.end(); ++ref_it, ++i) {
    ASSERT_EQ(vault_chunk_info_put.reference_list_entry(i).pmid(),
              ref_it->pmid);
    ASSERT_EQ(vault_chunk_info_put.reference_list_entry(i).last_seen(),
              ref_it->last_seen);
  }
  ASSERT_EQ(vault_chunk_info_put.watcher_count(), chunk_info.watcher_count);
  ASSERT_EQ(vault_chunk_info_put.watcher_checksum(),
            chunk_info.watcher_checksum);
  ASSERT_EQ(vault_chunk_info_put.chunk_size(), chunk_info.chunk_size);

  // Convert chunk_info to protocol buffer
  ChunkInfoMap::VaultChunkInfo vault_chunk_info_get;
  chunk_info.PutToPb(vault_chunk_info_put.chunk_name(), &vault_chunk_info_get);
  ASSERT_EQ(vault_chunk_info_put.chunk_name(),
            vault_chunk_info_get.chunk_name());
  ASSERT_EQ(vault_chunk_info_put.waiting_list_entry_size(),
            vault_chunk_info_get.waiting_list_entry_size());
  for (int i = 0; i < vault_chunk_info_put.waiting_list_entry_size(); ++i) {
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).pmid(),
              vault_chunk_info_get.waiting_list_entry(i).pmid());
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).creation_time(),
              vault_chunk_info_get.waiting_list_entry(i).creation_time());
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).storing_done(),
              vault_chunk_info_get.waiting_list_entry(i).storing_done());
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).payments_done(),
              vault_chunk_info_get.waiting_list_entry(i).payments_done());
    ASSERT_EQ(vault_chunk_info_put.waiting_list_entry(i).requested_payments(),
              vault_chunk_info_get.waiting_list_entry(i).requested_payments());
  }
  ASSERT_EQ(vault_chunk_info_put.watch_list_entry_size(),
            vault_chunk_info_get.watch_list_entry_size());
  for (int i = 0; i < vault_chunk_info_put.watch_list_entry_size(); ++i) {
    ASSERT_EQ(vault_chunk_info_put.watch_list_entry(i).pmid(),
              vault_chunk_info_get.watch_list_entry(i).pmid());
    ASSERT_EQ(vault_chunk_info_put.watch_list_entry(i).can_delete(),
              vault_chunk_info_get.watch_list_entry(i).can_delete());
  }
  ASSERT_EQ(vault_chunk_info_put.reference_list_entry_size(),
            vault_chunk_info_get.reference_list_entry_size());
  for (int i = 0; i < vault_chunk_info_put.reference_list_entry_size(); ++i) {
    ASSERT_EQ(vault_chunk_info_put.reference_list_entry(i).pmid(),
              vault_chunk_info_get.reference_list_entry(i).pmid());
    ASSERT_EQ(vault_chunk_info_put.reference_list_entry(i).last_seen(),
              vault_chunk_info_get.reference_list_entry(i).last_seen());
  }
  ASSERT_EQ(vault_chunk_info_put.watcher_count(),
            vault_chunk_info_get.watcher_count());
  ASSERT_EQ(vault_chunk_info_put.watcher_checksum(),
            vault_chunk_info_get.watcher_checksum());
  ASSERT_EQ(vault_chunk_info_put.chunk_size(),
            vault_chunk_info_get.chunk_size());

  // Check chunk_info can't be added again
  ASSERT_EQ(kChunkInfoExists,
            chunk_info_handler.InsertChunkInfoFromPb(vault_chunk_info_put));
  ASSERT_EQ(kNumEntries + 1, chunk_info_handler.chunk_infos_.size());
}

}  // namespace test

}  // namespace vault

}  // namespace maidsafe
