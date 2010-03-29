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
  ChunkInfoHandler cih(true);
  ASSERT_EQ(size_t(0), cih.chunk_infos_.size());
  ASSERT_FALSE(cih.HasWatchers("some chunk name"));
  ASSERT_EQ(0, cih.ActiveReferences("some chunk name"));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum) {
  ChunkInfoHandler cih(true);
  boost::uint64_t checksum = cih.GetChecksum(base::DecodeFromHex(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1234567890ABCDEF"));
  ASSERT_EQ(boost::uint64_t(0xEFCDAB9078563412ll), checksum);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerAdd) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client[kNumClients], creditor;
  int required_references, required_payments, refunds;

  for (int i = 0; i < kNumClients; ++i) {
    client[i] = co.Hash("id" + boost::lexical_cast<std::string>(i), "",
                        crypto::STRING_STRING, false);
  }

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
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);

  cih.SetStoringDone(chunk_name, client[0]);
  cih.SetPaymentsDone(chunk_name, client[0]);
  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[0], &creditor,
                                       &refunds));

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);

  ASSERT_EQ(kChunkInfoInvalidSize, cih.PrepareAddToWatchList(
            chunk_name, client[1], 321, &required_references,
            &required_payments));
  ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[1], 123,
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
    ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf" + base::itos(i), 123));
  }
  ASSERT_EQ(required_references, cih.ActiveReferences(chunk_name));

  ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[1], &creditor,
                                       &refunds));

  ASSERT_EQ(client[0], creditor);
  ASSERT_EQ(0, refunds);

  ASSERT_EQ(size_t(1), cih.chunk_infos_.count(chunk_name));
  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(kMinChunkCopies, cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(required_references),
            cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(size_t(2), cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(123), cih.chunk_infos_[chunk_name].chunk_size);

  ASSERT_EQ(0, cih.AddToReferenceList(chunk_name, "rf0", 123));
  ASSERT_EQ(size_t(required_references),
            cih.chunk_infos_[chunk_name].reference_list.size());

  for (int i = 2; i < kNumClients - 2; ++i) {
    ASSERT_EQ(0, cih.PrepareAddToWatchList(chunk_name, client[i], 123,
                                           &required_references,
                                           &required_payments));
    ASSERT_FLOAT_EQ(std::ceil(.25 * kMinChunkCopies), required_references);
    ASSERT_EQ(1, required_payments);

    cih.SetStoringDone(chunk_name, client[i]);
    cih.SetPaymentsDone(chunk_name, client[i]);

    ASSERT_TRUE(cih.TryCommitToWatchList(chunk_name, client[i], &creditor,
                                         &refunds));

    ASSERT_EQ(0, refunds);
    ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].waiting_list.size());

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

  ASSERT_EQ(size_t(0), cih.chunk_infos_[chunk_name].waiting_list.size());
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watch_list.size());
  ASSERT_EQ(size_t(kNumClients), cih.chunk_infos_[chunk_name].watcher_count);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRefund) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client[2], creditor;
  int required_references, required_payments, refunds;

  client[0] = co.Hash("id0", "", crypto::STRING_STRING, false);
  client[1] = co.Hash("id1", "", crypto::STRING_STRING, false);

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

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerRemove) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  const int kNumClients = kMinChunkCopies + kMaxReserveWatchListEntries + 1;
  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client[kNumClients], creditor;
  std::list<std::string> creditors, references;
  int required_references, required_payments, refunds, chunk_size;

  for (int i = 0; i < kNumClients; ++i) {
    client[i] = co.Hash("id" + boost::lexical_cast<std::string>(i), "",
                        crypto::STRING_STRING, false);
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

  ASSERT_EQ(kChunkInfoInvalidName, cih.RemoveFromWatchList("fail", client[0],
            &chunk_size, &creditors, &references));

  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[0], &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(0), creditors.size());
  ASSERT_EQ(size_t(0), references.size());

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
  ASSERT_EQ(size_t(0), references.size());
  ASSERT_EQ(size_t(kNumClients) - 1,
            cih.chunk_infos_[chunk_name].watcher_count);
  ASSERT_EQ(size_t(kNumClients) - 2,
            cih.chunk_infos_[chunk_name].watch_list.size());

  for (int i = kNumClients - 1; i >= 2; --i) {
    creditors.clear();
    ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[i], &chunk_size,
                                         &creditors, &references));
    ASSERT_EQ(123, chunk_size);
    ASSERT_EQ(size_t(0), references.size());
    if (i > kMinChunkCopies) {
      if (i == kNumClients - 1) {
        ASSERT_EQ(size_t(i) - 1,
                  cih.chunk_infos_[chunk_name].watcher_count);
        ASSERT_EQ(size_t(0), creditors.size());
      } else {
        ASSERT_EQ(size_t(i), cih.chunk_infos_[chunk_name].watcher_count);
        ASSERT_EQ(size_t(1), creditors.size());
        ASSERT_EQ(client[i], creditors.front());
      }
      ASSERT_EQ(size_t(i) - 1,
          cih.chunk_infos_[chunk_name].watch_list.size());
    } else {
      ASSERT_EQ(size_t(0), creditors.size());
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
  ASSERT_EQ(kChunkInfoCannotDelete, cih.RemoveFromReferenceList(chunk_name,
                                                                "rf0",
                                                                &chunk_size));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(size_t(1), cih.chunk_infos_[chunk_name].reference_list.size());
  ASSERT_EQ(1, cih.ActiveReferences(chunk_name));

  ASSERT_EQ(0, cih.RemoveFromWatchList(chunk_name, client[1], &chunk_size,
                                       &creditors, &references));
  ASSERT_EQ(123, chunk_size);
  ASSERT_EQ(kMinChunkCopies, creditors.size());
  ASSERT_EQ(size_t(1), references.size());
  ASSERT_EQ("rf0", references.front());
  ASSERT_EQ(size_t(0), cih.chunk_infos_.count(chunk_name));

  ASSERT_FALSE(cih.HasWatchers(chunk_name));
  ASSERT_EQ(0, cih.ActiveReferences(chunk_name));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerReset) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client[3];
  std::list<std::string> creditors, references;
  int required_references, required_payments;

  client[0] = co.Hash("id0", "", crypto::STRING_STRING, false);
  client[1] = co.Hash("id1", "", crypto::STRING_STRING, false);
  client[2] = co.Hash("id2", "", crypto::STRING_STRING, false);

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

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerFailsafe) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client1(co.Hash("client1", "", crypto::STRING_STRING, false));
  std::string client2(co.Hash("client2", "", crypto::STRING_STRING, false));

  ASSERT_FALSE(cih.HasWatchers(chunk_name));

  std::string creditor;
  std::list<std::string> creditors, references;
  int required_references, required_payments, refunds, chunk_size;

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

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerPruning) {
  ChunkInfoHandler cih(true);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_name(co.Hash("chunk", "", crypto::STRING_STRING, false));
  std::string client(co.Hash("client", "", crypto::STRING_STRING, false));
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

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerPutGetPb) {
  ChunkInfoHandler chunk_info_handler1(true), chunk_info_handler2(true);
  std::pair<std::map<std::string, ChunkInfo>::iterator, bool> result;
  const int kNumEntries(749);
  for (int i = 0; i < kNumEntries; ++i) {
    ChunkInfo chunk_info;
    for (boost::uint16_t j = 0; j < (base::random_32bit_uinteger() % 16); ++j) {
      WaitingListEntry waiting_list_entry;
      waiting_list_entry.pmid = base::RandomString(128);
      waiting_list_entry.creation_time = base::random_32bit_uinteger();
      waiting_list_entry.storing_done = waiting_list_entry.creation_time % 2;
      waiting_list_entry.payments_done = waiting_list_entry.creation_time % 3;
      waiting_list_entry.requested_payments = base::random_32bit_integer();
      chunk_info.waiting_list.push_back(waiting_list_entry);
    }
    for (boost::uint16_t j = 0; j < (base::random_32bit_uinteger() % 16); ++j) {
      WatchListEntry watch_list_entry;
      watch_list_entry.pmid = base::RandomString(128);
      watch_list_entry.can_delete =
          watch_list_entry.pmid.at(0) < watch_list_entry.pmid.at(1);
      chunk_info.watch_list.push_back(watch_list_entry);
    }
    for (boost::uint16_t j = 0; j < (base::random_32bit_uinteger() % 16); ++j) {
      ReferenceListEntry reference_list_entry;
      reference_list_entry.pmid = base::RandomString(128);
      reference_list_entry.last_seen = base::random_32bit_uinteger();
      chunk_info.reference_list.push_back(reference_list_entry);
    }
    chunk_info.watcher_count = base::random_32bit_uinteger();
    chunk_info.watcher_checksum = base::random_32bit_uinteger();
    chunk_info.chunk_size = base::random_32bit_uinteger();
    result = chunk_info_handler1.chunk_infos_.insert(
        std::pair<std::string, ChunkInfo>(base::RandomString(128), chunk_info));
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

}  // namespace maidsafe_vault
