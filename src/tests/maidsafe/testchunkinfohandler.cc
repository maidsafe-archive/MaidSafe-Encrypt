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
  ChunkInfoHandler cih;
  ASSERT_EQ(size_t(0), cih.chunk_infos_.size());
  ASSERT_FALSE(cih.HasWatchers("some chunk name"));
  ASSERT_EQ(size_t(0), cih.ActiveReferences("some chunk name"));
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerChecksum) {
  ChunkInfoHandler cih;
  boost::uint64_t checksum = cih.GetChecksum(base::DecodeFromHex(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1234567890ABCDEF"));
  ASSERT_EQ(boost::uint64_t(0xEFCDAB9078563412ll), checksum);
}

TEST_F(ChunkInfoHandlerTest, BEH_VAULT_ChunkInfoHandlerAdd) {
  ChunkInfoHandler cih;
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
  ChunkInfoHandler cih;
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
  ChunkInfoHandler cih;
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
  ChunkInfoHandler cih;
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
  ChunkInfoHandler cih;
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
  ChunkInfoHandler cih;
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

}  // namespace maidsafe_vault
