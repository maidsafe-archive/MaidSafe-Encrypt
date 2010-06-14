/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for InfoSynchroniser class.
* Version:      1.0
* Created:      2010-03-31-04.22
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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
#include "maidsafe/kadops.h"
#include "maidsafe/vault/infosynchroniser.h"

namespace maidsafe_vault {

namespace test_info_sync {
static const boost::uint8_t K(4);
}  // namespace test_info_sync

class InfoSynchroniserTest : public testing::Test {
 public:
  InfoSynchroniserTest()
      : co_(),
        pmid_(co_.Hash(base::RandomString(100), "",
                       crypto::STRING_STRING, false)),
        kMinRoutingTableSize_(100),
        routing_table_(new base::PublicRoutingTableHandler()),
        info_synchroniser_(pmid_, routing_table_, test_info_sync::K),
        closest_nodes_() {}
 protected:
  void SetUp() {
    ASSERT_EQ(crypto::SHA_512, co_.hash_algorithm());
    size_t table_size = (base::RandomUint32() % 999) +
                         kMinRoutingTableSize_;
    for (size_t i = 0; i < table_size; ++i) {
      std::string tuple_id = co_.Hash(base::RandomString(100), "",
                                      crypto::STRING_STRING, false);
      base::PublicRoutingTableTuple pdrtt(tuple_id, base::RandomString(13), i,
                                          "", 0, "", 0, 0, 0);
      routing_table_->AddTuple(pdrtt);
    }
    closest_nodes_.push_back(kad::Contact());
  }
  void TearDown() {}
  crypto::Crypto co_;
  std::string pmid_;
  const size_t kMinRoutingTableSize_;
  boost::shared_ptr<base::PublicRoutingTableHandler> routing_table_;
  InfoSynchroniser info_synchroniser_;
  std::vector<kad::Contact> closest_nodes_;
};

TEST_F(InfoSynchroniserTest, BEH_VAULT_InfoSyncShouldFetch) {
  ASSERT_EQ(size_t(0), info_synchroniser_.info_entries_.size());
  std::list<base::PublicRoutingTableTuple> nodes;
  std::string id = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING,
                            false);
  ASSERT_EQ(0, routing_table_->GetClosestContacts(id, 0, &nodes));
  ASSERT_GE(nodes.size(), kMinRoutingTableSize_);
  // Get a key which doesn't include test node's ID in test_info_sync::K closest node
  while (true) {
    ASSERT_EQ(0, routing_table_->GetClosestContacts(id, test_info_sync::K, &nodes));
    ASSERT_EQ(test_info_sync::K, nodes.size());
    kad::Contact this_test_contact(pmid_, "", 0);
    std::vector<kad::Contact> closest_nodes;
    std::for_each(nodes.begin(), nodes.end(), boost::bind(
        &InfoSynchroniser::AddNodeToClosest, &info_synchroniser_, _1,
        &closest_nodes));
    if (!maidsafe::ContactWithinClosest(id, this_test_contact, closest_nodes))
      break;
    else
      id = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING, false);
  }
  ASSERT_FALSE(closest_nodes_.empty());
  ASSERT_FALSE(info_synchroniser_.ShouldFetch(id, &closest_nodes_));
  ASSERT_TRUE(closest_nodes_.empty());
  ASSERT_EQ(size_t(1), info_synchroniser_.info_entries_.size());
  closest_nodes_.push_back(kad::Contact());
  ASSERT_FALSE(closest_nodes_.empty());
  ASSERT_FALSE(info_synchroniser_.ShouldFetch(id, &closest_nodes_));
  ASSERT_TRUE(closest_nodes_.empty());
  ASSERT_EQ(size_t(1), info_synchroniser_.info_entries_.size());

  // Shouldn't try to get our own ID
  closest_nodes_.push_back(kad::Contact());
  ASSERT_FALSE(closest_nodes_.empty());
  ASSERT_FALSE(info_synchroniser_.ShouldFetch(pmid_, &closest_nodes_));
  ASSERT_TRUE(closest_nodes_.empty());
  ASSERT_EQ(size_t(1), info_synchroniser_.info_entries_.size());

  // Should return true once for an ID close to our pmid
  id = pmid_;
  std::string::iterator it = id.end() - 6;
  while (id == pmid_)
    id.replace(it, id.end(),
               boost::lexical_cast<std::string>(base::RandomUint32() % 900000 +
                                                100000));
  closest_nodes_.push_back(kad::Contact());
  ASSERT_FALSE(closest_nodes_.empty());
  ASSERT_TRUE(info_synchroniser_.ShouldFetch(id, &closest_nodes_));
  ASSERT_EQ(test_info_sync::K, closest_nodes_.size());
  ASSERT_EQ(size_t(2), info_synchroniser_.info_entries_.size());
  closest_nodes_.push_back(kad::Contact());
  ASSERT_FALSE(closest_nodes_.empty());
  ASSERT_FALSE(info_synchroniser_.ShouldFetch(id, &closest_nodes_));
  ASSERT_TRUE(closest_nodes_.empty());
  ASSERT_EQ(size_t(2), info_synchroniser_.info_entries_.size());
}

TEST_F(InfoSynchroniserTest, FUNC_VAULT_InfoSyncTimestamps) {
  const size_t kTestMapSize = 100;
  while (info_synchroniser_.info_entries_.size() < kTestMapSize) {
    info_synchroniser_.ShouldFetch(co_.Hash(base::RandomString(100), "",
        crypto::STRING_STRING, false), &closest_nodes_);
  }
  std::string id1 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING,
                             false);
  std::string id2 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING,
                             false);
  while (id1 == id2)
    id2 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING, false);
  info_synchroniser_.ShouldFetch(id1, &closest_nodes_);
  info_synchroniser_.ShouldFetch(id2, &closest_nodes_);
  ASSERT_EQ(kTestMapSize + 2, info_synchroniser_.info_entries_.size());
  InfoSynchroniser::InfoEntryMap::iterator it =
      info_synchroniser_.info_entries_.find(id2);
  bool success(it != info_synchroniser_.info_entries_.end());
  ASSERT_TRUE(success);
  boost::uint32_t id2_insertion_time = it->second;
  it = info_synchroniser_.info_entries_.find(id1);
  boost::uint32_t id1_insertion_time = it->second;
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  ASSERT_EQ(id1_insertion_time, it->second);
  info_synchroniser_.ShouldFetch(id1, &closest_nodes_);
  ASSERT_GT(it->second, id1_insertion_time);
  it = info_synchroniser_.info_entries_.find(id2);
  ASSERT_EQ(id2_insertion_time, it->second);
}

TEST_F(InfoSynchroniserTest, FUNC_VAULT_InfoSyncRemoveEntry) {
  const size_t kTestMapSize = 1000;
  while (info_synchroniser_.info_entries_.size() < kTestMapSize) {
    info_synchroniser_.ShouldFetch(co_.Hash(base::RandomString(100), "",
        crypto::STRING_STRING, false), &closest_nodes_);
  }
  std::string id1 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING,
                             false);
  std::string id2 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING,
                             false);
  while (id1 == id2)
    id2 = co_.Hash(base::RandomString(100), "", crypto::STRING_STRING, false);
  info_synchroniser_.ShouldFetch(id1, &closest_nodes_);
  info_synchroniser_.ShouldFetch(id2, &closest_nodes_);
  ASSERT_EQ(kTestMapSize + 2, info_synchroniser_.info_entries_.size());
  InfoSynchroniser::InfoEntryMap::iterator it =
      info_synchroniser_.info_entries_.find(id1);
  bool success(it != info_synchroniser_.info_entries_.end());
  ASSERT_TRUE(success);
  it = info_synchroniser_.info_entries_.find(id2);
  success = (it != info_synchroniser_.info_entries_.end());
  ASSERT_TRUE(success);
  info_synchroniser_.RemoveEntry(id1);
  ASSERT_EQ(kTestMapSize + 1, info_synchroniser_.info_entries_.size());
  it = info_synchroniser_.info_entries_.find(id1);
  success = (it == info_synchroniser_.info_entries_.end());
  ASSERT_TRUE(success);
  it = info_synchroniser_.info_entries_.find(id2);
  success = (it != info_synchroniser_.info_entries_.end());
  ASSERT_TRUE(success);
}

TEST_F(InfoSynchroniserTest, FUNC_VAULT_InfoSyncPruneMap) {
  const size_t kTestMapSize = 100;
  while (info_synchroniser_.info_entries_.size() < kTestMapSize) {
    info_synchroniser_.ShouldFetch(co_.Hash(base::RandomString(100), "",
        crypto::STRING_STRING, false), &closest_nodes_);
  }
  info_synchroniser_.PruneMap();
  ASSERT_EQ(kTestMapSize, info_synchroniser_.info_entries_.size());
  typedef std::set<std::string> InfoEntrySet;
  InfoEntrySet expired_set, alive_set;
  InfoEntrySet::iterator expired_set_it = expired_set.begin();
  InfoEntrySet::iterator alive_set_it = alive_set.begin();
  InfoSynchroniser::InfoEntryMap::iterator it =
      info_synchroniser_.info_entries_.begin();
  boost::uint32_t expired = base::GetEpochTime() - 1;
  while (it != info_synchroniser_.info_entries_.end()) {
    it->second = expired;
    expired_set_it = expired_set.insert(expired_set_it, it->first);
    ++it;
    alive_set_it = alive_set.insert(alive_set_it, it->first);
    ++it;
  }
  info_synchroniser_.PruneMap();
  ASSERT_EQ(kTestMapSize / 2, info_synchroniser_.info_entries_.size());
  alive_set_it = alive_set.begin();
  while (alive_set_it != alive_set.end()) {
    it = info_synchroniser_.info_entries_.find(*alive_set_it);
    bool success = (it != info_synchroniser_.info_entries_.end());
    ASSERT_TRUE(success);
    ++alive_set_it;
  }
  expired_set_it = expired_set.begin();
  while (expired_set_it != expired_set.end()) {
    it = info_synchroniser_.info_entries_.find(*expired_set_it);
    bool success = (it == info_synchroniser_.info_entries_.end());
    ASSERT_TRUE(success);
    ++expired_set_it;
  }
}

}  // namespace maidsafe_vault
