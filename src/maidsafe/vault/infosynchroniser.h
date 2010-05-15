/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for holding set of account IDs or ChunkInfo IDs which
*               should potentially be held by this peer.
* Version:      1.0
* Created:      2010-03-30-09.09.10
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

#ifndef MAIDSAFE_VAULT_INFOSYNCHRONISER_H_
#define MAIDSAFE_VAULT_INFOSYNCHRONISER_H_

#include <gtest/gtest_prod.h>
#include <maidsafe/kademlia/contact.h>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include <map>
#include <string>
#include <vector>

namespace base {
class PublicRoutingTableHandler;
struct PublicRoutingTableTuple;
}  // namespace base

namespace maidsafe_vault {

const boost::uint16_t kInfoEntryLifespan = 120;  // seconds

class InfoSynchroniser {
 public:
  typedef std::map<std::string, boost::uint32_t> InfoEntryMap;
  InfoSynchroniser(const std::string &pmid,
                   boost::shared_ptr<base::PublicRoutingTableHandler> rt)
      : pmid_(pmid), routing_table_(rt), info_entries_(), mutex_() {}
  bool ShouldFetch(const std::string &id,
                   std::vector<kad::Contact> *closest_nodes);
  void RemoveEntry(const std::string &id);
  void PruneMap();
 private:
  InfoSynchroniser(const InfoSynchroniser&);
  InfoSynchroniser& operator=(const InfoSynchroniser&);
  FRIEND_TEST(InfoSynchroniserTest, BEH_VAULT_InfoSyncShouldFetch);
  FRIEND_TEST(InfoSynchroniserTest, FUNC_VAULT_InfoSyncTimestamps);
  FRIEND_TEST(InfoSynchroniserTest, FUNC_VAULT_InfoSyncRemoveEntry);
  FRIEND_TEST(InfoSynchroniserTest, FUNC_VAULT_InfoSyncPruneMap);
  void AddNodeToClosest(const base::PublicRoutingTableTuple &node,
                        std::vector<kad::Contact> *closest);
  std::string pmid_;
  boost::shared_ptr<base::PublicRoutingTableHandler> routing_table_;
  InfoEntryMap info_entries_;
  boost::mutex mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_INFOSYNCHRONISER_H_
