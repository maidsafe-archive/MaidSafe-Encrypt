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

#include "maidsafe/vault/infosynchroniser.h"

#include <maidsafe/base/routingtable.h>

#include <algorithm>
#include <list>

#include "maidsafe/kadops.h"
#include "maidsafe/maidsafe.h"

namespace maidsafe_vault {

bool InfoSynchroniser::ShouldFetch(const std::string &id,
                                   std::vector<kad::Contact> *closest_nodes) {
  if (closest_nodes == NULL)
    return false;
  else
    closest_nodes->clear();
  if (id == pmid_) {
#ifdef DEBUG
    printf("In InfoSynchroniser::ShouldFetch: this is our own PMID.\n");
#endif
    return false;
  }
  {
    boost::uint32_t expiry_time(base::GetEpochTime() + kInfoEntryLifespan);
    boost::mutex::scoped_lock lock(mutex_);
    InfoEntryMap::iterator it = info_entries_.lower_bound(id);
    // If the entry already exists, we either shouldn't hold the info, or we've
    // already tried to fetch it.  If it doesn't exist, add it.
    if (it != info_entries_.end() &&
        !(info_entries_.key_comp()(id, it->first))) {
      it->second = expiry_time;
#ifdef DEBUG
      printf("In InfoSynchroniser::ShouldFetch: Entry already exists (either "
             "we shouldn't hold this account or we're already fetching it).\n");
#endif
      return false;
    } else {
      info_entries_.insert(it, InfoEntryMap::value_type(id, expiry_time));
    }
  }

  // Assess if we should hold the info.
  std::list<base::PublicRoutingTableTuple> nodes;
  if (routing_table_->GetClosestContacts(id, K_, &nodes) != kSuccess) {
#ifdef DEBUG
    printf("In InfoSynchroniser::AddEntry(%s), failed to query local"
           "routing table.\n", HexSubstr(pmid_).c_str());
#endif
    return false;
  }
  kad::Contact our_contact(pmid_, "", 0);
  std::for_each(nodes.begin(), nodes.end(), boost::bind(
      &InfoSynchroniser::AddNodeToClosest, this, _1, closest_nodes));
  if (maidsafe::ContactWithinClosest(id, our_contact, *closest_nodes)) {
    return true;
  } else {
    closest_nodes->clear();
#ifdef DEBUG
    printf("In InfoSynchroniser::ShouldFetch: Not within closest nodes.\n");
#endif
    return false;
  }
}

void InfoSynchroniser::RemoveEntry(const std::string &id) {
  boost::mutex::scoped_lock lock(mutex_);
  info_entries_.erase(id);
}

void InfoSynchroniser::PruneMap() {
  boost::uint32_t current_time(base::GetEpochTime());
  boost::mutex::scoped_lock lock(mutex_);
  InfoEntryMap::iterator it = info_entries_.begin();
  while (it != info_entries_.end()) {
  if (it->second < current_time)
    info_entries_.erase(it++);
  else
    ++it;
  }
}

void InfoSynchroniser::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  info_entries_.clear();
}

void InfoSynchroniser::AddNodeToClosest(
    const base::PublicRoutingTableTuple &node,
    std::vector<kad::Contact> *closest) {
  closest->push_back(kad::Contact(node.kademlia_id, node.host_ip,
                                  node.host_port, node.host_ip, node.host_port,
                                  node.rendezvous_ip, node.rendezvous_port));
}

}  // namespace maidsafe_vault
