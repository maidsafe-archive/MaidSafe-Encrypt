/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class for manipulating pending store requests
* Version:      1.0
* Created:      30/07/2009 18:17:35 PM
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

#include "maidsafe/vault/pendingstores.h"

namespace maidsafe_vault {

int PendingStoreHandler::AddPendingStore(const std::string &pmid,
                                         const std::string &chunkname,
                                         const boost::uint64_t &chunk_size) {
  multi_index_mutex_.lock();
  if (pmid == "" || chunkname == "" || chunk_size == 0) {
#ifdef DEBUG
    printf("Parameters passed invalid (%s) -- (%s)  -- (%llu)\n", pmid.c_str(),
            chunkname.c_str(), chunk_size);
#endif
    multi_index_mutex_.unlock();
    return -2700;
  }

  PendingStoreRow psr(pmid, chunkname, chunk_size);
  pending_stores_.insert(psr);
  multi_index_mutex_.unlock();
  return 0;
}

int PendingStoreHandler::DeletePendingStore(const std::string &pmid,
                                            const std::string &chunkname) {
  multi_index_mutex_.lock();
  pending_store_set::iterator it =
      pending_stores_.get<pending_store_pmid_chunkname>().find(
      boost::make_tuple(pmid, chunkname));
  if (it == pending_stores_.end()) {
#ifdef DEBUG
    printf("PendingStore not found (%s) -- (%s)\n", pmid.c_str(),
            chunkname.c_str());
#endif
    multi_index_mutex_.unlock();
    return -2701;
  }
  pending_stores_.erase(it);
  multi_index_mutex_.unlock();
  return 0;
}

int PendingStoreHandler::AddContactsToPendingStore(const std::string &pmid,
    const std::string &chunkname,
    const std::vector<kad::ContactInfo> &contacts) {
  multi_index_mutex_.lock();
  pending_store_set::iterator it =
      pending_stores_.get<pending_store_pmid_chunkname>().find(
      boost::make_tuple(pmid, chunkname));
  if (it == pending_stores_.end()) {
#ifdef DEBUG
    printf("PendingStore not found (%s) -- (%s)\n", pmid.c_str(),
            chunkname.c_str());
#endif
    multi_index_mutex_.unlock();
    return -2702;
  }
  PendingStoreRow psr = *it;
  psr.contacts_ = contacts;
  pending_stores_.replace(it, psr);
  multi_index_mutex_.unlock();
  return 0;
}

boost::uint64_t PendingStoreHandler::QueuedSpace() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  typedef pending_store_set::index<pending_store_timestamp>::type
          private_share_set_timestamp;
  private_share_set_timestamp& pending_store_index =
      pending_stores_.get<pending_store_timestamp>();
  boost::uint64_t setTotal(0);
  for (private_share_set_timestamp::iterator it = pending_store_index.begin();
       it != pending_store_index.end(); it++)
    setTotal += (*it).chunk_size_;

  return setTotal;
}

int PendingStoreHandler::NextPendingStore(int phase, PendingStoreRow *psr) {
  multi_index_mutex_.lock();
  typedef pending_store_set::index<pending_store_phase>::type
          private_share_set_phase;
  private_share_set_phase& pending_store_index = pending_stores_.get<
                                                 pending_store_phase>();
  private_share_set_phase::iterator it = pending_store_index.find(phase);
  if (it == pending_store_index.end()) {
#ifdef DEBUG
    printf("No elements in phase %d\n", phase);
#endif
    multi_index_mutex_.unlock();
    return -2703;
  }

  *psr = *it;
  pending_store_index.erase(it);
  multi_index_mutex_.unlock();

  return 0;
}

int PendingStoreHandler::UpdatePendingStorePhase(const std::string &pmid,
                                                 const std::string &chunkname,
                                                 const int &phase) {
  multi_index_mutex_.lock();
  pending_store_set::iterator it =
      pending_stores_.get<pending_store_pmid_chunkname>().find(
      boost::make_tuple(pmid, chunkname));
  if (it == pending_stores_.end()) {
#ifdef DEBUG
    printf("PendingStore not found (%s) -- (%s)\n", pmid.c_str(),
            chunkname.c_str());
#endif
    multi_index_mutex_.unlock();
    return -2704;
  }
  PendingStoreRow psr = *it;
  psr.phase_ = phase;
  pending_stores_.replace(it, psr);
  multi_index_mutex_.unlock();
  return 0;
}

void PendingStoreHandler::ClearPendingStores() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  pending_stores_.clear();
}

int PendingStoreHandler::PendingStoresCount() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  return pending_stores_.size();
}

}  // namespace maidsafe_vault
