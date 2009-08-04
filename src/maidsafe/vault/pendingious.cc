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

#include "maidsafe/vault/pendingious.h"

#include <boost/lambda/lambda.hpp>

namespace maidsafe_vault {

int PendingIOUHandler::AddPendingIOU(const std::string &pmid,
                                     const boost::uint64_t &chunk_size,
                                     const std::string &authority,
                                     const boost::uint32_t &timestamp) {
  multi_index_mutex_.lock();
  if (pmid == "" || chunk_size == 0 || authority == "" ||
     (authority.size() == 8 && authority != "maidsafe")) {
#ifdef DEBUG
    printf("Parameters passed invalid (%s) -- (%s)  -- (%llu)\n", pmid.c_str(),
            authority.c_str(), chunk_size);
#endif
    multi_index_mutex_.unlock();
    return -2700;
  }

  PendingIOURow pir(pmid, chunk_size, authority, timestamp);
  pending_ious_.insert(pir);
  multi_index_mutex_.unlock();
  return 0;
}

int PendingIOUHandler::DeletePendingIOU(const std::string &pmid,
                                        const boost::uint64_t &chunk_size,
                                        const std::string &authority) {
  multi_index_mutex_.lock();
  pending_iou_set::iterator it =
      pending_ious_.get<pending_iou_pmid_cs_auth>().find(
      boost::make_tuple(pmid, chunk_size, authority));
  if (it == pending_ious_.end()) {
#ifdef DEBUG
    printf("PendingIOU not found (%s) -- (%s)\n", pmid.c_str(),
            authority.c_str());
#endif
    multi_index_mutex_.unlock();
    return -2701;
  }
  pending_ious_.erase(it);
  multi_index_mutex_.unlock();
  return 0;
}

bool PendingIOUHandler::IOUExists(const std::string &pmid,
                                  const boost::uint64_t &chunk_size,
                                  const std::string &authority) {
  multi_index_mutex_.lock();
  pending_iou_set::iterator it =
      pending_ious_.get<pending_iou_pmid_cs_auth>().find(
      boost::make_tuple(pmid, chunk_size, authority));
  if (it == pending_ious_.end()) {
#ifdef DEBUG
    printf("PendingIOU not found (%s) -- (%s)\n", pmid.c_str(),
            authority.c_str());
#endif
    multi_index_mutex_.unlock();
    return false;
  }
  multi_index_mutex_.unlock();
  return true;
}

void PendingIOUHandler::ClearPendingIOUs() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  pending_ious_.clear();
}

int PendingIOUHandler::PendingIOUsCount() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  return pending_ious_.size();
}

int PendingIOUHandler::PrunePendingIOUs(const boost::uint32_t &margin) {
  multi_index_mutex_.lock();
  typedef pending_iou_set::index<pending_iou_timestamp>::type
          pending_iou_set_timestamp;
  pending_iou_set_timestamp& pending_iou_index =
      pending_ious_.get<pending_iou_timestamp>();
  if (pending_iou_index.begin() == pending_iou_index.end()) {
#ifdef DEBUG
    printf("NO IOUs.\n");
#endif
    multi_index_mutex_.unlock();
    return -2702;
  }
  boost::uint32_t bound = margin;
  if (bound == 0)
    bound = base::get_epoch_time() - 86400;
  pending_iou_set_timestamp::iterator it = pending_iou_index.begin();
  pending_iou_set_timestamp::iterator limit =
      pending_iou_index.lower_bound(bound);
  if (pending_iou_index.begin() == limit) {
#ifdef DEBUG
    printf("NO prunable IOUs.\n");
#endif
    multi_index_mutex_.unlock();
    return -2702;
  }
  pending_iou_index.erase(pending_iou_index.begin(), limit);

  multi_index_mutex_.unlock();
  return 0;
}

int PendingIOUHandler::PrunableIOUsCount(const boost::uint32_t &margin) {
  multi_index_mutex_.lock();
  typedef pending_iou_set::index<pending_iou_timestamp>::type
          pending_iou_set_timestamp;
  pending_iou_set_timestamp& pending_iou_index =
      pending_ious_.get<pending_iou_timestamp>();
  if (pending_iou_index.begin() == pending_iou_index.end()) {
#ifdef DEBUG
    printf("NO IOUs.\n");
#endif
    multi_index_mutex_.unlock();
    return 0;
  }
  boost::uint32_t bound = margin;
  if (bound == 0)
    bound = base::get_epoch_time() - 86400;
  pending_iou_set_timestamp::iterator it = pending_iou_index.begin();
  pending_iou_set_timestamp::iterator limit =
      pending_iou_index.lower_bound(bound);
  int count = 0;
  while (it != limit) {
    ++count;
    ++it;
  }
  multi_index_mutex_.unlock();
  return count;
}

}  // namespace maidsafe_vault
