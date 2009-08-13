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

#include "maidsafe/vault/pendingoperations.h"


namespace maidsafe_vault {

void PendingOperationsHandler::ClearPendingOperations() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  pending_ops_.clear();
}

int PendingOperationsHandler::PendingOperationsCount() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  return pending_ops_.size();
}

int PendingOperationsHandler::AddPendingOperation(const std::string &pmid,
    const std::string &chunkname, const boost::uint64_t &chunk_size,
    const std::string &iou, const std::string &rank_authority,
    boost::uint32_t timestamp, const std::string &public_key,
    const vault_operation_status &status) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  if (AnalyseParameters(pmid, chunkname, chunk_size, iou,
      rank_authority, public_key, status) < 0) {
#ifdef DEBUG
    printf("PendingOperationsHandler::AddPendingOperation: Parameter incorrect "
           "for this status (%d).\n", status);
#endif
    return -1492;
  }
  PendingOperationRow por(pmid, chunkname, chunk_size, iou,
                          rank_authority, timestamp, public_key, status);
  std::pair<pending_operation_set::iterator, bool> p =
      pending_ops_.insert(por);
  if (!p.second) {
#ifdef DEBUG
    printf("PendingOperationsHandler::AddPendingOperation: Already a pending "
           "operation with these paramenters.\n");
#endif
    return -1492;
  }
  return 0;
}

int PendingOperationsHandler::AdvanceStatus(const std::string &pmid,
    const std::string &chunkname, const boost::uint64_t &chunk_size,
    const std::string &iou, const std::string &rank_authority,
    const std::string &public_key, const vault_operation_status &status) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  if (AnalyseParameters(pmid, chunkname, chunk_size, iou,
      rank_authority, public_key, status) < 0) {
#ifdef DEBUG
    printf("PendingOperationsHandler::AddPendingOperation: Parameter incorrect "
           "for this status (%d).\n", status);
#endif
    return -1493;
  }
  std::pair<pending_operation_set::iterator, pending_operation_set::iterator> p;
  switch (status) {
    case STORE_ACCEPTED:
      break;
    case STORE_DONE:
      p = pending_ops_.equal_range(boost::make_tuple(STORE_ACCEPTED, chunkname,
          pmid, chunk_size));
      break;
    case AWAITING_IOU:
      p = pending_ops_.equal_range(boost::make_tuple(STORE_DONE, chunkname,
          pmid, chunk_size));
      break;
    case IOU_READY:
      p = pending_ops_.equal_range(boost::make_tuple(AWAITING_IOU, chunkname));
      break;
    case IOU_RANK_RETREIVED:
      p = pending_ops_.equal_range(boost::make_tuple(IOU_READY, chunkname));
      break;
    default: break;
  }
  if (p.first == p.second) {
#ifdef DEBUG
    printf("Pending operation not found (%s).\n", chunkname.c_str());
#endif
    return -1493;
  }
  PendingOperationRow por = (*p.first);
  por.status_ = status;
  por.iou_ = iou;
  por.rank_authority_ = rank_authority;
  por.timestamp_ = base::get_epoch_time();
  pending_ops_.replace(p.first, por);
  return 0;
}

int PendingOperationsHandler::FindOperation(const std::string &pmid,
    const std::string &chunkname, const boost::uint64_t &chunk_size,
    const std::string &iou, const std::string &rank_authority,
    const vault_operation_status &status) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  if (pmid.empty() || chunkname.empty() || chunk_size == 0) {
#ifdef DEBUG
    printf("PendingOperationsHandler::FindOperation: Parameter incorrect "
           "for this search (%d).\n", status);
#endif
    return -1494;
  }

  // Need to add indexes for these two in the mult index
  if (iou != "" || rank_authority != "")
    return -1494;

  std::pair<pending_operation_set::iterator, pending_operation_set::iterator> p;
  p = pending_ops_.equal_range(boost::make_tuple(status, chunkname,
                               pmid, chunk_size));
  if (p.first == p.second) {
#ifdef DEBUG
    printf("Pending operation not found (%s).\n", chunkname.c_str());
#endif
    return -1494;
  }
  ++p.first;
  if (p.first != p.second) {
#ifdef DEBUG
    printf("More than one found (%s).\n", chunkname.c_str());
#endif
    return -1494;
  }
  return 0;
}

int PendingOperationsHandler::EraseOperation(
    const vault_operation_status &status,
    const std::string &pmid,
    const std::string &chunkname) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  std::pair<pending_operation_set::iterator, pending_operation_set::iterator> p;
  p = pending_ops_.equal_range(boost::make_tuple(status, chunkname, pmid));
  if (p.first == p.second) {
#ifdef DEBUG
    printf("Pending operation not found (%s).\n", chunkname.c_str());
#endif
    return -1495;
  }
  pending_ops_.erase(p.first);
  return 0;
}

int PendingOperationsHandler::GetSizeAndIOU(const std::string &pmid,
                                            const std::string &chunkname,
                                            boost::uint64_t *chunk_size,
                                            std::string *iou) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  *chunk_size = 0;
  *iou = "";
  std::pair<pending_operation_set::iterator, pending_operation_set::iterator> p;
  p = pending_ops_.equal_range(boost::make_tuple(IOU_RECEIVED, chunkname,
                               pmid));
  if (p.first == p.second) {
#ifdef DEBUG
    printf("Pending operation not found (%s).\n", chunkname.c_str());
#endif
    return -1496;
  }
  *chunk_size = (*p.first).chunk_size_;
  *iou = (*p.first).iou_;
  return 0;
}

int PendingOperationsHandler::PrunePendingOps() {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  int deletes = 0;
  typedef pending_operation_set::index<pending_op_timestamp>::type
          pending_operation_set_timestamp;
  pending_operation_set_timestamp& pending_op_index =
      pending_ops_.get<pending_op_timestamp>();
  if (pending_op_index.begin() == pending_op_index.end()) {
#ifdef DEBUG
    printf("NO pending ops.\n");
#endif
    return deletes;
  }
  boost::uint32_t bound = base::get_epoch_time() - 14;
  pending_operation_set_timestamp::iterator it = pending_op_index.begin();
  pending_operation_set_timestamp::iterator limit =
      pending_op_index.lower_bound(bound);
  if (pending_op_index.begin() == limit) {
#ifdef DEBUG
    printf("NO prunable ops.\n");
#endif
    return deletes;
  }
  while (it != limit) {
    if ((*it).status_ != STORE_ACCEPTED) {
      pending_op_index.erase(it);
      ++deletes;
    }
    ++it;
  }
  return deletes;
}

int PendingOperationsHandler::GetAllIouReadys(
    std::list< boost::tuple<std::string, std::string, boost::uint64_t,
                            std::string> > *iou_readys) {
  boost::mutex::scoped_lock loch(multi_index_mutex_);
  iou_readys->clear();
  std::pair<pending_operation_set::iterator, pending_operation_set::iterator> p;
  p = pending_ops_.equal_range(boost::make_tuple(IOU_READY));
  for (; p.first != p.second; ++p.first) {
    iou_readys->push_back(boost::make_tuple((*p.first).pmid_,
        (*p.first).chunk_name_, (*p.first).chunk_size_,
        (*p.first).public_key_));
  }
  return 0;
}

int PendingOperationsHandler::AnalyseParameters(const std::string &pmid,
    const std::string &chunkname, const boost::uint64_t &chunk_size,
    const std::string &iou, const std::string &rank_authority,
    const std::string &public_key, const vault_operation_status &status) {
  int res = 0;
  switch (status) {
    // Storing vault
    case STORE_ACCEPTED: if (public_key.empty()) return -1496;
    case STORE_DONE:
      if (pmid.empty() || chunkname.empty() || chunk_size == 0 ||
          !iou.empty() || !rank_authority.empty()) {
#ifdef DEBUG
        printf("Wrong parameters (%s) -- (%s) -- (%llu)-- (%s) -- (%s)\n",
               pmid.c_str(), chunkname.c_str(), chunk_size,
               iou.c_str(), rank_authority.c_str());
#endif
        res = -1496;
      }
      break;
    case IOU_READY:
    case AWAITING_IOU:
    case IOU_RANK_RETREIVED:
      if (chunkname.empty()) {
#ifdef DEBUG
        printf("Wrong parameters (%s) -- (%s)\n", iou.c_str(),
               rank_authority.c_str());
#endif
        res = -1496;
      }
      break;

    // Reference holder vault
    case IOU_RECEIVED:
      if (pmid.empty() || chunkname.empty() || chunk_size == 0 ||
         iou.empty() || !rank_authority.empty()) {
#ifdef DEBUG
        printf("Wrong parameters (%s) -- (%s) -- (%llu)-- (%s) -- (%s)\n",
               pmid.c_str(), chunkname.c_str(), chunk_size,
               iou.c_str(), rank_authority.c_str());
#endif
        res = -1497;
      }
      break;
    case IOU_COLLECTED:
      if (pmid.empty() || chunkname.empty() || chunk_size != 0 ||
          !iou.empty() || !rank_authority.empty()) {
#ifdef DEBUG
        printf("Wrong parameters (%s) -- (%s) -- (%llu)-- (%s) -- (%s)\n",
               pmid.c_str(), chunkname.c_str(), chunk_size,
               iou.c_str(), rank_authority.c_str());
#endif
        res = -1497;
      }
      break;

    // Rank holder vault
    case IOU_RANK_DELIVERED: break;
    case IOU_ERASED: break;
  }
  return res;
}

}  // namespace maidsafe_vault
