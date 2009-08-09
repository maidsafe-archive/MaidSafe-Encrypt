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

#ifndef MAIDSAFE_VAULT_PENDINGOPERATIONS_H_
#define MAIDSAFE_VAULT_PENDINGOPERATIONS_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <maidsafe/contact_info.pb.h>
#include <maidsafe/maidsafe-dht.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace maidsafe_vault {

const int maxQueueSize = 50;

enum vault_operation_status {
  // Storing vault
  STORE_ACCEPTED,
  STORE_DONE,
  AWAITING_IOU,
  IOU_READY,
  IOU_RANK_RETREIVED,

  // Reference holder vault
  IOU_RECEIVED,
  IOU_COLLECTED,

  //Rank holder vault
  IOU_RANK_DELIVERED,
  IOU_ERASED
};

struct PendingOperationRow {
  PendingOperationRow()
      : pmid_(), chunk_name_(), chunk_size_(0), iou_(),
        rank_authority_(), timestamp_(0), public_key_(), status_() { }
  PendingOperationRow(const std::string &pmid,
                      const std::string &chunkname,
                      const boost::uint64_t &chunk_size,
                      const std::string &iou,
                      const std::string &rank_authority,
                      const boost::uint32_t &timestamp,
                      const std::string &public_key,
                      const vault_operation_status &status)
      : pmid_(pmid), chunk_name_(chunkname), chunk_size_(chunk_size),
        iou_(iou),
        rank_authority_(rank_authority), timestamp_(timestamp),
        public_key_(public_key), status_(status) {
    if (timestamp == 0)
      timestamp_ = base::get_epoch_time();
  }
  std::string pmid_;
  std::string chunk_name_;
  boost::uint64_t chunk_size_;
  std::string iou_;
  std::string rank_authority_;
  boost::uint32_t timestamp_;
  std::string public_key_;
  vault_operation_status status_;
};

// Tags
struct pending_op_all {};

typedef boost::multi_index_container<
  PendingOperationRow,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<pending_op_all>,
      boost::multi_index::composite_key<
        PendingOperationRow,
        BOOST_MULTI_INDEX_MEMBER(PendingOperationRow, vault_operation_status,
                                 status_),
        BOOST_MULTI_INDEX_MEMBER(PendingOperationRow, std::string,
                                 chunk_name_),
        BOOST_MULTI_INDEX_MEMBER(PendingOperationRow, std::string, pmid_),
        BOOST_MULTI_INDEX_MEMBER(PendingOperationRow, boost::uint64_t,
                                 chunk_size_)
      >
    >
  >
> pending_operation_set;

class PendingOperationsHandler {
 public:
  PendingOperationsHandler() : multi_index_mutex_(), pending_ops_() {}
  ~PendingOperationsHandler() {}
  void ClearPendingOperations();
  int PendingOperationsCount();

  int AddPendingOperation(const std::string &pmid,
                          const std::string &chunkname,
                          const boost::uint64_t &chunk_size,
                          const std::string &iou,
                          const std::string &rank_authority,
                          boost::uint32_t timestamp,
                          const std::string &public_key,
                          const vault_operation_status &status);
  int AdvanceStatus(const std::string &pmid,
                    const std::string &chunkname,
                    const boost::uint64_t &chunk_size,
                    const std::string &iou,
                    const std::string &rank_authority,
                    const std::string &public_key,
                    const vault_operation_status &status);

  int FindOperation(const std::string &pmid,
                    const std::string &chunkname,
                    const boost::uint64_t &chunk_size,
                    const std::string &iou,
                    const std::string &rank_authority,
                    const vault_operation_status &status);

  int GetSizeAndIOU(const std::string &pmid,
                    const std::string &chunkname,
                    boost::uint64_t *chunk_size,
                    std::string *iou);
//  int AddPendingIOU(const std::string &pmid,
//                    const boost::uint64_t &chunk_size,
//                    const std::string &authority,
//                    const boost::uint32_t &timestamp);
//  int DeletePendingIOU(const std::string &pmid,
//                       const boost::uint64_t &chunk_size,
//                       const std::string &authority);
//  bool IOUExists(const std::string &pmid,
//                 const boost::uint64_t &chunk_size,
//                 const std::string &authority);
//  std::string GetIOU(const std::string &pmid,
//                     const boost::uint64_t &chunk_size);
//  int PrunePendingIOUs(const boost::uint32_t &margin);
//  int PrunableIOUsCount(const boost::uint32_t &margin);
 private:
  int AnalyseParameters(const std::string &pmid,
                        const std::string &chunkname,
                        const boost::uint64_t &chunk_size,
                        const std::string &iou,
                        const std::string &rank_authority,
                        const std::string &public_key,
                        const vault_operation_status &status);
  boost::mutex multi_index_mutex_;
  pending_operation_set pending_ops_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_PENDINGOPERATIONS_H_