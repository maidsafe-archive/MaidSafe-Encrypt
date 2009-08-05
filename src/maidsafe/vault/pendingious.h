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

#ifndef MAIDSAFE_VAULT_PENDINGIOUS_H_
#define MAIDSAFE_VAULT_PENDINGIOUS_H_

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

struct PendingIOURow {
  PendingIOURow()
      : pmid_(), chunk_size_(0), authority_(), timestamp_(0) { }
  PendingIOURow(const std::string &pmid, const boost::uint64_t chunk_size,
                const std::string &authority, boost::uint32_t timestamp)
      : pmid_(pmid), chunk_size_(chunk_size), authority_(authority),
        timestamp_(timestamp) {
    if (timestamp == 0)
      timestamp_ = base::get_epoch_time();
  }
  std::string pmid_;
  boost::uint64_t chunk_size_;
  std::string authority_;
  boost::uint32_t timestamp_;
};

// Tags
struct pending_iou_pmid_cs {};
struct pending_iou_pmid_cs_auth {};
struct pending_iou_timestamp {};

typedef boost::multi_index_container<
  PendingIOURow,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_iou_pmid_cs_auth>,
      boost::multi_index::composite_key<
        PendingIOURow,
        BOOST_MULTI_INDEX_MEMBER(PendingIOURow, std::string, pmid_),
        BOOST_MULTI_INDEX_MEMBER(PendingIOURow, boost::uint64_t, chunk_size_),
        BOOST_MULTI_INDEX_MEMBER(PendingIOURow, std::string, authority_)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_iou_timestamp>,
      BOOST_MULTI_INDEX_MEMBER(PendingIOURow, boost::uint32_t, timestamp_)
    >
  >
> pending_iou_set;

class PendingIOUHandler {
 public:
  PendingIOUHandler() : multi_index_mutex_(), pending_ious_() {}
  ~PendingIOUHandler() {}
  int AddPendingIOU(const std::string &pmid,
                    const boost::uint64_t &chunk_size,
                    const std::string &authority,
                    const boost::uint32_t &timestamp);
  int DeletePendingIOU(const std::string &pmid,
                       const boost::uint64_t &chunk_size,
                       const std::string &authority);
  bool IOUExists(const std::string &pmid,
                 const boost::uint64_t &chunk_size,
                 const std::string &authority);
  std::string GetIOU(const std::string &pmid,
                     const boost::uint64_t &chunk_size);
  void ClearPendingIOUs();
  int PendingIOUsCount();
  int PrunePendingIOUs(const boost::uint32_t &margin);
  int PrunableIOUsCount(const boost::uint32_t &margin);
 private:
  boost::mutex multi_index_mutex_;
  pending_iou_set pending_ious_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_PENDINGIOUS_H_
