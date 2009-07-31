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

#ifndef MAIDSAFE_VAULT_PENDINGSTORES_H_
#define MAIDSAFE_VAULT_PENDINGSTORES_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <maidsafe/maidsafe-dht.h>

#include <string>
#include <vector>

#include "maidsafe/maidsafe.h"
#include "protobuf/contact_info.pb.h"

namespace maidsafe_vault {

const int maxQueueSize = 50;

struct PendingStoreRow {
  PendingStoreRow()
    : pmid_(), chunk_name_(), contacts_(),
      chunk_size_(0), phase_(0), timestamp_(base::get_epoch_time()) { }
  PendingStoreRow(const std::string &pmid, const std::string &chunk_name,
                  const boost::uint64_t chunk_size)
    : pmid_(pmid), chunk_name_(chunk_name), contacts_(),
      chunk_size_(chunk_size), phase_(0), timestamp_(base::get_epoch_time()) { }
  std::string pmid_;
  std::string chunk_name_;
  std::vector<kad::ContactInfo> contacts_;
  boost::uint64_t chunk_size_;
  int phase_;
  boost::uint32_t timestamp_;
};

// Tags
struct pending_store_pmid_chunkname {};
struct pending_store_pmid {};
struct pending_store_chunkname {};
struct pending_store_phase {};
struct pending_store_timestamp {};

typedef boost::multi_index_container<
  PendingStoreRow,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<pending_store_pmid_chunkname>,
      boost::multi_index::composite_key<
        PendingStoreRow,
        BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, std::string, pmid_),
        BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, std::string, chunk_name_)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_store_pmid>,
      BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, std::string, pmid_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_store_chunkname>,
      BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, std::string, chunk_name_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_store_phase>,
      BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, int, phase_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<pending_store_timestamp>,
      BOOST_MULTI_INDEX_MEMBER(PendingStoreRow, boost::uint32_t, timestamp_)
    >
  >
> pending_store_set;

class PendingStoreHandler {
 public:
  PendingStoreHandler() : multi_index_mutex_(), pending_stores_() {}
  ~PendingStoreHandler() {}
  int AddPendingStore(const std::string &pmid, const std::string &chunkname,
                      const boost::uint64_t &chunk_size);
  int DeletePendingStore(const std::string &pmid, const std::string &chunkname);
  int UpdatePendingStorePhase(const std::string &pmid,
                              const std::string &chunkname,
                              const int &phase);
  int AddContactsToPendingStore(const std::string &pmid,
                                const std::string &chunkname,
                                const std::vector<kad::ContactInfo> &contacts);
  boost::uint64_t QueuedSpace();
  int NextPendingStore(int phase, PendingStoreRow *psr);
  void ClearPendingStores();
  int PendingStoresCount();
 private:
  boost::mutex multi_index_mutex_;
  pending_store_set pending_stores_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_PENDINGSTORES_H_
