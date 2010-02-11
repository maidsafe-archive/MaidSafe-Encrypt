/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  A mock KadOps object, used in multiple places
* Created:      2010-02-11
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

#ifndef TESTS_MAIDSAFE_MOCKKADOPS_H_
#define TESTS_MAIDSAFE_MOCKKADOPS_H_

#include <gmock/gmock.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <vector>
#include <string>

#include "maidsafe/maidsafe.h"

namespace maidsafe {

class MockKadOps : public KadOps {
 public:
  explicit MockKadOps(const boost::shared_ptr<kad::KNode> &knode)
      : KadOps(knode) {}
  MOCK_METHOD1(AddressIsLocal, bool(const kad::Contact &peer));
  MOCK_METHOD1(AddressIsLocal, bool(const kad::ContactInfo &peer));
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD3(FindValue, void(const std::string &kad_key,
                               bool check_local,
                               const base::callback_func_type &cb));
  MOCK_METHOD2(FindCloseNodes, void(const std::string &kad_key,
                                    const base::callback_func_type &callback));
  MOCK_METHOD2(FindKNodes, int(const std::string &kad_key,
                               std::vector<kad::Contact> *contacts));
  MOCK_METHOD4(GetStorePeer, int(const float &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
};

}  // namespace maidsafe

#endif  // TESTS_MAIDSAFE_MOCKKADOPS_H_
