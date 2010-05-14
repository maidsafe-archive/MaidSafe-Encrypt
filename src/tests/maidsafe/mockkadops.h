/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  A mock KadOps object, and related helper methods
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
#include "maidsafe/kadops.h"

namespace mock_kadops {

enum FindNodesResponseType {
  kFailParse,
  kResultFail,
  kTooFewContacts,
  kGood
};

std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  std::vector<std::string> *pmids);

void RunCallback(const std::string &find_nodes_response,
                 const kad::VoidFunctorOneString &callback);

}  // namespace mock_kadops

namespace maidsafe {

class MockKadOps : public KadOps {
 public:
  explicit MockKadOps(const boost::shared_ptr<kad::KNode> &knode)
      : KadOps(knode) {}
  MOCK_METHOD1(AddressIsLocal, bool(const kad::Contact &peer));
  MOCK_METHOD1(AddressIsLocal, bool(const kad::ContactInfo &peer));
  MOCK_METHOD3(FindValue, void(const kad::KadId &kad_key,
                               bool check_local,
                               const kad::VoidFunctorOneString &cb));
  MOCK_METHOD5(FindValue, int(const kad::KadId &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *values,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD2(FindKClosestNodes,
               void(const kad::KadId &kad_key,
                    const kad::VoidFunctorOneString &callback));
  MOCK_METHOD4(GetStorePeer, int(const double &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
};

}  // namespace maidsafe

#endif  // TESTS_MAIDSAFE_MOCKKADOPS_H_
