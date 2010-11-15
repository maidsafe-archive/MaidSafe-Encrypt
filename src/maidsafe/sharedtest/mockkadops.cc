/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Created:      2010-03-10
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

#include "maidsafe/sharedtest/mockkadops.h"

#include <string>
#include <vector>

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/maidsafe.h"

namespace mock_kadops {

std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  const boost::uint8_t k,
                                  std::vector<std::string> *pmids) {
  if (type == kFailParse)
    return "It's not going to parse.";
  std::string ser_node;
  kad::FindResponse find_response;
  if (type == kResultFail)
    find_response.set_result(kad::kRpcResultFailure);
  else
    find_response.set_result(kad::kRpcResultSuccess);
  int contact_count(k);
  if (type == kTooFewContacts)
    contact_count = 1;
  // Set all IDs close to value of account we're going to be looking for to
  // avoid test node replacing one of these after the kad FindCloseNodes
  std::string account_owner(maidsafe::SHA512String("Account Owner"));
  std::string account_name =
      maidsafe::SHA512String(account_owner + maidsafe::kAccount);
  char x = 'a';
  for (int i = 0; i < contact_count; ++i, ++x) {
    std::string name = account_name.replace(account_name.size() - 1, 1, 1, x);
    pmids->push_back(name);
    kad::Contact node(name, "192.168.1.1", 5000 + i);
    node.SerialiseToString(&ser_node);
    find_response.add_closest_nodes(ser_node);
  }
  find_response.SerializeToString(&ser_node);
  return ser_node;
}

}  // namespace mock_kadops
