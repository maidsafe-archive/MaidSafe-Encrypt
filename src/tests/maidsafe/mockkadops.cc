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

#include "tests/maidsafe/mockkadops.h"

#include <string>
#include <vector>

namespace mock_kadops {

std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  std::vector<std::string> *pmids) {
  if (type == kFailParse)
    return "It's not going to parse.";
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string ser_node;
  kad::FindResponse find_response;
  if (type == kResultFail)
    find_response.set_result(kad::kRpcResultFailure);
  else
    find_response.set_result(kad::kRpcResultSuccess);
  int contact_count(kad::K);
  if (type == kTooFewContacts)
    contact_count = 1;
  // Set all IDs close to value of account we're going to be looking for to
  // avoid test node replacing one of these after the kad FindCloseNodes
  std::string account_owner(co.Hash("Account Owner", "", crypto::STRING_STRING,
      false));
  std::string account_name(co.Hash(account_owner + kAccount, "",
      crypto::STRING_STRING, false));
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
};

void RunCallback(const std::string &find_nodes_response,
                 const base::callback_func_type &callback) {
  callback(find_nodes_response);
};

}  // namespace mock_kadops
