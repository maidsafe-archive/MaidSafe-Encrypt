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
                                  const std::string &target,
                                  const boost::uint8_t n,
                                  std::vector<kad::Contact> *nodes) {
  std::vector<kad::Contact> contacts;
  if (type == kFailParse) {
    if (nodes != NULL)
      *nodes = contacts;
    return "It's not going to parse.";
  }

  kad::FindResponse find_response;
  if (type == kResultFail)
    find_response.set_result(kad::kRpcResultFailure);
  else
    find_response.set_result(kad::kRpcResultSuccess);

  std::string ref_id(target);
  if (type == kFarContacts)
    ref_id = maidsafe::XORObfuscate(ref_id, std::string(ref_id.size(), 0xFF));
  
  boost::uint8_t orig(ref_id.at(ref_id.size() - 1)), idx(0);
  while (contacts.size() < n) {
    boost::uint8_t x = orig ^ idx++;
    std::string node_id = ref_id.replace(ref_id.size() - 1, 1, 1, x);
    contacts.push_back(kad::Contact(node_id, "192.168.1.1", 1234));
  }
  for (size_t i = 0; i < contacts.size(); ++i) {
    std::string ser_contact;
    contacts[i].SerialiseToString(&ser_contact);
    find_response.add_closest_nodes(ser_contact);
  }
  if (nodes != NULL)
    *nodes = contacts;
  
  return find_response.SerializeAsString();
}

}  // namespace mock_kadops
