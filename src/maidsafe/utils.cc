/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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

#include "maidsafe/utils.h"
#include <maidsafe/kademlia/contact.h>

namespace maidsafe {

std::string TidyPath(const std::string &original_path) {
  //  if path is root, don't change it
  if (original_path.size() == 1)
    return original_path;
  std::string amended_path = original_path;
  //  if path has training slash, remove it
  if (amended_path.at(amended_path.size() - 1) == '/' ||
      amended_path.at(amended_path.size() - 1) == '\\')
    amended_path = amended_path.substr(0, amended_path.size() - 1);
  //  if path has leading slash, remove it
  if (amended_path.at(0) == '/' || amended_path.at(0) == '\\')
    amended_path = amended_path.substr(1, amended_path.size() - 1);
  return amended_path;
}

std::string StringToLowercase(const std::string &str) {
  std::string lowercase;
  for (size_t i = 0; i < str.length(); ++i) {
    lowercase += tolower(str.at(i));
  }
  return lowercase;
}

bool ContactHasId(const std::string &id, const kad::Contact &contact) {
  return contact.node_id().String() == id;
}

}  // namespace maidsafe
