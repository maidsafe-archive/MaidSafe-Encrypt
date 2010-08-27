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

#ifndef MAIDSAFE_PDUTILS_H_
#define MAIDSAFE_PDUTILS_H_

#include <string>
#include "maidsafe/maidsafe.h"

namespace kad {
class Contact;
}  // namespace kad

namespace maidsafe_vault {
namespace test {
class PDVaultTest;
}  // namespace test
}  // namespace maidsafe_vault

namespace maidsafe {

class SessionSingleton;

std::string TidyPath(const std::string &original_path);

std::string StringToLowercase(const std::string &str);

bool ContactHasId(const std::string &id, const kad::Contact &contact);

class PdUtils {
 public:
  PdUtils();
  ~PdUtils() {}
  void GetChunkSignatureKeys(DirType dir_type,
                             const std::string &msid,
                             std::string *key_id,
                             std::string *public_key,
                             std::string *public_key_sig,
                             std::string *private_key);

  void GetPacketSignatureKeys(PacketType packet_type,
                              DirType dir_type,
                              const std::string &msid,
                              std::string *key_id,
                              std::string *public_key,
                              std::string *public_key_sig,
                              std::string *private_key);
 private:
  friend class maidsafe_vault::test::PDVaultTest;
  SessionSingleton *ss_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PDUTILS_H_
