/*
 * ============================================================================
 *
 * Copyright [2009] maidsafe.net limited
 *
 * Description:  Implementation of signature and signer id validation
 * Version:      1.0
 * Created:      2010-01-06
 * Revision:     none
 * Compiler:     gcc
 * Author:       Jose Cisneros
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

#ifndef TESTS_VALIDATIONIMPL_H_
#define TESTS_VALIDATIONIMPL_H_

#include <string>
#include "maidsafe/vault/maidsafevalidator.h"
#include <maidsafe/maidsafe-dht_config.h>

namespace maidsafe_vault {

bool MaidsafeValidator::ValidateSignerId(const std::string &signer_id,
      const std::string &public_key, const std::string &signed_public_key) {
  crypto::Crypto co;
  if (signer_id != "" && signer_id != co.Hash(public_key +
      signed_public_key, "", crypto::STRING_STRING, false))
    return false;
  return true;
}

bool  MaidsafeValidator::ValidateRequest(const std::string &signed_request,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &key) {
  crypto::Crypto co;
  if (co.AsymCheckSig(co.Hash(signed_public_key + key + id(), "",
      crypto::STRING_STRING, false), signed_request, public_key,
      crypto::STRING_STRING))
    return true;

  return co.AsymCheckSig(co.Hash(public_key + signed_public_key +
    key, "", crypto::STRING_STRING, false), signed_request, public_key,
    crypto::STRING_STRING);  
}

}  // namespace base
#endif  // TESTS_VALIDATIONIMPL_H_
