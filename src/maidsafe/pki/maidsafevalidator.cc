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

#ifndef MAIDSAFE_VALIDATIONIMPL_H_
#define MAIDSAFE_VALIDATIONIMPL_H_

#include "maidsafe/pki/maidsafevalidator.h"
#include <maidsafe/base/crypto.h>
#include <cstdio>
#include "maidsafe/common/returncodes.h"


namespace maidsafe {

namespace pki {

bool MaidsafeValidator::ValidateSignerId(const std::string &signer_id,
                                         const std::string &public_key,
                                         const std::string &signed_public_key) {
  crypto::Crypto co;
  if (signer_id.empty() || public_key.empty() || signed_public_key.empty()) {
#ifdef DEBUG
    if (signer_id.empty())
      printf("MaidsafeValidator::ValidateSignerId: signer_id empty.\n");
    if (public_key.empty())
      printf("MaidsafeValidator::ValidateSignerId: public_key empty.\n");
    if (signed_public_key.empty())
      printf("MaidsafeValidator::ValidateSignerId: signed_public_key empty.\n");
#endif
    return false;
  }
  if (signer_id != co.Hash(public_key + signed_public_key, "",
      crypto::STRING_STRING, false)) {
#ifdef DEBUG
    printf("MaidsafeValidator::ValidateSignerId - Id doesn't validate.\n");
#endif
    return false;
  }
  return true;
}

bool MaidsafeValidator::ValidateRequest(const std::string &signed_request,
                                        const std::string &public_key,
                                        const std::string &signed_public_key,
                                        const std::string &key) {
  crypto::Crypto co;
  if (co.AsymCheckSig(co.Hash(signed_public_key + key + id(), "",
      crypto::STRING_STRING, false), signed_request, public_key,
      crypto::STRING_STRING))
    return true;

  if (co.AsymCheckSig(co.Hash(public_key + signed_public_key +
      key, "", crypto::STRING_STRING, false), signed_request, public_key,
      crypto::STRING_STRING))
    return true;
#ifdef DEBUG
  printf("MaidsafeValidator::ValidateRequest - Failed to validate request.\n");
#endif
  return false;
}

int MaidsafeValidator::CreateRequestSignature(const std::string &private_key,
    const std::list<std::string> &parameters, std::string *request_signature) {
  if (private_key.empty())
    return kValidatorNoPrivateKey;
  if (parameters.size() == 0)
    return kValidatorNoParameters;

  std::string concatenation;
  std::list<std::string>::const_iterator it;
  for (it = parameters.begin(); it != parameters.end(); ++it)
    concatenation += *it;

  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string request;
  request = co.Hash(concatenation, "", crypto::STRING_STRING, false);
  *request_signature = co.AsymSign(request, "", private_key,
                       crypto::STRING_STRING);
  return 0;
}

}  // namespace pki

}  // namespace maidsafe

#endif  // MAIDSAFE_VALIDATIONIMPL_H_
