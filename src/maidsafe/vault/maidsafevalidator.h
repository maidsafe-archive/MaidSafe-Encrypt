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

#ifndef MAIDSAFE_VAULT_MAIDSAFEVALIDATOR_H_
#define MAIDSAFE_VAULT_MAIDSAFEVALIDATOR_H_

#include <string>
#include <maidsafe/validationinterface.h>

namespace maidsafe_vault {

class MaidsafeValidator : public base::SignatureValidator {
 public:
  /**
   * Ctor
   * pmid - pmid not encoded
   * Default Ctor, use base class set_id method to set pmid
   */ 
  MaidsafeValidator(const std::string &pmid)
    : base::SignatureValidator(pmid) {}
  MaidsafeValidator()
    : base::SignatureValidator() {}
  /**
   * Signer Id is not validated with the following rule:
   *   ID = H(public_key + signed_public_key)
   */
  bool ValidateSignerId(const std::string &signer_id,
    const std::string &public_key, const std::string &signed_public_key);
  /**
   * Validates the request signed with private key that corresponds
   * to public_key
   * The request is in the form  H(signed_public_key + key + rec_id) 
   * or H(public_key + signed_public_key + key)
   */
  bool ValidateRequest(const std::string &signed_request,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &key);
};

}  // maidsafe_vault
#endif  // MAIDSAFE_VAULT_MAIDSAFEVALIDATOR_H_
