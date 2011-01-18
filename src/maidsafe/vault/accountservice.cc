/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class providing Account services.
* Created:      2011-01-18
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

#include "maidsafe/vault/accountservice.h"

#include "maidsafe/common/account_messages.pb.h"

namespace maidsafe {

namespace vault {

void AccountService::AmendAccount(const transport::Info &info,
                                  const protobuf::AmendAccountRequest &request,
                                  protobuf::AmendAccountResponse *response) {
  // response->set_result(false);
  // TODO implement AccountService::AmendAccount body
}

void AccountService::ExpectAmendment(
    const transport::Info &info,
    const protobuf::ExpectAmendmentRequest &request,
    protobuf::ExpectAmendmentResponse *response) {
  // response->set_result(false);
  // TODO implement AccountService::ExpectAmendment body
}

void AccountService::AccountStatus(
    const transport::Info &info,
    const protobuf::AccountStatusRequest &request,
    protobuf::AccountStatusResponse *response) {
  // response->set_result(false);
  // TODO implement AccountService::AccountStatus body
}

}

}  // namespace maidsafe
