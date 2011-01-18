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

#ifndef MAIDSAFE_COMMON_ACCOUNTSERVICE_H_
#define MAIDSAFE_COMMON_ACCOUNTSERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
class AmendAccountRequest;
class AmendAccountResponse;
class ExpectAmendmentRequest;
class ExpectAmendmentResponse;
class AccountStatusRequest;
class AccountStatusResponse;
}  // namespace protobuf

namespace vault {

class AccountService {
 public:
  AccountService() {}
  void AmendAccount(const transport::Info &info,
                    const protobuf::AmendAccountRequest &request,
                    protobuf::AmendAccountResponse *response);
  void ExpectAmendment(const transport::Info &info,
                       const protobuf::ExpectAmendmentRequest &request,
                       protobuf::ExpectAmendmentResponse *response);
  void AccountStatus(const transport::Info &info,
                     const protobuf::AccountStatusRequest &request,
                     protobuf::AccountStatusResponse *response);
  // TODO setters...
 private:
  AccountService(const AccountService&);
  AccountService& operator=(const AccountService&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_ACCOUNTSERVICE_H_
