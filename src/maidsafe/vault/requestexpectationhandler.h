/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class to handle expected incoming requests
* Version:      1.0
* Created:      2010-05-13-14.24.16
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

#ifndef MAIDSAFE_VAULT_REQUESTEXPECTATIONHANDLER_H_
#define MAIDSAFE_VAULT_REQUESTEXPECTATIONHANDLER_H_

#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <map>
#include <string>
#include <vector>

namespace maidsafe {
class AmendAccountRequest;
class ExpectAmendmentRequest;
}  // namespace maidsafe

namespace maidsafe_vault {

struct ExpectedCallers {
  ExpectedCallers(const std::vector<std::string> &ids,
                  const boost::posix_time::ptime &expiry_tm)
      : callers_ids(ids), expiry_time(expiry_tm) {}
  std::vector<std::string> callers_ids;
  boost::posix_time::ptime expiry_time;
};

typedef std::multimap<std::string, ExpectedCallers> ExpectedCallersMultiMap;

class RequestExpectationHandler {
 public:
  // expectation_timeout in milliseconds
  RequestExpectationHandler(const size_t &max_expectations,
                            const size_t &max_repeated_expectations,
                            const boost::uint64_t &expectation_timeout)
      : kMaxExpectations_(max_expectations),
        kMaxRepeatedExpectations_(max_repeated_expectations),
        kExpectationTimeout_(expectation_timeout),
        expectations_(),
        mutex_() {}
  ~RequestExpectationHandler() {}
  // Assumes that request has already been validated
  int AddExpectation(
      const maidsafe::ExpectAmendmentRequest &expect_amendment_request);
  std::vector<std::string> GetExpectedCallersIds(
      const maidsafe::AmendAccountRequest &amend_account_request);
  // Removes expired entries from multimap which have timed out - returns a
  // count of the number of entries removed.
  int CleanUp();
 private:
  RequestExpectationHandler(const RequestExpectationHandler&);
  RequestExpectationHandler& operator=(const RequestExpectationHandler&);
  FRIEND_TEST(RequestExpectationHandlerTest, BEH_MAID_REH_AddSingleExpectation);
  FRIEND_TEST(RequestExpectationHandlerTest, BEH_MAID_REH_TooManyExpectations);
  FRIEND_TEST(RequestExpectationHandlerTest, BEH_MAID_REH_TooManyRepeats);
  FRIEND_TEST(RequestExpectationHandlerTest,
              BEH_MAID_REH_GetExpectedCallersIds);
  template <typename RequestType>
  std::string GetExpectationIdentifier(const RequestType &request);
  const size_t kMaxExpectations_;
  const size_t kMaxRepeatedExpectations_;
  const boost::posix_time::milliseconds kExpectationTimeout_;
  ExpectedCallersMultiMap expectations_;
  boost::mutex mutex_;
};

}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_REQUESTEXPECTATIONHANDLER_H_
