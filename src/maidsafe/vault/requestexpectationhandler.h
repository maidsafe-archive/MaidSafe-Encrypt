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
#include <map>
#include <string>
#include <vector>

namespace maidsafe {
class AmendAccountRequest;
class ExpectAmendmentRequest;
}  // namespace maidsafe

namespace maidsafe {

namespace vault {

namespace test {
class RequestExpectationHandlerTest_BEH_MAID_AddSingleExpectation_Test;
class RequestExpectationHandlerTest_BEH_MAID_TooManyExpectations_Test;
class RequestExpectationHandlerTest_BEH_MAID_TooManyRepeats_Test;
class RequestExpectationHandlerTest_BEH_MAID_GetExpectedCallersIds_Test;
class RequestExpectationHandlerTest_BEH_MAID_CleanUp_Test;
class RequestExpectationHandlerTest_BEH_MAID_Threaded_Test;
}  // namespace test

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
  int AddExpectation(const ExpectAmendmentRequest &expect_amendment_request);
  std::vector<std::string> GetExpectedCallersIds(
      const AmendAccountRequest &amend_account_request);
  // Removes expired entries from multimap which have timed out - returns a
  // count of the number of entries removed.
  int CleanUp();
 private:
  RequestExpectationHandler(const RequestExpectationHandler&);
  RequestExpectationHandler& operator=(const RequestExpectationHandler&);
  friend class
      test::RequestExpectationHandlerTest_BEH_MAID_AddSingleExpectation_Test;
  friend class
      test::RequestExpectationHandlerTest_BEH_MAID_TooManyExpectations_Test;
  friend class
      test::RequestExpectationHandlerTest_BEH_MAID_TooManyRepeats_Test;
  friend class
      test::RequestExpectationHandlerTest_BEH_MAID_GetExpectedCallersIds_Test;
  friend class test::RequestExpectationHandlerTest_BEH_MAID_CleanUp_Test;
  friend class test::RequestExpectationHandlerTest_BEH_MAID_Threaded_Test;
  template <typename RequestType>
  std::string GetExpectationIdentifier(const RequestType &request);
  const size_t kMaxExpectations_;
  const size_t kMaxRepeatedExpectations_;
  const boost::posix_time::milliseconds kExpectationTimeout_;
  ExpectedCallersMultiMap expectations_;
  boost::mutex mutex_;
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_REQUESTEXPECTATIONHANDLER_H_
