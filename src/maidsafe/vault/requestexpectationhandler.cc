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

#include "maidsafe/vault/requestexpectationhandler.h"

#include <boost/lexical_cast.hpp>

#include "maidsafe/returncodes.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe_vault {

int RequestExpectationHandler::AddExpectation(
    const maidsafe::ExpectAmendmentRequest &expect_amendment_request) {
  std::string expectation_identifier =
        GetExpectationIdentifier(expect_amendment_request);
  // Check group size is not too large
  size_t total_count(0), repeated_count(0);
  {
    boost::mutex::scoped_lock lock(mutex_);
    total_count = expectations_.size();
    repeated_count = expectations_.count(expectation_identifier);
  }
  bool tried_cleanup(false);
  while (total_count >= kMaxExpectations_ ||
         repeated_count >= kMaxRepeatedExpectations_) {
    if (!tried_cleanup) {
      if (CleanUp() != 0) {  // i.e. some deletions were made
        boost::mutex::scoped_lock lock(mutex_);
        total_count = expectations_.size();
        repeated_count = expectations_.count(expectation_identifier);
      }
      tried_cleanup = true;
    } else {
      return kRequestExpectationCountError;
    }
  }
  std::vector<std::string> ids(expect_amendment_request.amender_pmids().begin(),
                               expect_amendment_request.amender_pmids().end());
  ExpectedCallers new_entry(ids,
      boost::posix_time::microsec_clock::universal_time() +
      kExpectationTimeout_);
  boost::mutex::scoped_lock lock(mutex_);
  expectations_.insert(
      ExpectedCallersMultiMap::value_type(expectation_identifier, new_entry));
  return kSuccess;
}

std::vector<std::string> RequestExpectationHandler::GetExpectedCallersIds(
    const maidsafe::AmendAccountRequest &amend_account_request) {
  std::string expectation_identifier =
      GetExpectationIdentifier(amend_account_request);
  std::pair<ExpectedCallersMultiMap::iterator,
            ExpectedCallersMultiMap::iterator> lookup_result;
  ExpectedCallersMultiMap::iterator it, result_it;
  std::vector<std::string> result;
  boost::mutex::scoped_lock lock(mutex_);
  lookup_result = expectations_.equal_range(expectation_identifier);
  if (lookup_result.first != lookup_result.second) {
    result_it = lookup_result.first;
    for (it = lookup_result.first; it != lookup_result.second; ++it) {
      // Get the oldest entry
      if ((*it).second.expiry_time < (*result_it).second.expiry_time)
        result_it = it;
    }
    result = (*result_it).second.callers_ids;
    expectations_.erase(result_it);
  }
  return result;
}

int RequestExpectationHandler::CleanUp() {
  int count(0);
  boost::mutex::scoped_lock lock(mutex_);
  ExpectedCallersMultiMap::iterator it = expectations_.begin();
  while (it != expectations_.end()) {
    if ((*it).second.expiry_time <
        boost::posix_time::microsec_clock::universal_time()) {
      expectations_.erase(it);
      it = expectations_.begin();
      ++count;
    } else {
      ++it;
    }
  }
  return count;
}

void RequestExpectationHandler::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  expectations_.clear();
}

template <typename RequestType>
std::string RequestExpectationHandler::GetExpectationIdentifier(
    const RequestType &request) {
  return request.account_pmid() + request.chunkname() +
         boost::lexical_cast<std::string>(request.amendment_type());
}

}  // namespace maidsafe_vault
