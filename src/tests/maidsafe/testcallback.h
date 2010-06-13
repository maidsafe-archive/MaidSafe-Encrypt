/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Object with functions for use as functors in tests
* Created:      2010-06-02
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

#ifndef TESTS_MAIDSAFE_TESTCALLBACK_H_
#define TESTS_MAIDSAFE_TESTCALLBACK_H_

#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>
#include <string>
#include "maidsafe/returncodes.h"

namespace maidsafe {
namespace test {

class CallbackObject {
 public:
   CallbackObject() : result_(),
                      return_code_(kPendingResult),
                      mutex_(),
                      cv_() {}
  void StringCallback(const std::string &result) {
    boost::mutex::scoped_lock lock(mutex_);
    result_ = result;
    cv_.notify_one();
  }
  void ReturnCodeCallback(const ReturnCode &return_code) {
    boost::mutex::scoped_lock lock(mutex_);
    return_code_ = return_code;
    cv_.notify_one();
  }
  std::string WaitForStringResult() {
    std::string result;
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (result_.empty())
        cv_.wait(lock);
      result = result_;
      result_.clear();
    }
    return result;
  }
  ReturnCode WaitForReturnCodeResult() {
    ReturnCode result;
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (return_code_ == kPendingResult)
        cv_.wait(lock);
      result = return_code_;
      return_code_ = kPendingResult;
    }
    return result;
  }
  void Reset() {
    boost::mutex::scoped_lock lock(mutex_);
    result_.clear();
    return_code_ = kPendingResult;
  }
 private:
  std::string result_;
  ReturnCode return_code_;
  boost::mutex mutex_;
  boost::condition_variable cv_;
};

}  // namespace test
}  // namespace maidsafe

#endif  // TESTS_MAIDSAFE_TESTCALLBACK_H_
