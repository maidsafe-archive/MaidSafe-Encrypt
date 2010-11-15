/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
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

// TODO(Team) remove and replace with maidsafe-dht's identical threadpool

#ifndef MAIDSAFE_SHAREDTEST_THREADPOOL_H_
#define MAIDSAFE_SHAREDTEST_THREADPOOL_H_

#include <boost/thread/condition_variable.hpp>
#include <boost/function.hpp>
#include <boost/thread/thread.hpp>
#include <queue>
#include <vector>

namespace base {

class Threadpool {
 public:
  typedef boost::function<void()> VoidFunctor;
  explicit Threadpool(const boost::uint16_t &thread_count);
  // Resizes to 0 (doesn't complete tasks not already started)
  ~Threadpool();
  // Returns false if a thread resource error is thrown
  bool Resize(const boost::uint16_t &thread_count);
  bool EnqueueTask(const VoidFunctor &functor);
  bool WaitForTasksToFinish(const boost::posix_time::milliseconds &duration);
 private:
  Threadpool(const Threadpool&);
  Threadpool &operator=(const Threadpool&);
  void Run();
  bool Continue();
  bool TimedWait(const boost::posix_time::milliseconds &duration,
                 boost::function<bool()> predicate);
  bool ThreadCountCorrect() {
    return requested_thread_count_ == running_thread_count_;
  }
  bool AllTasksDone() { return remaining_tasks_ == 0U; }
  boost::uint16_t requested_thread_count_, running_thread_count_;
  boost::posix_time::milliseconds default_wait_timeout_;
  size_t remaining_tasks_;
  boost::mutex mutex_;
  boost::condition_variable condition_;
  std::queue<VoidFunctor> functors_;
};

}  // namespace base

#endif  // MAIDSAFE_SHAREDTEST_THREADPOOL_H_
