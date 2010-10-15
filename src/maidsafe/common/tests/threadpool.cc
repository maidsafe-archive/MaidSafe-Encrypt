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

#include "tests/maidsafe/threadpool.h"

namespace base {

Threadpool::Threadpool(const boost::uint16_t &thread_count)
    : requested_thread_count_(thread_count),
      running_thread_count_(0),
      default_wait_timeout_(100),
      remaining_tasks_(0),
      mutex_(),
      condition_(),
      functors_() {
  Resize(requested_thread_count_);
  TimedWait(default_wait_timeout_,
            boost::bind(&Threadpool::ThreadCountCorrect, this));
}

Threadpool::~Threadpool() {
  {
    boost::mutex::scoped_lock lock(mutex_);
    while (!functors_.empty())
      functors_.pop();
  }
  Resize(0);
  TimedWait(default_wait_timeout_,
            boost::bind(&Threadpool::ThreadCountCorrect, this));
}

bool Threadpool::Resize(const boost::uint16_t &thread_count) {
  boost::mutex::scoped_lock lock(mutex_);
  requested_thread_count_ = thread_count;
  boost::int32_t difference = requested_thread_count_ - running_thread_count_;
  if (difference > 0) {
    for (int i = 0; i < difference; ++i) {
      try {
        boost::thread(&Threadpool::Run, this);
      }
      catch(const std::exception &e) {
#ifdef DEBUG
        printf("Exception resizing threadpool to %u threads: %s\n",
               requested_thread_count_, e.what());
#endif
        return false;
      }
    }
  } else if (difference < 0) {
    condition_.notify_all();
  }
  return true;
}

bool Threadpool::EnqueueTask(const VoidFunctor &functor) {
  boost::mutex::scoped_lock lock(mutex_);
  if (requested_thread_count_ == 0)
    return false;
  functors_.push(functor);
  ++remaining_tasks_;
  condition_.notify_all();
  return true;
}

bool Threadpool::Continue() {
  return (requested_thread_count_ < running_thread_count_) ||
         !functors_.empty();
}

void Threadpool::Run() {
  {
    boost::mutex::scoped_lock lock(mutex_);
    ++running_thread_count_;
    condition_.notify_all();
  }
  bool run(true);
  while (run) {
    boost::mutex::scoped_lock lock(mutex_);
    condition_.wait(lock, boost::bind(&Threadpool::Continue, this));
    run = requested_thread_count_ >= running_thread_count_;
    if (!run) {
      --running_thread_count_;
    } else {
      // grab the first functor from the queue, but allow other threads to
      // operate while executing it
      VoidFunctor functor = functors_.front();
      functors_.pop();
      lock.unlock();
      functor();
      lock.lock();
      --remaining_tasks_;
    }
    condition_.notify_all();
  }
}

bool Threadpool::WaitForTasksToFinish(
    const boost::posix_time::milliseconds &duration) {
  return TimedWait(duration, boost::bind(&Threadpool::AllTasksDone, this));
}

bool Threadpool::TimedWait(const boost::posix_time::milliseconds &duration,
                           boost::function<bool()> predicate) {
  try {
    boost::mutex::scoped_lock lock(mutex_);
    return condition_.timed_wait(lock, duration, predicate);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Threadpool::TimedWait: %s\n", e.what());
#endif
    return false;
  }
}

}  // namespace base
