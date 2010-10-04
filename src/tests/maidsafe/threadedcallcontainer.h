/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Created:      2010-09-30
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

#ifndef TESTS_MAIDSAFE_THREADEDCALLCONTAINER_H_
#define TESTS_MAIDSAFE_THREADEDCALLCONTAINER_H_

#include <queue>
#include "maidsafe/maidsafe.h"

namespace maidsafe {

typedef boost::function<void()> VoidFunc;

/**
 * This is a thread pool, which takes boost functors and executes them in order.
 */
class ThreadedCallContainer {
 public:
  explicit ThreadedCallContainer(const size_t &num_threads)
    : running_(false), mutex_(), condition_(), threads_(), callbacks_() {
    for (size_t i = 0; i < num_threads; ++i) {
      threads_.push_back(new boost::thread(boost::bind(
          &ThreadedCallContainer::Run, this)));
    }
  }
  ~ThreadedCallContainer() {
    {
      boost::mutex::scoped_lock lock(mutex_);
      running_ = false;
      condition_.notify_all();
    }
    for (size_t i = 0; i < threads_.size(); ++i) {
      threads_[i]->join();
      delete threads_[i];
    }
  }
  void Enqueue(VoidFunc callback) {
    boost::mutex::scoped_lock lock(mutex_);
    if (!running_)
      return;
    callbacks_.push(callback);
    condition_.notify_all();
  }
  void Wait() {
    boost::mutex::scoped_lock lock(mutex_);
    while (running_ && !callbacks_.empty())
      condition_.wait(lock);
  }
 private:
  ThreadedCallContainer(const ThreadedCallContainer&);
  ThreadedCallContainer &operator=(const ThreadedCallContainer&);
  void Run() {
    boost::mutex::scoped_lock lock(mutex_);
    running_ = true;
    while (running_) {
      while (running_ && callbacks_.empty()) {
        condition_.wait(lock);
      }
      while (!callbacks_.empty()) {
        // grab the first cb from the queue, but allow other threads to operate
        // while executing it
        VoidFunc f = callbacks_.front();
        mutex_.unlock();
        f();
        mutex_.lock();
        callbacks_.pop();
        condition_.notify_all();
      }
    }
  }
  bool running_;
  boost::mutex mutex_;
  boost::condition_variable condition_;
  std::vector<boost::thread*> threads_;
  std::queue<VoidFunc> callbacks_;
};

}  // namespace maidsafe

#endif  // TESTS_MAIDSAFE_THREADEDCALLCONTAINER_H_
