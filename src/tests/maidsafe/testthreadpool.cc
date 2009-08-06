/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Threadpool class test.
* Version:      1.0
* Created:      2009-08-06-03.12.31
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include <gtest/gtest.h>
#include "maidsafe/threadpool.h"

namespace test_threadpool {

class ThreadedTest {
 public:
  ThreadedTest() : running_(false) {}
  ~ThreadedTest() {}
  void ThreadedFunction(const boost::posix_time::milliseconds &delay,
                        maidsafe::ThreadPool *thread_pool) {
    running_ = true;
    boost::this_thread::at_thread_exit(boost::bind(
        &maidsafe::ThreadPool::DeleteThread, thread_pool,
        boost::this_thread::get_id()));
    boost::this_thread::sleep(delay);
    running_ = false;
  }
 private:
  bool running_;
};

}  // namespace test_threadpool

namespace maidsafe {

class TestThreadPool : public testing::Test {
 protected:
  TestThreadPool() : thread_pool_() {}
  ThreadPool thread_pool_;
 private:
  TestThreadPool(const TestThreadPool&);
  TestThreadPool &operator=(const TestThreadPool&);
};

TEST_F(TestThreadPool, BEH_MAID_ThreadPool) {
  test_threadpool::ThreadedTest test_object;
  // The call to new boost::thread makes an internal copy of test_object, so it
  // needn't be threadsafe.
  for (int i = 0; i < 123; ++i) {
    boost::shared_ptr<boost::thread> thr(new boost::thread(
              &test_threadpool::ThreadedTest::ThreadedFunction, test_object,
              boost::posix_time::milliseconds(500), &thread_pool_));
    thread_pool_.AddThread(thr);
    boost::this_thread::sleep(boost::posix_time::milliseconds(6));
  }
  while (thread_pool_.size())
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
}
}  // namespace maidsafe
