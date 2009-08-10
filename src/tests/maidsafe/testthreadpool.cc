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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <gtest/gtest.h>
#include <vector>
// #include "maidsafe/threadpool.h"
#include "boost/threadpool.hpp"

namespace test_threadpool {

class Task {
 public:
  Task() {}
  ~Task() {}
  void TaskFunction(const int &task_no,
                    const int &delay,
                    std::vector<int> *result_order,
                    boost::mutex *mutex) {
    printf("Started Task %i - sleeping for %i milliseconds.\n", task_no, delay);
    boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
    {
      boost::mutex::scoped_lock lock(*mutex);
      result_order->push_back(task_no);
    }
    printf("Finished Task %i\n", task_no);
  }
};

}  // namespace test_threadpool

namespace maidsafe {

class TestThreadPool : public testing::Test {
 protected:
  TestThreadPool() {}
  ~TestThreadPool() {}
//  ThreadPool thread_pool_;
 private:
  TestThreadPool(const TestThreadPool&);
  TestThreadPool &operator=(const TestThreadPool&);
};

TEST_F(TestThreadPool, BEH_MAID_ThreadPool) {
  test_threadpool::Task task;
  std::vector<int> result_order;
  boost::mutex result_order_mutex;
  // Create a thread pool.
  boost::threadpool::pool tp(2);
  // Add some tasks to the pool.
  tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 0,
                          50, &result_order, &result_order_mutex));
  tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 1,
                          3000, &result_order, &result_order_mutex));
  tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 2,
                          150, &result_order, &result_order_mutex));
  tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 3,
                          100, &result_order, &result_order_mutex));
  tp.wait();
  ASSERT_EQ(static_cast<unsigned int>(4), result_order.size());
  ASSERT_EQ(0, result_order.at(0));
  ASSERT_EQ(2, result_order.at(1));
  ASSERT_EQ(3, result_order.at(2));
  ASSERT_EQ(1, result_order.at(3));
}

TEST_F(TestThreadPool, BEH_MAID_ThreadPoolCancel) {
  test_threadpool::Task task;
  std::vector<int> result_order;
  boost::mutex result_order_mutex;
  {
    // Create a thread pool.
    boost::threadpool::thread_pool<boost::threadpool::task_func,
                                   boost::threadpool::fifo_scheduler,
                                   boost::threadpool::static_size,
                                   boost::threadpool::resize_controller,
                                   boost::threadpool::immediately> tp(2);
    // Add some tasks to the pool.
    tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 0,
                            50, &result_order, &result_order_mutex));
    tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 1,
                            10000, &result_order, &result_order_mutex));
    tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 2,
                            150, &result_order, &result_order_mutex));
    tp.schedule(boost::bind(&test_threadpool::Task::TaskFunction, &task, 3,
                            100, &result_order, &result_order_mutex));
    boost::this_thread::sleep(boost::posix_time::milliseconds(400));
  }
  ASSERT_EQ(static_cast<unsigned int>(3), result_order.size());
  ASSERT_EQ(0, result_order.at(0));
  ASSERT_EQ(2, result_order.at(1));
  ASSERT_EQ(3, result_order.at(2));
}
}  // namespace maidsafe
