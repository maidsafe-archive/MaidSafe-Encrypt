/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for StoreManagerTasksHandler
* Created:      2009-12-19
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
#include <boost/thread/thread.hpp>
#include "maidsafe/client/storemanagertaskshandler.h"

namespace test_msm_tasks_handler {

void AddValidTasksWithoutCb(const size_t &count,
                            maidsafe::StoreManagerTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->AddTask(base::IntToString(i), maidsafe::kStoreChunk,
                           1, 0);
}

void AddValidTasksWithCb(const size_t &count,
                         maidsafe::StoreManagerTasksHandler *tasks_handler) {
  maidsafe::VoidFuncOneInt cb;
  for (size_t i = 1000; i < 1000 + count; ++i)
    tasks_handler->AddTask(base::IntToString(i), maidsafe::kStoreChunk,
                           1, 0, cb);
}

void AddInvalidTasks(const size_t &count,
                     maidsafe::StoreManagerTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->AddTask("", maidsafe::kStoreChunk, 0, 0);
}

void TaskCompletionCallback(const maidsafe::ReturnCode &reason,
                            const maidsafe::ReturnCode &expected_reason,
                            int *counter,
                            const int &expected_counter) {
  EXPECT_EQ(expected_reason, reason);
  EXPECT_EQ(expected_counter, *counter);
  ++(*counter);
}

}  // namespace test_msm_tasks_handler

namespace maidsafe {

class MSMTasksHandlerTest : public testing::Test {
 public:
  MSMTasksHandlerTest() : tasks_handler_() {}
 protected:
  void SetUp() {
    tasks_handler_.ClearTasksHandler();
  }
  void TearDown() {}
  StoreManagerTasksHandler tasks_handler_;
 private:
  MSMTasksHandlerTest &operator=(const MSMTasksHandlerTest&);
  MSMTasksHandlerTest(const MSMTasksHandlerTest&);
};

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskCount) {
  EXPECT_EQ(size_t(0), tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(1), tasks_handler_.TasksCount());
  for (int i = 0; i < 9; ++i)
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddTask(base::IntToString(i), kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(10), tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskAddWithoutCallback) {
  EXPECT_EQ(size_t(0), tasks_handler_.TasksCount());

  // Add valid task
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("aaa", kStoreChunk, 1, 0));

  // Try to add tasks with invalid parameters
  EXPECT_EQ(kStoreManagerTaskIncorrectParameter,
            tasks_handler_.AddTask("", kStoreChunk, 1, 0));
  EXPECT_EQ(kStoreManagerTaskIncorrectParameter,
            tasks_handler_.AddTask("bbb", kStoreChunk, 0, 0));

  // Try to add repeated task
  EXPECT_EQ(kStoreManagerTaskAlreadyExists,
            tasks_handler_.AddTask("aaa", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(1), tasks_handler_.TasksCount());

  // Replace existing inactive task
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("ccc", kStoreChunk, 1, 0));
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess("ccc"));
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("ccc", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(2), tasks_handler_.TasksCount());

  // Replace existing store task with delete task
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("ccc", kDeleteChunk, 1, 0));
  EXPECT_EQ(size_t(2), tasks_handler_.TasksCount());

  // Add several valid and invalid tasks on threads
  const size_t kValidCount(370);
  const size_t kValidCountCb(220);
  const size_t kInvalidCount(20);
  boost::thread_group add_thread_group;
  add_thread_group.create_thread(boost::bind(
      &test_msm_tasks_handler::AddValidTasksWithoutCb, kValidCount,
      &tasks_handler_));
  add_thread_group.create_thread(boost::bind(
      &test_msm_tasks_handler::AddValidTasksWithCb, kValidCountCb,
      &tasks_handler_));
  add_thread_group.create_thread(boost::bind(
      &test_msm_tasks_handler::AddInvalidTasks, kInvalidCount,
      &tasks_handler_));
  add_thread_group.join_all();
  ASSERT_EQ(kValidCount + kValidCountCb + 2, tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskHasTask) {
  EXPECT_EQ(size_t(0), tasks_handler_.TasksCount());
  EXPECT_FALSE(tasks_handler_.HasTask("abc", NULL, NULL));
  StoreManagerTaskType task_type;
  StoreManagerTaskStatus task_status;
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("abc", kStoreChunk, 1, 0));
  EXPECT_TRUE(tasks_handler_.HasTask("abc", &task_type, &task_status));
  EXPECT_EQ(kStoreChunk, task_type);
  EXPECT_EQ(kTaskActive, task_status);
  EXPECT_EQ(size_t(1), tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskAddChildTask) {
  EXPECT_EQ(size_t(0), tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("parent", kStoreChunk, 1, 0));
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.AddChildTask("child", "fail", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(1), tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddChildTask("child", "parent", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(2), tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess, tasks_handler_.CancelTask("parent", kGeneralError));
  EXPECT_EQ(kStoreManagerTaskParentNotActive,
            tasks_handler_.AddChildTask("child2", "parent", kStoreChunk, 1, 0));
  EXPECT_EQ(size_t(2), tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskNotifications) {
  EXPECT_EQ(kStoreManagerTaskNotFound, tasks_handler_.NotifyTaskSuccess("aaa"));
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("aaa", kStoreChunk, 10, 0));
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess("aaa"));
    StoreManagerTaskType task_type;
    StoreManagerTaskStatus task_status;
    EXPECT_TRUE(tasks_handler_.HasTask("aaa", &task_type, &task_status));
    EXPECT_EQ(kStoreChunk, task_type);
    if (i < 9)
      EXPECT_EQ(kTaskActive, task_status);
    else
      EXPECT_EQ(kTaskSucceeded, task_status);
  }

  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.NotifyTaskFailure("bbb", kGeneralError));
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("bbb", kStoreChunk, 1, 10));
  for (int i = 0; i < 11; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure("bbb", kGeneralError));
    StoreManagerTaskType task_type;
    StoreManagerTaskStatus task_status;
    EXPECT_TRUE(tasks_handler_.HasTask("bbb", &task_type, &task_status));
    EXPECT_EQ(kStoreChunk, task_type);
    if (i < 10)
      EXPECT_EQ(kTaskActive, task_status);
    else
      EXPECT_EQ(kTaskFailed, task_status);
  }
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskHierarchy) {
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("root", kStoreChunk, 1, 0));
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddChildTask("0", "root", kStoreChunk, 1, 0));
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask(base::IntToString(i),
                                          base::IntToString(i - 1),
                                          kStoreChunk, 1, 0));
  }

  EXPECT_EQ(size_t(101), tasks_handler_.TasksCount());
  StoreManagerTaskStatus task_status;
  EXPECT_TRUE(tasks_handler_.HasTask("root", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("99", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);

  EXPECT_EQ(kStoreManagerTaskIncorrectOperation,
            tasks_handler_.NotifyTaskSuccess("root"));
  EXPECT_EQ(kStoreManagerTaskIncorrectOperation,
            tasks_handler_.NotifyTaskSuccess("23"));
  EXPECT_EQ(kStoreManagerTaskIncorrectOperation,
            tasks_handler_.NotifyTaskSuccess("98"));
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess("99"));

  EXPECT_TRUE(tasks_handler_.HasTask("root", NULL, &task_status));
  EXPECT_EQ(kTaskSucceeded, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("99", NULL, &task_status));
  EXPECT_EQ(kTaskSucceeded, task_status);
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskCallbacks) {
  int counter(0);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("root", kStoreChunk, 1, 1,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 8)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_1", "root",
                                                  kStoreChunk, 2, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kGeneralError, &counter, 4)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_2", "root",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 6)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_3", "root",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 7)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_1_1", "child_1",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 1)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_1_2", "child_1",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kGeneralError, &counter, 3)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_1_1_1", "child_1_1",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 0)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_1_2_1", "child_1_2",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kGeneralError, &counter, 2)));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("child_2_1", "child_2",
                                                  kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 5)));
  EXPECT_EQ(size_t(9), tasks_handler_.TasksCount());

  /**
   *               child_1_1 -- child_1_1_1  (succeed)
   *              /
   *       child_1
   *      /       \
   *  root         child_1_2 -- child_1_2_1  (fail)
   *     |
   *     +-- child_2 -- child_2_1  (succeed)
   *     |
   *     `-- child_3  (auto-cancel)
   */

  StoreManagerTaskStatus task_status;
  EXPECT_TRUE(tasks_handler_.HasTask("root", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);

  // success for child_1_1_1, child_1 then will need 1 more
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess("child_1_1_1"));

  EXPECT_TRUE(tasks_handler_.HasTask("child_1", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);
  EXPECT_EQ(2, counter);

  // failure for child_1_2_1, child_1 will fail, root needs one success
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure("child_1_2_1",
                                                      kGeneralError));

  EXPECT_TRUE(tasks_handler_.HasTask("child_1", NULL, &task_status));
  EXPECT_EQ(kTaskFailed, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("root", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);
  EXPECT_EQ(5, counter);

  // success for child_2_1, results in success for root
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess("child_2_1"));

  EXPECT_TRUE(tasks_handler_.HasTask("child_2", NULL, &task_status));
  EXPECT_EQ(kTaskSucceeded, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("child_3", NULL, &task_status));
  EXPECT_EQ(kTaskCancelled, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("root", NULL, &task_status));
  EXPECT_EQ(kTaskSucceeded, task_status);
  EXPECT_EQ(9, counter);
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskCancelTasks) {
  int counter(0);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("0", kStoreChunk, 1, 0,
            boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                        kSuccess, &counter, 99)));
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask(base::IntToString(i),
                                                    base::IntToString(i - 1),
                                                    kStoreChunk, 1, 0,
              boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                          kSuccess, &counter, 99 - i)));
  }
  for (int i = 100; i < 200; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.AddTask(base::IntToString(i),
                                               kStoreChunk, 1, 0,
              boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                          kGeneralError, &counter, i)));
  }
  EXPECT_EQ(size_t(200), tasks_handler_.TasksCount());

  EXPECT_EQ(kSuccess, tasks_handler_.CancelTask("0", kSuccess));

  StoreManagerTaskStatus task_status;
  EXPECT_TRUE(tasks_handler_.HasTask("0", NULL, &task_status));
  EXPECT_EQ(kTaskCancelled, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("23", NULL, &task_status));
  EXPECT_EQ(kTaskCancelled, task_status);
  EXPECT_TRUE(tasks_handler_.HasTask("123", NULL, &task_status));
  EXPECT_EQ(kTaskActive, task_status);
  EXPECT_EQ(100, counter);

  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.CancelTask("abc", kSuccess));

  tasks_handler_.CancelAllPendingTasks(kGeneralError);

  EXPECT_TRUE(tasks_handler_.HasTask("123", NULL, &task_status));
  EXPECT_EQ(kTaskCancelled, task_status);
  EXPECT_EQ(200, counter);
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StoreTaskClearTasks) {
  int counter(0);
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.AddTask(base::IntToString(i),
                                               kStoreChunk, 1, 0,
              boost::bind(&test_msm_tasks_handler::TaskCompletionCallback, _1,
                          kSuccess, &counter, i)));
  }
  EXPECT_EQ(size_t(100), tasks_handler_.TasksCount());
  EXPECT_TRUE(tasks_handler_.HasTask("23", NULL, NULL));

  tasks_handler_.ClearTasksHandler();

  EXPECT_FALSE(tasks_handler_.HasTask("23", NULL, NULL));
  EXPECT_EQ(size_t(0), tasks_handler_.TasksCount());
  EXPECT_EQ(0, counter);  // no callbacks
}

}  // namespace maidsafe
