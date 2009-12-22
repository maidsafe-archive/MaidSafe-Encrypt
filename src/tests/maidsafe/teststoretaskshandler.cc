/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for StoreTaskMap Handler
* Version:      1.0
* Created:      2009-12-19-01.23.46
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
#include "maidsafe/client/storetaskshandler.h"

namespace test_store_task_handler {

void AddValidTasksWithoutCb(const size_t &count,
                            maidsafe::StoreTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->AddTask(base::itos(i), maidsafe::kStoreChunk, 3, 1, 0);
}

void AddValidTasksWithCb(const size_t &count,
                         maidsafe::StoreTasksHandler *tasks_handler) {
  base::callback_func_type cb;
  for (size_t i = 1000; i < 1000 + count; ++i)
    tasks_handler->AddTask(base::itos(i), maidsafe::kStoreChunk, 3, 1, 0, cb);
}

void AddInvalidTasks(const size_t &count,
                     maidsafe::StoreTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->AddTask("", maidsafe::kStoreChunk, 3, 1, 0);
}

void StopSubTasksSucceeded(const size_t &count,
                           const std::string &data_name,
                           const maidsafe::StoreTaskType &task_type,
                           maidsafe::StoreTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->StopSubTask(data_name, task_type, true);
}

void StopSubTasksFailed(const size_t &count,
                        const std::string &data_name,
                        const maidsafe::StoreTaskType &task_type,
                        maidsafe::StoreTasksHandler *tasks_handler) {
  for (size_t i = 0; i < count; ++i)
    tasks_handler->StopSubTask(data_name, task_type, false);
}

std::string result;
bool called(false);

void CallbackFunc(const std::string &res) {
  result = res;
  called = true;
}

}  // namespace test_store_task_handler

namespace maidsafe {

class StoreTasksHandlerTest : public testing::Test {
 public:
  StoreTasksHandlerTest() : tasks_handler_() {}
 protected:
  void SetUp() {
    tasks_handler_.ClearTasksHandler();
  }
  void TearDown() {}
  StoreTasksHandler tasks_handler_;
 private:
  StoreTasksHandlerTest &operator=(const StoreTasksHandlerTest&);
  StoreTasksHandlerTest(const StoreTasksHandlerTest&);
};

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskCount) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 3, 1, 1));
  ASSERT_EQ(size_t(1), tasks_handler_.TasksCount());
  for (int i = 0; i < 9; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 1, 1));
  ASSERT_EQ(size_t(10), tasks_handler_.TasksCount());
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskAddWithoutCallback) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add valid task
  ASSERT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 3, 1, 1));
  // Try to add tasks with invalid parameters
  ASSERT_EQ(kStoreTaskIncorrectParameter,
            tasks_handler_.AddTask("", kStoreChunk, 3, 1, 1));
  ASSERT_EQ(kStoreTaskIncorrectParameter,
            tasks_handler_.AddTask("b", kStoreChunk, 1, 1, 1));
  ASSERT_EQ(kStoreTaskIncorrectParameter,
            tasks_handler_.AddTask("b", kStoreChunk, 3, 0, 1));
  // Try to add repeated task
  ASSERT_EQ(kStoreTaskAlreadyExists,
            tasks_handler_.AddTask("a", kStoreChunk, 3, 1, 1));
  ASSERT_EQ(size_t(1), tasks_handler_.TasksCount());
  // Add several valid and invalid tasks on threads
  const size_t kValidCount(37);
  const size_t kValidCountCb(22);
  const size_t kInvalidCount(14);
  boost::thread_group add_thread_group;
  add_thread_group.create_thread(boost::bind(
      &test_store_task_handler::AddValidTasksWithoutCb, kValidCount,
      &tasks_handler_));
  add_thread_group.create_thread(boost::bind(
      &test_store_task_handler::AddValidTasksWithCb, kValidCountCb,
      &tasks_handler_));
  add_thread_group.create_thread(boost::bind(
      &test_store_task_handler::AddInvalidTasks, kInvalidCount,
      &tasks_handler_));
  add_thread_group.join_all();
  ASSERT_EQ(kValidCount + kValidCountCb + 1, tasks_handler_.TasksCount());
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskFindTask) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 1, 1));
  StoreTask find_task("Non empty", kStorePacket, 9, 4, 1);
  ASSERT_FALSE(tasks_handler_.Task("Test", kLoadChunk, &find_task));
  ASSERT_TRUE(find_task.data_name_.empty());
  ASSERT_EQ(kStoreChunk, find_task.task_type_);
  ASSERT_EQ(boost::uint64_t(0), find_task.data_size_);
  ASSERT_EQ(boost::uint8_t(0), find_task.successes_required_);
  ASSERT_EQ(boost::uint8_t(0), find_task.max_failures_);
  ASSERT_EQ(kSuccess, tasks_handler_.AddTask("Test", kLoadChunk, 10, 5, 2));
  ASSERT_TRUE(tasks_handler_.Task("Test", kLoadChunk, &find_task));
  ASSERT_EQ("Test", find_task.data_name_);
  ASSERT_EQ(kLoadChunk, find_task.task_type_);
  ASSERT_EQ(boost::uint64_t(10), find_task.data_size_);
  ASSERT_EQ(boost::uint8_t(5), find_task.successes_required_);
  ASSERT_EQ(boost::uint8_t(2), find_task.max_failures_);
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskSetSuccessesRequired) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 1, 1));
  StoreTask find_task("Non empty", kStorePacket, 9, 4, 1);
  ASSERT_TRUE(tasks_handler_.Task("9", kStoreChunk, &find_task));
  ASSERT_EQ(boost::uint8_t(1), find_task.successes_required_);
  ASSERT_EQ(kSuccess, tasks_handler_.SetSuccessesRequired("9", kStoreChunk, 9));
  ASSERT_EQ(boost::uint8_t(1), find_task.successes_required_);
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskStartSubTask) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 1, 1));
  // Check they're not started
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    ASSERT_FALSE((*it.first).started_);
    ASSERT_EQ(0, (*it.first).active_subtask_count_);
    ASSERT_EQ(size_t(0), (*it.first).exclude_peers_.size());
  }
  // Check we can't start a subtask using invalid credentials
  kad::Contact peer("a", "1", 1, "1", 1);
  ASSERT_EQ(kStoreTaskNotFound,
            tasks_handler_.StartSubTask("a", kStoreChunk, peer));
  ASSERT_EQ(kStoreTaskNotFound,
            tasks_handler_.StartSubTask("9", kStorePacket, peer));
  ASSERT_EQ(size_t(kTaskCount), tasks_handler_.TasksCount());
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    ASSERT_FALSE((*it.first).started_);
    ASSERT_EQ(0, (*it.first).active_subtask_count_);
    ASSERT_EQ(size_t(0), (*it.first).exclude_peers_.size());
  }
  // Start subtask and check it's been started
  ASSERT_EQ(kSuccess, tasks_handler_.StartSubTask("9", kStoreChunk, peer));
  ASSERT_EQ(size_t(kTaskCount), tasks_handler_.TasksCount());
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    if (i == 9) {
      ASSERT_TRUE((*it.first).started_);
      ASSERT_EQ(boost::uint8_t(1), (*it.first).active_subtask_count_);
      ASSERT_EQ(size_t(1), (*it.first).exclude_peers_.size());
      continue;
    }
    ASSERT_FALSE((*it.first).started_);
    ASSERT_EQ(0, (*it.first).active_subtask_count_);
    ASSERT_EQ(size_t(0), (*it.first).exclude_peers_.size());
  }
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskStopSubTask) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 13, 30));
  // Check we can't stop a subtask of a task that's not started
  const int kTester(50);
  kad::Contact peer("a", "1", 1, "1", 1);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(kTester),
                                                           kStoreChunk));
  bool found = (it.first != it.second);
  ASSERT_TRUE(found);
  ASSERT_FALSE((*it.first).started_);
  ASSERT_EQ(0, (*it.first).active_subtask_count_);
  ASSERT_EQ(kStoreTaskHandlerError, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, true));
  ASSERT_FALSE((*it.first).started_);
  ASSERT_EQ(0, (*it.first).active_subtask_count_);
  // Check we can't stop a subtask of a task that's not in the set
  ASSERT_EQ(kStoreTaskNotFound, tasks_handler_.StopSubTask(
      base::itos(kTester), kStorePacket, true));
  // Start subtasks
  const int kRepeats(40);
  for (int i = 0; i < kRepeats; ++i) {
    ASSERT_EQ(kSuccess, tasks_handler_.StartSubTask(base::itos(kTester),
        kStoreChunk, peer));
  }
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(kTester),
                                                           kStoreChunk));
  found = (it.first != it.second);
  ASSERT_TRUE(found);
  ASSERT_TRUE((*it.first).started_);
  ASSERT_EQ(boost::uint8_t(kRepeats), (*it.first).active_subtask_count_);
  ASSERT_EQ(boost::uint8_t(kRepeats), (*it.first).exclude_peers_.size());
  // Call Stop subtasks with valid and invalid data, but not enough to end task
  const size_t kValidCount(11);
  const size_t kInvalidCount(23);
  boost::thread_group stop_thread_group;
  stop_thread_group.create_thread(boost::bind(
      &test_store_task_handler::StopSubTasksSucceeded, kValidCount,
      base::itos(kTester), kStoreChunk, &tasks_handler_));
  stop_thread_group.create_thread(boost::bind(
      &test_store_task_handler::StopSubTasksFailed, kInvalidCount,
      base::itos(kTester), kStoreChunk, &tasks_handler_));
  stop_thread_group.join_all();
  // Check counts are OK
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(kTester),
                                                           kStoreChunk));
  found = (it.first != it.second);
  ASSERT_TRUE(found);
  ASSERT_EQ(boost::uint8_t(kRepeats - kValidCount - kInvalidCount),
            (*it.first).active_subtask_count_);
  ASSERT_EQ(size_t(kRepeats), (*it.first).exclude_peers_.size());
  ASSERT_EQ(size_t(kValidCount), (*it.first).success_count_);
  ASSERT_EQ(size_t(kInvalidCount), (*it.first).failures_count_);
  // Call Stop subtasks final twice to end task with overall success
  ASSERT_EQ(kStoreTaskNotFinished, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, true));
  ASSERT_EQ(kStoreTaskFinishedPass, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, true));
  // Manipulate task's internal data to re-activate it
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(kTester),
                                                           kStoreChunk));
  found = (it.first != it.second);
  ASSERT_TRUE(found);
  StoreTask task = (*it.first);
  task.success_count_ = 0;
  task.failures_count_ = 29;
  tasks_handler_.tasks_.replace(it.first, task);
  // Call Stop subtasks to end task with overall failure (max fails)
  ASSERT_EQ(kStoreTaskFinishedFail, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, false));
  // Manipulate task's internal data to re-activate it
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(kTester),
                                                           kStoreChunk));
  found = (it.first != it.second);
  ASSERT_TRUE(found);
  task = (*it.first);
  task.cancelled_ = true;
  task.success_count_ = 0;
  task.failures_count_ = 0;
  task.active_subtask_count_ = 2;
  tasks_handler_.tasks_.replace(it.first, task);
  // Call Stop subtasks final twice to end task with overall failure (cancelled)
  ASSERT_EQ(kStoreTaskNotFinished, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, true));
  ASSERT_EQ(kStoreTaskFinishedFail, tasks_handler_.StopSubTask(
      base::itos(kTester), kStoreChunk, true));
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskDelete) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 13, 30));
  // Check we can't delete a task that's not in the set
  ASSERT_EQ(kStoreTaskNotFound,
            tasks_handler_.DeleteTask("a", kStoreChunk, ""));
  // Check we can delete a task
  ASSERT_EQ(kSuccess, tasks_handler_.DeleteTask("50", kStoreChunk, ""));
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(50),
                                                           kStoreChunk));
  bool found = (it.first != it.second);
  ASSERT_FALSE(found);
  // Add a callback task
  base::callback_func_type cb =
      boost::bind(&test_store_task_handler::CallbackFunc, _1);
  ASSERT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 3, 1, 30, cb));
  test_store_task_handler::result.clear();
  test_store_task_handler::called = false;
  ASSERT_TRUE(test_store_task_handler::result.empty());
  ASSERT_FALSE(test_store_task_handler::called);
  // Check the task runs the callback when deleted
  std::string ok("OK");
  ASSERT_EQ(kSuccess, tasks_handler_.DeleteTask("a", kStoreChunk, ok));
  it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(50),
                                                           kStoreChunk));
  found = (it.first != it.second);
  ASSERT_FALSE(found);
  ASSERT_EQ(ok, test_store_task_handler::result);
  ASSERT_TRUE(test_store_task_handler::called);
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelOne) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 13, 30));
  // Check we can't cancel a task that's not in the set
  ASSERT_EQ(kStoreTaskNotFound,
            tasks_handler_.CancelTask("a", kStoreChunk));
  // Check we can cancel a task
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    ASSERT_FALSE((*it.first).cancelled_);
  }
  ASSERT_EQ(kSuccess, tasks_handler_.CancelTask("50", kStoreChunk));
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    if (i == 50) {
      ASSERT_TRUE((*it.first).cancelled_);
      continue;
    }
    ASSERT_FALSE((*it.first).cancelled_);
  }
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelAll) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 13, 30));
  // Check we can cancel all tasks
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    ASSERT_FALSE((*it.first).cancelled_);
  }
  tasks_handler_.CancelAllPendingTasks();
  for (int i = 0; i < kTaskCount; ++i) {
    it = tasks_handler_.tasks_.equal_range(boost::make_tuple(base::itos(i),
                                                             kStoreChunk));
    bool found = (it.first != it.second);
    ASSERT_TRUE(found);
    ASSERT_TRUE((*it.first).cancelled_);
  }
}

TEST_F(StoreTasksHandlerTest, BEH_MAID_StoreTaskClearAll) {
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Add tasks
  const int kTaskCount(100);
  for (int i = 0; i < kTaskCount; ++i)
    ASSERT_EQ(kSuccess,
              tasks_handler_.AddTask(base::itos(i), kStoreChunk, 3, 13, 30));
  // Add a callback task
  base::callback_func_type cb =
      boost::bind(&test_store_task_handler::CallbackFunc, _1);
  ASSERT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 3, 1, 30, cb));
  test_store_task_handler::result.clear();
  test_store_task_handler::called = false;
  ASSERT_TRUE(test_store_task_handler::result.empty());
  ASSERT_FALSE(test_store_task_handler::called);
  ASSERT_EQ(size_t(kTaskCount + 1), tasks_handler_.TasksCount());
  // Check we can clear all tasks
  tasks_handler_.ClearTasksHandler();
  ASSERT_EQ(size_t(0), tasks_handler_.TasksCount());
  // Check callback wasn't run
  ASSERT_TRUE(test_store_task_handler::result.empty());
  ASSERT_FALSE(test_store_task_handler::called);
}

}  // namespace maidsafe
