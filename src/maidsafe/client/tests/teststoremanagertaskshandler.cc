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
#include <boost/concept_check.hpp>
#include <algorithm>
#include "maidsafe/client/storemanagertaskshandler.h"

namespace test_msm_tasks_handler {

const maidsafe::StoreManagerTaskType kMaxTaskType(maidsafe::kModifyPacket);

void AddValidTasksWithoutCb(
    const size_t &count,
    maidsafe::StoreManagerTasksHandler *tasks_handler) {
  maidsafe::TaskId task_id;
  for (size_t i = 0; i < count; ++i) {
    maidsafe::StoreManagerTaskType task_type =
        static_cast<maidsafe::StoreManagerTaskType>(i % (kMaxTaskType + 1));
    tasks_handler->AddTask(base::IntToString(i), task_type, 1, 0, NULL,
                           &task_id);
  }
}

void AddValidTasksWithCb(const size_t &count,
                         maidsafe::StoreManagerTasksHandler *tasks_handler) {
  maidsafe::VoidFuncTaskIdInt cb;
  maidsafe::TaskId task_id;
  for (size_t i = 1000; i < 1000 + count; ++i) {
    maidsafe::StoreManagerTaskType task_type =
        static_cast<maidsafe::StoreManagerTaskType>(i % (kMaxTaskType + 1));
    tasks_handler->AddTask(base::IntToString(i), task_type, 1, 0, cb,
                           &task_id);
  }
}

void AddInvalidTasks(const size_t &count,
                     maidsafe::StoreManagerTasksHandler *tasks_handler) {
  maidsafe::TaskId task_id;
  for (size_t i = 0; i < count; ++i) {
    maidsafe::StoreManagerTaskType task_type =
        static_cast<maidsafe::StoreManagerTaskType>(i % (kMaxTaskType + 1));
    tasks_handler->AddTask("", task_type, 0, 0, NULL, &task_id);
  }
}

void TaskCompletionCallback(
    const maidsafe::TaskId &task_id,
    const maidsafe::ReturnCode &reason,
    std::vector< std::pair<maidsafe::TaskId, maidsafe::ReturnCode> > *cbs) {
//  printf("Callback: Task %i - result %i\n", task_id, reason);
  cbs->push_back(std::pair<maidsafe::TaskId, maidsafe::ReturnCode>(task_id,
                                                                   reason));
}

void DeleteTaskCallback(
    const maidsafe::TaskId &task_id,
    const maidsafe::ReturnCode &reason,
    std::vector< std::pair<maidsafe::TaskId, maidsafe::ReturnCode> > *cbs,
    maidsafe::StoreManagerTasksHandler *tasks_handler,
    maidsafe::TaskId *deletable_task_id) {
  TaskCompletionCallback(task_id, reason, cbs);
  tasks_handler->DeleteTask(*deletable_task_id, reason);
}

}  // namespace test_msm_tasks_handler

namespace maidsafe {

namespace test {

typedef std::pair<TaskId, ReturnCode> TaskReturn;

class MSMTasksHandlerTest : public testing::Test {
 public:
  MSMTasksHandlerTest()
      : tasks_handler_(),
        task_types_(),
        kMaxTask_(static_cast<int>(test_msm_tasks_handler::kMaxTaskType)),
        results_(),
        functor_(boost::bind(&test_msm_tasks_handler::TaskCompletionCallback,
                             _1, _2, &results_)) {}
 protected:
  void SetUp() {
    // It's horrible, but it gets the job done :-)
    task_types_.push_back(kStoreChunk);
    task_types_.push_back(kAddToWatchListMaster);
    task_types_.push_back(kAddToWatchList);
    task_types_.push_back(kSpaceTakenIncConfirmation);
    task_types_.push_back(kChunkCopyMaster);
    task_types_.push_back(kChunkCopy);
    task_types_.push_back(kChunkCopyPrep);
    task_types_.push_back(kChunkCopyData);
    task_types_.push_back(kStorePacket);
    task_types_.push_back(kLoadChunk);
    task_types_.push_back(kLoadPacket);
    task_types_.push_back(kDeleteChunk);
    task_types_.push_back(kRemoveFromWatchListMaster);
    task_types_.push_back(kRemoveFromWatchList);
    task_types_.push_back(kSpaceTakenDecConfirmation);
    task_types_.push_back(kDeletePacket);
    task_types_.push_back(test_msm_tasks_handler::kMaxTaskType);
    for (int i = 0; i < 17; ++i)
      ASSERT_EQ(i, static_cast<int>(task_types_.at(i))) << "StoreManagerTaskTyp"
                "e has been modified.  Check test_msm_tasks_handler::MaxTaskTyp"
                "e is still correct.";
  }
  void TearDown() {}
  StoreManagerTasksHandler tasks_handler_;
  std::vector<StoreManagerTaskType> task_types_;
  const int kMaxTask_;
  std::vector<TaskReturn> results_;
  VoidFuncTaskIdInt functor_;
 private:
  MSMTasksHandlerTest &operator=(const MSMTasksHandlerTest&);
  MSMTasksHandlerTest(const MSMTasksHandlerTest&);
};

TEST_F(MSMTasksHandlerTest, BEH_MAID_TaskCount) {
  EXPECT_EQ(0U, tasks_handler_.TasksCount());
  TaskId task_id(kRootTask);
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 1, 0, NULL, &task_id));
  EXPECT_NE(kRootTask, task_id);
  EXPECT_EQ(1U, tasks_handler_.TasksCount());
  for (int i = 0; i < 9; ++i) {
    task_id = kRootTask;
    EXPECT_EQ(kSuccess, tasks_handler_.AddTask(base::IntToString(i),
                                               kStoreChunk, 1, 0, NULL,
                                               &task_id));
    EXPECT_NE(kRootTask, task_id);
  }
  EXPECT_EQ(10U, tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_StatusAndName) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  std::vector<TaskId> task_ids;
  const int kTestSize(4);
  for (int i = 0; i < kTestSize; ++i) {
    task_ids.push_back(kRootTask);
    EXPECT_EQ(kSuccess, tasks_handler_.AddTask(base::IntToString(i),
                                               kStoreChunk, 1, 0, NULL,
                                               &task_ids.at(i)));
    EXPECT_NE(kRootTask, task_ids.at(i));
  }
  for (int i = 0; i < kTestSize; ++i) {
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_ids.at(i)));
    EXPECT_EQ(base::IntToString(i), tasks_handler_.DataName(task_ids.at(i)));
  }
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(task_ids.at(0)));
  EXPECT_EQ(kTaskSucceeded, tasks_handler_.Status(task_ids.at(0)));
  EXPECT_EQ("0", tasks_handler_.DataName(task_ids.at(0)));
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure(task_ids.at(1),
                                                       kSuccess));
  EXPECT_EQ(kTaskFailed, tasks_handler_.Status(task_ids.at(1)));
  EXPECT_EQ("1", tasks_handler_.DataName(task_ids.at(1)));
  EXPECT_EQ(kSuccess, tasks_handler_.CancelTask(task_ids.at(2), kSuccess));
  EXPECT_EQ(kTaskCancelled, tasks_handler_.Status(task_ids.at(2)));
  EXPECT_EQ("2", tasks_handler_.DataName(task_ids.at(2)));
  EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_ids.at(3)));
  EXPECT_EQ("3", tasks_handler_.DataName(task_ids.at(3)));
  EXPECT_EQ(kNotATask, tasks_handler_.Status(task_ids.at(3) + 1));
  EXPECT_TRUE(tasks_handler_.DataName(task_ids.at(3) + 1).empty());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_GetByNameAndType) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  std::vector<TaskId> task_ids;
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, NULL,
                                             &task_ids.at(0)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("b", kStoreChunk, 1, 0, NULL,
                                             &task_ids.at(1)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kLoadChunk, 1, 0, NULL,
                                             &task_ids.at(2)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("b", kLoadChunk, 1, 0, NULL,
                                             &task_ids.at(3)));
  boost::this_thread::sleep(boost::posix_time::milliseconds(1010));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, NULL,
                                             &task_ids.at(4)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("b", kStoreChunk, 1, 0, NULL,
                                             &task_ids.at(5)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kLoadChunk, 1, 0, NULL,
                                             &task_ids.at(6)));
  task_ids.push_back(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("b", kLoadChunk, 1, 0, NULL,
                                             &task_ids.at(7)));
  EXPECT_EQ(task_ids.at(0),
      tasks_handler_.GetOldestActiveTaskByDataNameAndType("a", kStoreChunk));
  EXPECT_EQ(task_ids.at(1),
      tasks_handler_.GetOldestActiveTaskByDataNameAndType("b", kStoreChunk));
  EXPECT_EQ(task_ids.at(2),
      tasks_handler_.GetOldestActiveTaskByDataNameAndType("a", kLoadChunk));
  EXPECT_EQ(task_ids.at(3),
      tasks_handler_.GetOldestActiveTaskByDataNameAndType("b", kLoadChunk));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_AddWithoutCallback) {
  EXPECT_EQ(0U, tasks_handler_.TasksCount());

  // Add valid task
  TaskId store_task1_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("aaa", kStoreChunk, 1, 0, NULL,
                                             &store_task1_id));
  EXPECT_NE(kRootTask, store_task1_id);
  EXPECT_EQ(1U, tasks_handler_.TasksCount());

  // Try to add tasks with invalid parameters
  TaskId bad_task_id(store_task1_id);
  EXPECT_EQ(kStoreManagerTaskIncorrectParameter,
            tasks_handler_.AddTask("", kStoreChunk, 1, 0, NULL, &bad_task_id));
  EXPECT_EQ(kRootTask, bad_task_id);
  bad_task_id = store_task1_id;
  EXPECT_EQ(kStoreManagerTaskIncorrectParameter,
            tasks_handler_.AddTask("b", kStoreChunk, 0, 0, NULL, &bad_task_id));
  EXPECT_EQ(kRootTask, bad_task_id);
  EXPECT_EQ(1U, tasks_handler_.TasksCount());

  // Add repeated task after waiting > 1 sec
  boost::this_thread::sleep(boost::posix_time::milliseconds(1001));
  TaskId store_task2_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("aaa", kStoreChunk, 1, 0, NULL,
                                             &store_task2_id));
  EXPECT_NE(kRootTask, store_task2_id);
  EXPECT_NE(store_task1_id, store_task2_id);
  EXPECT_EQ(2U, tasks_handler_.TasksCount());

  // Replace existing (oldest) store task with delete task
  TaskId delete_task1_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("aaa", kDeleteChunk, 1, 0, NULL,
                                             &delete_task1_id));
  EXPECT_EQ(kNotATask, tasks_handler_.Status(store_task1_id));
  EXPECT_EQ(kTaskActive, tasks_handler_.Status(store_task2_id));
  EXPECT_EQ(kNotATask, tasks_handler_.Status(delete_task1_id));

  EXPECT_EQ(kRootTask, delete_task1_id);
  EXPECT_EQ(1U, tasks_handler_.TasksCount());

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
  ASSERT_EQ(kValidCount + kValidCountCb + 1, tasks_handler_.TasksCount());
}

testing::AssertionResult TaskReturnsAsExpected(
    const std::vector<TaskReturn> &expected_results,
    const std::vector<TaskReturn> &actual_results) {
  if (expected_results.size() != actual_results.size())
    return testing::AssertionFailure() << "expected_results size (" <<
        expected_results.size() << ") != actual_results size (" <<
        actual_results.size() << ")";
  for (size_t i = 0; i < actual_results.size(); ++i) {
    if (expected_results.at(i).first != actual_results.at(i).first ||
        expected_results.at(i).second != actual_results.at(i).second)
      return testing::AssertionFailure() << "expected_result " << i <<
          ": task_id " << expected_results.at(i).first << ", return_code " <<
          expected_results.at(i).second << " --- actual_result " << i <<
          ": task_id " << actual_results.at(i).first << ", return_code " <<
          actual_results.at(i).second;
  }
  return testing::AssertionSuccess();
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_AddConflictingTasks) {
  std::vector<TaskReturn> expected_results;
  for (int i = 0; i < 4; ++i) {
    // Add one of every task type with callbacks
    std::string data_name;
    TaskId task_id(kRootTask);
    for (int j = 0; j <= kMaxTask_; ++j) {
      data_name = base::IntToString(j);
      StoreManagerTaskType task_type = static_cast<StoreManagerTaskType>(j);
      EXPECT_EQ(kSuccess, tasks_handler_.AddTask(data_name, task_type, 1, 0,
                                                 functor_, &task_id));
      EXPECT_NE(kRootTask, task_id);
      if ((i == 0 && j == 11) || (i == 1 && j == 15) ||
          (i == 2 && j == 0) || (i == 3 && j == 8)) {
        expected_results.push_back(TaskReturn(task_id,
            kStoreManagerTaskCancelledOrDone));
      }
    }
    StoreManagerTaskType conflicting_type;
    switch (i) {
      case 0:  // kStoreChunk (0) conflicts with kDeleteChunk (11)
        conflicting_type = kStoreChunk;
        data_name = base::IntToString(11);
        break;
      case 1:  // kStorePacket (8) conflicts with kDeletePacket (15)
        conflicting_type = kStorePacket;
        data_name = base::IntToString(15);
        break;
      case 2:  // kDeleteChunk (11) conflicts with kStoreChunk (0)
        conflicting_type = kDeleteChunk;
        data_name = base::IntToString(0);
        break;
      case 3:  // kDeletePacket (15) conflicts with kStorePacket (8)
        conflicting_type = kDeletePacket;
        data_name = base::IntToString(8);
        break;
      default:
        FAIL();
    }
    EXPECT_EQ(kSuccess, tasks_handler_.AddTask(data_name, conflicting_type, 1,
                                               0, functor_, &task_id));
    EXPECT_EQ(kRootTask, task_id);
    EXPECT_EQ(kMaxTask_, tasks_handler_.TasksCount());
    tasks_handler_.ClearTasksHandler();
  }
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_AddChildTask) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  EXPECT_EQ(100U, tasks_handler_.TasksCount());
  TaskId parent_task_id(kRootTask);
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 1, 0, NULL,
                                   &parent_task_id));
  TaskId child_task_id(kRootTask + 1);
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.AddChildTask("a", parent_task_id + 1, kStoreChunk,
                                        1, 0, NULL, &child_task_id));
  EXPECT_EQ(kRootTask, child_task_id);
  EXPECT_EQ(101U, tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddChildTask("a", parent_task_id, kStoreChunk, 1, 0,
                                        NULL, &child_task_id));
  EXPECT_NE(kRootTask, child_task_id);
  EXPECT_EQ(102U, tasks_handler_.TasksCount());
  EXPECT_EQ(kSuccess, tasks_handler_.CancelTask(parent_task_id, kGeneralError));
  EXPECT_EQ(kStoreManagerTaskParentNotActive,
            tasks_handler_.AddChildTask("a", parent_task_id, kStoreChunk, 1, 0,
                                        NULL, &child_task_id));
  EXPECT_EQ(kRootTask, child_task_id);
  EXPECT_EQ(102U, tasks_handler_.TasksCount());
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_Notifications) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.NotifyTaskSuccess(kRootTask));
  EXPECT_EQ(kStoreManagerTaskNotFound, tasks_handler_.NotifyTaskSuccess(1000));
  TaskId task_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 10, 0, functor_,
                                             &task_id));
  std::vector<TaskReturn> expected_results;
  expected_results.push_back(TaskReturn(task_id, kSuccess));
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(task_id));
    if (i < 9)
      EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_id));
    else
      EXPECT_EQ(kTaskSucceeded, tasks_handler_.Status(task_id));
  }

  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.NotifyTaskFailure(kRootTask, kGeneralError));
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.NotifyTaskFailure(1000, kGeneralError));
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 10, functor_,
                                             &task_id));
  expected_results.push_back(TaskReturn(task_id, kGeneralError));
  for (int i = 0; i < 11; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure(task_id,
                                                         kGeneralError));
    if (i < 10)
      EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_id));
    else
      EXPECT_EQ(kTaskFailed, tasks_handler_.Status(task_id));
  }
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, NULL,
                                             &task_id));
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", task_id, kStoreChunk, 1,
                                                  0, NULL, NULL));
  EXPECT_EQ(kStoreManagerTaskIncorrectOperation,
            tasks_handler_.NotifyTaskSuccess(task_id));
  EXPECT_EQ(kStoreManagerTaskIncorrectOperation,
            tasks_handler_.NotifyTaskFailure(task_id, kGeneralError));
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_GetAndResetProgress) {
  boost::uint8_t succ_req, max_fail, succ_count, fail_count;
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.GetTaskProgress(kRootTask, &succ_req, &max_fail,
                                           &succ_count, &fail_count));
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.GetTaskProgress(1000, &succ_req, &max_fail,
                                           &succ_count, &fail_count));
  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.ResetTaskProgress(kRootTask));
  EXPECT_EQ(kStoreManagerTaskNotFound, tasks_handler_.ResetTaskProgress(1000));
  TaskId task_id(kRootTask);
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 10, 9, functor_,
                                   &task_id));
  EXPECT_EQ(kSuccess,
            tasks_handler_.GetTaskProgress(task_id, &succ_req, &max_fail,
                                           &succ_count, &fail_count));
  EXPECT_EQ(boost::uint8_t(10), succ_req);
  EXPECT_EQ(boost::uint8_t(9), max_fail);
  EXPECT_EQ(boost::uint8_t(0), succ_count);
  EXPECT_EQ(boost::uint8_t(0), fail_count);

  for (int i = 0; i < 9; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(task_id));
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure(task_id,
                                                         kGeneralError));
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_id));
    EXPECT_EQ(kSuccess,
              tasks_handler_.GetTaskProgress(task_id, &succ_req, &max_fail,
                                             &succ_count, &fail_count));
    EXPECT_EQ(boost::uint8_t(10), succ_req);
    EXPECT_EQ(boost::uint8_t(9), max_fail);
    EXPECT_EQ(boost::uint8_t(i + 1), succ_count);
    EXPECT_EQ(boost::uint8_t(i + 1), fail_count);
  }

  EXPECT_EQ(kSuccess, tasks_handler_.ResetTaskProgress(task_id));
  EXPECT_EQ(kSuccess,
            tasks_handler_.GetTaskProgress(task_id, &succ_req, &max_fail,
                                           &succ_count, &fail_count));
  EXPECT_EQ(boost::uint8_t(10), succ_req);
  EXPECT_EQ(boost::uint8_t(9), max_fail);
  EXPECT_EQ(boost::uint8_t(0), succ_count);
  EXPECT_EQ(boost::uint8_t(0), fail_count);

  for (int i = 0; i < 9; ++i) {
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(task_id));
    EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure(task_id,
                                                         kGeneralError));
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(task_id));

    EXPECT_EQ(kSuccess,
              tasks_handler_.GetTaskProgress(task_id, &succ_req, &max_fail,
                                             &succ_count, &fail_count));
    EXPECT_EQ(boost::uint8_t(10), succ_req);
    EXPECT_EQ(boost::uint8_t(9), max_fail);
    EXPECT_EQ(boost::uint8_t(i + 1), succ_count);
    EXPECT_EQ(boost::uint8_t(i + 1), fail_count);
  }
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_TaskHierarchy) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  TaskId parent_task_id(kRootTask), child_task_id(kRootTask);
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddTask("root", kStoreChunk, 1, 0, NULL,
                                   &parent_task_id));
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddChildTask("root", parent_task_id, kStoreChunk, 1,
                                        0, NULL, &child_task_id));
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask("root", child_task_id, kStoreChunk, 1,
                                          0, NULL, &child_task_id));
  }

  EXPECT_EQ(size_t(201), tasks_handler_.TasksCount());
  for (TaskId i = parent_task_id; i <= child_task_id; ++i)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(i));

  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(child_task_id));
  for (TaskId i = parent_task_id; i <= child_task_id; ++i)
    EXPECT_EQ(kTaskSucceeded, tasks_handler_.Status(i));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_TaskCallbacks) {
  test_msm_tasks_handler::AddValidTasksWithoutCb(100, &tasks_handler_);
  std::vector<TaskReturn> expected_results;

  TaskId root_task_id(kRootTask);  // ID 1
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 1, functor_,
                                             &root_task_id));

  TaskId child_1_task_id(kRootTask);  // ID 2
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", root_task_id,
      kChunkCopyMaster, 2, 0, functor_, &child_1_task_id));

  TaskId child_2_task_id(kRootTask);  // ID 3
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", root_task_id,
      kAddToWatchListMaster, 1, 0, functor_, &child_2_task_id));

  TaskId child_3_task_id(kRootTask);  // ID 4
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", root_task_id,
      kSpaceTakenIncConfirmation, 1, 0, functor_, &child_3_task_id));

  TaskId child_1_1_task_id(kRootTask);  // ID 5
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", child_1_task_id,
      kChunkCopy, 1, 0, functor_, &child_1_1_task_id));

  TaskId child_1_2_task_id(kRootTask);  // ID 6
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", child_1_task_id,
      kChunkCopy, 1, 0, functor_, &child_1_2_task_id));

  TaskId child_1_1_1_task_id(kRootTask);  // ID 7
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", child_1_1_task_id,
      kChunkCopyPrep, 1, 0, functor_, &child_1_1_1_task_id));

  TaskId child_1_2_1_task_id(kRootTask);  // ID 8
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", child_1_2_task_id,
      kChunkCopyPrep, 1, 0, functor_, &child_1_2_1_task_id));

  TaskId child_2_1_task_id(kRootTask);  // ID 9
  EXPECT_EQ(kSuccess, tasks_handler_.AddChildTask("a", child_2_task_id,
      kAddToWatchList, 1, 0, functor_, &child_2_1_task_id));

  EXPECT_EQ(109U, tasks_handler_.TasksCount());

  /**
   *               child_1_1 (5) -- child_1_1_1 (7)  (succeed)
   *              /
   *       child_1 (2)
   *      /       \
   *  root (1)     child_1_2 (6) -- child_1_2_1 (8)  (fail)
   *     |
   *     +-- child_2 (3) -- child_2_1 (9)  (succeed)
   *     |
   *     `-- child_3 (4) (auto-cancel)
   */

  EXPECT_EQ(kTaskActive, tasks_handler_.Status(root_task_id));

  // success for child_1_1_1, child_1 then will need 1 more
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(child_1_1_1_task_id));
  expected_results.push_back(TaskReturn(child_1_1_1_task_id, kSuccess));
  expected_results.push_back(TaskReturn(child_1_1_task_id, kSuccess));
  EXPECT_EQ(kTaskActive, tasks_handler_.Status(child_1_task_id));
  EXPECT_EQ(2U, results_.size());

  // failure for child_1_2_1, child_1 will fail, root needs one success
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskFailure(child_1_2_1_task_id,
                                                       kGeneralError));
  expected_results.push_back(TaskReturn(child_1_2_1_task_id, kGeneralError));
  expected_results.push_back(TaskReturn(child_1_2_task_id, kGeneralError));
  expected_results.push_back(TaskReturn(child_1_task_id, kGeneralError));
  EXPECT_EQ(kTaskFailed, tasks_handler_.Status(child_1_task_id));
  EXPECT_EQ(kTaskActive, tasks_handler_.Status(root_task_id));
  EXPECT_EQ(5U, results_.size());

  // success for child_2_1, results in success for root
  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(child_2_1_task_id));
  expected_results.push_back(TaskReturn(child_2_1_task_id, kSuccess));
  expected_results.push_back(TaskReturn(child_2_task_id, kSuccess));
  expected_results.push_back(TaskReturn(child_3_task_id, kSuccess));
  expected_results.push_back(TaskReturn(root_task_id, kSuccess));
  EXPECT_EQ(kTaskSucceeded, tasks_handler_.Status(child_2_task_id));
  EXPECT_EQ(kTaskCancelled, tasks_handler_.Status(child_3_task_id));
  EXPECT_EQ(kTaskSucceeded, tasks_handler_.Status(root_task_id));
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_CancelTasks) {
  std::vector<TaskReturn> expected_results;
  TaskId root_task_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, functor_,
                                             &root_task_id));
  expected_results.push_back(TaskReturn(root_task_id, kNotConnected));

  TaskId task_id1(root_task_id);
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask("a", task_id1, kStoreChunk, 1, 0,
                                          functor_, &task_id1));
    expected_results.push_back(TaskReturn(task_id1, kNotConnected));
  }
  std::reverse(expected_results.begin(), expected_results.end());

  TaskId task_id2(kRootTask);
  for (int i = 100; i < 200; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddTask(base::IntToString(i), kStoreChunk, 1, 0,
                                     functor_, &task_id2));
    expected_results.push_back(TaskReturn(task_id2, kGeneralError));
  }
  EXPECT_EQ(200U, tasks_handler_.TasksCount());
  TaskId id;
  for (id = root_task_id; id <= task_id2; ++id)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(id));

  EXPECT_EQ(kSuccess, tasks_handler_.CancelTask(root_task_id, kNotConnected));
  for (id = root_task_id; id <= task_id1; ++id)
    EXPECT_EQ(kTaskCancelled, tasks_handler_.Status(id));
  for (id = task_id1 + 1; id <= task_id2; ++id)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(id));
  EXPECT_EQ(100U, results_.size());

  EXPECT_EQ(kStoreManagerTaskNotFound,
            tasks_handler_.CancelTask(task_id2 + 1, kSuccess));

  tasks_handler_.CancelAllPendingTasks(kGeneralError);
  for (id = root_task_id; id <= task_id2; ++id)
    EXPECT_EQ(kTaskCancelled, tasks_handler_.Status(id));
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_DeleteTasks) {
  std::vector<TaskReturn> expected_results;
  TaskId root_task_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, functor_,
                                             &root_task_id));
  expected_results.push_back(TaskReturn(root_task_id, kNotConnected));

  TaskId task_id(root_task_id);
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask("a", task_id, kStoreChunk, 1, 0,
                                          functor_, &task_id));
    expected_results.push_back(TaskReturn(task_id, kNotConnected));
  }
  std::reverse(expected_results.begin(), expected_results.end());

  EXPECT_EQ(100U, tasks_handler_.TasksCount());
  TaskId id;
  for (id = root_task_id; id <= task_id; ++id)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(id));

  EXPECT_EQ(kSuccess, tasks_handler_.DeleteTask(root_task_id, kNotConnected));
  EXPECT_EQ(0U, tasks_handler_.TasksCount());
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_DeleteViaCallback) {
  std::vector<TaskReturn> expected_results;
  TaskId root_task_id(kRootTask);
  EXPECT_EQ(kSuccess,
            tasks_handler_.AddTask("a", kStoreChunk, 1, 0,
                boost::bind(&test_msm_tasks_handler::DeleteTaskCallback,
                            _1, _2, &results_, &tasks_handler_, &root_task_id),
                &root_task_id));
  expected_results.push_back(TaskReturn(root_task_id, kSuccess));
  TaskId task_id(root_task_id);
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask("a", task_id, kStoreChunk, 1, 0,
                                          functor_, &task_id));
    expected_results.push_back(TaskReturn(task_id, kSuccess));
  }
  std::reverse(expected_results.begin(), expected_results.end());

  EXPECT_EQ(100U, tasks_handler_.TasksCount());
  TaskId id;
  for (id = root_task_id; id <= task_id; ++id)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(id));

  EXPECT_EQ(kSuccess, tasks_handler_.NotifyTaskSuccess(task_id));
  EXPECT_EQ(0U, tasks_handler_.TasksCount());
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

TEST_F(MSMTasksHandlerTest, BEH_MAID_ClearHandler) {
  TaskId root_task_id(kRootTask);
  EXPECT_EQ(kSuccess, tasks_handler_.AddTask("a", kStoreChunk, 1, 0, functor_,
                                             &root_task_id));

  TaskId task_id(root_task_id);
  for (int i = 1; i < 100; ++i) {
    EXPECT_EQ(kSuccess,
              tasks_handler_.AddChildTask("a", task_id, kStoreChunk, 1, 0,
                                          functor_, &task_id));
  }

  EXPECT_EQ(100U, tasks_handler_.TasksCount());
  TaskId id;
  for (id = root_task_id; id <= task_id; ++id)
    EXPECT_EQ(kTaskActive, tasks_handler_.Status(id));

  tasks_handler_.ClearTasksHandler();

  EXPECT_EQ(0U, tasks_handler_.TasksCount());
  for (id = root_task_id; id <= task_id; ++id)
    EXPECT_EQ(kNotATask, tasks_handler_.Status(id));
  std::vector<TaskReturn> expected_results;
  EXPECT_TRUE(TaskReturnsAsExpected(expected_results, results_));
}

}  // namespace test

}  // namespace maidsafe
