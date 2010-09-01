/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for index of tasks running & pending in maidstoremanager
* Version:      1.0
* Created:      2009-12-18-13.58.04
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

#ifndef MAIDSAFE_CLIENT_STOREMANAGERTASKSHANDLER_H_
#define MAIDSAFE_CLIENT_STOREMANAGERTASKSHANDLER_H_

#include <boost/function.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/base/utils.h>
#include <maidsafe/kademlia/contact.h>

#include <string>
#include <map>
#include <vector>

#include "maidsafe/returncodes.h"

namespace maidsafe {

typedef boost::function<void (const ReturnCode&)> VoidFuncOneInt;

enum StoreManagerTaskType {
  kStoreChunk,
  kStorePacket,
  kLoadChunk,
  kLoadPacket,
  kDeleteChunk,
  kDeletePacket,
  kModifyPacket
};

enum StoreManagerTaskStatus {
  kTaskActive,
  kTaskSucceeded,
  kTaskFailed,
  kTaskCancelled
};

struct StoreManagerTask {
  StoreManagerTask()
    : parent_name(),
      type(kStoreChunk),
      status(kTaskActive),
      timestamp(0),
      successes_required(0),
      max_failures(0),
      success_count(0),
      failures_count(0),
      child_task_count(0),
      callback() {}
  StoreManagerTask(const std::string &parent_name_,
                   const StoreManagerTaskType &type_,
                   boost::uint8_t successes_required_,
                   boost::uint8_t max_failures_,
                   VoidFuncOneInt callback_)
    : parent_name(parent_name_),
      type(type_),
      status(kTaskActive),
      timestamp(base::GetEpochTime()),
      successes_required(successes_required_),
      max_failures(max_failures_),
      success_count(0),
      failures_count(0),
      child_task_count(0),
      callback(callback_) {}
  std::string parent_name;  // name of parent task, or empty if root
  StoreManagerTaskType type;
  StoreManagerTaskStatus status;
  boost::uint32_t timestamp;  // creation time, to enable purging after timeout
  boost::uint8_t successes_required;  // no. of successes for overall success
  boost::uint8_t max_failures;  // no. of allowed failures before task fails
  boost::uint8_t success_count;
  boost::uint8_t failures_count;
  boost::uint8_t child_task_count;
  VoidFuncOneInt callback;  // to be run upon success or failure
};

class StoreManagerTasksHandler {
 public:
  StoreManagerTasksHandler() : mutex_(), tasks_() {}
  ~StoreManagerTasksHandler() {}
  // Count of all tasks in set.
  size_t TasksCount();
  // Returns false if task not found.
  bool HasTask(const std::string &task_name, StoreManagerTaskType *type,
               StoreManagerTaskStatus *status);
  // Adds a main task with optional callback to be run on completion
  int AddTask(const std::string &task_name,
              const StoreManagerTaskType &type,
              boost::uint8_t successes_required,
              boost::uint8_t max_failures,
              VoidFuncOneInt callback = NULL);
  // Adds a child task with optional callback to be run on completion
  int AddChildTask(const std::string &task_name,
                   const std::string &parent_name,
                   const StoreManagerTaskType &type,
                   boost::uint8_t successes_required,
                   boost::uint8_t max_failures,
                   VoidFuncOneInt callback = NULL);
  // Increases a task's success counter, must not have child tasks
  int NotifyTaskSuccess(const std::string &task_name);
  // Increases a task's failure counter, must not have child tasks
  int NotifyTaskFailure(const std::string &task_name, const ReturnCode &reason);
  // Resets a task's success and failure counters, must not have child tasks
  int ResetTaskProgress(const std::string &task_name);
  // Removes the task and its child tasks from the set, regardless of state of
  // the tasks' progress.  If the tasks have callbacks, they're run with
  // before deletion.
  int DeleteTask(const std::string &task_name, const ReturnCode &reason);
  // Marks task and children as cancelled, but doesn't remove them from set.
  int CancelTask(const std::string &task_name, const ReturnCode &reason);
  // Marks all tasks as cancelled, but doesn't remove any from the set.
  void CancelAllPendingTasks(const ReturnCode &reason);
  // Deletes all tasks from the set, regardless of state of each task's
  // progress.  Does not allow for callbacks to be run.
  void ClearTasksHandler();
 private:
  StoreManagerTasksHandler &operator=(const StoreManagerTasksHandler&);
  StoreManagerTasksHandler(const StoreManagerTasksHandler&);
  /* FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskStartSubTask);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskStopSubTask);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskDelete);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelOne);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelAll);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_RemoveFromWatchList); */
  int DoAddTask(const std::string &task_name, StoreManagerTask task);
  void DoDeleteTask(const std::string &task_name, const ReturnCode &reason);
  void DoDeleteTask(std::map<std::string, StoreManagerTask>::iterator it,
                    const ReturnCode &reason);
  int NotifyStateChange(const std::string &task_name, const ReturnCode &reason);
  // recursive, assumes parent is not active anymore
  void CancelChildTasks(const std::string &parent_name,
                        const ReturnCode &reason);
  void DeleteChildTasks(const std::string &parent_name,
                        const ReturnCode &reason);
  boost::mutex mutex_;
  std::map<std::string, StoreManagerTask> tasks_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STOREMANAGERTASKSHANDLER_H_
