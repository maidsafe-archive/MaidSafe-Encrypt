/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for index of tasks running & pending in maidstoremanager
* Version:      1.0
* Created:      2009-12-18-13.58.04
* Revision:     none
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
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/thread/mutex.hpp>
#include <maidsafe/base/utils.h>

#include <string>
#include <map>

#include "maidsafe/common/returncodes.h"

namespace mi = boost::multi_index;

namespace maidsafe {

typedef boost::uint32_t TaskId;
typedef boost::function<void (const TaskId&, const ReturnCode&)>
    VoidFuncTaskIdInt;

const TaskId kRootTask(0);

enum StoreManagerTaskType {
  kStoreChunk,
  kAddToWatchListMaster,
  kAddToWatchList,
  kSpaceTakenIncConfirmation,
  kChunkCopyMaster,
  kChunkCopy,
  kChunkCopyPrep,
  kChunkCopyData,
  kStorePacket,
  kLoadChunk,
  kLoadPacket,
  kDeleteChunk,
  kRemoveFromWatchListMaster,
  kRemoveFromWatchList,
  kSpaceTakenDecConfirmation,
  kDeletePacket,
  kModifyPacket
};

enum StoreManagerTaskStatus {
  kTaskActive,
  kTaskSucceeded,
  kTaskFailed,
  kTaskCancelled,
  kNotATask
};

struct StoreManagerTask {
  StoreManagerTask(const TaskId &task_id,
                   const std::string &data_name,
                   const TaskId &parent_id,
                   const StoreManagerTaskType &type,
                   boost::uint8_t successes_required,
                   boost::uint8_t max_failures,
                   VoidFuncTaskIdInt callback)
      : task_id(task_id),
        data_name(data_name),
        parent_id(parent_id),
        type(type),
        status(kTaskActive),
        timestamp(base::GetEpochTime()),
        successes_required(successes_required),
        max_failures(max_failures),
        success_count(0),
        failures_count(0),
        child_task_count(0),
        callback(callback) {}
  bool operator<(const StoreManagerTask &other) const {
    return task_id < other.task_id;
  }
  TaskId task_id;
  std::string data_name;
  TaskId parent_id;  // id of parent task, or kRootTask if root
  StoreManagerTaskType type;
  StoreManagerTaskStatus status;
  boost::uint32_t timestamp;  // creation time, to enable purging after timeout
  boost::uint8_t successes_required;  // no. of successes for overall success
  boost::uint8_t max_failures;  // no. of allowed failures before task fails
  boost::uint8_t success_count;
  boost::uint8_t failures_count;
  boost::uint8_t child_task_count;
  VoidFuncTaskIdInt callback;  // to be run upon success or failure
};

struct by_task_id {};
struct by_parent_id {};
struct by_data_name {};

typedef mi::multi_index_container<
  StoreManagerTask,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<by_task_id>,
      BOOST_MULTI_INDEX_MEMBER(StoreManagerTask, TaskId, task_id)
    >,
    mi::ordered_non_unique<
      mi::tag<by_parent_id>,
      BOOST_MULTI_INDEX_MEMBER(StoreManagerTask, TaskId, parent_id)
    >,
    mi::ordered_non_unique<
      mi::tag<by_data_name>,
      BOOST_MULTI_INDEX_MEMBER(StoreManagerTask, std::string, data_name)
    >
  >
> StoreManagerTaskSet;
typedef StoreManagerTaskSet::index<by_task_id>::type TasksById;
typedef StoreManagerTaskSet::index<by_parent_id>::type TasksByParentId;
typedef StoreManagerTaskSet::index<by_data_name>::type TasksByDataName;

class StoreManagerTasksHandler {
 public:
  typedef StoreManagerTaskSet::iterator TaskIterator;
  typedef std::pair<TasksByParentId::iterator,
                    TasksByParentId::iterator> TaskRangeByParentId;
  typedef std::pair<TasksByDataName::iterator,
                    TasksByDataName::iterator> TaskRangeByDataName;
  StoreManagerTasksHandler();
  ~StoreManagerTasksHandler() {}
  // Count of all tasks in set.
  size_t TasksCount();
  // Return status for task_id (kNotATask returned if task doesn't exist)
  StoreManagerTaskStatus Status(const TaskId &task_id);
  // Returns data_name for task_id, or "" if not found.
  std::string DataName(const TaskId &task_id);
  // Yes, I know it's a long function name.
  TaskId GetOldestActiveTaskByDataNameAndType(const std::string &data_name,
                                              const StoreManagerTaskType &type);
  // Adds a main task.  If callback != NULL, it will be run on completion
  int AddTask(const std::string &data_name,
              const StoreManagerTaskType &type,
              boost::uint8_t successes_required,
              boost::uint8_t max_failures,
              VoidFuncTaskIdInt callback,
              TaskId *task_id);
  // Adds a child task.  If callback != NULL, it will be run on completion
  int AddChildTask(const std::string &data_name,
                   const TaskId &parent_id,
                   const StoreManagerTaskType &type,
                   boost::uint8_t successes_required,
                   boost::uint8_t max_failures,
                   VoidFuncTaskIdInt callback,
                   TaskId *task_id);
  // Increases a task's success counter, must not have child tasks
  int NotifyTaskSuccess(const TaskId &task_id);
  // Increases a task's failure counter, must not have child tasks
  int NotifyTaskFailure(const TaskId &task_id, const ReturnCode &reason);
  // Retrieves a task's success and failure counters
  int GetTaskProgress(const TaskId &task_id,
                      boost::uint8_t *successes_required,
                      boost::uint8_t *max_failures,
                      boost::uint8_t *success_count,
                      boost::uint8_t *failures_count);
  // Resets a task's success and failure counters, must not have child tasks
  int ResetTaskProgress(const TaskId &task_id);
  // Removes the task and its child tasks from the set, regardless of state of
  // the tasks' progress.  If the tasks have callbacks, they're run with
  // before deletion.
  int DeleteTask(const TaskId &task_id, const ReturnCode &reason);
  // Marks task and children as cancelled, but doesn't remove them from set.
  int CancelTask(const TaskId &task_id, const ReturnCode &reason);
  // Marks all tasks as cancelled, but doesn't remove any from the set.
  void CancelAllPendingTasks(const ReturnCode &reason);
  // Deletes all tasks from the set, regardless of state of each task's
  // progress.  Does not allow for callbacks to be run.
  void ClearTasksHandler();
 private:
  StoreManagerTasksHandler &operator=(const StoreManagerTasksHandler&);
  StoreManagerTasksHandler(const StoreManagerTasksHandler&);
  int DoAddTask(StoreManagerTask task, TaskId *task_id);
  // NB - Assumes mutex_ already locked when call to this function is made.
  void DoDeleteTask(TasksById::iterator task_iter, const ReturnCode &reason);
  // NB - Assumes mutex_ already locked when call to this function is made.
  int NotifyStateChange(TasksById::iterator task_iter,
                        const ReturnCode &reason);
  // NB - Assumes mutex_ already locked when call to this function is made.
  void DeleteChildTasks(const TaskId &parent_id, const ReturnCode &reason);
  // NB - Assumes mutex_ already locked when call to this function is made.
  // Recursive, assumes parent is not active anymore
  void CancelChildTasks(const TaskId &parent_id, const ReturnCode &reason);
  TaskId GetNextId();
  // NB - Assumes mutex_ already locked when call to this function is made.
  // If task_iter == end() returns failure.  If check_no_children, then returns
  // failure if *task_iter has child tasks.
  int ValidateTaskId(TasksById::iterator task_iter, bool check_no_children);
  // The following four methods are only to be used as boost::functions for
  // updating tasks in the set rather than copy and replace.
  void IncrementCount(bool successes, StoreManagerTask &task) {  // NOLINT - Fraser
    successes ? ++task.success_count : ++task.failures_count;
  }
  void ResetSuccessFailuresCounts(StoreManagerTask &task) {  // NOLINT - Fraser
    task.success_count = 0;
    task.failures_count = 0;
  }
  void ModifyChildTaskCount(bool increment, StoreManagerTask &task) {  // NOLINT - Fraser
    increment ? ++task.child_task_count : --task.child_task_count;
  }
  void SetTaskStatus(StoreManagerTaskStatus status, StoreManagerTask &task) {  // NOLINT - Fraser
    task.status = status;
  }
  boost::mutex mutex_;
  StoreManagerTaskSet tasks_;
  TaskId last_id_;
  boost::function<void (StoreManagerTask &task)> increment_success_count_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> increment_failures_count_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> reset_success_failures_count_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> increment_child_task_count_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> decrement_child_task_count_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> set_task_status_to_succeeded_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> set_task_status_to_failed_;  // NOLINT - Fraser
  boost::function<void (StoreManagerTask &task)> set_task_status_to_cancelled_;  // NOLINT - Fraser
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STOREMANAGERTASKSHANDLER_H_
