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

#include "maidsafe/client/storemanagertaskshandler.h"
#include <utility>
#include "maidsafe/maidsafe.h"

namespace maidsafe {

StoreManagerTasksHandler::StoreManagerTasksHandler()
    : mutex_(),
      tasks_(),
      last_id_(kRootTask),
      increment_success_count_(),
      increment_failures_count_(),
      reset_success_failures_count_(),
      increment_child_task_count_(),
      decrement_child_task_count_(),
      set_task_status_to_succeeded_(),
      set_task_status_to_failed_(),
      set_task_status_to_cancelled_() {
  increment_success_count_ =
      boost::bind(&StoreManagerTasksHandler::IncrementCount, this, true, _1);
  increment_failures_count_ =
      boost::bind(&StoreManagerTasksHandler::IncrementCount, this, false, _1);
  reset_success_failures_count_ = boost::bind(
      &StoreManagerTasksHandler::ResetSuccessFailuresCounts, this, _1);
  increment_child_task_count_ = boost::bind(
      &StoreManagerTasksHandler::ModifyChildTaskCount, this, true, _1);
  decrement_child_task_count_ = boost::bind(
      &StoreManagerTasksHandler::ModifyChildTaskCount, this, false, _1);
  set_task_status_to_succeeded_ = boost::bind(
      &StoreManagerTasksHandler::SetTaskStatus, this, kTaskSucceeded, _1);
  set_task_status_to_failed_ = boost::bind(
      &StoreManagerTasksHandler::SetTaskStatus, this, kTaskFailed, _1);
  set_task_status_to_cancelled_ = boost::bind(
      &StoreManagerTasksHandler::SetTaskStatus, this, kTaskCancelled, _1);
}

size_t StoreManagerTasksHandler::TasksCount() {
  boost::mutex::scoped_lock lock(mutex_);
  return tasks_.size();
}

StoreManagerTaskStatus StoreManagerTasksHandler::Status(const TaskId &task_id) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  return task_iter != tasks_by_id.end() ? (*task_iter).status : kNotATask;
}

std::string StoreManagerTasksHandler::DataName(const TaskId &task_id) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  return task_iter != tasks_by_id.end() ? (*task_iter).data_name : "";
}

TaskId StoreManagerTasksHandler::GetOldestActiveTaskByDataNameAndType(
    const std::string &data_name,
    const StoreManagerTaskType &type) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksByDataName &tasks_by_data_name = tasks_.get<by_data_name>();
  TaskRangeByDataName result = tasks_by_data_name.equal_range(data_name);
  TaskId task_id(kRootTask);
  boost::uint32_t oldest(-1);
  while (result.first != result.second) {
    if ((*result.first).type == type && (*result.first).timestamp < oldest) {
      task_id = (*result.first).task_id;
      oldest = (*result.first).timestamp;
    }
    ++result.first;
  }
  return task_id;
}

int StoreManagerTasksHandler::AddTask(const std::string &data_name,
                                      const StoreManagerTaskType &type,
                                      boost::uint8_t successes_required,
                                      boost::uint8_t max_failures,
                                      VoidFuncTaskIdInt callback,
                                      TaskId *task_id) {
  return DoAddTask(StoreManagerTask(GetNextId(), data_name, kRootTask, type,
                   successes_required, max_failures, callback), task_id);
}

int StoreManagerTasksHandler::AddChildTask(const std::string &data_name,
                                           const TaskId &parent_id,
                                           const StoreManagerTaskType &type,
                                           boost::uint8_t successes_required,
                                           boost::uint8_t max_failures,
                                           VoidFuncTaskIdInt callback,
                                           TaskId *task_id) {
  return DoAddTask(StoreManagerTask(GetNextId(), data_name, parent_id, type,
                   successes_required, max_failures, callback), task_id);
}

int StoreManagerTasksHandler::DoAddTask(StoreManagerTask task,
                                        TaskId *task_id) {
  boost::mutex::scoped_lock lock(mutex_);
  if (task_id)
    *task_id = kRootTask;
  if (task.data_name.empty() || task.successes_required == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::DoAddTask, parameter incorrect.\n");
#endif
    return kStoreManagerTaskIncorrectParameter;
  }

  // Locate oldest conflicting task
  boost::uint32_t oldest(-1);
  TasksByDataName &tasks_by_data_name = tasks_.get<by_data_name>();
  TasksByDataName::iterator existing_task_iter = tasks_by_data_name.end();
  ReturnCode existing_task_return_code = kPendingResult;
  TaskRangeByDataName result = tasks_by_data_name.equal_range(task.data_name);
  while (result.first != result.second) {
    switch (task.type) {
      case kStoreChunk:
        if ((*result.first).type == kDeleteChunk &&
            (*result.first).timestamp < oldest) {
          existing_task_iter = result.first;
          existing_task_return_code = kStoreManagerTaskCancelledOrDone;
          oldest = (*result.first).timestamp;
        }
        break;
      case kStorePacket:
        if ((*result.first).type == kDeletePacket &&
            (*result.first).timestamp < oldest) {
          existing_task_iter = result.first;
          existing_task_return_code = kStoreManagerTaskCancelledOrDone;
          oldest = (*result.first).timestamp;
        }
        break;
      case kDeleteChunk:
        if ((*result.first).type == kStoreChunk &&
            (*result.first).timestamp < oldest) {
          existing_task_iter = result.first;
          existing_task_return_code = kStoreManagerTaskCancelledOrDone;
          oldest = (*result.first).timestamp;
        }
        break;
      case kDeletePacket:
        if ((*result.first).type == kStorePacket &&
            (*result.first).timestamp < oldest) {
          existing_task_iter = result.first;
          existing_task_return_code = kStoreManagerTaskCancelledOrDone;
          oldest = (*result.first).timestamp;
        }
        break;
      default:
        break;
    }
    ++result.first;
  }
  // If conflicting task found, delete it and return.
  if (existing_task_iter != tasks_by_data_name.end()) {
    DoDeleteTask(tasks_.project<by_task_id>(existing_task_iter),
                 existing_task_return_code);
    return kSuccess;
  }

  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  if (task.parent_id != kRootTask) {
    TasksById::iterator parent_iter = tasks_by_id.find(task.parent_id);
    if (parent_iter == tasks_by_id.end()) {
#ifdef DEBUG
      printf("In StoreManagerTasksHandler::DoAddTask, parent task does not "
             "exist (%u).\n", task.parent_id);
#endif
      return kStoreManagerTaskNotFound;
    }

    if ((*parent_iter).status != kTaskActive) {
#ifdef DEBUG
      printf("In StoreManagerTasksHandler::DoAddTask, parent task is not "
             "active (%u).\n", task.parent_id);
#endif
      return kStoreManagerTaskParentNotActive;
    }
    tasks_.modify(parent_iter, increment_child_task_count_);
  }

  if (tasks_.empty())
    tasks_.insert(task);
  else
    tasks_.insert(--(tasks_.end()), task);
  if (task.status != kTaskActive && task.callback)
    task.callback(task.task_id, kStoreManagerTaskCancelledOrDone);
  if (task_id)
    *task_id = task.task_id;
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyTaskSuccess(const TaskId &task_id) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  int result(ValidateTaskId(task_iter, true));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("StoreManagerTasksHandler::NotifyTaskSuccess, %u fail.\n", task_id);
#endif
    return result;
  }

  tasks_.modify(task_iter, increment_success_count_);
// #ifdef DEBUG
//   printf(">>> SMTH::NotifyTaskSuccess - success %d of %d <<<\n",
//          task.success_count, task.successes_required);
// #endif

  if ((*task_iter).status == kTaskActive &&
      (*task_iter).success_count >= (*task_iter).successes_required) {
    tasks_.modify(task_iter, set_task_status_to_succeeded_);
    return NotifyStateChange(task_iter, kSuccess);
  }
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyTaskFailure(const TaskId &task_id,
                                                const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  int result(ValidateTaskId(task_iter, true));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("StoreManagerTasksHandler::NotifyTaskFailure, %u fail.\n", task_id);
#endif
    return result;
  }

  tasks_.modify(task_iter, increment_failures_count_);
// #ifdef DEBUG
//   printf(">>> SMTH::NotifyTaskFailure - failure %d of %d <<<\n",
//          task.failures_count, task.max_failures);
// #endif

  if ((*task_iter).status == kTaskActive &&
      (*task_iter).failures_count > (*task_iter).max_failures) {
    tasks_.modify(task_iter, set_task_status_to_failed_);
    return NotifyStateChange(task_iter, reason);
  }
  return kSuccess;
}

int StoreManagerTasksHandler::ResetTaskProgress(const TaskId &task_id) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  int result(ValidateTaskId(task_iter, true));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("StoreManagerTasksHandler::ResetTaskProgress, %u fail.\n", task_id);
#endif
    return result;
  }

  tasks_.modify(task_iter, reset_success_failures_count_);
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyStateChange(TasksById::iterator task_iter,
                                                const ReturnCode &reason) {
  // Ensure mutex_ is already locked when call to this function is made.
  if ((*task_iter).status == kTaskActive) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyStateChange, task active.\n");
#endif
    return kStoreManagerTaskHandlerError;
  }
  CancelChildTasks((*task_iter).task_id, reason);
  bool success = (*task_iter).status == kTaskSucceeded;

//  #ifdef DEBUG
//      printf("In SMTH::NotifyStateChange, task %u completed (%s).\n",
//             (*task_iter).task_id, success ? "succeeded" : "failed");
//  #endif

  bool notify_parent(false);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator parent_iter = tasks_by_id.find((*task_iter).parent_id);

  // notify parent
  if (parent_iter != tasks_by_id.end() &&
      (*parent_iter).status == kTaskActive) {
    if (success) {
      tasks_.modify(parent_iter, increment_success_count_);
      if ((*parent_iter).success_count >= (*parent_iter).successes_required) {
        tasks_.modify(parent_iter, set_task_status_to_succeeded_);
        notify_parent = true;
      }
    } else {
      tasks_.modify(parent_iter, increment_failures_count_);
      if ((*parent_iter).failures_count > (*parent_iter).max_failures) {
        tasks_.modify(parent_iter, set_task_status_to_failed_);
        notify_parent = true;
      }
    }
  }

  if ((*task_iter).callback) {
    mutex_.unlock();
    (*task_iter).callback((*task_iter).task_id, reason);
    mutex_.lock();
  }

  if (notify_parent)
    return NotifyStateChange(parent_iter, reason);

  return kSuccess;
}

int StoreManagerTasksHandler::DeleteTask(const TaskId &task_id,
                                         const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  int result(ValidateTaskId(task_iter, false));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("StoreManagerTasksHandler::DeleteTask, %u fail.\n", task_id);
#endif
    return result;
  }
  DoDeleteTask(task_iter, reason);
  return kSuccess;
}

void StoreManagerTasksHandler::DoDeleteTask(TasksById::iterator task_iter,
                                            const ReturnCode &reason) {
  // Ensure mutex_ is already locked when call to this function is made.
  DeleteChildTasks((*task_iter).task_id, reason);

  if ((*task_iter).callback && (*task_iter).status == kTaskActive) {
    mutex_.unlock();
    (*task_iter).callback((*task_iter).task_id, reason);
    mutex_.lock();
  }

  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator parent_iter = tasks_by_id.find((*task_iter).parent_id);
  if (parent_iter != tasks_by_id.end())
    tasks_.modify(parent_iter, decrement_child_task_count_);

  tasks_.erase(task_iter);
}

void StoreManagerTasksHandler::DeleteChildTasks(const TaskId &parent_id,
                                                const ReturnCode &reason) {
  // Ensure mutex_ is already locked when call to this function is made.
  TasksByParentId &tasks_by_parent_id = tasks_.get<by_parent_id>();
  TaskRangeByParentId p = tasks_by_parent_id.equal_range(parent_id);
  while (p.first != p.second)
    DoDeleteTask(tasks_.project<by_task_id>(p.first++), reason);
}

int StoreManagerTasksHandler::CancelTask(const TaskId &task_id,
                                         const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  TasksById &tasks_by_id = tasks_.get<by_task_id>();
  TasksById::iterator task_iter = tasks_by_id.find(task_id);
  int result(ValidateTaskId(task_iter, false));
  if (result != kSuccess) {
#ifdef DEBUG
    printf("StoreManagerTasksHandler::CancelTask, %u fail.\n", task_id);
#endif
    return result;
  }
  tasks_.modify(task_iter, set_task_status_to_cancelled_);
  return NotifyStateChange(task_iter, reason);
}

void StoreManagerTasksHandler::CancelChildTasks(const TaskId &parent_id,
                                                const ReturnCode &reason) {
  // Ensure mutex_ is already locked when call to this function is made.
  TasksByParentId &tasks_by_parent_id = tasks_.get<by_parent_id>();
  TaskRangeByParentId p = tasks_by_parent_id.equal_range(parent_id);
  while (p.first != p.second && p.first->status == kTaskActive) {
    tasks_by_parent_id.modify(p.first, set_task_status_to_cancelled_);
    NotifyStateChange(tasks_.project<by_task_id>(p.first++), reason);
  }
}

void StoreManagerTasksHandler::CancelAllPendingTasks(const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  for (StoreManagerTaskSet::iterator task_iter = tasks_.begin();
       task_iter != tasks_.end(); ++task_iter) {
    if ((*task_iter).status == kTaskActive) {
      tasks_.modify(task_iter, set_task_status_to_cancelled_);
      NotifyStateChange(task_iter, reason);
    }
  }
}

void StoreManagerTasksHandler::ClearTasksHandler() {
  boost::mutex::scoped_lock lock(mutex_);
  tasks_.clear();
}

TaskId StoreManagerTasksHandler::GetNextId() {
  boost::mutex::scoped_lock lock(mutex_);
  return ++last_id_ != kRootTask ? last_id_ : ++last_id_;
}

int StoreManagerTasksHandler::ValidateTaskId(TasksById::iterator task_iter,
                                             bool check_no_children) {
  // Ensure mutex_ is already locked when call to this function is made.
  if (task_iter == tasks_.get<by_task_id>().end()) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::ValidateTaskId, task not found.\n");
#endif
    return kStoreManagerTaskNotFound;
  }
  if (check_no_children && (*task_iter).child_task_count > 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::ValidateTaskId, cannot modify a parent"
           " task directly.\n");
#endif
    return kStoreManagerTaskIncorrectOperation;
  }
  return kSuccess;
}

}  // namespace maidsafe
