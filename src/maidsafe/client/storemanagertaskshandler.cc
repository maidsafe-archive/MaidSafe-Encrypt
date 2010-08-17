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

#include "maidsafe/client/storemanagertaskshandler.h"
#include <utility>
#include "maidsafe/maidsafe.h"

namespace maidsafe {

size_t StoreManagerTasksHandler::TasksCount() {
  boost::mutex::scoped_lock lock(mutex_);
  return tasks_.size();
}

bool StoreManagerTasksHandler::HasTask(const std::string &task_name,
                                       StoreManagerTaskType *type,
                                       StoreManagerTaskStatus *status) {
  boost::mutex::scoped_lock lock(mutex_);
  std::map<std::string, StoreManagerTask>::iterator it = tasks_.find(task_name);
  if (it != tasks_.end()) {
    if (type != NULL)
      *type = it->second.type;
    if (status != NULL)
      *status = it->second.status;
  }
  return it != tasks_.end();
}

int StoreManagerTasksHandler::AddTask(const std::string &task_name,
                                      const StoreManagerTaskType &type,
                                      boost::uint8_t successes_required,
                                      boost::uint8_t max_failures,
                                      VoidFuncOneInt callback) {
  return DoAddTask(task_name, StoreManagerTask("", type, successes_required,
                                               max_failures, callback));
}

int StoreManagerTasksHandler::AddChildTask(const std::string &task_name,
                                           const std::string &parent_name,
                                           const StoreManagerTaskType &type,
                                           boost::uint8_t successes_required,
                                           boost::uint8_t max_failures,
                                           VoidFuncOneInt callback) {
  return DoAddTask(task_name, StoreManagerTask(parent_name, type,
                                               successes_required, max_failures,
                                               callback));
}

int StoreManagerTasksHandler::DoAddTask(const std::string &task_name,
                                        StoreManagerTask task) {
  boost::mutex::scoped_lock lock(mutex_);
  if (task_name.empty() || task.successes_required == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::DoAddTask, parameter incorrect.\n");
#endif
    return kStoreManagerTaskIncorrectParameter;
  }

  if (tasks_.count(task_name) == 1) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::DoAddTask, already a task with name "
           "%s.\n", HexSubstr(task_name).c_str());
#endif
    StoreManagerTask &old_task = tasks_[task_name];
    if (old_task.status == kTaskActive) {
      if (old_task.type == kStoreChunk || old_task.type == kLoadChunk) {
        if (task.type == kDeleteChunk) {
          DoDeleteTask(task_name, kStoreCancelledOrDone);
        } else {
          old_task.timestamp = base::GetEpochTime();
          return kStoreManagerTaskAlreadyExists;
        }
      } else if (old_task.type == kStorePacket ||
                old_task.type == kLoadPacket ||
                old_task.type == kModifyPacket) {
        if (task.type == kDeletePacket) {
          DoDeleteTask(task_name, kStoreCancelledOrDone);
        } else {
          old_task.timestamp = base::GetEpochTime();
          return kStoreManagerTaskAlreadyExists;
        }
      } else {
        old_task.timestamp = base::GetEpochTime();
        return kStoreManagerTaskAlreadyExists;
      }
    } else {
      DoDeleteTask(task_name, kStoreCancelledOrDone);
    }
  }

  if (!task.parent_name.empty()) {
    if (tasks_.count(task.parent_name) == 0) {
#ifdef DEBUG
      printf("In StoreManagerTasksHandler::DoAddTask, parent task does not "
             "exist (%s).\n", HexSubstr(task.parent_name).c_str());
#endif
      return kStoreManagerTaskNotFound;
    }

    StoreManagerTask &parent = tasks_[task.parent_name];
    ++parent.child_task_count;
    if (parent.status != kTaskActive)
      task.status = kTaskCancelled;
  }

  tasks_[task_name] = task;
  if (task.status != kTaskActive && task.callback)
    task.callback(kStoreCancelledOrDone);
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyTaskSuccess(const std::string &task_name) {
  boost::mutex::scoped_lock lock(mutex_);
  if (tasks_.count(task_name) == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyTaskSuccess, task not found "
           "(%s).\n", HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskNotFound;
  }
  StoreManagerTask &task = tasks_[task_name];
  if (task.child_task_count > 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyTaskSuccess, cannot modify "
           "a parent task directly (%s).\n", HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskIncorrectOperation;
  }
  ++task.success_count;
  if (task.status == kTaskActive &&
      task.success_count >= task.successes_required) {
    task.status = kTaskSucceeded;
    return NotifyStateChange(task_name, kSuccess);
  }
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyTaskFailure(
    const std::string &task_name, const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  if (tasks_.count(task_name) == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyTaskFailure, task not found "
           "(%s).\n", HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskNotFound;
  }
  StoreManagerTask &task = tasks_[task_name];
  if (task.child_task_count > 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyTaskFailure, cannot modify "
           "a parent task directly (%s).\n", HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskIncorrectOperation;
  }
  ++task.failures_count;
  if (task.status == kTaskActive && task.failures_count > task.max_failures) {
    task.status = kTaskFailed;
    return NotifyStateChange(task_name, reason);
  }
  return kSuccess;
}

int StoreManagerTasksHandler::NotifyStateChange(
    const std::string &task_name, const ReturnCode &reason) {
  // boost::mutex::scoped_lock lock(mutex_);
  StoreManagerTask &task = tasks_[task_name];
  if (task.status == kTaskActive) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::NotifyStateChange, task still active "
           "(%s)\n", HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskHandlerError;
  }
  CancelChildTasks(task_name, reason);
  bool success = task.status == kTaskSucceeded;

#ifdef DEBUG
  printf("In StoreManagerTasksHandler::NotifyStateChange, task %s completed "
         "(%s).\n", HexSubstr(task_name).c_str(),
         success ? "succeeded" : "failed");
#endif
  
  if (task.callback) {
    mutex_.unlock();
    printf("-- calling callback for %s (%d) --\n", HexSubstr(task_name).c_str(), reason);
    task.callback(reason);
    mutex_.lock();
  }

  // notify parent
  if (!task.parent_name.empty() && tasks_.count(task.parent_name) == 1) {
    StoreManagerTask &parent = tasks_[task.parent_name];
    printf(" ## 1 parent found\n");
    if (parent.status == kTaskActive) {
      printf(" ## 2 parent active\n");
      if (success) {
        printf(" ## 3 parent successes %d+1\n", parent.success_count);
        ++parent.success_count;
        if (parent.success_count >= parent.successes_required) {
          parent.status = kTaskSucceeded;
          printf(" ## 4 parent set to succeeded\n");
          return NotifyStateChange(task.parent_name, reason);
        }
      } else {
        printf(" ## 3 parent failures %d+1\n", parent.failures_count);
        ++parent.failures_count;
        if (parent.failures_count > parent.max_failures) {
          printf(" ## 4 parent set to failed\n");
          parent.status = kTaskFailed;
          return NotifyStateChange(task.parent_name, reason);
        }
      }
    }
  }

  return kSuccess;
}

/* int StoreManagerTasksHandler::DeleteTask(const std::string &task_name,
                                         const ReturnCode &callback_argument) {
  boost::mutex::scoped_lock lock(mutex_);
  if (tasks_.count(task_name) == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::DeleteTask, task not found (%s).\n",
           HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskNotFound;
  }
  DoDeleteTask(task_name, callback_argument);
  return kSuccess;
} */

void StoreManagerTasksHandler::DoDeleteTask(
    const std::string &task_name,
    const ReturnCode &reason) {
  DoDeleteTask(tasks_.find(task_name), reason);
}

void StoreManagerTasksHandler::DoDeleteTask(
    std::map<std::string, StoreManagerTask>::iterator it,
    const ReturnCode &reason) {
  if (it == tasks_.end())
    return;
  if (it->second.callback && it->second.status == kTaskActive) {
    mutex_.unlock();
    it->second.callback(reason);
    mutex_.lock();
  }
  DeleteChildTasks(it->first, reason);
  if (!it->second.parent_name.empty() &&
      tasks_.count(it->second.parent_name))
    --tasks_[it->second.parent_name].child_task_count;
  tasks_.erase(it);
}

void StoreManagerTasksHandler::DeleteChildTasks(
    const std::string &parent_name, const ReturnCode &reason) {
  boost::uint8_t n = tasks_[parent_name].child_task_count;
  tasks_[parent_name].child_task_count = 0;
  for (std::map<std::string, StoreManagerTask>::iterator it = tasks_.begin();
       it != tasks_.end() && n > 0; ++it) {
    if (it->second.parent_name == parent_name) {
      --n;  // to save some time on huge lists
      DoDeleteTask(it, reason);
    }
  }
}

int StoreManagerTasksHandler::CancelTask(
    const std::string &task_name, const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  if (tasks_.count(task_name) == 0) {
#ifdef DEBUG
    printf("In StoreManagerTasksHandler::CancelTask, task not found (%s).\n",
           HexSubstr(task_name).c_str());
#endif
    return kStoreManagerTaskNotFound;
  }
  tasks_[task_name].status = kTaskCancelled;
  return NotifyStateChange(task_name, reason);
}

void StoreManagerTasksHandler::CancelChildTasks(
    const std::string &parent_name, const ReturnCode &reason) {
  boost::uint8_t n = tasks_[parent_name].child_task_count;
  for (std::map<std::string, StoreManagerTask>::iterator it = tasks_.begin();
       it != tasks_.end() && n > 0; ++it) {
    if (it->second.parent_name == parent_name) {
      --n;  // to save some time on huge lists
      if (it->second.status == kTaskActive) {
        it->second.status = kTaskCancelled;
        NotifyStateChange(it->first, reason);
      }
    }
  }
}

void StoreManagerTasksHandler::CancelAllPendingTasks(const ReturnCode &reason) {
  boost::mutex::scoped_lock lock(mutex_);
  for (std::map<std::string, StoreManagerTask>::iterator it = tasks_.begin();
       it != tasks_.end(); ++it) {
    if (it->second.status == kTaskActive) {
      it->second.status = kTaskCancelled;
      NotifyStateChange(it->first, reason);
    }
  }
}

void StoreManagerTasksHandler::ClearTasksHandler() {
  boost::mutex::scoped_lock lock(mutex_);
  tasks_.clear();
}

}  // namespace maidsafe
