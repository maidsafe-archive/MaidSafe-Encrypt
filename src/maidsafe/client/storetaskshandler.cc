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

#include "maidsafe/client/storetaskshandler.h"
#include "maidsafe/maidsafe.h"

namespace maidsafe {

size_t StoreTasksHandler::TasksCount() {
  boost::mutex::scoped_lock lock(mutex_);
  return tasks_.size();
}

bool StoreTasksHandler::Task(const std::string &data_name,
                             const StoreTaskType &task_type,
                             StoreTask *task) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::Task, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    StoreTask default_task;
    *task = default_task;
    return false;
  }
  *task = (*it.first);
  return true;
}

int StoreTasksHandler::AddTask(const std::string &data_name,
                               const StoreTaskType &task_type,
                               const boost::uint64_t &data_size,
                               boost::uint8_t successes_required,
                               boost::uint8_t max_failures) {
  StoreTask task(data_name, task_type, data_size, successes_required,
                 max_failures);
  return DoAddTask(task);
}

int StoreTasksHandler::AddTask(const std::string &data_name,
                               const StoreTaskType &task_type,
                               const boost::uint64_t &data_size,
                               boost::uint8_t successes_required,
                               boost::uint8_t max_failures,
                               const base::callback_func_type &callback) {
  StoreTask task(data_name, task_type, data_size, successes_required,
                 max_failures, callback);
  return DoAddTask(task);
}

int StoreTasksHandler::DoAddTask(const StoreTask &task) {
  boost::mutex::scoped_lock lock(mutex_);
  if (task.data_name_.empty() || task.data_size_ < 2 ||
      task.successes_required_ == 0) {
#ifdef DEBUG
    printf("In StoreTasksHandler::DoAddTask, parameter incorrect.\n");
#endif
    return kStoreTaskIncorrectParameter;
  }
  std::pair<StoreTaskSet::iterator, bool> p = tasks_.insert(task);
  if (!p.second) {  // task exists - reset timestamp
#ifdef DEBUG
    printf("In StoreTasksHandler::DoAddTask, already a task with these "
           "parameters.\n");
#endif
    std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
    it = tasks_.equal_range(boost::make_tuple(task.data_name_,
                                              task.task_type_));
    if (it.first == it.second) {
      return kStoreTaskHandlerError;
    }
    StoreTask existing_task = (*it.first);
    existing_task.timestamp_ = base::get_epoch_time();
    tasks_.replace(it.first, existing_task);
    return kStoreTaskAlreadyExists;
  }
  return kSuccess;
}

int StoreTasksHandler::SetSuccessesRequired(const std::string &data_name,
                                            const StoreTaskType &task_type,
                                            boost::uint8_t successes_required) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::SetSuccessesRequired, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    return kStoreTaskNotFound;
  }
  StoreTask task = (*it.first);
  task.successes_required_ = successes_required;
  tasks_.replace(it.first, task);
  return kSuccess;
}

int StoreTasksHandler::StartSubTask(const std::string &data_name,
                                    const StoreTaskType &task_type,
                                    const kad::Contact &exclude_peer) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::StartSubTask, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    return kStoreTaskNotFound;
  }
  StoreTask task = (*it.first);
  task.started_ = true;
  task.exclude_peers_.push_back(exclude_peer);
  ++task.active_subtask_count_;
  tasks_.replace(it.first, task);
  return kSuccess;
}

int StoreTasksHandler::StopSubTask(const std::string &data_name,
                                   const StoreTaskType &task_type,
                                   bool subtask_success) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::StopSubTask, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    return kStoreTaskNotFound;
  }
  StoreTask task = (*it.first);
  if (task.active_subtask_count_ == 0 || !task.started_) {
#ifdef DEBUG
    printf("In StoreTasksHandler::StopSubTask, no active subtasks or task not "
           "started (%s)\n", HexSubstr(data_name).c_str());
#endif
    return kStoreTaskHandlerError;
  }
  if (subtask_success) {
    ++task.success_count_;
  } else {
    ++task.failures_count_;
  }
  --task.active_subtask_count_;
  tasks_.replace(it.first, task);
  if (task.success_count_ >= task.successes_required_)
    return kStoreTaskFinishedPass;
  else if ((task.failures_count_ >= task.max_failures_) ||
           (task.active_subtask_count_ == 0 && task.cancelled_))
    return kStoreTaskFinishedFail;
  else
    return kStoreTaskNotFinished;
}

int StoreTasksHandler::DeleteTask(const std::string &data_name,
                                  const StoreTaskType &task_type,
                                  const std::string &callback_argument) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::DeleteTask, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    return kStoreTaskNotFound;
  }
  if ((*it.first).has_callback_) {
    (*it.first).callback_(callback_argument);
  }
  tasks_.erase(it.first);
  return kSuccess;
}

int StoreTasksHandler::CancelTask(const std::string &data_name,
                                  const StoreTaskType &task_type) {
  boost::mutex::scoped_lock lock(mutex_);
  std::pair<StoreTaskSet::iterator, StoreTaskSet::iterator> it;
  it = tasks_.equal_range(boost::make_tuple(data_name, task_type));
  if (it.first == it.second) {
#ifdef DEBUG
    printf("In StoreTasksHandler::CancelTask, task not found (%s)\n",
           HexSubstr(data_name).c_str());
#endif
    return kStoreTaskNotFound;
  }
  StoreTask task = (*it.first);
  task.cancelled_ = true;
  tasks_.replace(it.first, task);
  return kSuccess;
}

void StoreTasksHandler::CancelAllPendingTasks() {
  boost::mutex::scoped_lock lock(mutex_);
  for (StoreTaskSet::iterator it = tasks_.begin(); it != tasks_.end(); ++it) {
    StoreTask task = (*it);
    task.cancelled_ = true;
    tasks_.replace(it, task);
  }
}

void StoreTasksHandler::ClearTasksHandler() {
  boost::mutex::scoped_lock lock(mutex_);
  tasks_.clear();
}

}  // namespace maidsafe
