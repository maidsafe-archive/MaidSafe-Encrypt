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

#ifndef MAIDSAFE_CLIENT_STORETASKSHANDLER_H_
#define MAIDSAFE_CLIENT_STORETASKSHANDLER_H_

#include <boost/cstdint.hpp>
#include <boost/multi_index_container.hpp>
#include <gtest/gtest_prod.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <string>
#include <vector>

#include "maidsafe/returncodes.h"

namespace mi = boost::multi_index;

namespace maidsafe {

enum StoreTaskType {
  kStoreChunk,
  kStorePacket,
  kLoadChunk,
  kLoadPacket,
  kDeleteChunk,
  kDeletePacket,
  kModifyPacket
};

struct StoreTask {
  StoreTask()
      : data_name_(),
        task_type_(kStoreChunk),
        data_size_(0),
        started_(false),
        cancelled_(false),
        has_callback_(false),
        timestamp_(0),
        exclude_peers_(),
        successes_required_(0),
        max_failures_(0),
        success_count_(0),
        failures_count_(0),
        active_subtask_count_(0),
        callback_() {}
  StoreTask(const std::string &data_name,
            const StoreTaskType &task_type,
            const boost::uint64_t &data_size,
            boost::uint8_t successes_required,
            boost::uint8_t max_failures)
      : data_name_(data_name),
        task_type_(task_type),
        data_size_(data_size),
        started_(false),
        cancelled_(false),
        has_callback_(false),
        timestamp_(base::get_epoch_time()),
        exclude_peers_(),
        successes_required_(successes_required),
        max_failures_(max_failures),
        success_count_(0),
        failures_count_(0),
        active_subtask_count_(0),
        callback_() {}
  StoreTask(const std::string &data_name,
            const StoreTaskType &task_type,
            const boost::uint64_t &data_size,
            boost::uint8_t successes_required,
            boost::uint8_t max_failures,
            const base::callback_func_type &callback)
      : data_name_(data_name),
        task_type_(task_type),
        data_size_(data_size),
        started_(false),
        cancelled_(false),
        has_callback_(true),
        timestamp_(base::get_epoch_time()),
        exclude_peers_(),
        successes_required_(successes_required),
        max_failures_(max_failures),
        success_count_(0),
        failures_count_(0),
        active_subtask_count_(0),
        callback_(callback) {}
  std::string data_name_;
  StoreTaskType task_type_;
  boost::uint64_t data_size_;
  bool started_;
  bool cancelled_;
  bool has_callback_;
  boost::uint32_t timestamp_;
  std::vector<kad::Contact> exclude_peers_;
  boost::uint8_t successes_required_;
  boost::uint8_t max_failures_;
  boost::uint8_t success_count_;
  boost::uint8_t failures_count_;
  boost::uint8_t active_subtask_count_;
  base::callback_func_type callback_;
};

struct all_tasks {};

typedef boost::multi_index_container<
  StoreTask,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<all_tasks>,
      mi::composite_key<
        StoreTask,
        BOOST_MULTI_INDEX_MEMBER(StoreTask, std::string, data_name_),
        BOOST_MULTI_INDEX_MEMBER(StoreTask, StoreTaskType, task_type_)
      >
    >
  >
> StoreTaskSet;

class StoreTasksHandler {
 public:
  StoreTasksHandler() : mutex_(), tasks_() {}
  ~StoreTasksHandler() {}
  // Count of all tasks in set.
  size_t TasksCount();
  // Returns false if task not found.
  bool Task(const std::string &data_name,
            const StoreTaskType &task_type,
            StoreTask *task);
  // Adds a task with no callback to be run at completion.
  int AddTask(const std::string &data_name,
              const StoreTaskType &task_type,
              const boost::uint64_t &data_size,
              boost::uint8_t successes_required,
              boost::uint8_t max_failures);
  // Adds a task which has a callback to be run at completion.
  int AddTask(const std::string &data_name,
              const StoreTaskType &task_type,
              const boost::uint64_t &data_size,
              boost::uint8_t successes_required,
              boost::uint8_t max_failures,
              const base::callback_func_type &callback);
  // Set the task's successes_required_ field.
  int SetSuccessesRequired(const std::string &data_name,
                           const StoreTaskType &task_type,
                           boost::uint8_t successes_required);
  // Method to allow subtasks to update the parent task's progress.  Sets
  // started_ to true, adds exclude_peer to exclude_peers_ and increments
  // active_subtask_count_ by 1.
  int StartSubTask(const std::string &data_name,
                   const StoreTaskType &task_type,
                   const kad::Contact &exclude_peer);
  // Method to allow subtasks to update the parent task's progress.  Increments
  // or decrements by 1 success_count_ or failures_count_ based on
  // subtask_success.  Decrements active_subtask_count_ by 1.  Returns
  // kStoreTaskNotFound, kStoreTaskNotFinished, kStoreTaskFinishedFail or
  // kStoreTaskFinishedPass.
  int StopSubTask(const std::string &data_name,
                  const StoreTaskType &task_type,
                  bool subtask_success);
  // Removes the task from the set, regardless of state of the task's progress.
  // If the task has a callback, it's run with callback_argument before deletion
  int DeleteTask(const std::string &data_name,
                 const StoreTaskType &task_type,
                 const std::string &callback_argument);
  // Marks task as cancelled, but doesn't remove it from set.
  int CancelTask(const std::string &data_name,
                 const StoreTaskType &task_type);
  // Marks all tasks as cancelled, but doesn't remove any from the set.
  void CancelAllPendingTasks();
  // Deletes all tasks from the set, regardless of state of each task's
  // progress.  Does not allow for callbacks to be run.
  void ClearTasksHandler();
 private:
  StoreTasksHandler &operator=(const StoreTasksHandler&);
  StoreTasksHandler(const StoreTasksHandler&);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskStartSubTask);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskStopSubTask);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskDelete);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelOne);
  FRIEND_TEST(StoreTasksHandlerTest, BEH_MAID_StoreTaskCancelAll);
  int DoAddTask(const StoreTask &task);
  boost::mutex mutex_;
  StoreTaskSet tasks_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STORETASKSHANDLER_H_
