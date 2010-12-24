/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  In-memory container for holding ongoing results of filesystem
*               assessment.
* Version:      1.0
* Created:      24-12-2010
* Revision:     none
* Author:       Fraser Hutchison
* Company:      Sigmoid Solutions
*
* The following source code is property of Sigmoid Solutions and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.sigmoidsolutions.com
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of Sigmoid
* Solutions.
* ============================================================================
*/

#include "maidsafe/dedup_analyser/in_memory_result_holder.h"
#include <algorithm>
#include "maidsafe/dedup_analyser/filesystem_analyser.h"

namespace maidsafe {

boost::uintmax_t InMemoryResultHolder::UniqueFileCount() {
  return PrepareResults() ? unique_count_ : 0;
}

boost::uintmax_t InMemoryResultHolder::DuplicateFileCount() {
  return PrepareResults() ? duplicate_count_ : 0;
}

boost::uintmax_t InMemoryResultHolder::TotalUniqueSize() {
  return PrepareResults() ? unique_size_ : 0;
}

boost::uintmax_t InMemoryResultHolder::TotalDuplicateSize() {
  return PrepareResults() ? duplicate_size_ : 0;
}

boost::uintmax_t InMemoryResultHolder::ErrorsCount() {
  return error_messages_.size();
}

Results InMemoryResultHolder::GetResults() {
  return PrepareResults() ? Results(unique_count_, duplicate_count_,
      unique_size_, duplicate_size_, error_messages_.size()) : Results();
}

void InMemoryResultHolder::HandleFileProcessed(FileInfo file_info) {
  boost::mutex::scoped_lock lock(file_processed_mutex_);
  file_infos_.push_back(file_info);
}

void InMemoryResultHolder::HandleFailure(std::string error_message) {
  boost::mutex::scoped_lock lock(handle_failure_mutex_);
  error_messages_.push_back(error_message);
}

bool InMemoryResultHolder::PrepareResults() {
  boost::mutex::scoped_lock lock(result_mutex_);
  std::sort(file_infos_.begin(), file_infos_.end());
  std::vector<FileInfo>::iterator it(file_infos_.begin());
  if (it == file_infos_.end())
    return false;

  unique_count_ = 1;
  duplicate_count_ = 0;
  unique_size_ = (*it).file_size;
  duplicate_size_ = 0;
  ++it;

  bool previous_unique(true);
  for (it = file_infos_.begin() + 1; it != file_infos_.end(); ++it) {
    if ((*it).file_hash == (*(it - 1)).file_hash) {
      if (previous_unique) {
        previous_unique = false;
        --unique_count_;
        unique_size_ -= (*it).file_size;
        ++duplicate_count_;
        duplicate_size_ += (*it).file_size;
      }
      ++duplicate_count_;
      duplicate_size_ += (*it).file_size;
    } else {
      previous_unique = true;
      ++unique_count_;
      unique_size_ += (*it).file_size;
    }
  }
  return true;
}

}  // namespace maidsafe
