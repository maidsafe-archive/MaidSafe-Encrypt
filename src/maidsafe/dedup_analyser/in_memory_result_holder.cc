/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

void InMemoryResultHolder::HandleFileProcessed(FileInfo file_info) {
  boost::mutex::scoped_lock lock(file_processed_mutex_);
  file_infos_.push_back(file_info);
}

void InMemoryResultHolder::HandleFailure(std::string error_message) {
  boost::mutex::scoped_lock lock(handle_failure_mutex_);
  error_messages_.push_back(error_message);
}

bool InMemoryResultHolder::PrepareResults() {
//   boost::mutex::scoped_lock lock(result_mutex_);
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
