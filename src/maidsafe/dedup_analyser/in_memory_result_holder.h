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

#ifndef SRC_IN_MEMORY_RESULT_HOLDER_H_
#define SRC_IN_MEMORY_RESULT_HOLDER_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/interprocess/detail/atomic.hpp>
#include <string>
#include <vector>
#include "result_holder.h"

namespace maidsafe {

class FilesystemAnalyser;

class InMemoryResultHolder : public ResultHolder {
 public:
  InMemoryResultHolder()
      : ResultHolder(),
        file_infos_(),
        unique_count_(0),
        duplicate_count_(0),
        unique_size_(0),
        duplicate_size_(0),
        error_messages_() {}
  virtual ~InMemoryResultHolder() {}
  virtual boost::uintmax_t UniqueFileCount();
  virtual boost::uintmax_t DuplicateFileCount();
  virtual boost::uintmax_t TotalUniqueSize();
  virtual boost::uintmax_t TotalDuplicateSize();
  virtual boost::uintmax_t ErrorsCount();
  std::vector<std::string> error_messages() const { return error_messages_; }
 protected:
  virtual void HandleFileProcessed(FileInfo file_info);
  virtual void HandleFailure(std::string error_message);
  std::vector<FileInfo> file_infos_;
  boost::uintmax_t unique_count_, duplicate_count_;
  boost::uintmax_t unique_size_, duplicate_size_;
  std::vector<std::string> error_messages_;
 private:
  bool PrepareResults();
  boost::mutex result_mutex_;
  boost::mutex file_precessed_mutex_;
  boost::mutex handle_failure_mutex_;  
};

}  // namespace maidsafe

#endif  // SRC_IN_MEMORY_RESULT_HOLDER_H_
