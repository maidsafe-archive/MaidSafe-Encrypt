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

#ifndef MAIDSAFE_DEDUP_ANALYSER_IN_MEMORY_RESULT_HOLDER_H_
#define MAIDSAFE_DEDUP_ANALYSER_IN_MEMORY_RESULT_HOLDER_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <string>
#include <vector>
#include "maidsafe/dedup_analyser/result_holder.h"

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
  boost::mutex file_processed_mutex_;
  boost::mutex handle_failure_mutex_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_IN_MEMORY_RESULT_HOLDER_H_
