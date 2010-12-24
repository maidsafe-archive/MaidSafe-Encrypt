/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Base class container for holding ongoing results of filesystem
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

#ifndef MAIDSAFE_DEDUP_ANALYSER_RESULT_HOLDER_H_
#define MAIDSAFE_DEDUP_ANALYSER_RESULT_HOLDER_H_

#include <boost/cstdint.hpp>
#include <QObject>
#include "maidsafe/dedup_analyser/filesystem_analyser.h"

namespace maidsafe {

struct Results {
  boost::uintmax_t unique_file_count, duplicate_file_count, total_unique_size;
  boost::uintmax_t total_duplicate_size, errors_count;
};

class ResultHolder : public QObject {
  Q_OBJECT
 public:
  ResultHolder() {}
  virtual ~ResultHolder() { /*DisconnectFromFilesystemAnalyser();*/ }
  void ConnectToFilesystemAnalyser(FilesystemAnalyser *analyser);
//  void DisconnectFromFilesystemAnalyser();
  virtual boost::uintmax_t UniqueFileCount() = 0;
  virtual boost::uintmax_t DuplicateFileCount() = 0;
  virtual boost::uintmax_t TotalUniqueSize() = 0;
  virtual boost::uintmax_t TotalDuplicateSize() = 0;
  virtual boost::uintmax_t ErrorsCount() = 0;
 public slots:
  virtual void HandleFileProcessed(FileInfo file_info) = 0;
  virtual void HandleFailure(std::string error_message) = 0;
 signals:
  void UpdatedResults(Results results);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_RESULT_HOLDER_H_
