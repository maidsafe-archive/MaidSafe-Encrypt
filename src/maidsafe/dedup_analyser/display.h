/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Base class for displaying results
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

#ifndef MAIDSAFE_DEDUP_ANALYSER_DISPLAY_H_
#define MAIDSAFE_DEDUP_ANALYSER_DISPLAY_H_

#include <boost/filesystem.hpp>
#include <QObject>

namespace fs3 = boost::filesystem3;

namespace maidsafe {

class ResultHolder;
class FilesystemAnalyser;

struct FileInfo {
  explicit FileInfo(const fs3::path &file_path_in)
      : file_path(file_path_in), file_hash(), file_size(0) {}
  fs3::path file_path;
  std::string file_hash;
  boost::uintmax_t file_size;
  bool operator < (const FileInfo &r) const { return file_hash < r.file_hash; }
};

struct Results {
  boost::uintmax_t unique_file_count, duplicate_file_count, total_unique_size;
  boost::uintmax_t total_duplicate_size, errors_count;
};

class Display : public QObject {
  Q_OBJECT
 public:
  explicit Display(boost::shared_ptr<ResultHolder> result_holder);
  virtual ~Display() {}
  bool ConnectToFilesystemAnalyser(
      boost::shared_ptr<FilesystemAnalyser> analyser);
 signals:
  void OnFileProcessed(FileInfo file_info);
  void OnDirectoryEntered(fs3::path directory_path);
  void OnFailure(std::string error_message);
  void UpdatedResults(Results results);
 public slots:
  virtual void HandleFileProcessed(FileInfo file_info) = 0;
  virtual void HandleDirectoryEntered(fs3::path directory_path) = 0;
  virtual void HandleFailure(std::string error_message) = 0;
 protected:
  boost::shared_ptr<ResultHolder> result_holder_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_DISPLAY_H_
