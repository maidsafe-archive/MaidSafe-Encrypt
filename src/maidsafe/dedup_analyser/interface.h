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

#ifndef MAIDSAFE_DEDUP_ANALYSER_INTERFACE_H_
#define MAIDSAFE_DEDUP_ANALYSER_INTERFACE_H_

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread/mutex.hpp>
#include <QObject>

namespace fs3 = boost::filesystem3;

namespace maidsafe {

class ResultHolder;
class FilesystemAnalyser;

struct FileInfo {
  FileInfo() {}
  explicit FileInfo(const fs3::path &file_path_in)
      : file_path(file_path_in), file_hash(), file_size(0) {}
  fs3::path file_path;
  std::string file_hash;
  boost::uintmax_t file_size;
  bool operator < (const FileInfo &r) const { return file_hash < r.file_hash; }
};

struct Results {
  Results()
      : unique_file_count(0),
        duplicate_file_count(0),
        total_unique_size(0),
        total_duplicate_size(0),
        errors_count(0) {}
  Results(const boost::uintmax_t &unique_file_count_in,
          const boost::uintmax_t &duplicate_file_count_in,
          const boost::uintmax_t &total_unique_size_in,
          const boost::uintmax_t &total_duplicate_size_in,
          const boost::uintmax_t &errors_count_in)
      : unique_file_count(unique_file_count_in),
        duplicate_file_count(duplicate_file_count_in),
        total_unique_size(total_unique_size_in),
        total_duplicate_size(total_duplicate_size_in),
        errors_count(errors_count_in) {}
  boost::uintmax_t unique_file_count, duplicate_file_count, total_unique_size;
  boost::uintmax_t total_duplicate_size, errors_count;
};

class Interface : public QObject {
  Q_OBJECT
 public:
  Interface(boost::shared_ptr<boost::asio::io_service> asio_service,
            boost::shared_ptr<ResultHolder> result_holder);
  ~Interface() {}
  bool ConnectToFilesystemAnalyser(
      boost::shared_ptr<FilesystemAnalyser> analyser);
  void StartRunningResultUpdates();
  void StopRunningResultUpdates();
  void set_update_interval(
      const boost::posix_time::milliseconds &update_interval);
 signals:
  void OnFileProcessed(FileInfo file_info);
  void OnDirectoryEntered(fs3::path directory_path);
  void OnFailure(std::string error_message);
  void UpdatedResults(Results results);
 public slots:
  virtual void HandleFileProcessed(FileInfo file_info);
  virtual void HandleDirectoryEntered(fs3::path directory_path);
  virtual void HandleFailure(std::string error_message);
 protected:
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  boost::shared_ptr<ResultHolder> result_holder_;
 private:
  void FetchResults(const boost::system::error_code &error_code);
  boost::mutex mutex_;
  bool running_;
  boost::asio::deadline_timer timer_;
  boost::posix_time::milliseconds update_interval_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_INTERFACE_H_
