/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Filesystem iterator which accumulates hashes and file sizes of
*               all accessible files.
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

#ifndef MAIDSAFE_DEDUP_ANALYSER_FILESYSTEM_ANALYSER_H_
#define MAIDSAFE_DEDUP_ANALYSER_FILESYSTEM_ANALYSER_H_

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
//  #include <boost/thread.hpp>
//  #include <boost/bind.hpp>
#include <QObject>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "maidsafe/dedup_analyser/display.h"
#include "maidsafe/base/crypto.h"

namespace fs3 = boost::filesystem3;

namespace maidsafe {

std::string SHA1(const fs3::path &file_path);

class FilesystemAnalyser : public QObject {
  Q_OBJECT
 public:
  explicit FilesystemAnalyser(boost::shared_ptr<boost::asio::io_service> io)
      : asio_service_(io) {
//     work_.reset(new boost::asio::io_service::work(io_service_));
//     if (boost::thread::hardware_concurrency() > 1)
//       cores_ = boost::thread::hardware_concurrency() -1;
//     else
//       cores_ = 4;
//
//     for (uint i = 0; i < cores_ ; ++i) {
//       thread_group_.create_thread(boost::bind
//               (&boost::asio::io_service::run, &io_service_));
//     }
//     boost::shared_ptr<crypto::Crypto> crypt_(new crypto::Crypto);
//     crypt_->set_hash_algorithm(crypto::Adler_32);

  }
  ~FilesystemAnalyser() {
    Stop();
  }
  void Stop() {
//     work_.reset();
//     thread_group_.join_all();
  }
  void ProcessDirectories(std::vector<fs3::path> directory_paths);
 signals:
  void OnFileProcessed(FileInfo file_info);
  void OnDirectoryEntered(fs3::path directory_path);
  void OnFailure(std::string error_message);
 private:
  FilesystemAnalyser(const FilesystemAnalyser&);
  FilesystemAnalyser &operator=(const FilesystemAnalyser&);
  fs3::path Normalise(const fs3::path &directory_path);
  void ProcessFile(const fs3::path &file_path);
  void ProcessDirectory(const fs3::path &directory_path);
  boost::shared_ptr<boost::asio::io_service> asio_service_;
//  boost::shared_ptr<boost::asio::io_service::work> work_;
//   boost::uint16_t cores_;
//   boost::thread_group thread_group_;
//   boost::shared_ptr<crypto::Crypto> crypt_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_FILESYSTEM_ANALYSER_H_
