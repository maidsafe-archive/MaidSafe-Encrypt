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

#include <boost/bind.hpp>
#include "maidsafe/dedup_analyser/display.h"
#include "maidsafe/dedup_analyser/result_holder.h"

namespace maidsafe {

Display::Display(boost::shared_ptr<boost::asio::io_service> asio_service,
                boost::shared_ptr<ResultHolder> result_holder)
    : asio_service_(asio_service),
      result_holder_(result_holder),
      mutex_(),
      running_(false),
      timer_(*asio_service_, update_interval_),
      update_interval_(3000) {}

bool Display::ConnectToFilesystemAnalyser(
    boost::shared_ptr<FilesystemAnalyser> analyser) {
  return QObject::connect(analyser.get(), SIGNAL(OnFileProcessed(FileInfo)),
                          this, SLOT(HandleFileProcessed(FileInfo))) &&
      QObject::connect(analyser.get(), SIGNAL(OnDirectoryEntered(fs3::path)),
                       this, SLOT(HandleDirectoryEntered(fs3::path))) &&
      QObject::connect(analyser.get(), SIGNAL(OnFailure(std::string)), this,
                       SLOT(HandleFailure(std::string))) &&
      QObject::connect(analyser.get(), SIGNAL(OnFileProcessed(FileInfo)),
                       result_holder_.get(),
                       SLOT(HandleFileProcessed(FileInfo))) &&
      QObject::connect(analyser.get(), SIGNAL(OnFailure(std::string)),
                       result_holder_.get(), SLOT(HandleFailure(std::string)));

}

void Display::StartRunningResultUpdates() {
  {
    boost::mutex::scoped_lock lock(mutex_);
    running_ = true;
  }
  timer_.async_wait(boost::bind(&Display::FetchResults, this, _1));
}

void Display::StopRunningResultUpdates() {
  {
    boost::mutex::scoped_lock lock(mutex_);
    running_ = true;
  }
  timer_.cancel();
}

void Display::set_update_interval(
    const boost::posix_time::milliseconds &update_interval) {
  boost::mutex::scoped_lock lock(mutex_);
  update_interval_ = update_interval;
}

void Display::FetchResults(const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted)
      emit OnFailure(error_code.message());
  } else {
    Results results(result_holder_->GetResults());
    std::cout << std::endl << "££££££££££££££££££££££££££££££££££££££££££ " << results.unique_file_count << std::endl;
    emit UpdatedResults(results);
    timer_.expires_from_now(update_interval_);
    timer_.async_wait(boost::bind(&Display::FetchResults, this, _1));
  }
}

void Display::HandleFileProcessed(FileInfo file_info) {
  emit OnFileProcessed(file_info);
}

void Display::HandleDirectoryEntered(fs3::path directory_path) {
  emit OnDirectoryEntered(directory_path);
}

void Display::HandleFailure(std::string error_message) {
  emit OnFailure(error_message);
}

}  // namespace maidsafe
