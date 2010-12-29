/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Detail window for dedup application
* Version:      1.0
* Created:      2010, 21 / 12
* Revision:     none
* Author:       Saidle
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
#include <boost/thread.hpp>
#include <QDebug>
#include <QDir>
#include "maidsafe/dedup_analyser/widgets/dedupmainwindow.h"
#include "maidsafe/dedup_analyser/widgets/pathselector.h"
#include "maidsafe/dedup_analyser/widgets/analyser.h"
#include "ui_dedupmainwindow.h"  // NOLINT (Fraser) - This is generated during
                                 // CMake and exists outwith normal source dir.

namespace fs3 = boost::filesystem3;

namespace maidsafe {

DedupMainWindow::DedupMainWindow(QWidget *parent)
    : QMainWindow(parent),
      state_(kStateNull),
      ui_dedup_main_window_(new Ui::DedupMainWindow),
      path_selector_widget_(),
      analyser_widget_(),
      asio_service_(new boost::asio::io_service),
      work_(new boost::asio::io_service::work(*asio_service_)),
      filesystem_analyser_(new maidsafe::FilesystemAnalyser(asio_service_)),
      in_memory_result_holder_(new maidsafe::InMemoryResultHolder),
      interface_(new maidsafe::Interface(asio_service_,
                                         in_memory_result_holder_)),
      thrd1_(boost::bind(&boost::asio::io_service::run, asio_service_)),
      thrd2_(boost::bind(&boost::asio::io_service::run, asio_service_)),
      thrd3_(boost::bind(&boost::asio::io_service::run, asio_service_)),
      dirs_() {
  setWindowIcon(QPixmap(":/icons/32/ms_icon_blue.gif"));
  ui_dedup_main_window_->setupUi(this);
  CreateAndAddStackedWidgets();
  set_state(kPathSelect);
  SetupConnections();
}

void DedupMainWindow::set_state(State state) {
  switch (state) {
    case kPathSelect:
      if (HandlePathSelectState() == kErrorNone)
        state_ = state;
      break;
    case kAnalyse:
      if (HandleAnalyseState() == kErrorNone)
        state_ = state;
      break;
    case kReport:
      if (HandleReportState() == kErrorNone)
        state_ = state;
      break;
    default:
      break;
  }
}

DedupMainWindow::ErrorVal DedupMainWindow::HandlePathSelectState() {
  ErrorVal ret = kErrorNone;

  try {
    // show the path select widget
    ui_dedup_main_window_->stackedWidget->
        setCurrentWidget(path_selector_widget_.get());
  }
  catch(...) {
    ret = kErrorWidgetDisplay;
  }

  return ret;
}

DedupMainWindow::ErrorVal DedupMainWindow::HandleAnalyseState() {
  ErrorVal ret = kErrorNone;

  try {
    // show the analyser widget now
    ui_dedup_main_window_->stackedWidget->
        setCurrentWidget(analyser_widget_.get());

    // do the background processing
    interface_->ConnectToFilesystemAnalyser(filesystem_analyser_);
    interface_->StartRunningResultUpdates();

    asio_service_->post(boost::bind(
        &FilesystemAnalyser::ProcessDirectories, filesystem_analyser_, dirs_));
  }
  catch(...) {
    ret = kErrorWidgetDisplay;
  }

  return ret;
}

DedupMainWindow::ErrorVal DedupMainWindow::HandleReportState() {
  ErrorVal ret = kErrorNone;

  /*
  std::cout << "Total processed file count:           " << in_memory_result_holder->UniqueFileCount() + in_memory_result_holder->DuplicateFileCount() << std::endl;
  std::cout << "Total of all processed files' sizes:  " << in_memory_result_holder->TotalUniqueSize() + in_memory_result_holder->TotalDuplicateSize() << std::endl;
  std::cout << "Unprocessed file count:               " << in_memory_result_holder->ErrorsCount() << std::endl << std::endl;
  std::cout << "Unique file count:                    " << in_memory_result_holder->UniqueFileCount() << std::endl;
  std::cout << "Total of unique files' sizes:         " << in_memory_result_holder->TotalUniqueSize() << std::endl << std::endl;
  std::cout << "Duplicate file count:                 " << in_memory_result_holder->DuplicateFileCount() << std::endl;
  std::cout << "Total of duplicate files' sizes:      " << in_memory_result_holder->TotalDuplicateSize() << std::endl << std::endl << std::endl;
  std::cout << "Duplicate files as a percentage of all files:  " << static_cast<double>(in_memory_result_holder->DuplicateFileCount()) * 100 / (in_memory_result_holder->UniqueFileCount() + in_memory_result_holder->DuplicateFileCount()) << " %" << std::endl;
  std::cout << "Duplicate size as a percentage of total size:  " << static_cast<float>(in_memory_result_holder->TotalDuplicateSize()) * 100 / (in_memory_result_holder->TotalUniqueSize() + in_memory_result_holder->TotalDuplicateSize()) << " %" <<  std::endl;

  interface_->StopRunningResultUpdates();
  work_.reset();
  thrd1_.join();
  thrd2_.join();
  thrd3_.join();
  */

  return ret;
}

void DedupMainWindow::CreateAndAddStackedWidgets() {
  try {
    path_selector_widget_.reset(new PathSelectorWidget(this));
    analyser_widget_.reset(new AnalyserWidget(this));
    ui_dedup_main_window_->stackedWidget->addWidget(
        path_selector_widget_.get());
    ui_dedup_main_window_->stackedWidget->addWidget(analyser_widget_.get());
  }
  catch(...) {
    qDebug() << "\nError in DedupMainWindow::createStackedWidgets";
  }
}

void DedupMainWindow::SetupConnections() {
  QObject::connect(path_selector_widget_.get(),
                   SIGNAL(AnalyseNow(std::vector<fs3::path>)), this,
                   SLOT(ValidatePathSelection(std::vector<fs3::path>)));
  QObject::connect(path_selector_widget_.get(), SIGNAL(ExitDedupAnalyser()),
                   this, SLOT(ExitRequest()));
  QObject::connect(analyser_widget_.get(), SIGNAL(StopScanning()), this,
                   SLOT(StopProcessing()));
}

void DedupMainWindow::ValidatePathSelection(std::vector<fs3::path> dirs) {
  // TODO(Fraser#5#): 2010-12-25 - do validation of any sort.. skipping just now
  // We can use boost filesystem to check all drives and dirs (paths) exist

  QObject::connect(interface_.get(), SIGNAL(UpdatedResults(Results)),
                            this, SLOT(GetResults(Results)),
                            Qt::DirectConnection);
  dirs_ = dirs;
  set_state(kAnalyse);
}

void DedupMainWindow::ExitRequest() {
  // application is exiting
  // TODO(Fraser#5#): 2010-12-25 - do any stuff necessary before exit
  this->close();
}

void DedupMainWindow::FileProcessed() {
  int x = 0;
  x++;
}

void DedupMainWindow::StopProcessing() {
  filesystem_analyser_->Stop();  // make sure all threads completed
  interface_->StopRunningResultUpdates();
  work_.reset();
  thrd1_.join();
  thrd2_.join();
  thrd3_.join();
}

void DedupMainWindow::GetResults(Results res) {
  try {
    int total_count = res.unique_file_count + res.duplicate_file_count;

    if (total_count != 0) {
      double dupe_percentage = (res.duplicate_file_count * 100) / total_count;
      analyser_widget_.get()->UpdateDupeSpeedometer(dupe_percentage);
      qDebug() << "\n\nDuplicate % = " << dupe_percentage << "\n\n";
    }

    total_count = res.total_unique_size + res.total_duplicate_size;
    if ( total_count != 0 ) {
      float space_percentage = (res.total_duplicate_size * 100) / total_count;
      analyser_widget_.get()->UpdateSpaceSpeedometer(space_percentage);
      qDebug() << "space % = " << space_percentage << "\n\n";
    }
  } catch (...) {
    qDebug() << "\n\n Exception in GetResults\n";
  }
}

}  // namespace maidsafe
