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
#ifndef MAIDSAFE_DEDUP_ANALYSER_WIDGETS_DEDUPMAINWINDOW_H
#define MAIDSAFE_DEDUP_ANALYSER_WIDGETS_DEDUPMAINWINDOW_H

#include <QMainWindow>
#include <boost/thread.hpp>
#include "maidsafe/dedup_analyser/filesystem_analyser.h"
#include "maidsafe/dedup_analyser/in_memory_result_holder.h"
#include "maidsafe/dedup_analyser/interface.h"

namespace fs3 = boost::filesystem3;

namespace Ui { class DedupMainWindow; }

namespace maidsafe {

class PathSelectorWidget;
class AnalyserWidget;

class DedupMainWindow : public QMainWindow {
  Q_OBJECT
 public:
  explicit DedupMainWindow(QWidget *parent);
  ~DedupMainWindow() {}

 public slots:
  void FileProcessed();
  void StopProcessing();
  void GetResults(Results);  // gets results from the interface_

 private slots:
  /* 
  * Checks if user selected paths are okay!
  */
  void ValidatePathSelection(std::vector<fs3::path>);

  /*
  * exit called
  */
  void ExitRequest();

 private:
  enum State { kStateNull, kPathSelect, kAnalyse, kReport };
  enum ErrorVal { kErrorNone, kErrorWidgetDisplay };
  void set_state(State state);

  /*
  * handler for kPathSelect
  * returns ErrorVal 
  */
  ErrorVal HandlePathSelectState();

  /*
  * handler for kAnalyse
  * returns ErrorVal
  */
  ErrorVal HandleAnalyseState();

  /*
  * handler for kReport
  * returns ErrorVal
  */
  ErrorVal HandleReportState();  

  /*
  * create child widgets for dedup_analyser
  * adds them to DedupMainWindow
  */
  void CreateAndAddStackedWidgets();

  /* 
  * Qt connections between widgets
  */
  void SetupConnections();

  State state_;  
  boost::shared_ptr<Ui::DedupMainWindow> ui_dedup_main_window_;
  boost::shared_ptr<PathSelectorWidget> path_selector_widget_;
  boost::shared_ptr<AnalyserWidget> analyser_widget_;
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  boost::shared_ptr<boost::asio::io_service::work> work_;
  boost::shared_ptr<FilesystemAnalyser> filesystem_analyser_;
  boost::shared_ptr<InMemoryResultHolder> in_memory_result_holder_;
  boost::shared_ptr<Interface> interface_;
  boost::thread thrd1_, thrd2_, thrd3_;
  std::vector<fs3::path> dirs_;
};

}  // namespace maidsafe

#endif // MAIDSAFE_DEDUP_ANALYSER_WIDGETS_DEDUPMAINWINDOW_H
