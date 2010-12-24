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
#ifndef DEDUPMAINWINDOW_H
#define DEDUPMAINWINDOW_H

#include <QMainWindow>
#include <boost/thread.hpp>
#include "maidsafe/dedup_analyser/filesystem_analyser.h"
#include "maidsafe/dedup_analyser/in_memory_result_holder.h"
#include "maidsafe/dedup_analyser/display.h"

namespace Ui {
    class DedupMainWindow;
}

namespace maidsafe {

class PathSelectorWidget;
class AnalyserWidget;

class DedupMainWindow : public QMainWindow
{
    Q_OBJECT

private:
    enum State {
        STATE_NULL,
        PATH_SELECT,
        ANALYSE,
        REPORT
    };

    enum ErrorVal {
        KERROR_NONE,
        KERROR_WIDGET_DISPLAY
    };

    State mState;  

public:
    explicit DedupMainWindow(QWidget *parent = 0);
    ~DedupMainWindow();
    
    inline State state(){return mState;}

private:
    // set the new state
    void setState(State);

    /*
    * handler for PATH_SELECT
    * returns ErrorVal 
    */
    ErrorVal handlePathSelectState();

    /*
    * handler for ANALYSE
    * returns ErrorVal
    */
    ErrorVal handleAnalyseState();

    /*
    * handler for REPORT
    * returns ErrorVal
    */
    ErrorVal handleReportState();  

    /*
    * create child widgets for dedup_analyser
    * adds them to DedupMainWindow
    */
    void createAndAddStackedWidgets();

    /* 
    * Qt connections between widgets
    */
    void setupConnections();

private slots:
    /* 
    * Checks if user selected paths are okay!
    */
    void validatePathSelection(std::vector<boost::filesystem3::path>);

    /*
    * exit called
    */
    void exitRequest();

 public slots:
  void FileProcessed();
  void StopProcessing();
  void GetResults(Results);  // gets results from the interface_

 private:
  ::Ui::DedupMainWindow *ui;
  PathSelectorWidget *pathSelector_;
  AnalyserWidget *analyser_;
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  boost::shared_ptr<boost::asio::io_service::work> work_;
  boost::shared_ptr<maidsafe::FilesystemAnalyser> filesystem_analyser_;
  boost::shared_ptr<maidsafe::InMemoryResultHolder> in_memory_result_holder_;
  boost::shared_ptr<maidsafe::Display> interface_;
  boost::thread thrd1_;
  boost::thread thrd2_;
  boost::thread thrd3_;
  std::vector<boost::filesystem3::path> dirs_;
};
}  // namespace maidsafe

#endif // DEDUPMAINWINDOW_H

