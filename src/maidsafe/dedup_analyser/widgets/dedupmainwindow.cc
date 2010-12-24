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
#include <QDebug>
#include <QDir>
#include <boost/thread.hpp>
#include "dedupmainwindow.h"
#include "ui_dedupmainwindow.h"
#include "pathselector.h"
#include "analyser.h"

namespace maidsafe {

DedupMainWindow::DedupMainWindow(QWidget *parent) :
    QMainWindow(parent),
      ui(new ::Ui::DedupMainWindow),
    mState(STATE_NULL), pathSelector_(NULL), analyser_(NULL),
    asio_service_(new boost::asio::io_service),
    work_(new boost::asio::io_service::work(*asio_service_)),
    filesystem_analyser_(new maidsafe::FilesystemAnalyser(asio_service_)),
    in_memory_result_holder_(new maidsafe::InMemoryResultHolder),
    interface_(new maidsafe::Display(asio_service_, in_memory_result_holder_)),
    thrd1_(boost::bind(&boost::asio::io_service::run, asio_service_)),
    thrd2_(boost::bind(&boost::asio::io_service::run, asio_service_)),
    thrd3_(boost::bind(&boost::asio::io_service::run, asio_service_))
{
  setWindowIcon(QPixmap(":/icons/32/ms_icon_blue.gif"));
  ui->setupUi(this);  
  createAndAddStackedWidgets();
  setState(PATH_SELECT);

  setupConnections();    
}

DedupMainWindow::~DedupMainWindow()
{
    delete ui;
}

void DedupMainWindow::setState(State aState)
{
    switch (aState) {
        case PATH_SELECT:
            {
                // call state handler
                if (handlePathSelectState() == KERROR_NONE) {

                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        case ANALYSE:
            {
                // call state handler
                if (handleAnalyseState() == KERROR_NONE) {
                    
                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        case REPORT:
            {
                // call state handler
                if (handleReportState() == KERROR_NONE) { 
                    
                    // successfully changed state
                    mState = aState;
                }
            }
            break;

        default:
            break;
    }
}


DedupMainWindow::ErrorVal DedupMainWindow::handlePathSelectState()
{
    ErrorVal ret = KERROR_NONE; 

    try {
        // show the path select widget
        ui->stackedWidget->setCurrentWidget(pathSelector_);
    } catch (...) {
        ret = KERROR_WIDGET_DISPLAY;
    }

    return ret;
}


DedupMainWindow::ErrorVal DedupMainWindow::handleAnalyseState()
{
    ErrorVal ret = KERROR_NONE;

    try {
        // show the analyser widget now
        this->ui->stackedWidget->setCurrentWidget(analyser_);

        // do the background processing
        interface_->ConnectToFilesystemAnalyser(filesystem_analyser_);
        interface_->StartRunningResultUpdates();

        asio_service_->post(boost::bind(&FilesystemAnalyser::ProcessDirectories, filesystem_analyser_, dirs_));
        //filesystem_analyser_->ProcessDirectories(dirs_);
        

    } catch (...) {
        ret = KERROR_WIDGET_DISPLAY;
    }

    return ret;
}

DedupMainWindow::ErrorVal DedupMainWindow::handleReportState()
{
   ErrorVal ret = KERROR_NONE;

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

void DedupMainWindow::createAndAddStackedWidgets()
{
    try {
        pathSelector_   = new PathSelectorWidget(this);
        analyser_       = new AnalyserWidget(this);
        this->ui->stackedWidget->addWidget(pathSelector_);
        this->ui->stackedWidget->addWidget(analyser_);
    } catch (...) {
        qDebug() << "\nError in DedupMainWindow::createStackedWidgets";
    }
}

void DedupMainWindow::setupConnections()
{
  bool t = QObject::connect(pathSelector_, SIGNAL(analyseNow(std::vector<boost::filesystem3::path>)),
    this, SLOT(validatePathSelection(std::vector<boost::filesystem3::path>)));
  QObject::connect(pathSelector_, SIGNAL(exitDedupAnalyser()),
    this, SLOT(exitRequest()));
  QObject::connect(analyser_, SIGNAL(StopScanning()),
    this, SLOT(StopProcessing()));  
}

void DedupMainWindow::validatePathSelection(std::vector<boost::filesystem3::path> dirs)
{
    // TODO: do validation of any sort.. skipping at the moment
    // We can use boost filesystem to check all drives and dirs (paths) exist
    
  bool r = QObject::connect(interface_.get(), SIGNAL(UpdatedResults(Results)), 
    this, SLOT(GetResults(Results)), Qt::DirectConnection);
  dirs_ = dirs;
    setState(ANALYSE);
}

void DedupMainWindow::exitRequest()
{
    // application is exiting
    // TODO: do any stuff necessary before exit
    this->close();
}

void DedupMainWindow::FileProcessed() {
  int x = 0;
  x++;
}

void DedupMainWindow::StopProcessing()
{
  filesystem_analyser_->Stop(); // make sure all threads completed
  interface_->StopRunningResultUpdates();
  work_.reset();
  thrd1_.join();
  thrd2_.join();
  thrd3_.join();
}

void DedupMainWindow::GetResults(Results res)
{
  unsigned int dupe_count = res.duplicate_file_count;
  unsigned int dupe_size = res.total_duplicate_size;
}

}

