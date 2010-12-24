/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Main function.
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

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <iostream>
#include <QApplication>
#include "maidsafe/dedup_analyser/filesystem_analyser.h"
#include "maidsafe/dedup_analyser/in_memory_result_holder.h"
#include "maidsafe/dedup_analyser/display.h"
#include "maidsafe/dedup_analyser/terminal_display.h"
#include "maidsafe/dedup_analyser/widgets/dedupmainwindow.h"
/*
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    DedupMainWindow mainWin;
    mainWin.show();

    return app.exec();
}
*/

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cout << "Usage: Dedup <path to start recursive check>" << std::endl << std::endl;
    return -1;
  }
  boost::filesystem3::path path(argv[1]);
  boost::filesystem3::space_info size = boost::filesystem3::space(path);
  boost::uintmax_t capacity = size.capacity/(1024*1024*1024);
  boost::uintmax_t free_space = size.free/(1024*1024*1024);

  std::cout << "Drive capacity is : " << capacity << " GB and of that "
                                      << capacity-free_space << " GB has been used!" << std::endl;

  boost::shared_ptr<boost::asio::io_service>
      asio_service(new boost::asio::io_service);
  boost::shared_ptr<boost::asio::io_service::work>
      work(new boost::asio::io_service::work(*asio_service));
  boost::thread thrd1(boost::bind(&boost::asio::io_service::run, asio_service));
  boost::thread thrd2(boost::bind(&boost::asio::io_service::run, asio_service));
  boost::shared_ptr<maidsafe::FilesystemAnalyser>
      filesystem_analyser(new maidsafe::FilesystemAnalyser(asio_service));

  boost::shared_ptr<maidsafe::InMemoryResultHolder>
      in_memory_result_holder(new maidsafe::InMemoryResultHolder);
  boost::shared_ptr<maidsafe::Display> display(
      new maidsafe::Display(asio_service, in_memory_result_holder));
  display->ConnectToFilesystemAnalyser(filesystem_analyser);
  maidsafe::TerminalDisplay terminal_display(display);
  display->StartRunningResultUpdates();
  std::vector<boost::filesystem3::path>
      dirs(1, boost::filesystem3::path(argv[1]));
  filesystem_analyser->ProcessDirectories(dirs);
  filesystem_analyser->Stop(); // make sure all threads completed

  std::cout << std::endl << std::endl << "Processing results..." << std::endl << std::endl;
  std::cout << "Drive capacity is : " << capacity << " GB and of that "
                                      << capacity-free_space << " GB has been used!" << std::endl;

  std::cout << "Total processed file count:           " << in_memory_result_holder->UniqueFileCount() + in_memory_result_holder->DuplicateFileCount() << std::endl;
  std::cout << "Total of all processed files' sizes:  " << in_memory_result_holder->TotalUniqueSize() + in_memory_result_holder->TotalDuplicateSize() << std::endl;
  std::cout << "Unprocessed file count:               " << in_memory_result_holder->ErrorsCount() << std::endl << std::endl;
  std::cout << "Unique file count:                    " << in_memory_result_holder->UniqueFileCount() << std::endl;
  std::cout << "Total of unique files' sizes:         " << in_memory_result_holder->TotalUniqueSize() << std::endl << std::endl;
  std::cout << "Duplicate file count:                 " << in_memory_result_holder->DuplicateFileCount() << std::endl;
  std::cout << "Total of duplicate files' sizes:      " << in_memory_result_holder->TotalDuplicateSize() << std::endl << std::endl << std::endl;
  std::cout << "Duplicate files as a percentage of all files:  " << static_cast<double>(in_memory_result_holder->DuplicateFileCount()) * 100 / (in_memory_result_holder->UniqueFileCount() + in_memory_result_holder->DuplicateFileCount()) << " %" << std::endl;
  std::cout << "Duplicate size as a percentage of total size:  " << static_cast<float>(in_memory_result_holder->TotalDuplicateSize()) * 100 / (in_memory_result_holder->TotalUniqueSize() + in_memory_result_holder->TotalDuplicateSize()) << " %" <<  std::endl;

  work.reset();
  thrd1.join();
  thrd2.join();
  return 0;
}

