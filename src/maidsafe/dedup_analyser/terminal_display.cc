/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Display class outputting to std::cout
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

#include "maidsafe/dedup_analyser/terminal_display.h"
#include <iostream>
#include <QMetaType>

namespace maidsafe {

TerminalDisplay::TerminalDisplay(boost::shared_ptr<Display> display) {
  qRegisterMetaType<Results>("Results");
  QObject::connect(display.get(), SIGNAL(OnFileProcessed(FileInfo)), this,
                   SLOT(HandleFileProcessed(FileInfo)));
  QObject::connect(display.get(), SIGNAL(OnDirectoryEntered(fs3::path)), this,
                   SLOT(HandleDirectoryEntered(fs3::path)));
  QObject::connect(display.get(), SIGNAL(OnFailure(std::string)), this,
                   SLOT(HandleFailure(std::string)));
  QObject::connect(display.get(), SIGNAL(UpdatedResults(Results)), this,
                   SLOT(HandleResults(Results)));
}

void TerminalDisplay::HandleFileProcessed(FileInfo /*file_info*/) {
  std::cout << ".";
}

void TerminalDisplay::HandleDirectoryEntered(fs3::path directory_path) {
  std::cout << "\nEntered " << directory_path.string().c_str() << std::endl;
//  std::cout << "." ;
}

void TerminalDisplay::HandleFailure(std::string error_message) {
  std::cout << error_message.c_str() << std::endl;
}

void TerminalDisplay::HandleResults(Results results) {
  std::cout << std::endl << "************************************" << std::endl;
  std::cout << "Duplicate count: " << results.duplicate_file_count << std::endl;
  std::cout << "Duplicate size:  " << results.total_duplicate_size << std::endl;
  std::cout << "************************************" << std::endl;
}

}  // namespace maidsafe
