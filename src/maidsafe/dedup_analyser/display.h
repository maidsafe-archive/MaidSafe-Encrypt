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
#include "maidsafe/dedup_analyser/filesystem_analyser.h"

namespace fs3 = boost::filesystem3;

namespace maidsafe {

class Display : public QObject {
  Q_OBJECT
 public:
  Display() {}
  virtual ~Display() { /*DisconnectFromFilesystemAnalyser();*/ }
  void ConnectToFilesystemAnalyser(FilesystemAnalyser *analyser);
//  void DisconnectFromFilesystemAnalyser();
 public slots:
  virtual void HandleFileProcessed(FileInfo file_info) = 0;
  virtual void HandleDirectoryEntered(fs3::path directory_path) = 0;
  virtual void HandleFailure(std::string error_message) = 0;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_DISPLAY_H_
