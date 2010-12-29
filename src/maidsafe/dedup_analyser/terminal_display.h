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

#ifndef MAIDSAFE_DEDUP_ANALYSER_TERMINAL_DISPLAY_H_
#define MAIDSAFE_DEDUP_ANALYSER_TERMINAL_DISPLAY_H_

#include <boost/filesystem/path.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <QObject>
#include <string>
#include "maidsafe/dedup_analyser/interface.h"

namespace fs3 = boost::filesystem3;

namespace maidsafe {

struct FileInfo;
struct Results;
class Interface;

class TerminalDisplay : public QObject {
  Q_OBJECT
 public:
  explicit TerminalDisplay(boost::shared_ptr<Interface> interface);
  virtual ~TerminalDisplay() {}
 public slots:  // NOLINT (fraser)
  void HandleFileProcessed(FileInfo file_info);
  void HandleDirectoryEntered(fs3::path directory_path);
  void HandleFailure(std::string error_message);
  void HandleResults(Results results);
 private:
  boost::mutex mutex_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_TERMINAL_DISPLAY_H_
