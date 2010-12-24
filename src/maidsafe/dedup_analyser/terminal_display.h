/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Derived display class outputting to std::cout
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

#include "maidsafe/dedup_analyser/filesystem_analyser.h"
#include "maidsafe/dedup_analyser/display.h"
#include "maidsafe/dedup_analyser/result_holder.h"

namespace maidsafe {

class TerminalDisplay : public Display {
 public:
  explicit TerminalDisplay(boost::shared_ptr<ResultHolder> result_holder)
      : Display(result_holder) {}
  virtual ~TerminalDisplay() {}
 protected:
  virtual void HandleFileProcessed(FileInfo file_info);
  virtual void HandleDirectoryEntered(fs3::path directory_path);
  virtual void HandleFailure(std::string error_message);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DEDUP_ANALYSER_TERMINAL_DISPLAY_H_
