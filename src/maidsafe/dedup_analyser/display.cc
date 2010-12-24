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

#include "maidsafe/dedup_analyser/display.h"
#include "maidsafe/dedup_analyser/result_holder.h"

namespace maidsafe {

Display::Display(boost::shared_ptr<ResultHolder> result_holder)
    : result_holder_(result_holder) {}

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

}  // namespace maidsafe
