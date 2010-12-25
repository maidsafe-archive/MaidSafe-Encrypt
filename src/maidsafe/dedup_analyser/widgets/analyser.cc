/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Main window for dedup application
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
#include "maidsafe/dedup_analyser/widgets/analyser.h"
#include "ui_analyser.h"  // NOLINT (Fraser) - This is generated during CMake
                          // and exists outwith normal source directory.

namespace maidsafe {

AnalyserWidget::AnalyserWidget(QWidget *parent)
    : QWidget(parent),
      ui_analyser_(new Ui::Analyser) {
//      spacePercentageMeter(NULL),
//      dupePercentageMeter(NULL) {
  ui_analyser_->setupUi(this);
  QObject::connect(ui_analyser_->buttonStop, SIGNAL(clicked()), this,
                   SLOT(StopButtonClicked()));
  QObject::connect(ui_analyser_->buttonStop, SIGNAL(clicked()), this,
                   SIGNAL(StopScanning()));
//  spacePercentageMeter = new SpeedoMeter(this);
//  dupePercentageMeter = new SpeedoMeter(this);
}

void AnalyserWidget::StopButtonClicked() {
  ui_analyser_->buttonStop->setEnabled(false);
}

}  // namespace maidsafe
