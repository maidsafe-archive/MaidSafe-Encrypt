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
#include "maidsafe/dedup_analyser/widgets/speedometer.h"
#include "ui_analyser.h"  // NOLINT (Fraser) - This is generated during CMake
                          // and exists outwith normal source directory.

namespace maidsafe {

AnalyserWidget::AnalyserWidget(QWidget *parent)
    : QWidget(parent),
      ui_analyser_(new Ui::Analyser),
      space_sm_widget_(new Speedometer(this)),
      dupe_sm_widget_(new Speedometer(this)),
      dupe_percentage_(0),
      space_percentage_(0) {

  ui_analyser_->setupUi(this);

  QObject::connect(ui_analyser_->buttonStop, SIGNAL(clicked()), this,
                   SLOT(StopButtonClicked()));
  QObject::connect(ui_analyser_->buttonStop, SIGNAL(clicked()), this,
                   SIGNAL(StopScanning()));

  PositionSpeedometers();

}

void AnalyserWidget::StopButtonClicked() {
  ui_analyser_->buttonStop->setEnabled(false);
}

void AnalyserWidget::PositionSpeedometers() {
  Ui::Analyser * wid = ui_analyser_.get();

  Speedometer *dupe_wid = dupe_sm_widget_.get();
  wid->gridLayout->addWidget(dupe_wid, 1, 0);
  dupe_wid->setRange(0.0, 100.0);
	dupe_wid->setScale(-1, 2, 10);
	dupe_wid->setValue(0);
	dupe_wid->setLabel(tr("Duplicate"));

  Speedometer *space_wid = space_sm_widget_.get();
  wid->gridLayout->addWidget(space_wid, 1, 1);
  space_wid->setRange(0.0, 100.0);
	space_wid->setScale(-1, 2, 10);
	space_wid->setValue(0);
	space_wid->setLabel(tr("Space Savings"));
}

void AnalyserWidget::UpdateDupeSpeedometer(double value) {
  if (value != dupe_percentage_) {
    dupe_percentage_ = value;
    Speedometer *dupe_wid = dupe_sm_widget_.get();
    dupe_wid->setValue(value);
  }
}

void AnalyserWidget::UpdateSpaceSpeedometer(double value) {
  if (value != space_percentage_) {
    space_percentage_ = value;
    Speedometer *space_wid = space_sm_widget_.get();
    space_wid->setValue(value);
  }
}

} // namespace maidsafe
