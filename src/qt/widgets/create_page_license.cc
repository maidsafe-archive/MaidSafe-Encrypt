/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#include "qt/widgets/create_page_license.h"

// qt
#include <QDebug>


CreateLicensePage::CreateLicensePage(QWidget* parent)
    : QWizardPage(parent) {
  ui_.setupUi(this);

  setTitle(tr("License agreement"));

  connect(ui_.accept, SIGNAL(toggled(bool)),
          this,       SLOT(onAcceptToggled(bool)));
}

CreateLicensePage::~CreateLicensePage() { }

void CreateLicensePage::onAcceptToggled(bool) {
  emit completeChanged();
}

bool CreateLicensePage::isComplete() const {
  return ui_.accept->isChecked();
}

void CreateLicensePage::cleanupPage() {
  ui_.decline->setChecked(true);
}
