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

#include "qt/widgets/create_page_options.h"

// qt
#include <QDebug>

#include "qt/client/client_controller.h"

CreateOptionsPage::CreateOptionsPage(QWidget* parent)
    : QWizardPage(parent) {
  ui_.setupUi(this);

  setTitle(tr("Storage Options"));
  ui_.buy->setEnabled(false);
  ui_.borrow->setEnabled(false);
}

CreateOptionsPage::~CreateOptionsPage() { }

void CreateOptionsPage::cleanupPage() {
//  if (ClientController::instance()->IsLocalVaultOwned()) {
//    ui_.local->setEnabled(false);
//  } else {
    ui_.local->setChecked(true);
//  }
}

int CreateOptionsPage::VaultType() {
  if (ui_.buy->isChecked())
    return 1;
  else if (ui_.borrow->isChecked())
    return 2;
  return 0;
}

void CreateOptionsPage::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    // TODO Get lang from ClientController and Update as Neccesary
    //ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}

