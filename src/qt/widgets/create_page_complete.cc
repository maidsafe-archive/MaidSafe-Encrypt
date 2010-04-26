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

#include "qt/widgets/create_page_complete.h"

// qt
#include <QDebug>


CreateCompletePage::CreateCompletePage(QWidget* parent)
    : QWizardPage(parent) {
  ui_.setupUi(this);

  setTitle(tr("Ready to Create Account"));

  cleanupPage();
}

CreateCompletePage::~CreateCompletePage() {}

void CreateCompletePage::showCreationProgress(bool show) {
  ui_.progress_label->setVisible(show);
  ui_.progress_bar->setVisible(show);
}

void CreateCompletePage::setMessage(const QString& msg) {
  ui_.label->setText(msg);
}

void CreateCompletePage::setProgressMessage(const QString& msg) {
  ui_.progress_label->setText(msg);
}

void CreateCompletePage::cleanupPage() {
  setMessage(tr("<qt>We now have all the details required to create a new user "
                "account. Press 'Finish' to complete the process.<br/><br/>"
                "Please note that this can take several minutes.</qt>"));

  showCreationProgress(false);
}

void CreateCompletePage::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}


