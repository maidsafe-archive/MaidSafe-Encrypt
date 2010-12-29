/*
 * copyright maidsafe.net limited 2009
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board rof directors of maidsafe.net
 *
 *  Created on: May 8, 2009
 *      Author: Team
 */

#include "maidsafe/lifestuff/widgets/public_username.h"

// qt
#include <QMessageBox>

// core
#include "maidsafe/lifestuff/client/client_controller.h"

// local
#include "maidsafe/lifestuff/client/create_public_username_thread.h"

PublicUsername::PublicUsername(QWidget* parent)
    : Panel(parent)
    , init_(false) {
  ui_.setupUi(this);
  ui_.create->setAutoDefault(true);

  connect(ui_.create, SIGNAL(clicked(bool)),
          this,       SLOT(onCreateUsernameClicked()));

  connect(ui_.contactLineEdit, SIGNAL(returnPressed()),
          this,                SLOT(onCreateUsernameClicked()));

  ui_.progressLabel->setVisible(false);
  ui_.progressBar->setVisible(false);
}

void PublicUsername::clearPubUsername() {
  ui_.contactLineEdit->setText("");
}

void PublicUsername::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
  }
}

void PublicUsername::reset() {
  init_ = false;
  ui_.progressBar->reset();
  ui_.progressLabel->setVisible(false);
  ui_.progressBar->setVisible(false);
}

PublicUsername::~PublicUsername() { }

void PublicUsername::onCreateUsernameClicked() {
  QString text = ui_.contactLineEdit->text().trimmed();
  if (text.isEmpty()) {
    QMessageBox::warning(this, tr("Error"),
                         tr("Please specify a username."));
    return;
  }

  CreatePublicUsernameThread* cput = new CreatePublicUsernameThread(text, this);

  connect(cput, SIGNAL(completed(bool)),
          this, SLOT(onCreateUsernameCompleted(bool)));

  ui_.progressLabel->setVisible(true);
  ui_.progressBar->setVisible(true);

  // we are in process of creating the public user name
  // so hide the button
  ui_.create->setVisible(false);
  // and make the edit box readonly
  ui_.contactLineEdit->setReadOnly(true);

  cput->start();
}

void PublicUsername::onCreateUsernameCompleted(bool success) {
  if (success) {
    ui_.contactLineEdit->setText("");
    emit complete();
    ClientController::instance()->StartCheckingMessages();
  } else {
    QMessageBox::warning(this, tr("Error"), tr("Could not set new username."));
  }
  ui_.progressLabel->setVisible(false);
  ui_.progressBar->setVisible(false);

  // we are done, show the button again
  ui_.create->setVisible(true);
  // and revert the edit box to editable
  ui_.contactLineEdit->setReadOnly(false);
}

void PublicUsername::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}
