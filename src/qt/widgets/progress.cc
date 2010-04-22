/*
 * copyright maidsafe.net limited 2009
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: May 6, 2009
 *      Author: Team
 */

#include "qt/widgets/progress.h"

// qt
#include <QDebug>


Progress::Progress(QWidget* parent) : QWidget(parent) {
  ui_.setupUi(this);

  connect(ui_.ok, SIGNAL(clicked(bool)),
          this,   SIGNAL(ok()));

  connect(ui_.cancel, SIGNAL(clicked(bool)),
          this,       SIGNAL(cancel()));
}

Progress::~Progress() {}

void Progress::setTitle(const QString& msg) {
  ui_.title->setText(msg);
}

void Progress::setMessage(const QString& msg) {
  ui_.progress_label->setText(msg);
}

void Progress::setProgressMessage(const QString& msg) {
  ui_.progress_label->setText(msg);
}

void Progress::setError(bool error) {
  ui_.ok->setVisible(error);
  ui_.cancel->setVisible(!error);
  ui_.progress_bar->setVisible(!error);
}

void Progress::setCanCancel(bool cancancel) {
  ui_.cancel->setEnabled(cancancel);
}

void Progress::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    // TODO Get lang from ClientController and Update as Neccesary
    //ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}


