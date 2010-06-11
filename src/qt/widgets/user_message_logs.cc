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
 *  Created on: June 09, 2010
 *      Author: Team
 */

#include "qt/widgets/user_message_logs.h"

// qt
#include <QDebug>
#include <QtGui>
#include <QStringList>

// local
#include "qt/client/client_controller.h"
#include "qt/widgets/user_panels.h"

MessageLogs::MessageLogs(QWidget* parent)
    : Panel(parent), init_(false) {
  ui_.setupUi(this);
  sortType_ = 0;

  ui_.logListWidget->setContextMenuPolicy(Qt::CustomContextMenu);

  connect(ClientController::instance(),
        SIGNAL(messageReceived(int,
                                  const QDateTime&,
                                  const QString&,
                                  const QString&,
                                  const QString&)),
        this,
        SLOT(onMessageReceived(int,
                                  const QDateTime&,
                                  const QString&,
                                  const QString&,
                                  const QString&)));
}

MessageLogs::~MessageLogs() { }

void MessageLogs::setActive(bool b) {
  if (b && !init_) {
    // Do Any New Instance Stuff
    init_ = true;    
  }
}

void MessageLogs::reset() {
  // clear the list of Messages
}

void MessageLogs::addMessage(QString message) {
  ui_.logListWidget->addItem(message);
}

void MessageLogs::onMessageReceived(int type,
                                      const QDateTime&,
                                      const QString& sender,
                                      const QString& detail,
                                      const QString&) {
  // TODO(Stephen) :: grab important messages and put in Log
  if (ClientController::MessageType(type) == ClientController::TEXT) {   
    // ui_.logListWidget->insertItem(0, detail);
  }
}

void MessageLogs::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}



