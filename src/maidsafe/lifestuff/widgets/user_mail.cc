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
 *  Created on: May 18, 2010
 *      Author: Stephen Alexander
 */
#include "maidsafe/lifestuff/widgets/user_mail.h"

#include <QMessageBox>
#include <QDebug>

#include "maidsafe/lifestuff/client/client_controller.h"


UserMail::UserMail(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);

  userInbox_		= new UserInbox;
  userSendMail_ = new UserSendMail;

  ui_.stackedWidget->addWidget(userInbox_);
  ui_.stackedWidget->addWidget(userSendMail_);
	
}

UserMail::~UserMail() {}

void UserMail::onCurrentRowChanged(int index) {
  switch (index) {
    case 0:
      setState(INBOX);
      break;
    case 1:
      setState(SENT);
      break;
  }
}

void UserMail::createSettingsMenu() {
	ui_.mailMenuList->addItem("Inbox");
  ui_.mailMenuList->addItem("Sent Messages");
}

void UserMail::setState(State state) {
  state_ = state;

  switch (state_) {
    case INBOX:
    {
      ui_.stackedWidget->setCurrentWidget(userInbox_);
      break;
    }
    case SENT:
    {
      ui_.stackedWidget->setCurrentWidget(userSendMail_);
      break;
    }
    default:
    {
      break;
    }
  }
}

void UserMail::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

