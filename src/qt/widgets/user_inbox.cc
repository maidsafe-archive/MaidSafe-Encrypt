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
#include "qt/widgets/user_inbox.h"

#include <QMessageBox>
#include <QDebug>

#include "qt/client/client_controller.h"


UserInbox::UserInbox(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);

	//TODO: get	list of conversations sorted by last contacted
	QStringList mailList;

	ui_.messageListWidget->addItems(mailList);

	connect(ui_.replyButton, SIGNAL(clicked()),
          this,             SLOT(onReplyClicked()));
	
	connect(ui_.messageListWidget, SIGNAL(itemClicked(QListWidgetItem*)),
					this,								SLOT(onEmailClicked(QListWidgetItem*)));

	ui_.groupBox->setVisible(false);
}

UserInbox::~UserInbox() {}

void UserInbox::onReplyClicked() {	
	//TODO: Send update email message
}

void UserInbox::onEmailClicked(QListWidgetItem* item) {
	//TODO: Receive Email Message and Display in TextBox
	QString email = item->text();
}

void UserInbox::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

