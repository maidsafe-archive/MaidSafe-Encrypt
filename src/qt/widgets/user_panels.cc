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
 *  Created on: Apr 09, 2009
 *      Author: Team
 */

#include "qt/widgets/user_panels.h"

// qt
#include <QDebug>
#include <QLabel>
#include <QValidator>


// local
#include "qt/widgets/panel.h"
#include "qt/widgets/messages.h"
#include "qt/widgets/shares.h"
#include "qt/widgets/contacts.h"
#include "qt/widgets/vault_info.h"
#include "qt/widgets/public_username.h"
#include "qt/client/client_controller.h"
#include "qt/client/user_space_filesystem.h"

namespace {
}

UserPanels::UserPanels(QWidget* parent)
    : QWidget(parent)
    , messages_(NULL)
    , shares_(NULL)
    , contacts_(NULL)
    , panel_(-1) {
  ui_.setupUi(this);

  connect(ui_.listWidget, SIGNAL(currentRowChanged(int)),
          this,           SLOT(onCurrentRowChanged(int)));

  ui_.stackedWidget->addWidget(contacts_ = new Contacts);
  ui_.stackedWidget->addWidget(shares_   = new Shares);
  ui_.stackedWidget->addWidget(messages_ = new Messages);
  ui_.stackedWidget->addWidget(vaultinfo_ = new VaultInfo);
//  ui_.stackedWidget->addWidget(new QLabel("settings"));
  ui_.stackedWidget->addWidget(new QLabel("activities"));
  ui_.stackedWidget->addWidget(new QLabel("help"));
  ui_.stackedWidget->addWidget(public_username_ = new PublicUsername);


  Q_ASSERT(messages_);
  Q_ASSERT(shares_);
  Q_ASSERT(contacts_);
  Q_ASSERT(vaultinfo_);

  connect(messages_, SIGNAL(messageReceived()),
          this,      SLOT(onMessageReceived()));

  connect(public_username_, SIGNAL(complete()),
          this,             SLOT(onPublicUsernameChosen()));

  connect(ui_.my_files_button, SIGNAL(clicked(bool)),
          this,                SLOT(onMyFilesClicked()));
}

UserPanels::~UserPanels() { }

void UserPanels::onMessageReceived() {
  emit unreadMessages(messages_->unreadMessages());
}

void UserPanels::onPublicUsernameChosen() {
  ui_.listWidget->setEnabled(true);
  onCurrentRowChanged(ui_.stackedWidget->indexOf(contacts_));
  ui_.user_public_username->setText(
      ClientController::instance()->publicUsername());
  ClientController::instance()->StartCheckingMessages();
}

void UserPanels::onMyFilesClicked() {
  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::MY_FILES);
}

void UserPanels::onCurrentRowChanged(int i) {
  // change the active panel
#ifdef DEBUG
  printf("Current: %i -- Next: %i\n", panel_, i);
#endif
  activatePanel(panel_, false);
  panel_ = i;
  activatePanel(panel_, true);

  ui_.stackedWidget->setCurrentIndex(i);
}

void UserPanels::activatePanel(int i, bool active) {
  if (i == -1)
    return;

  if (Panel* panel = static_cast<Panel*>(ui_.stackedWidget->widget(i))) {
    panel->setActive(active);
  }
}

void UserPanels::setActive(bool active) {
  if (active) {
    const QString username = ClientController::instance()->publicUsername();

    qDebug() << "UserPanels::setActive - public name:" << username;

    if (username.isEmpty()) {
      ui_.listWidget->setEnabled(false);
//      ui_.listWidget->item(0)->setFlags(Qt::NoItemFlags);
//      ui_.listWidget->item(1)->setFlags(Qt::NoItemFlags);
//      ui_.listWidget->item(2)->setFlags(Qt::NoItemFlags);
//      ui_.listWidget->item(3)->setFlags(Qt::ItemIsSelectable|
//                                        Qt::ItemIsUserCheckable|
//                                        Qt::ItemIsEnabled);
//      ui_.listWidget->item(4)->setFlags(Qt::NoItemFlags);
//      ui_.listWidget->item(5)->setFlags(Qt::NoItemFlags);
//      ui_.listWidget->setCurrentRow(0);
//      static_cast<Panel*>(ui_.stackedWidget->widget(3))->reset();
      onCurrentRowChanged(ui_.stackedWidget->indexOf(public_username_));
      ui_.user_public_username->clear();
      ui_.my_files_button->setEnabled(true);
    } else {
      onPublicUsernameChosen();
    }
  } else {
//    for (int n = 0; n < ui_.listWidget->count(); n++) {
//      ui_.listWidget->item(n)->setFlags(Qt::ItemIsSelectable|
//                                        Qt::ItemIsUserCheckable|
//                                        Qt::ItemIsEnabled);
//    }
//    ui_.listWidget->item(4)->setFlags(Qt::NoItemFlags);
//    ui_.listWidget->item(5)->setFlags(Qt::NoItemFlags);
    QList<Panel*> panels = findChildren<Panel*>();
    foreach(Panel* panel, panels) {
      panel->reset();
    }
    // To clear the Public Username field for the next user
    // Change 6 to appropriate panel number
    // if more panels are added to the stack
    PublicUsername* p =
                static_cast<PublicUsername*>(ui_.stackedWidget->widget(6));
    p->clearPubUsername();
    ui_.user_public_username->clear();
    ui_.my_files_button->setEnabled(true);
  }
}

