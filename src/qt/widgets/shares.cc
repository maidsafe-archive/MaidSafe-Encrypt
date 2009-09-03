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
 *  Created on: Apr 12, 2009
 *      Author: Team
 */

#include "qt/widgets/shares.h"

// qt
#include <QMessageBox>
#include <QUrl>
#include <QDesktopServices>
#include <QProcess>
#include <QDebug>

// local
#include "qt/widgets/share_participants.h"
#include "qt/client/client_controller.h"
#include "qt/client/create_share_thread.h"
#include "qt/client/user_space_filesystem.h"


Shares::Shares(QWidget* parent)
    : Panel(parent), init_(false), shareInProcess_() {
  ui_.setupUi(this);

  connect(ui_.create, SIGNAL(clicked(bool)),
          this,       SLOT(onCreateShareClicked()));
  connect(ui_.shareNameLineEdit, SIGNAL(returnPressed()),
          this,                  SLOT(onCreateShareClicked()));

  connect(ui_.listWidget, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
          this,           SLOT(onItemDoubleClicked(QListWidgetItem*)));

  connect(ClientController::instance(),
          SIGNAL(addedPrivateShare(const QString&)),
          this, SLOT(onAddedPrivateShare(const QString&)));
  ui_.labelCreate->setVisible(false);
  ui_.progressBarCreate->setVisible(false);
}

Shares::~Shares() { }

void Shares::setActive(bool b) {
  if (b && !init_) {
    init();
  }
}

void Shares::reset() {
  // clear the list of share
  ui_.listWidget->clear();
  ui_.labelCreate->setVisible(false);
  ui_.progressBarCreate->setVisible(false);

  ui_.shareNameLineEdit->setText(tr(""));

  init_ = false;
}

void Shares::onCreateShareClicked() {
  // 1 - choose share name
  // 2 - choose admin contacts
  // 3 - choose ro contacts
  // 4 - submit

  // Check if a share is being created
  if (!shareInProcess_.isEmpty()) {
    QMessageBox::warning(this, tr("Patience!"),
                 tr("A share is being created."));
    return;
  }

  // Check if share name isn't already in list
  const QString share_name = ui_.shareNameLineEdit->text().trimmed();
  QList<QListWidgetItem*> items = ui_.listWidget->findItems(share_name,
                                Qt::MatchCaseSensitive);
  if (items.size() > 0) {
    QMessageBox::warning(this, tr("Problem!"),
                 tr("You already have a share with this name."));
    return;
  }

  // Check for contacts to share with
  if (ClientController::instance()->contactsNames().size() == 0) {
    QMessageBox::warning(this, tr("Problem!"),
                 tr("You have no contacts to include in this share."));
    return;
  }

  if (ui_.shareNameLineEdit->text().isEmpty()) {
    QMessageBox::warning(this, tr("Problem!"),
                         tr("Please type a valid name for the share."));
    return;
  }

  QStringList admin_set;
  ShareParticipantsChoice spc_admin(this, tr("Administrators"), &admin_set);
  int n = spc_admin.exec();

  QStringList db_contacts = ClientController::instance()->contactsNames();
  foreach(const QString& s, admin_set) {
    db_contacts.removeAll(s);
  }


  QStringList ro_set(admin_set);
  if (db_contacts.size() > 0) {
    ShareParticipantsChoice spc_ro(this, tr("Read Onlys"), &ro_set);
    n = spc_ro.exec();
  } else {
    ro_set.clear();
  }

  if (ro_set.size() == 0 && admin_set.size() == 0) {
    return;
  }

  CreateShareThread* cst = new CreateShareThread(share_name, admin_set,
                                                 ro_set, this);

  connect(cst,  SIGNAL(completed(bool)),
          this, SLOT(onCreateShareCompleted(bool)));

  ui_.labelCreate->setText(tr("Creating share: ") + share_name);
  ui_.labelCreate->setVisible(true);
  ui_.progressBarCreate->reset();
  ui_.progressBarCreate->setVisible(true);

  cst->start();
  shareInProcess_ = share_name;
}

void Shares::onCreateShareCompleted(bool b) {
  ui_.labelCreate->setVisible(false);
  ui_.progressBarCreate->setVisible(false);
  if (b) {
    addShare(shareInProcess_);
    ui_.shareNameLineEdit->clear();
  } else {
    QMessageBox::warning(this, tr("Problem!"),
                         tr("There was an issue creating this share."));
  }
  shareInProcess_ = tr("");
}

void Shares::onItemDoubleClicked(QListWidgetItem* item) {
  qDebug() << "Shares::onItemDoubleClicked:" << item->text();

  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::PRIVATE_SHARES,
                                           item->text());
}

void Shares::init() {
  if (init_)
    return;

  const QString username = ClientController::instance()->publicUsername();
  if (!username.isEmpty()) {
    const ShareList shares = ClientController::instance()->shares();
    foreach(const Share& share, shares) {
      addShare(share.name());
    }

    // only init if had public name
    init_ = true;
  }
}

void Shares::addShare(const QString& shareName) {
  bool alreadyInList = false;
  for (int n = 0; n < ui_.listWidget->count(); ++n) {
    if (ui_.listWidget->item(n)->text() == shareName) {
      alreadyInList = true;
      break;
    }
  }

  if (!alreadyInList) {
    ui_.listWidget->addItem(shareName);
  }
}

void Shares::onAddedPrivateShare(const QString& name) {
  qDebug() << "Shares::onAddedPrivateShare()";
  addShare(name);
}

