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

#include "maidsafe/lifestuff/widgets/shares.h"

// qt
#include <QMessageBox>
#include <QUrl>
#include <QDesktopServices>
#include <QProcess>
#include <QDebug>
#include <QInputDialog>

// local
#include "maidsafe/lifestuff/widgets/share_participants.h"
#include "maidsafe/lifestuff/client/client_controller.h"
#include "maidsafe/lifestuff/client/create_share_thread.h"
#include "maidsafe/lifestuff/client/user_space_filesystem.h"


Shares::Shares(QWidget* parent)
    : Panel(parent), init_(false), shareInProcess_() {
  ui_.setupUi(this);

  ui_.shareNameLineEdit->installEventFilter(this);

  sortType_ = 0;
  filterType_ = 0;

  connect(ui_.create, SIGNAL(clicked(bool)),
          this,       SLOT(onCreateShareClicked()));

  connect(ui_.shareNameLineEdit, SIGNAL(returnPressed()),
          this,                  SLOT(onCreateShareClicked()));

  connect(ui_.listWidget, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
          this,           SLOT(onItemDoubleClicked(QListWidgetItem*)));

  connect(ui_.shareNameLineEdit, SIGNAL(textChanged(const QString &)),
          this,       SLOT(onSharesBoxTextEdited(const QString &)));

  connect(ui_.shareNameLineEdit, SIGNAL(editingFinished()),
          this,       SLOT(onSharesBoxLostFocus()));

  connect(ui_.sharesFilter, SIGNAL(activated(int)),
          this,       SLOT(onShareFilterChanged(int)));

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

  // qDeleteAll(&shares_);
  shares_.clear();

  init_ = false;
}

void Shares::onCreateShareClicked() {
  // 1 - choose share name
  // 2 - choose admin contacts
  // 3 - choose ro contacts
  // 4 - submit

  // Check if a share is being created
  if (!shareInProcess_.isEmpty()) {
    QMessageBox::warning(this, tr("Patience..."),
                 tr("A share is being created."));
    return;
  }
  QString text;
  if (ui_.shareNameLineEdit->text() != "Search Shares" && ui_.shareNameLineEdit->text() != "") {
    text = ui_.shareNameLineEdit->text();
    ui_.shareNameLineEdit->clear();
  } else {
    bool ok;
    text = QInputDialog::getText(this,
                                 tr("Add Share"),
                                 tr("Please enter a share to add:"),
                                 QLineEdit::Normal,
                                 QString(),
                                 &ok);
    if (!ok || text.isEmpty()) {
        return;
    }
  }

  // Check if share name isn't already in list
  const QString share_name = text.trimmed();
  QList<QListWidgetItem*> items = ui_.listWidget->findItems(share_name,
                                Qt::MatchCaseSensitive);
  if (items.size() > 0) {
    QMessageBox::warning(this, tr("Error"),
        tr("You already have a share with this name."));
    return;
  }

  // Check for contacts to share with
  if (ClientController::instance()->contactsNames().size() == 0) {
    QMessageBox::warning(this, tr("Error"),
        tr("You have no contacts to include in this share."));
    return;
  }

  if (share_name.isEmpty()) {
    QMessageBox::warning(this, tr("Error"),
        tr("Please enter a valid name for the share."));
    return;
  }

  QStringList admin_set;
//  ShareParticipantsChoice spc_admin(this, tr("Administrators"), &admin_set);
//  int n = spc_admin.exec();
//
  QStringList db_contacts = ClientController::instance()->contactsNames();
//  foreach(const QString& s, admin_set) {
//    db_contacts.removeAll(s);
//  }
//

  QStringList ro_set(admin_set);
  if (db_contacts.size() > 0) {
    ShareParticipantsChoice spc_ro(this, tr("Read-only Participants"), &ro_set);
    spc_ro.exec();
  } else {
    ro_set.clear();
  }

  if (ro_set.size() == 0 /*&& admin_set.size() == 0*/) {
    return;
  }

  CreateShareThread* cst = new CreateShareThread(share_name, admin_set,
                                                 ro_set, this);

  connect(cst,  SIGNAL(completed(bool)),
          this, SLOT(onCreateShareCompleted(bool)));

  ui_.labelCreate->setText(tr("Creating share: %1").arg(share_name));
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
  } else {
    QMessageBox::warning(this, tr("Error"),
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
    const ShareList shares = ClientController::instance()->shares(sortType_,
                                                                  filterType_);
    foreach(const Share& share, shares) {
      addShare(share.name());
      shares_.push_back(share);
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

void Shares::onSharesBoxTextEdited(const QString&) {
  qDebug() << "in search shares";

  const QString share_name = ui_.shareNameLineEdit->text().trimmed();

  if (share_name != "") {
    ShareList foundShares_;

    foreach(const Share& share, shares_) {
      if (share.name().startsWith(share_name)) {
        foundShares_.push_back(share);
      }
    }
    if (foundShares_.count() > 0) {
      ui_.listWidget->clear();
      foreach(const Share& share, foundShares_) {
        QListWidgetItem* item = new QListWidgetItem;
        item->setText(share.name());
        ui_.listWidget->addItem(item);
       }
    } else {
      ui_.listWidget->clear();
      QString label = "No Contacts Match ";
      label.append(share_name);

      QListWidgetItem* item = new QListWidgetItem;
      item->setText(label);
      ui_.listWidget->addItem(item);
    }
  } else {
    reset();
    setActive(true);
  }
}

void Shares::onSharesBoxLostFocus() {
  if (ui_.shareNameLineEdit->text() == "") {
        ui_.shareNameLineEdit->setText("Search Shares");
        QPalette pal;
        pal.setColor(QPalette::Text, Qt::lightGray);
        ui_.shareNameLineEdit->setPalette(pal);
        reset();
        setActive(true);
  }
}

bool Shares::eventFilter(QObject *obj, QEvent *event) {
  if (obj == ui_.shareNameLineEdit) {
    if (event->type() == QEvent::FocusIn) {
      if (ui_.shareNameLineEdit->text() == "Search Shares") {
        ui_.shareNameLineEdit->clear();
        QPalette pal;
        pal.setColor(QPalette::Text, Qt::black);
        ui_.shareNameLineEdit->setPalette(pal);
      }
      return true;
    } else {
      return false;
    }
  } else {
    // pass the event on to the parent class
    return Shares::eventFilter(obj, event);
  }
}

void Shares::onShareFilterChanged(int index) {
  filterType_ = index;
  reset();
  setActive(true);
}

void Shares::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}
