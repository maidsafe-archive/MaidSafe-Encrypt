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
#include <QPixmap>
#include <QList>


// local
#include "qt/widgets/panel.h"
#include "qt/widgets/messages.h"

#ifdef PD_LIGHT
#include "qt/widgets/file_browser.h"
#endif

#include "qt/widgets/shares.h"
#include "qt/widgets/contacts.h"
#include "qt/widgets/user_message_logs.h"
#include "qt/widgets/personal_messages.h"
#include "qt/widgets/user_inbox.h"
#include "qt/widgets/vault_info.h"
#include "qt/widgets/public_username.h"
#include "qt/client/client_controller.h"
#include "qt/client/user_space_filesystem.h"

namespace {
}

UserPanels::UserPanels(QWidget* parent)
    : QWidget(parent),
      shares_(NULL),
      contacts_(NULL),
      panel_(-1) {
  ui_.setupUi(this);

  ui_.tabWidget_2->setContextMenuPolicy(Qt::CustomContextMenu);

  public_username_ = new PublicUsername;
#ifdef PD_LIGHT
  browser_ = new FileBrowser;
#endif

  connect(public_username_, SIGNAL(complete()),
          this,             SLOT(onPublicUsernameChosen()));

  /*connect(ui_.my_files_button, SIGNAL(clicked(bool)),
          this,                SLOT(onMyFilesClicked()));

  connect(ui_.emailButton, SIGNAL(clicked(bool)),
          this,                SLOT(onEmailsClicked())); */

  connect(ui_.tabWidget_2, SIGNAL(currentChanged(int)),
          this,                 SLOT(onCurrentChanged(int)));

  // tabBar shares menu builder

  menuContacts = new QMenu(this);

  sortAlpha = new QAction(tr("Sort alphabetically"), this);
  sortContacted = new QAction(tr("Sort by most contacted"), this);
  sortRecent = new QAction(tr("Sort by most recent"), this);

  menuContacts->addAction(sortAlpha);
  menuContacts->addAction(sortContacted);
  menuContacts->addAction(sortRecent);

  ui_.tabWidget_2->setContextMenuPolicy(Qt::CustomContextMenu);

  // tabbar Shares menu builder

  menuShares = new QMenu(this);

  sortShareAlpha = new QAction(tr("Sort alphabetically"), this);
  sortShareUsed = new QAction(tr("Sort by most contacted"), this);
  sortShareRecent = new QAction(tr("Sort by most recent"), this);

  menuShares->addAction(sortShareAlpha);
  menuShares->addAction(sortShareUsed);
  menuShares->addAction(sortShareRecent);

  // connectors signals/slots

  connect(ui_.tabWidget_2, SIGNAL(customContextMenuRequested(const QPoint &)),
             this,         SLOT(customContentsMenu(const QPoint &)));

  connect(sortAlpha, SIGNAL(triggered()),
          this,        SLOT(onSortAlphaClicked()));

  connect(sortContacted, SIGNAL(triggered()),
          this,        SLOT(onSortContactedClicked()));

  connect(sortRecent, SIGNAL(triggered()),
          this,        SLOT(onSortRecentClicked()));

  connect(sortShareAlpha, SIGNAL(triggered()),
          this,        SLOT(onSortShareAlphaClicked()));

  connect(sortShareUsed, SIGNAL(triggered()),
          this,        SLOT(onSortShareUsedClicked()));

  connect(sortShareRecent, SIGNAL(triggered()),
          this,        SLOT(onSortShareRecentClicked()));
}

UserPanels::~UserPanels() { }

void UserPanels::onPublicUsernameChosen() {
  if (ui_.tabWidget_2->currentWidget() == public_username_) {
    ui_.tabWidget_2->removeTab(0);
  }

  if (ui_.tabWidget_2->count() > 1) {
  } else {
    QPixmap contactIcon_  = QPixmap(":/icons/32/contacts");
    QPixmap shareIcon_    = QPixmap(":/icons/32/shares");
    QPixmap logIcon_      = QPixmap(":/icons/32/log");
    QPixmap emailIcon_  = QPixmap(":/icons/32/email");
    QPixmap myFilesIcon_  = QPixmap(":/icons/32/32/VaultGrey-32.png");

    ui_.tabWidget_2->addTab(contacts_ = new Contacts, contactIcon_, "");
    ui_.tabWidget_2->addTab(shares_   = new Shares, shareIcon_, "");
    ui_.tabWidget_2->addTab(logs_     = new MessageLogs, logIcon_, "");
    ui_.tabWidget_2->addTab(logs_     = new MessageLogs, emailIcon_, "");
    ui_.tabWidget_2->addTab(logs_     = new MessageLogs, myFilesIcon_, "");

    ui_.tabWidget_2->setTabToolTip(0, "Contacts");
    ui_.tabWidget_2->setTabToolTip(1, "Shares");
    ui_.tabWidget_2->setTabToolTip(2, "Message Log");
    ui_.tabWidget_2->setTabToolTip(3, "Emails");
    ui_.tabWidget_2->setTabToolTip(4, "My Files");

    ui_.tabWidget_2->setTabWhatsThis(0, "All Contacts are here");
  }

  ui_.tabWidget_2->setEnabled(true);
  ui_.tabWidget_2->setCurrentWidget(contacts_);
  activatePanel(true);
/*  ui_.user_public_username->setText(
      ClientController::instance()->publicUsername()); */

#ifdef PD_LIGHT
  browser_->setActive(true);
#endif
}

void UserPanels::onMyFilesClicked() {
#ifdef PD_LIGHT
  browser_->setActive(true);
  browser_->show();
#else
  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::MY_FILES);
#endif
}

void UserPanels::onEmailsClicked() {
  // ui_.lblEmails->setText("");
  inbox_ = new UserInbox(this);
  inbox_->show(); 
}

void UserPanels::onCurrentChanged(int i) {
  if (i == 3) {
    onMyFilesClicked();
    ui_.tabWidget_2->setCurrentWidget(contacts_);
    int curr = ui_.tabWidget_2->currentIndex();
  } else if (i == 4) {
    onEmailsClicked();
    ui_.tabWidget_2->setCurrentWidget(contacts_);
  }
  activatePanel(true);
}

/*void UserPanels::onCurrentRowChanged(int i) {
  // change the active panel
#ifdef DEBUG
  printf("Current: %i -- Next: %i\n", panel_, i);
#endif
  activatePanel(panel_, false);
  panel_ = i;
  activatePanel(panel_, true);

  ui_.stackedWidget->setCurrentIndex(i);
}*/

void UserPanels::activatePanel(bool active) {
  QList<Panel*> panels = findChildren<Panel*>();
  foreach(Panel* panel, panels) {
    panel->reset();
  }

  if (Panel* panel = static_cast<Panel*>(ui_.tabWidget_2->currentWidget())) {
    panel->setActive(active);
  }
}

void UserPanels::setActive(bool active) {
  if (active) {
    const QString username = ClientController::instance()->publicUsername();

    qDebug() << "UserPanels::setActive - public name:" << username;

    if (ui_.tabWidget_2->count() < 2)
        ui_.tabWidget_2->removeTab(0);

    if (username.isEmpty()) {
      ui_.tabWidget_2->clear();
      ui_.tabWidget_2->setEnabled(true);
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
      ui_.tabWidget_2->addTab(public_username_, "");
      ui_.tabWidget_2->setCurrentWidget(public_username_);
//      ui_.user_public_username->clear();
//      ui_.my_files_button->setEnabled(true);
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
//    PublicUsername* p = static_cast<PublicUsername*>(
//                       ui_.stackedWidget->widget(6));
    public_username_->clearPubUsername();
//    ui_.user_public_username->clear();
//    ui_.my_files_button->setEnabled(true);
  }
}

void UserPanels::customContentsMenu(const QPoint &pos) {
  // QPoint point = contacts_->mapFromGlobal(QPoint(0,0));
  // QPoint point2 = shares_->mapFromGlobal(QPoint(0,0));
  QTabBar * tabBar = qobject_cast<QTabBar *>(ui_.tabWidget_2->childAt(pos));
  if (!tabBar)
      return;
  QPoint pos2 = tabBar->mapFromParent(pos);
  int tabIndex = tabBar->tabAt(pos2);

  if (tabIndex == 0) {
    // Contacts
    QPoint globalPos = ui_.tabWidget_2->mapToGlobal(pos);
    menuContacts->exec(globalPos);
  }
  if (tabIndex ==1) {
    // Shares
    QPoint globalPos = ui_.tabWidget_2->mapToGlobal(pos);
    menuShares->exec(globalPos);
  }
  // if ((pos.x() < 58) && (pos.y() < 40)) {
  // QPoint globalPos = ui_.tabWidget_2->mapToGlobal(pos);
  // menuContacts->exec(globalPos);
  // }
}

void UserPanels::addConvToList(QString) {
//  if(name != "")
//    openConvList_.append("test");
}

QList<QString> UserPanels::getConvList() {
  return openConvList_;
}

void UserPanels::setConvList(QList<QString> theList) {
  openConvList_ = theList;
}

void UserPanels::onSortAlphaClicked() {
  contacts_->reset();
  contacts_->sortType_ = 0;
  contacts_->setActive(true);
}

void UserPanels::onSortContactedClicked() {
  contacts_->reset();
  contacts_->sortType_ = 1;
  contacts_->setActive(true);
}

void UserPanels::onSortRecentClicked() {
  contacts_->reset();
  contacts_->sortType_ = 2;
  contacts_->setActive(true);
}

void UserPanels::onSortShareAlphaClicked() {
  shares_->reset();
  shares_->sortType_ = 0;
  shares_->setActive(true);
}

void UserPanels::onSortShareUsedClicked() {
  shares_->reset();
  shares_->sortType_ = 1;
  shares_->setActive(true);
}

void UserPanels::onSortShareRecentClicked() {
  shares_->reset();
  shares_->sortType_ = 2;
  shares_->setActive(true);
}

void UserPanels::setEmailLabel(QString mess) {
//  ui_.lblEmails->setText(mess);
}

void UserPanels::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}


