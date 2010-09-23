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
#include "qt/client/user_space_filesystem.h"

namespace {
}

UserPanels::UserPanels(QWidget* parent)
    : QWidget(parent),
      shares_(NULL),
      contacts_(NULL),
      panel_(-1) {
  ui_.setupUi(this);
  level_ = ClientController::instance()->FULL;

  ui_.toolBarListWidget->setContextMenuPolicy(Qt::CustomContextMenu);
  ui_.toolBarListWidget->setVisible(false);

  public_username_ = new PublicUsername;

  inbox_ = new UserInbox(this);

  connect(public_username_, SIGNAL(complete()),
          this,             SLOT(onPublicUsernameChosen()));

  /*connect(ui_.my_files_button, SIGNAL(clicked(bool)),
          this,                SLOT(onMyFilesClicked()));

  connect(ui_.emailButton, SIGNAL(clicked(bool)),
          this,                SLOT(onEmailsClicked())); */

  connect(ui_.toolBarListWidget, SIGNAL(itemClicked(QListWidgetItem*)),
          this,                 SLOT(onItemClicked(QListWidgetItem*)));

  // tabBar shares menu builder

  menuContacts = new QMenu(this);

  sortAlpha = new QAction(tr("Sort alphabetically"), this);
  sortContacted = new QAction(tr("Sort by most contacted"), this);
  sortRecent = new QAction(tr("Sort by most recent"), this);

  menuContacts->addAction(sortAlpha);
  menuContacts->addAction(sortContacted);
  menuContacts->addAction(sortRecent);

  // tabbar Shares menu builder

  menuShares = new QMenu(this);

  sortShareAlpha = new QAction(tr("Sort alphabetically"), this);
  sortShareUsed = new QAction(tr("Sort by most contacted"), this);
  sortShareRecent = new QAction(tr("Sort by most recent"), this);

  menuShares->addAction(sortShareAlpha);
  menuShares->addAction(sortShareUsed);
  menuShares->addAction(sortShareRecent);

  // connectors signals/slots

  connect(ui_.toolBarListWidget, SIGNAL(customContextMenuRequested(const QPoint &)),
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

UserPanels::~UserPanels() {}

#ifdef PD_LIGHT
void UserPanels::CloseFileBrowser() {
 // browser_->setActive(false);
 // browser_->reset();
 // browser_->hide();
}
#endif

void UserPanels::onPublicUsernameChosen() {
  if (ui_.userStackedWidget->currentWidget() == public_username_) {
    ui_.toolBarListWidget->clear();
  }

  if (ui_.toolBarListWidget->count() > 1) {
  } else {
    QPixmap contactIcon_  = QPixmap(":icons/32/Contact_Tab");
    QPixmap shareIcon_    = QPixmap(":icons/32/Share_Tab");
    QPixmap logIcon_      = QPixmap(":icons/32/Log_Tab");
    QPixmap emailIcon_    = QPixmap(":icons/32/Email_Tab");
    QPixmap myFilesIcon_  = QPixmap(":icons/32/Files_Tab");

    QListWidgetItem *contact = new QListWidgetItem(contactIcon_, tr("Contacts"), ui_.toolBarListWidget);
    QListWidgetItem *share = new QListWidgetItem(shareIcon_, tr("Shares"), ui_.toolBarListWidget);
    QListWidgetItem *log = new QListWidgetItem(logIcon_, tr("Logs"), ui_.toolBarListWidget);
    QListWidgetItem *email = new QListWidgetItem(emailIcon_, tr("Email"), ui_.toolBarListWidget);
    QListWidgetItem *myFiles = new QListWidgetItem(myFilesIcon_, tr("My Files"), ui_.toolBarListWidget);

    contact->setToolTip("Contacts");
    share->setToolTip("Shares");
    log->setToolTip("Logs");
    email->setToolTip("Email");
    myFiles->setToolTip("My Files");

    contact->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);
    share->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);
    log->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);
    email->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);
    myFiles->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);

    ui_.userStackedWidget->addWidget(contacts_ = new Contacts);
    ui_.userStackedWidget->addWidget(shares_ = new Shares);
    ui_.userStackedWidget->addWidget(logs_ = new MessageLogs);

    this->adjustSize();
  }

  emit publicUsernameChosen();

  ui_.userStackedWidget->setEnabled(true);
  ui_.userStackedWidget->setCurrentWidget(contacts_);
  activatePanel(true);
  //ui_.public_username->setText(ClientController::instance()->publicUsername());
  updateTooltips();

#ifdef PD_LIGHT
 // browser_->setActive(true);
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
  inbox_->setActive(true);
  inbox_->show();
}

void UserPanels::onItemClicked(QListWidgetItem* item) {
  const QString username = ClientController::instance()->publicUsername();

  if (username.isEmpty()) {
    if (item->text() == tr("My Files")) {
      onMyFilesClicked();
      return;
    }
  }
  if (item->text() == tr("My Files")) {
    onMyFilesClicked();
  } else if (item->text() == tr("Email")) {
    onEmailsClicked();
  } else if (item->text() == tr("Logs")) {
    ui_.userStackedWidget->setCurrentWidget(logs_);
  } else if (item->text() == tr("Shares")) {
    ui_.userStackedWidget->setCurrentWidget(shares_);
  } else if (item->text() == tr("Contacts")) {
    ui_.userStackedWidget->setCurrentWidget(contacts_);
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

  if (Panel* panel = static_cast<Panel*>(ui_.userStackedWidget->currentWidget())) {
    panel->setActive(active);
  }
}

void UserPanels::setActive(bool active) {
  if (active) {
    const QString username = ClientController::instance()->publicUsername();

    qDebug() << "UserPanels::setActive - public name:" << username;

    if (ui_.userStackedWidget->count() < 2)
      ui_.userStackedWidget->removeWidget(public_username_);

    if (username.isEmpty()) {
      ui_.toolBarListWidget->clear();
      ui_.toolBarListWidget->setEnabled(true);

      ui_.userStackedWidget->addWidget(public_username_);
      ui_.userStackedWidget->setCurrentWidget(public_username_);

      QPixmap myFilesIcon_  = QPixmap(":icons/32/Files_Tab");
      QListWidgetItem *myFiles = new QListWidgetItem(myFilesIcon_, tr("My Files"), ui_.toolBarListWidget);
      myFiles->setTextAlignment(Qt::AlignHCenter | Qt::AlignBottom);
      myFiles->setToolTip("My Files");

    } else {
      onPublicUsernameChosen();
    }
  } else {
    QList<Panel*> panels = findChildren<Panel*>();
    foreach(Panel* panel, panels) {
      panel->reset();
    }

    public_username_->clearPubUsername();

  }
}

void UserPanels::customContentsMenu(const QPoint &pos) {
  QPoint pos2 = ui_.toolBarListWidget->mapFromParent(pos);
  QListWidgetItem* item = ui_.toolBarListWidget->itemAt(pos);

  if (item->text() == "Contacts") {
    // Contacts
    QPoint globalPos = ui_.toolBarListWidget->mapToGlobal(pos);
    menuContacts->exec(globalPos);
  }
  if (item->text() == "Shares") {
    // Shares
    QPoint globalPos = ui_.toolBarListWidget->mapToGlobal(pos);
    menuShares->exec(globalPos);
  }
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

void UserPanels::setEmailLabel(QString) {
//  ui_.lblEmails->setText(mess);
}

void UserPanels::setHintLevel(ClientController::HintLevel level) {
  level_ = level;
  updateTooltips();
}

void UserPanels::updateTooltips() {
  ui_.toolBarListWidget->item(0)->setToolTip(ClientController::instance()->getContactTooltip(level_));
  ui_.toolBarListWidget->item(1)->setToolTip(ClientController::instance()->getSharesTooltip(level_));
  ui_.toolBarListWidget->item(2)->setToolTip(ClientController::instance()->getLogsTooltip(level_));
  ui_.toolBarListWidget->item(3)->setToolTip(ClientController::instance()->getMyFilesTooltip(level_));
  ui_.toolBarListWidget->item(4)->setToolTip(ClientController::instance()->getEmailTooltip(level_));
}

void UserPanels::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}


