/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#include "qt/widgets/create_user.h"

// qt
#include <QDebug>
#include <QValidator>
#include <QMessageBox>

// core
#include <maidsafe/maidsafe-dht.h>
#include "maidsafe/client/clientcontroller.h"
#include "protobuf/maidsafe_service_messages.pb.h"

// local

// generated
#include "qt/widgets/create_page_welcome.h"
#include "qt/widgets/create_page_license.h"
#include "qt/widgets/create_page_localvault_setup.h"
#include "qt/widgets/create_page_options.h"
#include "qt/widgets/create_page_complete.h"


CreateUser::CreateUser(QWidget* parent)
    : QWidget(parent), vault_type_(0), space_(), port_(), directory_() {
  ui_.setupUi(this);

  ui_.next->setAutoDefault(true);

  connect(ui_.back, SIGNAL(clicked(bool)), this, SLOT(onBack()));
  connect(ui_.next, SIGNAL(clicked(bool)), this, SLOT(onNext()));
  connect(ui_.cancel, SIGNAL(clicked(bool)), this, SIGNAL(cancelled()));

  pages_ << new CreateWelcomePage;
  pages_ << new CreateLicensePage;
  pages_ << new CreateOptionsPage;
  pages_ << new CreateLocalVaultPage;
  pages_ << new CreateCompletePage;

  while (ui_.stack->count() > 0) {
    ui_.stack->removeWidget(ui_.stack->widget(0));
  }

  foreach(QWizardPage* p, pages_) {
    ui_.stack->addWidget(p);
  }

  reset();
}

CreateUser::~CreateUser() { }


void CreateUser::reset() {
  setCurrentPage(0, 0);
  foreach(QWizardPage* p, pages_) {
    p->cleanupPage();
  }
  vault_type_ = 0;
  space_ = tr("");
  port_ = tr("");
  directory_ = tr("");
}

void CreateUser::onBack() {
  int index = ui_.stack->currentIndex();
  if (index == 0) {
    return;
  }
  if (vault_type_ != 0)
    --index;
  setCurrentPage(--index, -1);
}

void CreateUser::onNext() {
  int index = ui_.stack->currentIndex();
  if (index == pages_.size() - 1) {
    // go off and create the user...
    emit complete();
    return;
  }

  // Vault choice page
  if (index == pages_.size() - 3) {
    CreateOptionsPage* cop =
        static_cast<CreateOptionsPage*>(pages_.at(ui_.stack->currentIndex()));
    vault_type_ = cop->VaultType();
    if (vault_type_ != 0)
      ++index;
  } else if (index == pages_.size() - 2) {  // Local vault setup page
    CreateLocalVaultPage* clvp =
       static_cast<CreateLocalVaultPage*>(pages_.at(ui_.stack->currentIndex()));
    space_ = clvp->SpaceOffered();
    port_ = clvp->PortChosen();
    directory_ = clvp->DirectoryChosen();
  }
  ++index;

  setCurrentPage(index, 1);
}

void CreateUser::setCurrentPage(int index, int dir) {
  disconnect(ui_.stack->currentWidget(), NULL, this, NULL);

  QWizardPage* page = pages_.at(ui_.stack->currentIndex());
  if (dir < 0) {
    page->cleanupPage();
  }

  ui_.stack->setCurrentIndex(index);

  connect(ui_.stack->currentWidget(), SIGNAL(completeChanged()),
          this,                       SLOT(onCompleteChanged()));

  page = pages_.at(ui_.stack->currentIndex());

  ui_.label->setText(page->title());
  ui_.back->setEnabled(index > 0);
  ui_.next->setEnabled(page->isComplete());
  ui_.next->setText(index == pages_.size() - 1 ? tr("Finish") : tr("Next >"));
  if (index == pages_.size() - 1) {
    qDebug() << "CreateUser::setCurrentPage VaultType: " << VaultType();
    qDebug() << "CreateUser::setCurrentPage SpaceOffered: " << SpaceOffered();
    qDebug() << "CreateUser::setCurrentPage PortChosen: " << PortChosen();
    qDebug() << "CreateUser::setCurrentPage DirectoryChosen: "
             << DirectoryChosen();
  }
}

void CreateUser::onCompleteChanged() {
  QWizardPage* page = pages_.at(ui_.stack->currentIndex());
  ui_.next->setEnabled(page->isComplete());
}

int CreateUser::VaultType() {
  return vault_type_;
}

QString CreateUser::SpaceOffered() const {
  return space_;
}

QString CreateUser::PortChosen() const {
  return port_;
}

QString CreateUser::DirectoryChosen() const {
  return directory_;
}
