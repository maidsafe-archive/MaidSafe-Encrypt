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
 *  Created on: Apr 10, 2009
 *      Author: Team
 */

#include "qt/widgets/vault_info.h"

// boost
#include <boost/progress.hpp>

// qt
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QDebug>

// std
#include <string>

// local
#include "qt/client/client_controller.h"


VaultInfo::VaultInfo(QWidget* parent)
    : Panel(parent)
    , init_(false) {
  ui_.setupUi(this);

  connect(ui_.updateButton, SIGNAL(clicked(bool)),
          this,             SLOT(onUpdateClicked()));
}

void VaultInfo::setActive(bool b) {
  if (b && !init_) {
//    qDebug() << "VaultInfo::setActive b && !init_";
    onUpdateVaultInfo();
    init_ = true;
  } else if (!b && init_) {
    reset();
  }
}

void VaultInfo::reset() {
  init_ = false;
}

VaultInfo::~VaultInfo() { }

void VaultInfo::onUpdateClicked() {
  onUpdateVaultInfo();
}

void VaultInfo::onUpdateVaultInfo() {
  QString chunkstore;
  boost::uint64_t offered_space;
  boost::uint64_t free_space;
  QString ip;
  boost::uint32_t port;
  bool b = ClientController::instance()->PollVaultInfo(&chunkstore,
         &offered_space, &free_space, &ip, &port);
  if (b) {
    std::string s_port(base::itos_ul(port));
    ui_.offeredLbl->setText(tr("%1 KB").arg(offered_space/1024));
    ui_.freeLbl->setText(tr("%1 KB").arg(free_space/1024));
    ui_.usedLbl->setText(tr("%1 KB").arg((offered_space - free_space)/1024));
    ui_.labelStoringDirectory->setText(chunkstore);
    ui_.labelIP->setText(ip);
    ui_.labelPort->setText(QString::fromStdString(s_port));

    ui_.vaultSpaceBar->setMinimum(0);
    ui_.vaultSpaceBar->setMaximum(offered_space);
    ui_.vaultSpaceBar->setValue(offered_space - free_space);

    if ((offered_space * 0.1) < free_space) {
      ui_.labelVaultStatusMessage->setText(
          tr("Vault is in good condition.")
          .prepend("<font color=green>").append("</font>"));
    } else {
      ui_.labelVaultStatusMessage->setText(
          tr("It might be time to share some more space!")
          .prepend("<font color=orange>").append("</font>"));
    }
  } else {
    ui_.labelVaultStatusMessage->setText(
        tr("Attention, your vault seems to be offline!")
        .prepend("<font color=red><strong>").append("</strong></font>"));
  }
}
