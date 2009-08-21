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

// local
#include "qt/client/client_controller.h"


VaultInfo::VaultInfo(QWidget* parent)
    : Panel(parent)
    , init_(false) {
  ui_.setupUi(this);
}

void VaultInfo::setActive(bool b) {
  if (b && !init_) {
//    qDebug() << "VaultInfo::setActive b && !init_";
    QString chunkstore;
    boost::uint64_t offered_space;
    boost::uint64_t free_space;
    bool res = ClientController::instance()->PollVaultInfo(&chunkstore,
               &offered_space, &free_space);
    if (res) {
      std::string offered(base::itos_ull(offered_space));
      std::string free(base::itos_ull(free_space));
      std::string used(base::itos_ull(offered_space - free_space));
      ui_.lcdOffered->display(QString::fromStdString(offered));
      ui_.lcdFree->display(QString::fromStdString(free));
      ui_.lcdUsed->display(QString::fromStdString(used));
      ui_.labelStoringDirectory->setText(chunkstore);
      if ((offered_space * 0.1) < free_space) {
        ui_.labelVaultStatusMessage->setText(tr("<font color=green>Vault is "
                                             "feeling goooood =)</font>"));
      } else {
        ui_.labelVaultStatusMessage->setText(tr("<font color=red>It might be "
                                      "time to share some more space!</font>"));
      }

    } else {
      ui_.labelVaultStatusMessage->setText(tr("<font color=red><strong>"
          "Attention! Your vault seems to be offline!</strong></font>"));
    }
    init_ = true;
    infoPollTimer_.start(5000);  // 60 secs
    connect(&infoPollTimer_, SIGNAL(timeout()),
            this,            SLOT(onUpdateVaultInfo()));
  } else if (!b && init_) {
    reset();
  }
}

void VaultInfo::reset() {
  qDebug() << "VaultInfo::reset";

  infoPollTimer_.stop();
  disconnect(&infoPollTimer_, NULL, this, NULL);
  init_ = false;
}

VaultInfo::~VaultInfo() { }

void VaultInfo::onUpdateVaultInfo() {
  QString chunkstore;
  boost::uint64_t offered_space;
  boost::uint64_t free_space;
  bool b = ClientController::instance()->PollVaultInfo(&chunkstore,
         &offered_space, &free_space);
  if (b) {
    std::string offered(base::itos_ull(offered_space));
    std::string free(base::itos_ull(free_space));
    std::string used(base::itos_ull(offered_space - free_space));
    ui_.lcdOffered->display(QString::fromStdString(offered));
    ui_.lcdFree->display(QString::fromStdString(free));
    ui_.lcdUsed->display(QString::fromStdString(used));
    ui_.labelStoringDirectory->setText(chunkstore);
    if ((offered_space * 0.1) < free_space) {
      ui_.labelVaultStatusMessage->setText(tr("<font color=green>Vault is "
                                           "feeling goooood =)</font>"));
    } else {
      ui_.labelVaultStatusMessage->setText(tr("<font color=red>It might be "
                                    "time to share some more space!</font>"));
    }
  } else {
    ui_.labelVaultStatusMessage->setText(tr("<font color=red><strong>Attention!"
        " Your vault seems to be offline!</strong></font>"));
  }
}
