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

#include "qt/widgets/create_page_localvault_setup.h"

// qt
#include <QDebug>
#include <QFileDialog>
#include <QMessageBox>
#include <QValidator>

#include <boost/filesystem.hpp>

#include "fs/filesystem.h"
#include "qt/client/client_controller.h"

// Must be at least a 2 digit number
class SpaceValidator : public QIntValidator {
 public:
  explicit SpaceValidator(QObject* parent)
      : QIntValidator(0, INT_MAX, parent) { }

  virtual State validate(QString& input, int& pos) const {
    State s = QIntValidator::validate(input, pos);
    if (s == Acceptable && input.length() < 2)
      return Intermediate;
    return s;
  }

  virtual void fixup(QString& input) {
    QIntValidator::fixup(input);
  }
};

CreateLocalVaultPage::CreateLocalVaultPage(QWidget* parent)
    : QWizardPage(parent), spaceReady_(false), dirReady_(false) {
  ui_.setupUi(this);

  setTitle(tr("Local Vault Configuration"));
  ui_.lineSpace->setValidator(new SpaceValidator(this));
  connect(ui_.buttonBrowse, SIGNAL(clicked()),
          this,             SLOT(onBrowseClicked()));
  connect(ui_.lineSpace, SIGNAL(textChanged(const QString&)),
          this,          SLOT(onSpaceEdited(const QString&)));
  connect(ui_.linePort, SIGNAL(editingFinished()),
          this,         SLOT(onPortModified()));
  connect(ui_.lineDirectory, SIGNAL(textChanged(const QString&)),
          this,              SLOT(onDirectoryEdited(const QString&)));
}

CreateLocalVaultPage::~CreateLocalVaultPage() { }

void CreateLocalVaultPage::cleanupPage() {
  boost::filesystem::path chunkdir(QDir::homePath().toStdString());
  boost::filesystem::space_info info;
  if ("/" != chunkdir.root_directory())
    info = boost::filesystem::space(boost::filesystem::path("/"));
  else
    info = boost::filesystem::space(boost::filesystem::path(chunkdir.root_name()
           + chunkdir.root_directory()));
  availableSpace_ = base::itos_ull(info.available / (1024 * 1024));
  spaceReady_ = true;
  dirReady_ = false;
  QString qs(tr("Space to offer in MB (available %1 MB):")
          .arg(QString(availableSpace_.c_str())));
  ui_.labelSpace->setText(qs);
  ui_.lineDirectory->setReadOnly(true);
  ui_.lineSpace->setText("10240");
  ui_.linePort->setText("0");
  ui_.lineDirectory->setText(QString::fromStdString(
      file_system::ApplicationDataDir().string()));
}

bool CreateLocalVaultPage::isComplete() const {
//  bool b = false;
//  boost::uint64_t spaceChosen = base::stoi_ull(
//                                ui_.lineSpace->text().toStdString());
//  boost::uint64_t spaceAvailable = base::stoi_ull(availableSpace_);
//  if (spaceChosen < spaceAvailable)
//    b = true;
  return spaceReady_ && dirReady_/* && b*/;
}

void CreateLocalVaultPage::onBrowseClicked() {
  QString directory = QFileDialog::getExistingDirectory(this,
                      tr("Find Files"), QDir::homePath());
  ui_.lineDirectory->setText(directory);
  onDirectoryEdited(directory);
}

void CreateLocalVaultPage::onSpaceEdited(const QString& text) {
  if (!text.isEmpty() && text.size() > 1) {
    boost::uint64_t spaceChosen = base::stoi_ull(
                                  ui_.lineSpace->text().toStdString());
    boost::uint64_t spaceAvailable = base::stoi_ull(availableSpace_);
    if (spaceChosen < spaceAvailable) {
      spaceReady_ = true;
    } else {
      QMessageBox::warning(this, tr("Error"), tr("You don't have that much "
                                                 "space available!"));
      ui_.lineSpace->setText("1024");
      return;
    }
    if (dirReady_) {
      emit completeChanged();
    }
  } else {
    spaceReady_ = false;
    emit completeChanged();
  }
}

void CreateLocalVaultPage::onPortModified() {
  if (ui_.linePort->text().toInt() != 0) {
    int ret = QMessageBox::question(this, tr("Change port?"),
              tr("It is recommended to leave the port as 0, so it can be "
                 "chosen automatically. Do you really want to change this "
                 "setting?"),
              QMessageBox::Yes|QMessageBox::No);
    if (ret != QMessageBox::Yes)
      ui_.linePort->setText("0");
  }
}

void CreateLocalVaultPage::onDirectoryEdited(const QString& text) {
  if (!text.isEmpty()) {
    dirReady_ = true;
    if (spaceReady_) {
      emit completeChanged();
    }
  } else {
    dirReady_ = false;
    emit completeChanged();
  }
}

QString CreateLocalVaultPage::SpaceOffered() const {
  return ui_.lineSpace->text();
}

QString CreateLocalVaultPage::PortChosen() const {
  return ui_.linePort->text();
}

QString CreateLocalVaultPage::DirectoryChosen() const {
  return ui_.lineDirectory->text();
}
