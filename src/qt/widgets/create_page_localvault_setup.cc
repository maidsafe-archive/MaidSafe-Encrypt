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
  spaceReady_ = true;
  dirReady_ = false;
  ui_.lineDirectory->setReadOnly(true);
  ui_.lineSpace->setText(tr("1024"));
  ui_.linePort->setText(tr("0"));
  ui_.lineDirectory->setText(tr(""));
}

bool CreateLocalVaultPage::isComplete() const {
  return spaceReady_ && dirReady_;
}

void CreateLocalVaultPage::onBrowseClicked() {
  QString directory = QFileDialog::getExistingDirectory(this,
                      tr("Find Files"), QDir::homePath());
  ui_.lineDirectory->setText(directory);
  onDirectoryEdited(directory);
}

void CreateLocalVaultPage::onSpaceEdited(const QString& text) {
  if (!text.isEmpty() && text.size() > 1) {
    spaceReady_ = true;
    qDebug() << spaceReady_ << " -- " << dirReady_;
    if (dirReady_) {
      emit completeChanged();
    }
  } else {
    spaceReady_ = false;
    emit completeChanged();
  }
}

void CreateLocalVaultPage::onPortModified() {
  if (ui_.linePort->text() != tr("0")) {
    int ret = QMessageBox::warning(this, tr("Warning!"),
              tr("It is a recommended setting to leave 0 on this field!"),
              QMessageBox::Ok|QMessageBox::Cancel);
    if (ret != 1024)
      ui_.linePort->setText(tr("0"));
  }
}

void CreateLocalVaultPage::onDirectoryEdited(const QString& text) {
  if (!text.isEmpty()) {
    dirReady_ = true;
    qDebug() << spaceReady_ << " -- " << dirReady_;
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
