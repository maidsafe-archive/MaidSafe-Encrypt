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
 *  Created on: Aug 16th, 2010
 *      Author: Stephen Alexander
 */
#include "qt/widgets/pending_operations_dialog.h"

#include <QMessageBox>
#include <QDebug>
#include <QInputDialog>
#include <QTranslator>

#include "qt/client/client_controller.h"


PendingOperationsDialog::PendingOperationsDialog(QWidget* parent)
    : QDialog(parent), ops_(), pending_files_connection_() {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

  getOps(ops_);

  connect(ui_.cancelBtn, SIGNAL(clicked(bool)),
          this, SLOT(onCancel()));

  connect(ui_.cancelAllBtn, SIGNAL(clicked(bool)),
          this, SLOT(onCancelAll()));

  pending_files_connection_ =
      ClientController::instance()->ConnectToOnFileNetworkStatus(
          boost::bind(&PendingOperationsDialog::OperationStatus, this, _1, _2));
}

PendingOperationsDialog::~PendingOperationsDialog() {
  pending_files_connection_.disconnect();
}

void PendingOperationsDialog::onCancelAll() {
  emit opsComplete();
  this->hide();
}

void PendingOperationsDialog::onCancel() {
}

bool PendingOperationsDialog::getOps(QList<ClientController::PendingOps> ops){
    ClientController::instance()->getPendingOps(ops);
  if (ops.empty()){
    return true;
  } else {
    return true;
  }
}

void PendingOperationsDialog::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

bool PendingOperationsDialog::hasPendingOps() {
  if(ui_.opTreeWidget->topLevelItemCount() < 1) {
    return false;
  }
  return true;
}

void PendingOperationsDialog::OperationStatus(const std::string &file,
                                              int percentage) {
  QList<QTreeWidgetItem *> items =
    ui_.opTreeWidget->findItems(QString::fromStdString(file),
                                Qt::MatchExactly, 0);
  if (items.empty()) {
    QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.opTreeWidget);
    newItem->setText(0, QString::fromStdString(file));
    std::string str = base::IntToString(percentage);
    newItem->setText(1, QString::fromStdString(str));
  } else {
    QTreeWidgetItem* theWidget = items[0];
    if (percentage == 100) {
      printf("\n\n\n100000000000000000000000000000000000\n\n\n");
      ui_.opTreeWidget->removeItemWidget(theWidget, 0);
    } else {
      theWidget->setText(0, QString::fromStdString(file));
      std::string str = base::IntToString(percentage);
      theWidget->setText(1, QString::fromStdString(str));
    }
  }
  if (ui_.opTreeWidget->topLevelItemCount() < 1) {
    emit opsComplete();
  }
}


