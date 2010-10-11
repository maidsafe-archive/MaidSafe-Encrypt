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

#include <QDebug>
#include <QInputDialog>
#include <QMessageBox>
#include <QObject>
#include <QTranslator>

#include "qt/client/client_controller.h"


PendingOperationsDialog::PendingOperationsDialog(QWidget* parent)
    : QDialog(parent), ops_(), pending_files_connection_() {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

  connect(ui_.cancelBtn, SIGNAL(clicked(bool)),
          this,          SLOT(onCancel()));

  connect(ui_.cancelAllBtn, SIGNAL(clicked(bool)),
          this,             SLOT(onCancelAll()));

  pending_files_connection_ =
      ClientController::instance()->ConnectToOnFileNetworkStatus(
          boost::bind(&PendingOperationsDialog::OperationStatus, this, _1, _2));
  file_added_connection_ =
      ClientController::instance()->ConnectToOnFileAdded(
          boost::bind(&PendingOperationsDialog::FileAdded, this, _1));
}

PendingOperationsDialog::~PendingOperationsDialog() {
  pending_files_connection_.disconnect();
  file_added_connection_.disconnect();
}

void PendingOperationsDialog::onCancelAll() {
  {
    boost::mutex::scoped_lock loch_lochy(pending_files_mutex_);
    ui_.opTreeWidget->clear();
  }
  emit opsComplete();
  this->hide();
}

void PendingOperationsDialog::onCancel() { }

void PendingOperationsDialog::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

bool PendingOperationsDialog::hasPendingOps() {
  QObjectList l;
  {
    boost::mutex::scoped_lock loch_lochy(pending_files_mutex_);
    l = ui_.opTreeWidget->children();
  }
  return l.isEmpty();
}

void PendingOperationsDialog::OperationStatus(const std::string &file,
                                              int percentage) {
#ifdef DEBUG
  printf("PendingOperationsDialog::OperationStatus - %s - %d\n",
         file.c_str(), percentage);
#endif
  boost::mutex::scoped_lock loch_lochy(pending_files_mutex_);
  QList<QTreeWidgetItem*> items =
    ui_.opTreeWidget->findItems(QString::fromStdString(file),
                                Qt::MatchExactly, 0);

  if (items.isEmpty()) {
#ifdef DEBUG
    printf("PendingOperationsDialog::OperationStatus - %s not in list\n",
           file.c_str());
#endif
    return;
  }

  QTreeWidgetItem* theWidget = items.first();
  if (percentage == 100) {
    ui_.opTreeWidget->removeItemWidget(theWidget, 0);
    delete theWidget;
  } else {
    std::string str = base::IntToString(percentage);
    theWidget->setText(1, QString::fromStdString(str));
  }
  if (ui_.opTreeWidget->topLevelItemCount() < 1) {
#ifdef DEBUG
    printf("PendingOperationsDialog::OperationStatus - opsComplete signal\n");
#endif
    emit opsComplete();
  } else {
#ifdef DEBUG
    printf("PendingOperationsDialog::OperationStatus - item count: %d\n",
           ui_.opTreeWidget->topLevelItemCount());
#endif
  }
}

void PendingOperationsDialog::FileAdded(const std::string &file) {
#ifdef DEBUG
  printf("PendingOperationsDialog::FileAdded - %s - %d\n", file.c_str(), 0);
#endif
  boost::mutex::scoped_lock loch_lochy(pending_files_mutex_);
  QTreeWidgetItem *newItem = new QTreeWidgetItem(ui_.opTreeWidget);
  newItem->setText(0, QString::fromStdString(file));
  newItem->setText(1, tr("0"));
}

