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


PendingOperationsDialog::PendingOperationsDialog(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

  getOps(ops_);

  connect(ui_.cancelBtn, SIGNAL(clicked(bool)),
          this, SLOT(onCancel()));

  connect(ui_.cancelAllBtn, SIGNAL(clicked(bool)),
          this, SLOT(onCancelAll()));
}

PendingOperationsDialog::~PendingOperationsDialog() {}

void PendingOperationsDialog::onCancelAll(){
  this->close();
  emit opsComplete();
}

void PendingOperationsDialog::onCancel(){
}

bool PendingOperationsDialog::getOps(QList<ClientController::PendingOps> ops){
    ClientController::instance()->getPendingOps(ops);
  
  if (ops.empty()){
    return false;
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

