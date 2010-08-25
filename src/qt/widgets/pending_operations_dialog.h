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


#ifndef QT_WIDGETS_PENDING_OPERATIONS_DIALOG_H_
#define QT_WIDGETS_PENDING_OPERATIONS_DIALOG_H_

#include <QWidget>
#include <QString>

// local
#include "qt/client/client_controller.h"

#include "ui_pending_operations_dialog.h"

class PendingOperationsDialog : public QDialog {
    Q_OBJECT

 public:
  explicit PendingOperationsDialog(QWidget* parent = 0);
  virtual ~PendingOperationsDialog();

  private slots:
    void onCancelAll();
    void onCancel();

  signals:
    void langChanged(const QString &lang);
    void opsComplete();

 private:
  Ui::PendingOperationsDialog ui_;
  QList<ClientController::PendingOps> ops_;

  bool getOps(QList<ClientController::PendingOps> ops);

  enum State {
    PERSONAL,
    CONNECTION,
    FILE_TRANSFER,
    SECURITY,
    VAULT_INFO,
    PROFILE
    };

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_PENDING_OPERATIONS_DIALOG_H_
