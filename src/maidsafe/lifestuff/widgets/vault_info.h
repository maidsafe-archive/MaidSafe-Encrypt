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
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#ifndef QT_WIDGETS_VAULT_INFO_H_
#define QT_WIDGETS_VAULT_INFO_H_

#include <QTimer>

// local
#include "maidsafe/lifestuff/widgets/panel.h"

// generated
#include "ui_user_vault_info.h"

// Custom widget that displays contacts
/*!
    Displays a list of contacts and lets you add them.
*/
class VaultInfo : public Panel {
    Q_OBJECT
 public:
  explicit VaultInfo(QWidget* parent = 0);
  virtual ~VaultInfo();

  virtual void setActive(bool b);
  virtual void reset();

  private slots:
    void onUpdateClicked();
    void onUpdateVaultInfo();

 private:
  Ui::VaultInfoPage ui_;
  bool init_;
  QTimer infoPollTimer_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_VAULT_INFO_H_
