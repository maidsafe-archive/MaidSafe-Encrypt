
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
 *  Created on: Jan 23, 2010
 *      Author: Stephen Alexander
 */


#ifndef QT_WIDGETS_SECURITY_SETTINGS_H_
#define QT_WIDGETS_SECURITY_SETTINGS_H_

#include <QWidget>
#include <QString>

// local
#include "maidsafe/lifestuff/client/client_controller.h"

#include "ui_security_settings.h"

class SecuritySettings : public QWidget {
    Q_OBJECT

 public:
  explicit SecuritySettings(QWidget* parent = 0);
  virtual ~SecuritySettings();
  QHash<QString, QString> changedValues_;

  private slots:
    void onUsernameTextEdit(const QString&);
    void onPinTextEdit(const QString&);
    void onPasswordTextEdit(const QString&);

 private:
  Ui::SecuritySettingsPage ui_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_SECURITY_SETTINGS_H_

