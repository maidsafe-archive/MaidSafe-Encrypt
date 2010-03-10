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


#ifndef PROFILE_SETTINGS_H_INCLUDED
#define PROFILE_SETTINGS_H_INCLUDED

#include <QWidget>
#include <QString>

#include "qt/client/contact.h"
// local
#include "qt/client/client_controller.h"

#include "ui_profile_settings.h"

class ProfileSettings : public QWidget {
    Q_OBJECT
 public:
  explicit ProfileSettings(QWidget* parent = 0);
  virtual ~ProfileSettings();

  virtual void setActive(bool active);
  virtual void reset();

  QHash<QString, QString> changedValues_;

 private:
  Ui::ProfileSettingsPage ui_;
  bool init_;
};


#endif // PROFILE_SETTINGS_H_INCLUDED
