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


#ifndef MAIDSAFE_LIFESTUFF_WIDGETS_PROFILE_SETTINGS_H_
#define MAIDSAFE_LIFESTUFF_WIDGETS_PROFILE_SETTINGS_H_

#include <QWidget>
#include <QString>

#include "maidsafe/lifestuff/client/contact.h"
// local
#include "maidsafe/lifestuff/client/client_controller.h"

#include "ui_profile_settings.h"

class ProfileSettings : public QWidget {
    Q_OBJECT
 public:
  explicit ProfileSettings(QWidget* parent = 0);
  virtual ~ProfileSettings();

  virtual void setActive(bool active);
  virtual void reset();

  QHash<QString, QString> changedValues_;

  private slots:
    void onPubNameTextEdit(const QString&);
    void onFullNameTextEdit(const QString&);
    void onPhoneTextEdit(const QString&);
    void onBirthDayTextEdit(const QString&);
    void onLanguageTextEdit(const QString&);
    void onCityTextEdit(const QString&);
    void onCountryTextEdit(const QString&);
    void onFemaleChanged(bool);
    void onMaleChanged(bool);

 private:
  Ui::ProfileSettingsPage ui_;
  bool init_;

 protected:
  void changeEvent(QEvent *event);
};


#endif  //  MAIDSAFE_LIFESTUFF_WIDGETS_PROFILE_SETTINGS_H_
