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


#ifndef MAIDSAFE_LIFESTUFF_WIDGETS_PERSONAL_SETTINGS_H_
#define MAIDSAFE_LIFESTUFF_WIDGETS_PERSONAL_SETTINGS_H_

#include <QWidget>
#include <QString>

// local

#include "ui_personal_settings.h"

class PersonalSettings : public QWidget {
    Q_OBJECT

 public:
  explicit PersonalSettings(QWidget* parent = 0);
  virtual ~PersonalSettings();

  virtual void setActive(bool active);
  virtual void reset();

  QHash<QString, QString> changedValues_;

  private slots:
    void onUsernameTextEdit(const QString&);
    void onMessageTextEdit(const QString&);
    void onPicChangeClicked(bool);
    void onLangSelect(QListWidgetItem*);

 private:
  Ui::PersonalSettingsPage ui_;
  bool init_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  //  MAIDSAFE_LIFESTUFF_WIDGETS_PERSONAL_SETTINGS_H_
