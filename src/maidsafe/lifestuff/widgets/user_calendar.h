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
 *  Created on: Aug 18th, 2010
 *      Author: Stephen Alexander
 */


#ifndef MAIDSAFE_LIFESTUFF_WIDGETS_USER_CALENDAR_H_
#define MAIDSAFE_LIFESTUFF_WIDGETS_USER_CALENDAR_H_

#include <QWidget>
#include <QString>

// local
#include "maidsafe/lifestuff/client/client_controller.h"
#include "maidsafe/lifestuff/widgets/add_calendar_entry.h"

#include "ui_user_calendar.h"

class UserCalendar : public QDialog {
    Q_OBJECT

 public:
  explicit UserCalendar(QWidget* parent = 0);
  virtual ~UserCalendar();

  private slots:
    void onCancel();
    void onCalActivated(const QDate&);

  signals:
    void langChanged(const QString &lang);

 private:
  Ui::UserCalendar ui_;
  void checkCalendar();
  AddCalendarEntry* addCal_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  //  MAIDSAFE_LIFESTUFF_WIDGETS_USER_CALENDAR_H_
