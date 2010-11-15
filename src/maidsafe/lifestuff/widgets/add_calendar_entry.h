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
 *  Created on: Aug 19th, 2010
 *      Author: Stephen Alexander
 */


#ifndef QT_WIDGETS_ADD_CALENDAR_ENTRY_H_
#define QT_WIDGETS_ADD_CALENDAR_ENTRY_H_

#include <QWidget>
#include <QString>

// local
#include "maidsafe/lifestuff/client/client_controller.h"

#include "ui_add_calendar_entry.h"

class AddCalendarEntry : public QDialog {
    Q_OBJECT

 public:
  explicit AddCalendarEntry(QWidget* parent = 0);
  virtual ~AddCalendarEntry();
  void setCalDate(QDateTime &date);

  private slots:
    void onCancel();
    void onSave();

  signals:
    void langChanged(const QString &lang);
    void onAccepted(const QString &type, const QDateTime date,
                    const QString &heading, const QString &note);              

 private:
  Ui::AddCalendarEntry ui_;
  QString Type_;
  QDateTime date_;
  QString heading_;
  QString note_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_ADD_CALENDAR_ENTRY_H_
