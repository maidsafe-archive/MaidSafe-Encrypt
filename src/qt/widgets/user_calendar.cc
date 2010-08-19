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
#include "qt/widgets/user_calendar.h"

#include <QMessageBox>
#include <QDebug>
#include <QInputDialog>
#include <QTranslator>

#include "qt/client/client_controller.h"

UserCalendar::UserCalendar(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

//    connect(ui_.cancelBtn, SIGNAL(clicked(bool)),
//        this, SLOT(onCancel()));

  connect(ui_.calendarWidget, SIGNAL(activated(const QDate&)),
          this, SLOT(onCalActivated(const QDate&)));
}

UserCalendar::~UserCalendar() {}


void UserCalendar::onCancel(){
}

void UserCalendar::checkCalendar() {
}

void UserCalendar::onCalActivated(const QDate& selected) {
   addCal_ = new AddCalendarEntry;
   QDateTime* date = new QDateTime(selected);
   date->addSecs(3600 * 12);
   addCal_->setCalDate(*date);
   addCal_->show();  
}

void UserCalendar::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

