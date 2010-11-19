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
#include "maidsafe/lifestuff/widgets/add_calendar_entry.h"

#include <QMessageBox>
#include <QDebug>
#include <QInputDialog>
#include <QTranslator>

#include "maidsafe/lifestuff/client/client_controller.h"


AddCalendarEntry::AddCalendarEntry(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

  connect(ui_.buttonBox, SIGNAL(accepted()),
          this, SLOT(onSave()));

  connect(ui_.buttonBox, SIGNAL(rejected()),
          this, SLOT(onCancel()));
}

AddCalendarEntry::~AddCalendarEntry() {}

void AddCalendarEntry::setCalDate(QDateTime &date) {
  ui_.dateTimeEdit->setDateTime(date);
}

void AddCalendarEntry::onSave() {
  if (!ui_.headingLineEdit->text().isEmpty()) {
    // Must be heading
  } else {
    // set up variables and emit signal
    
  }
}

void AddCalendarEntry::onCancel() {
  this->close();
}

void AddCalendarEntry::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

