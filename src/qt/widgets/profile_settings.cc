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

#include <QDebug>
#include <QMessageBox>

#include "qt/widgets/profile_settings.h"
#include "qt/client/client_controller.h"

ProfileSettings::ProfileSettings(QWidget* parent) : init_(false) {
  ui_.setupUi(this);
}

ProfileSettings::~ProfileSettings() { }

void ProfileSettings::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
    maidsafe::mi_contact mic;

  QString pub = ClientController::instance()->publicUsername();

  int n = ClientController::instance()->GetContactInfo(
          "tommy", &mic);

  if (n != 0) {
    QMessageBox::warning(this, tr("Error"),
                         QString(tr("contact doesn't exist. %1").arg(pub)));
    return;
  }

  qDebug() << mic.full_name_.c_str() ;
  ui_.fullNameEdit->setText(QString(mic.full_name_.c_str()));
  ui_.phoneNumberEdit->setText(QString(mic.office_phone_.c_str()));
  ui_.birthDayEdit->setText(QString(mic.birthday_.c_str()));
  ui_.languageEdit->setText("English");
  ui_.cityEdit->setText(QString(mic.city_.c_str()));
  ui_.countryEdit->setText("UK");
  QString gender = QString(1, QChar(mic.gender_));

  if(gender.contains("F", Qt::CaseInsensitive))
    ui_.radioFemale->setChecked(true);
  else
    ui_.radioMale->setChecked(true);
  }
}

void ProfileSettings::reset() { }
