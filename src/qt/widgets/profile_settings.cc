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

    connect(ui_.pubNameEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onPubNameTextEdit(const QString&)));

    connect(ui_.fullNameEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onFullNameTextEdit(const QString&)));

    connect(ui_.phoneNumberEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onPhoneTextEdit(const QString&)));

    connect(ui_.birthDayEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onBirthDayTextEdit(const QString&)));

    connect(ui_.languageEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onLanguageTextEdit(const QString&)));

    connect(ui_.cityEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onCityTextEdit(const QString&)));

    connect(ui_.countryEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onCountryTextEdit(const QString&)));

    connect(ui_.radioFemale, SIGNAL(stateChanged(int)),
          this,           SLOT(onFemaleChanged(int)));

    connect(ui_.radioMale, SIGNAL(stateChanged(int)),
          this,           SLOT(onMaleChanged(int)));

}

ProfileSettings::~ProfileSettings() { }

void ProfileSettings::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
    //maidsafe::SessionSingleton::Pd;

  QString pub = ClientController::instance()->publicUsername();
  std::vector<std::string>* profileInfo;

  ui_.pubNameEdit->setText(pub);

  //int n = ClientController::instance()->GetInfo("", profileInfo);

  //if (n != 0) {
  //  QMessageBox::warning(this, tr("Error"),
//                         QString(tr("contact doesn't exist. %1").arg(pub)));
  //  return;
  //}

 // qDebug() << profileInfo ;
  /*ui_.fullNameEdit->setText(QString(mic.full_name_.c_str()));
  ui_.phoneNumberEdit->setText(QString(mic.office_phone_.c_str()));
  ui_.birthDayEdit->setText(QString(mic.birthday_.c_str()));
  ui_.languageEdit->setText("English");
  ui_.cityEdit->setText(QString(mic.city_.c_str()));
  ui_.countryEdit->setText("UK");
  QString gender = QString(1, QChar(mic.gender_));

  if(gender.contains("F", Qt::CaseInsensitive))
    ui_.radioFemale->setChecked(true);
  else
    ui_.radioMale->setChecked(true);*/
  }
}

void ProfileSettings::reset() { }

void ProfileSettings::onFullNameTextEdit(const QString& text){
  changedValues_.insert("FullName", text);
}
void ProfileSettings::onPhoneTextEdit(const QString& text){
  changedValues_.insert("Phone", text);
}
void ProfileSettings::onBirthDayTextEdit(const QString& text){
  changedValues_.insert("BirthDay", text);
}
void ProfileSettings::onLanguageTextEdit(const QString& text){
  changedValues_.insert("Language", text);
}
void ProfileSettings::onCityTextEdit(const QString& text){
  changedValues_.insert("City", text);
}
void ProfileSettings::onCountryTextEdit(const QString& text){
  changedValues_.insert("Country", text);
}
void ProfileSettings::onPubNameTextEdit(const QString& text){
  changedValues_.insert("PubName", text);
}
void ProfileSettings::onFemaleChanged(int i){
  changedValues_.insert("Gender", "F");
}
void ProfileSettings::onMaleChanged(int i){
  changedValues_.insert("Gender", "M");
}

