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
#include "qt/widgets/profile_settings.h"

#include <QDebug>
#include <QMessageBox>

#include <string>
#include <vector>

#include "qt/client/client_controller.h"

ProfileSettings::ProfileSettings(QWidget* parent)
    : QWidget(parent), init_(false) {
  ui_.setupUi(this);

    connect(ui_.pubNameEdit, SIGNAL(textEdited(const QString&)),
            this,            SLOT(onPubNameTextEdit(const QString&)));

    connect(ui_.fullNameEdit, SIGNAL(textChanged(const QString&)),
            this,             SLOT(onFullNameTextEdit(const QString&)));

    connect(ui_.phoneNumberEdit, SIGNAL(textChanged(const QString&)),
            this,                SLOT(onPhoneTextEdit(const QString&)));

    connect(ui_.birthDayEdit, SIGNAL(textChanged(const QString&)),
            this,             SLOT(onBirthDayTextEdit(const QString&)));

    connect(ui_.languageEdit, SIGNAL(textChanged(const QString&)),
            this,             SLOT(onLanguageTextEdit(const QString&)));

    connect(ui_.cityEdit, SIGNAL(textChanged(const QString&)),
            this,         SLOT(onCityTextEdit(const QString&)));

    connect(ui_.countryEdit, SIGNAL(textChanged(const QString&)),
            this,            SLOT(onCountryTextEdit(const QString&)));

    connect(ui_.radioFemale, SIGNAL(toggled(bool)),
            this,            SLOT(onFemaleChanged(bool)));

    connect(ui_.radioMale, SIGNAL(toggled(bool)),
            this,          SLOT(onMaleChanged(bool)));
}

ProfileSettings::~ProfileSettings() { }

void ProfileSettings::setActive(bool b) {
  if (b && !init_) {
    init_ = true;

    QString pub = ClientController::instance()->publicUsername();
    // std::vector<std::string> profileInfo;

    ui_.pubNameEdit->setText(pub);

//    qDebug() << "ProfileSettings::setActive - avant getinfo";
//    int n = ClientController::instance()->GetInfo("", &profileInfo);
//    qDebug() << "ProfileSettings::setActive - got info";

//    if (n != 0) {
//      QMessageBox::warning(this, tr("Error"),
//                           QString(tr("contact doesn't exist. %1").arg(pub)));
//      return;
//    }

    // qDebug() << profileInfo ;
    maidsafe::PersonalDetails pd =
        maidsafe::SessionSingleton::getInstance()->Pd();
    ui_.fullNameEdit->setText(QString(pd.full_name().c_str()));
    ui_.phoneNumberEdit->setText(QString(pd.phone_number().c_str()));
    ui_.birthDayEdit->setText(QString(pd.birthday().c_str()));
    ui_.languageEdit->setText(QString(pd.language().c_str()));
    ui_.cityEdit->setText(QString(pd.city().c_str()));
    ui_.countryEdit->setText(QString(pd.country().c_str()));
    //  QString gender = QString(1, QChar(pd.));

    QString gender = QString::fromStdString(pd.gender().c_str());

    qDebug() << "gender reading :" + gender;

    if (gender.contains("F", Qt::CaseInsensitive))
      ui_.radioFemale->setChecked(true);
    else
      ui_.radioMale->setChecked(true);
  }
}

void ProfileSettings::reset() { }

void ProfileSettings::onFullNameTextEdit(const QString& text) {
  changedValues_.insert("FullName", text);
}
void ProfileSettings::onPhoneTextEdit(const QString& text) {
  changedValues_.insert("Phone", text);
}
void ProfileSettings::onBirthDayTextEdit(const QString& text) {
  changedValues_.insert("BirthDay", text);
}
void ProfileSettings::onLanguageTextEdit(const QString& text) {
  changedValues_.insert("Language", text);
}
void ProfileSettings::onCityTextEdit(const QString& text) {
  changedValues_.insert("City", text);
}
void ProfileSettings::onCountryTextEdit(const QString& text) {
  changedValues_.insert("Country", text);
}
void ProfileSettings::onPubNameTextEdit(const QString& text) {
  changedValues_.insert("PubName", text);
}
void ProfileSettings::onFemaleChanged(bool checked) {
  if (checked) {
    changedValues_.insert("Gender", "F");
  } else {
    changedValues_.insert("Gender", "M");
  }
}
void ProfileSettings::onMaleChanged(bool checked) {
  if (checked) {
    changedValues_.insert("Gender", "M");
  } else {
    changedValues_.insert("Gender", "F");
  }
}

void ProfileSettings::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

