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


#include "qt/widgets/personal_settings.h"
#include "qt/client/client_controller.h"

PersonalSettings::PersonalSettings(QWidget* parent) : init_(false) {
  ui_.setupUi(this);

    connect(ui_.usernameEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onUsernameTextEdit(const QString&)));

    connect(ui_.messageEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onMessageTextEdit(const QString&)));

    connect(ui_.pushButtonPicture, SIGNAL(clicked(bool)),
          this,           SLOT(void onPicChangeClicked(bool)));
}

PersonalSettings::~PersonalSettings() { }

void PersonalSettings::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
    ui_.usernameEdit->setText(ClientController::instance()->publicUsername());
    ui_.messageEdit->setText("Hello This is my message!");
  }
}

void PersonalSettings::reset() { }

void PersonalSettings::onUsernameTextEdit(const QString& text) {
  changedValues_.insert("username", text);
}

void PersonalSettings::onMessageTextEdit(const QString& text) {
  changedValues_.insert("message", text);
}

void PersonalSettings::onPicChangeClicked(bool b) {
  changedValues_.insert("changepic", "");
}


