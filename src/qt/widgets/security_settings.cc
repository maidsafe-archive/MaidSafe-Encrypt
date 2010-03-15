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

#include "qt/widgets/security_settings.h"
#include "qt/client/client_controller.h"

SecuritySettings::SecuritySettings(QWidget* parent) {
  ui_.setupUi(this);

  connect(ui_.usernameEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onUsernameTextEdit(const QString&)));

  connect(ui_.pinEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onPinTextEdit(const QString&)));

  connect(ui_.passwordEdit, SIGNAL(textEdited(const QString&)),
          this,           SLOT(onPasswordTextEdit(const QString&)));
}

SecuritySettings::~SecuritySettings() {}

void SecuritySettings::onUsernameTextEdit(const QString& text) {
  changedValues_.insert("username", text);
}

void SecuritySettings::onPinTextEdit(const QString& text) {
  changedValues_.insert("pin", text);
}

void SecuritySettings::onPasswordTextEdit(const QString& text) {
  changedValues_.insert("password", text);
}




