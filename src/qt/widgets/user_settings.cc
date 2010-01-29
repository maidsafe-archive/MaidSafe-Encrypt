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


#include "qt/widgets/user_settings.h"
#include "qt/widgets/personal_settings.h"
#include "qt/widgets/vault_info.h"
#include "qt/widgets/connection_settings.h"
#include "qt/widgets/file_transfer_settings.h"
#include "qt/widgets/security_settings.h"
#include "qt/client/client_controller.h"

UserSettings::UserSettings(QWidget* parent){
  ui_.setupUi(this);

  createSettingsMenu();

  personal_     = new PersonalSettings;
  vault_        = new VaultInfo;
  fileTransfer_ = new FileTransferSettings;
  security_     = new SecuritySettings;
  connection_   = new ConnectionSettings;


  ui_.stackedWidget->addWidget(personal_);
  ui_.stackedWidget->addWidget(vault_);
  ui_.stackedWidget->addWidget(fileTransfer_);
  ui_.stackedWidget->addWidget(security_);
  ui_.stackedWidget->addWidget(connection_);

  ui_.stackedWidget->setCurrentWidget(personal_);

  connect(ui_.settingsMenuList, SIGNAL(currentRowChanged(int)),
          this,           SLOT(onCurrentRowChanged(int)));

}

UserSettings::~UserSettings() {}

void UserSettings::onCurrentRowChanged(int index) {
    switch (index){
      case 0:
        setState(PERSONAL);
        break;
      case 1:
        setState(CONNECTION);
        break;
      case 2:
        setState(FILE_TRANSFER);
        break;
      case 3:
        setState(SECURITY);
        break;
      case 4:
        setState(VAULT_INFO);
        break;
    }

}

void UserSettings::createSettingsMenu(){
  ui_.settingsMenuList->addItem("Personal");
  ui_.settingsMenuList->addItem("Connection");
  ui_.settingsMenuList->addItem("File Transfer");
  ui_.settingsMenuList->addItem("Security");
  ui_.settingsMenuList->addItem("Vault Info");
}

void UserSettings::setState(State state) {
  state_ = state;

  switch (state_) {
    case PERSONAL:
    {
      ui_.stackedWidget->setCurrentWidget(personal_);
      personal_->setActive(true);
      break;
    }
    case CONNECTION:
    {
      ui_.stackedWidget->setCurrentWidget(connection_);
      break;
    }
    case FILE_TRANSFER:
    {
      ui_.stackedWidget->setCurrentWidget(fileTransfer_);
      break;
    }
    case SECURITY:
    {
      ui_.stackedWidget->setCurrentWidget(security_);
      break;
    }
    case VAULT_INFO:
    {
      ui_.stackedWidget->setCurrentWidget(vault_);
      vault_->setActive(true);
      break;
    }
    default:
    {
      break;
    }
  }
}
