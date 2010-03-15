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
 *  Created on: March 15, 2010
 *      Author: Stephen
 */

#include "qt/client/save_security_settings_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"


SaveSecuritySettingsThread::SaveSecuritySettingsThread(
    QHash<QString, QString> theHash, QObject* parent)
      : WorkerThread(parent), theHash_(theHash) { }

SaveSecuritySettingsThread::~SaveSecuritySettingsThread() { }

void SaveSecuritySettingsThread::run() {
  bool success = false;
  qDebug() << "SaveSecuritySettingsThread::run";

  if (theHash_.contains("username")) {
    success = ClientController::instance()->ChangeUsername(
                  theHash_.value("username").toStdString());
  }
  if (theHash_.contains("Pin")) {
  }
  if (theHash_.contains("Password")) {
  }
  emit completed(success);
}
