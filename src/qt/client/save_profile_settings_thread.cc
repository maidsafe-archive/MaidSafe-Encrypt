
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

#include "qt/client/save_profile_settings_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"


SaveProfileSettingsThread::SaveProfileSettingsThread(
                              QHash<QString, QString> theHash, QObject* parent)
    : WorkerThread(parent), theHash_(theHash) { }

SaveProfileSettingsThread::~SaveProfileSettingsThread() { }

void SaveProfileSettingsThread::run() {
  qDebug() << "SaveProfileSettingsThread::run";

  std::vector<std::string> profileInfo;

  profileInfo.push_back(theHash_["FullName"].toStdString());
  profileInfo.push_back(theHash_["Phone"].toStdString());
  profileInfo.push_back(theHash_["BirthDay"].toStdString());
  profileInfo.push_back(theHash_["Gender"].toStdString());
  profileInfo.push_back(theHash_["Language"].toStdString());
  profileInfo.push_back(theHash_["City"].toStdString());
  profileInfo.push_back(theHash_["Country"].toStdString());

  const bool success = ClientController::instance()->SetInfo(profileInfo);

  emit completed(success);
}


