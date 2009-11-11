
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
 *  Created on: May 5, 2009
 *      Author: Team
 */

#include "qt/client/validate_user_thread.h"

// qt
#include <QDebug>

// std
#include <string>

// core
#include "maidsafe/client/clientcontroller.h"

// local

ValidateUserThread::ValidateUserThread(const QString& password,
                                       QObject* parent)
    : WorkerThread(parent), password_(password) { }

ValidateUserThread::~ValidateUserThread() { }

void ValidateUserThread::run() {
  qDebug() << "ValidateUserThread::run";
#ifdef DEBUG
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  qDebug() << "ValidateUserThread::run - After SLEEP";
#endif
  const std::string password = password_.toStdString();

  if (maidsafe::ClientController::getInstance()->ValidateUser(password)) {
    emit completed(true);
  } else {
    emit completed(false);
  }

  deleteLater();
}


