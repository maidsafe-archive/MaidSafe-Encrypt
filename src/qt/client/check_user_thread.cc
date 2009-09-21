
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

#include "qt/client/check_user_thread.h"

// qt
#include <QDebug>

// core
#include "maidsafe/client/clientcontroller.h"

// local

CheckUserThread::CheckUserThread(const QString& username,
                                   const QString& pin,
                                   QObject* parent)
    : WorkerThread(parent), username_(username), pin_(pin) { }

CheckUserThread::~CheckUserThread() { }

void CheckUserThread::run() {
  qDebug() << "CheckUserThread::run";
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  qDebug() << "CheckUserThread::run - After SLEEP";

  const std::string username = username_.toStdString();
  const std::string pin = pin_.toStdString();

  maidsafe::Exitcode ec = maidsafe::ClientController::getInstance()->
                          CheckUserExists(username, pin, maidsafe::DEFCON3);

  if (ec == maidsafe::NON_EXISTING_USER) {
    emit completed(false);
  } else {
    emit completed(true);
  }

  deleteLater();
}


