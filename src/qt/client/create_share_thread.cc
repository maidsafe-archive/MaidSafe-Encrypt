
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

#include "qt/client/create_share_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"

// local

CreateShareThread::CreateShareThread(const QString& shareName,
                                     const QStringList& adminSet,
                                     const QStringList& roSet,
                                     QObject* parent)
    : WorkerThread(parent), shareName_(shareName), adminSet_(adminSet),
      roSet_(roSet) { }

CreateShareThread::~CreateShareThread() { }

void CreateShareThread::run() {
  qDebug() << "CreateShareThread::run";
  std::set<std::string> sAdminSet;
  std::set<std::string> sRoSet;
  QListStringToStdSet(adminSet_, &sAdminSet);
  QListStringToStdSet(roSet_, &sRoSet);

  if (ClientController::instance()->CreateNewShare(
      shareName_.toStdString(), sAdminSet, sRoSet) != 0) {
    qDebug() << "CreateShareThread::run FAIL";
    emit completed(false);
  } else {
    qDebug() << "CreateShareThread::run SUCCESS";
    emit completed(true);
  }

  deleteLater();
}

void CreateShareThread::QListStringToStdSet(const QStringList& qList,
                                            std::set<std::string> *sSet) {
  sSet->clear();
  foreach(const QString& s, qList) {
    sSet->insert(s.toStdString());
  }
}


