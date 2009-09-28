
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

#include "qt/client/join_kademlia_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"

JoinKademliaThread::JoinKademliaThread(QObject* parent)
    : WorkerThread(parent) { }

JoinKademliaThread::~JoinKademliaThread() { }

void JoinKademliaThread::run() {
  qDebug() << "JoinKademliaThread::run";
#ifdef DEBUG
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  qDebug() << "JoinKademliaThread::run - After SLEEP";
#endif
  if (ClientController::instance()->Init()) {
    emit completed(true);
  } else {
    emit completed(false);
  }

  deleteLater();
}


