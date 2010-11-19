
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
 *  Created on: May 20, 2009
 *      Author: Team
 */

#include "maidsafe/lifestuff/client/create_public_username_thread.h"

// qt
#include <QDebug>

// core
#include "maidsafe/lifestuff/client/client_controller.h"


CreatePublicUsernameThread::CreatePublicUsernameThread(const QString& username,
                                                       QObject* parent)
    : WorkerThread(parent), username_(username) { }

CreatePublicUsernameThread::~CreatePublicUsernameThread() { }

void CreatePublicUsernameThread::run() {
  qDebug() << "CreatePublicUsernameThread::run";

  const bool success = ClientController::instance()->
                       CreatePublicUsername(username_.toStdString());

  emit completed(success);
}


