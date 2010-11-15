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

#include "maidsafe/lifestuff/client/create_user_thread.h"

// qt
#include <QDebug>

#include <boost/lexical_cast.hpp>
// std
#include <string>

// core
#include "maidsafe/lifestuff/client/client_controller.h"

// local

CreateUserThread::CreateUserThread(const QString& username,
                                   const QString& pin,
                                   const QString& password,
                                   const int& vault_type,
                                   const QString& space,
                                   const QString& port,
                                   const QString& directory,
                                   QObject* parent)
    : WorkerThread(parent), username_(username), pin_(pin),
      password_(password), vault_type_(vault_type), space_(space),
      port_(port), directory_(directory) { }

CreateUserThread::~CreateUserThread() { }

void CreateUserThread::run() {
  qDebug() << "CreateUserThread::run";

  if (!ClientController::instance()->
      CreateUser(username_, pin_, password_, vault_type_,
                 space_, port_, directory_)) {
    emit completed(false);
  } else {
    emit completed(true);
  }

  deleteLater();
}


