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
 *  Created on: March 23 2010
 *      Author: Stephen
 */

#include "qt/client/save_file_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"


SaveFileThread::SaveFileThread(const QString& filepath, QObject* parent)
    : WorkerThread(parent), filepath_(filepath) { }

SaveFileThread::~SaveFileThread() { }

void SaveFileThread::run() {
  qDebug() << "SaveFileThread::run" << filepath_ ;

  int success = ClientController::instance()->write(filepath_.toStdString());

  emit saveFileCompleted(success, filepath_);
}

