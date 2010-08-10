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
 *      Author: Team
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
  qDebug() << "SaveFileThread::run" << filepath_;

  QString fileSize;
  QString lastModified;
  int success = ClientController::instance()->getattr(filepath_, lastModified, fileSize);
  if (success != 0) {
    success = ClientController::instance()->mknod(filepath_);
    if (success != 0) {
      emit saveFileCompleted(success, filepath_);
      return;
    }
  }

  success = ClientController::instance()->write(filepath_);
  this->sleep(3);

  emit saveFileCompleted(success, filepath_);
}

