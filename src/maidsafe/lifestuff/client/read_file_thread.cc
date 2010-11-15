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

#include "maidsafe/lifestuff/client/read_file_thread.h"

// qt
#include <QDebug>

// core
#include "maidsafe/lifestuff/client/client_controller.h"


ReadFileThread::ReadFileThread(const QString& filepath, QObject* parent)
    : WorkerThread(parent), filepath_(filepath) { }

ReadFileThread::~ReadFileThread() { }

void ReadFileThread::run() {
  qDebug() << "ReadFileThread::run" << filepath_;

  int success = ClientController::instance()->read(filepath_);
  this->sleep(2);

  emit readFileCompleted(success, filepath_);
}

