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
 *  Created on: March 24  int rename(const std::string &path, const std::string &path2); 2010
 *      Author: Stephen
 */

 #include "qt/client/rename_file_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"


RenameFileThread::RenameFileThread(const QString& filepath,
                                 const QString& newFilePath, QObject* parent)
    : WorkerThread(parent), filepath_(filepath), newFilePath_(newFilePath) { }

RenameFileThread::~RenameFileThread() { }

void RenameFileThread::run() {
  qDebug() << "RenameFileThread::run" << filepath_ ;

  int success = ClientController::instance()->rename(filepath_.toStdString(),
                                                    newFilePath_.toStdString());

  emit renameFileCompleted(success, filepath_, newFilePath_);
}
