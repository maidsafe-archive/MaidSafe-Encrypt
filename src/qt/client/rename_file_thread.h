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

#ifndef RENAME_FILE_THREAD_H_INCLUDED
#define RENAME_FILE_THREAD_H_INCLUDED

#include "qt/client/worker_thread.h"

// Worker thread for creating the pulbic username of users
/*!
    renaming a file from the network is blocking and can take a while so we
    use a worker thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class RenameFileThread : public WorkerThread {
  Q_OBJECT
 public:
  RenameFileThread(const QString& filepath, const QString& newFilePath,
                             QObject* parent = 0);
  virtual ~RenameFileThread();

  virtual void run();

 private:
  QString filepath_;
  QString newFilePath_;

  signals:
  void renameFileCompleted(int, const QString&, const QString&);
};

#endif // RENAME_FILE_THREAD_H_INCLUDED
