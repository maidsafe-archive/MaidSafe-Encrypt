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
 *  Created on: April 07 2010
 *      Author: Stephen
 */

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_REMOVE_DIR_THREAD_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_REMOVE_DIR_THREAD_H_

#include "maidsafe/lifestuff/client/worker_thread.h"

// Worker thread for removing a directory
/*!
    removing a directory from the network is blocking and can take a while so we
    use a worker thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class RemoveDirThread : public WorkerThread {
  Q_OBJECT
 public:
  RemoveDirThread(const QString& filepath,
                             QObject* parent = 0);
  virtual ~RemoveDirThread();

  virtual void run();

 private:
  QString filepath_;

  signals:
  void removeDirCompleted(int, const QString&);
};

#endif  // MAIDSAFE_LIFESTUFF_CLIENT_REMOVE_DIR_THREAD_H_
