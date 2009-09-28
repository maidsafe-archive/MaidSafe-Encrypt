
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

#ifndef QT_CLIENT_JOIN_KADEMLIA_THREAD_H_
#define QT_CLIENT_JOIN_KADEMLIA_THREAD_H_

#include "qt/client/worker_thread.h"

// Worker thread for creating users
/*!
    Checking for a user is blocking and can take a while so we use a worker
    thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class JoinKademliaThread : public WorkerThread {
  Q_OBJECT
 public:
  JoinKademliaThread(QObject* parent = 0);
  virtual ~JoinKademliaThread();

  virtual void run();

 private:
  QString username_, pin_;
};

#endif  // QT_CLIENT_JOIN_KADEMLIA_THREAD_H_

