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

#ifndef LOGOUT_USER_THREAD_H_INCLUDED
#define LOGOUT_USER_THREAD_H_INCLUDED

#include "qt/client/worker_thread.h"

// Worker thread for logging out users files
/*!
    logging out users from the network is blocking and can take a while so we
    use a worker thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class LogoutUserThread : public WorkerThread {
  Q_OBJECT
 public:
  LogoutUserThread();
  virtual ~LogoutUserThread();

  virtual void run();

  signals:
  void logoutUserCompleted(bool);
};

#endif // LOGOUT_USER_THREAD_H_INCLUDED
