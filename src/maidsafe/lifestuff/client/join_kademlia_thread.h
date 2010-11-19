
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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_JOIN_KADEMLIA_THREAD_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_JOIN_KADEMLIA_THREAD_H_

#include "maidsafe/lifestuff/client/worker_thread.h"

// Worker thread for joining the kademlia network
/*!
    Joining the kadmlia network is blocking and can take a while so we
    use a worker thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class JoinKademliaThread : public WorkerThread {
  Q_OBJECT
 public:
  explicit JoinKademliaThread(QObject* parent = 0);
  virtual ~JoinKademliaThread();

  virtual void run();
};

#endif  //  MAIDSAFE_LIFESTUFF_CLIENT_JOIN_KADEMLIA_THREAD_H_

