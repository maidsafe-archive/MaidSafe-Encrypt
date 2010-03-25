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
 *  Created on: Feb 25, 2010
 *      Author: Stephen
 */

#ifndef QT_CLIENT_CHECK_FOR_MESSAGES_THREAD_H_
#define QT_CLIENT_CHECK_FOR_MESSAGES_THREAD_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include "qt/client/worker_thread.h"

class CheckForMessagesThread : public WorkerThread {
  Q_OBJECT
 public:
  explicit CheckForMessagesThread(QObject* parent = 0);
  virtual ~CheckForMessagesThread();
  virtual void run();
  boost::uint16_t interval();
  void set_interval(boost::uint16_t the_interval);
  bool started();
  void set_started(bool turn_on);
 private:
  boost::uint16_t interval_;
  bool started_;
  boost::mutex interval_mutex_, start_mutex_;
};

#endif  // QT_CLIENT_CHECK_FOR_MESSAGES_THREAD_H_
