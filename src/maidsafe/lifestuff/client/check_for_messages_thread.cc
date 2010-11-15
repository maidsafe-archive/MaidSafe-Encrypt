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
 *      Author: Team
 */

#include "maidsafe/lifestuff/client/check_for_messages_thread.h"

// qt
#include <QDebug>

// core
#include "maidsafe/lifestuff/client/client_controller.h"


CheckForMessagesThread::CheckForMessagesThread(QObject* parent)
    : QThread(parent), interval_(3), started_(false),
      interval_mutex_(), start_mutex_() { }

CheckForMessagesThread::~CheckForMessagesThread() { }

void CheckForMessagesThread::run() {
  qDebug() << "CheckForMessagesThread::run";
  while (started()) {
    const bool success = ClientController::instance()->GetMessages();
    emit completed(success);
    boost::this_thread::sleep(boost::posix_time::seconds(interval()));
  }
}

boost::uint16_t CheckForMessagesThread::interval() {
  boost::mutex::scoped_lock loch_ness(start_mutex_);
  return interval_;
}
void CheckForMessagesThread::set_interval(boost::uint16_t the_interval) {
  boost::mutex::scoped_lock loch_ness(start_mutex_);
  interval_ = the_interval;
}
bool CheckForMessagesThread::started() {
  boost::mutex::scoped_lock loch_lomond(start_mutex_);
  return started_;
}
void CheckForMessagesThread::set_started(bool turn_on) {
  boost::mutex::scoped_lock loch_lomond(start_mutex_);
  started_ = turn_on;
}
