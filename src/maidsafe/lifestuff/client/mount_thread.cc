
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

#include "maidsafe/lifestuff/client/mount_thread.h"

// qt
#include <QDebug>

// local
#include "maidsafe/lifestuff/client/user_space_filesystem.h"


MountThread::MountThread(MountAction action, QObject* parent)
    : WorkerThread(parent), action_(action) { }

MountThread::~MountThread() { }

void MountThread::run() {
  qDebug() << "MountThread::run";
  bool success = false;
  if (action_ == MOUNT) {
    success = UserSpaceFileSystem::instance()->mount();
  } else {
    success = UserSpaceFileSystem::instance()->unmount();
  }

  emit completed(success);

  deleteLater();
}


