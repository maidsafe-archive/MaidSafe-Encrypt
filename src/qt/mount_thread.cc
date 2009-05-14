
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

#include "mount_thread.h"

// qt
#include <QDebug>

// local
#include "perpetual_data.h"


MountThread::MountThread( PerpetualData* pd, MountAction action )
    : QThread( pd )
    , pd_ ( pd )
    , action_ ( action )
{

}

MountThread::~MountThread()
{
    qDebug() << "MountThread >> DTOR";

    quit();  // the event loop
    wait();  // until run has exited

    qDebug() << "MountThread << DTOR";

    if ( isRunning() || !isFinished() )
    {
        qDebug() << "\nMountThread - not shutdown";
    }
}

void MountThread::run()
{
    qDebug() << "MountThread::run";

    bool success = false;
    if ( action_ == MOUNT )
    {
        success = pd_->mount();
    }
    else
    {
        success = pd_->unmount();
    }

    emit completed( success );
}


