
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

#ifndef QT_MOUNT_THREAD_H_
#define QT_MOUNT_THREAD_H_

#include <QThread>

class PerpetualData;

//! Worker thread for mounting
/*!
    Mounting is blocking and can take a while so we use a worker thread
    to ensure that it doesn't block the main gui.

    Currently intended for single use.

    \TODO there are likely to be lots of actions that needs to be performed
    in a non blocking worker thread.  consider a single class that can perform
    multiple different actions

    \sa PerpetualData::mount()
*/
class MountThread : public QThread
{
    Q_OBJECT
public:
    typedef enum MountAction
    {
        MOUNT,
        UNMOUNT
    };

    MountThread( PerpetualData* pd, MountAction action );
    virtual ~MountThread();

    virtual void run();

signals:
    void completed( bool success );

private:
    PerpetualData* pd_;
    MountAction action_;
};

#endif // QT_MOUNT_THREAD_H_

