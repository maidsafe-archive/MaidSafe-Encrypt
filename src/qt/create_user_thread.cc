
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

#include "create_user_thread.h"

// qt
#include <QDebug>

// core
#include "maidsafe/client/clientcontroller.h"

// local
#include "perpetual_data.h"


CreateUserThread::CreateUserThread( const QString& username,
                                    const QString& pin,
                                    const QString& password,
                                    QObject* parent )
    : QThread( parent )
    , username_ ( username )
    , pin_ ( pin )
    , password_ ( password )
{

}

CreateUserThread::~CreateUserThread()
{
    qDebug() << "CreateUserThread >> DTOR";

    quit();  // the event loop
    wait();  // until run has exited

    qDebug() << "CreateUserThread << DTOR";

    if ( isRunning() || !isFinished() )
    {
        qDebug() << "\nCreateUserThread - not shutdown";
    }
}

void CreateUserThread::run()
{
    qDebug() << "CreateUserThread::run";

    const std::string username = username_.toStdString();
    const std::string pin =      pin_.toStdString();
    const std::string password = password_.toStdString();

    if ( !maidsafe::ClientController::getInstance()->
                                        CreateUser(username, pin, password) )
    {
        createUserCompleted( false );
        return;
    }

    emit createUserCompleted( true );
}


