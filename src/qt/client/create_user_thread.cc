
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



CreateUserThread::CreateUserThread( const QString& username,
                                    const QString& pin,
                                    const QString& password,
                                    QObject* parent )
    : WorkerThread( parent )
    , username_ ( username )
    , pin_ ( pin )
    , password_ ( password )
{

}

CreateUserThread::~CreateUserThread()
{

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
        emit completed( false );
    }
    else
    {
        emit completed( true );
    }

    deleteLater();
}


