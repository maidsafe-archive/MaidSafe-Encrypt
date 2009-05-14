/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Notification interface implemented by maidsafe gui
* Version:      1.0
* Created:      2009-05-09-00.00.00
* Revision:     none
* Compiler:     gcc
* Author:       William Cook (wdsc), info@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/
#include <QObject>

#include "qt_client_controller.h"

class ClientController::ClientControllerImpl
{

public:
    ClientControllerImpl()
    {
    }

};


//#include "qt_client_controller.moc"


ClientController* ClientController::instance()
{
    static ClientController qtcc;
    return &qtcc;
}

ClientController::ClientController( QObject* parent )
    : QObject( parent )
    , impl_( new ClientControllerImpl )
{

}

ClientController::~ClientController()
{
    delete impl_;
    impl_ = NULL;
}



void ClientController::messageReceived( const std::string& from,
                                        const std::string& msg )
{

}

void ClientController::contactStatusChanged( const std::string& from,
                                             int status )
{

}

void ClientController::contactAdditionRequested( const std::string& from,
                                                 const std::string& msg )
{

}

void ClientController::shareReceived( const std::string& from,
                                      const std::string& share_name )
{

}

void ClientController::shareChanged( const std::string& from,
                                     const std::string& share_name )
{

}

void ClientController::fileReceived( const std::string& from,
                               const std::string& file_name )
{

}

void ClientController::systemMessage( const std::string& message )
{

}






