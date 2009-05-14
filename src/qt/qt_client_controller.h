/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Notification interface implemented by maidsafe gui
* Version:      1.0
* Created:      2009-05-06-00.00.00
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

#ifndef QT_CLIENT_CONTROLLER_H_
#define QT_CLIENT_CONTROLLER_H_

// qt
#include <QObject>
#include <QString>

// core
#include "maidsafe/client/clientinterface.h"



//! Qt freidly wrapper for maidsafe::ClientController
/*!
    Implements the ClientController notification interface and wraps up
    the ClientController methods in a Qt style API
*/
class ClientController : public QObject,
                         public maidsafe::ClientInterface
{
    Q_OBJECT
public:
    static ClientController* instance();

signals:
    void messageReceived( const QString& from,
                          const QString& msg );

    //! A contact's status has changed
    /*!
        TODO: emnumerate possible status
    */
    void contactStatusChanged( const QString& from,
                               int status );

    //! User requested add of contact
    /*!
        \param from contact who wants to add you
        \param msg introduction message

        In response, the request should be accepted or declined via client
        controller.
    */
    void contactAdditionRequested( const QString& from,
                                   const QString& msg );

    //! A user has shared something with you
    void shareReceived( const QString& from,
                        const QString& share_name );

    //! A share has been changed in some way e.g. permissions or removed
    void shareChanged( const QString& from,
                       const QString& share_name );

    //! A user has sent you a file
    /*!
        Currently saved directly into private file's section.
        Would be nice to prompt for new filename, whether to accept etc
    */
    void fileReceived( const QString& from,
                       const QString& file_name );

    //! System messages - to be decided
    void systemMessage( const QString& message );

public:
    //! Implementation of the ClientInterface

    //! A user has sent you a message
    virtual void messageReceived( const std::string& from,
                                  const std::string& msg );

    //! A contact's status has changed
    /*!
        TODO: emnumerate possible status
    */
    virtual void contactStatusChanged( const std::string& from,
                                       int status );

    //! User requested add of contact
    /*!
        \param from contact who wants to add you
        \param msg introduction message

        In response, the request should be accepted or declined via client
        controller.
    */
    virtual void contactAdditionRequested( const std::string& from,
                                           const std::string& msg );

    //! A user has shared something with you
    virtual void shareReceived( const std::string& from,
                                const std::string& share_name );

    //! A share has been changed in some way e.g. permissions or removed
    virtual void shareChanged( const std::string& from,
                               const std::string& share_name );

    //! A user has sent you a file
    /*!
        Currently saved directly into private file's section.
        Would be nice to prompt for new filename, whether to accept etc
    */
    virtual void fileReceived( const std::string& from,
                               const std::string& file_name );

    //! System messages - to be decided
    virtual void systemMessage( const std::string& message );

private:
    explicit ClientController( QObject* parent = 0 );
    virtual ~ClientController();

    class ClientControllerImpl;
    ClientControllerImpl* impl_;
};



#endif  // QT_CLIENT_CONTROLLER_H_





