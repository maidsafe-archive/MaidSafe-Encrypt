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
 *  Created on: May 9, 2009
 *      Author: Team
 */

#ifndef QT_CLIENT_CONTROLLER_H_
#define QT_CLIENT_CONTROLLER_H_

// qt
#include <QObject>
#include <QString>
#include <QDateTime>
#include <QDir>

// core
#include "maidsafe/client/clientinterface.h"
#include "maidsafe/client/clientcontroller.h"

// local
#include "qt/client/share.h"
#include "qt/client/contact.h"



//! Wrapper for maidsafe::ClientController
/*!
    Implements the ClientController notification interface and wraps up
    the ClientController methods in a Qt style API.

    The ClientController class, in conjunction with the other classes in
    qt/client, act as a layer between the Qt gui world and the maidsafe
    world.
*/
class ClientController : public QObject,
                         public maidsafe::ClientInterface
{
    Q_OBJECT
public:
    static ClientController* instance();

    //!
    void shutdown();

    //! Public username of current user.
    /*!
        Public username is actually on the SessionSingleton interface.  If
        we need to access more of the SessionSingleton inteface then we may
        be as well to split into a sepetate Qt wrapper
    */
    QString publicUsername() const;


    /// Contacts
    //! Current contacts.
    ContactList contacts() const;

    //! Public names of all current contacts
    QStringList contactsNames() const;

    //! Add a contact.
    /*!
        \param name public name of the contact you want to add.

        This sends a request to \a name asking if they want to be added.

        The result of this request will be notified contactStatusChanged
    */
    bool addContact( const QString& name );

    //! Remove a contact
    bool removeContact( const QString& name );


    /// Shares
    //! Create a share
    bool createShare( const QString& shareName,
                      const QStringList& admin,
                      const QStringList& readOnly );

    //! Current shares
    ShareList shares() const;

    //! Root directory of a named share
    /*!
        Note: doesn't check validity of share name
        TODO: move onto Share interface
    */
    QDir shareDirRoot( const QString& name ) const;
    QDir myFilesDirRoot( const QString& name ) const;


    /// Messaging
    //! Send an instant message to someone
    /*!
        \param txt the message
        \param to public user name of the intended recipient

        TODO - any length or format restrictions?
    */
    bool sendInstantMessage( const QString& txt, const QString& to );

    //! Send a file to someone
    /*!
        \param path full file path of file
        \param txt accompanying message
        \param to public user name of the intended recipient

        The file must be within the maidsage file system
    */
    bool sendInstantFile( const QString& filePath,
                          const QString& txt,
                          const QString& to );

signals:
    //! A message has been received.
    void messageReceived( const QDateTime& time,
                          const QString& from,
                          const QString& msg );

    //! We've added a contact
    void addedContact( const QString& name );

    //! We've added a private share
    void addedPrivateShare( const QString& name );

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

private slots:
    //! temporary while we emulate message notifications
    void checkForMessages();

private:
    explicit ClientController( QObject* parent = 0 );
    virtual ~ClientController();

    //! Analyse an instanst message and emit the appropriate signals
    /*!
        handles:
         contacts added
         private shares added
    */
    int analyseMessage(
      const packethandler::InstantMessage& im,
      QString *sender, QString *message);
    class ClientControllerImpl;
    ClientControllerImpl* impl_;
};



#endif  // QT_CLIENT_CONTROLLER_H_





