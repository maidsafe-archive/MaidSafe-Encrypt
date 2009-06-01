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

#include "client_controller.h"

// qt
#include <QObject>
#include <QStringList>
#include <QDebug>
#include <QTimer>

// core
#include "maidsafe/maidsafe-dht.h"
#include "fs/filesystem.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/privateshares.h"

const int MESSAGE_POLL_TIMEOUT_MS = 6000;

namespace
{
    bool contactSortLessThan( const Contact* c1, const Contact* c2 )
    {
        return c1->publicName() < c2->publicName();
    }
}

class ClientController::ClientControllerImpl
{

public:
    ClientControllerImpl()
    {
        messagePollTimer.start( MESSAGE_POLL_TIMEOUT_MS );
    }


    QTimer messagePollTimer;
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
    maidsafe::ClientController::getInstance()->JoinKademlia();
    maidsafe::ClientController::getInstance()->Init();


    connect( &impl_->messagePollTimer, SIGNAL( timeout() ),
             this,                     SLOT( checkForMessages() ) );

}

ClientController::~ClientController()
{
    delete impl_;
    impl_ = NULL;
}

void ClientController::shutdown()
{
    maidsafe::ClientController::getInstance()->CloseConnection();
}

QString ClientController::publicUsername() const
{
    return QString::fromStdString(
            maidsafe::SessionSingleton::getInstance()->PublicUsername() );
}

bool ClientController::createShare( const QString& shareName,
                                    const QStringList& admin,
                                    const QStringList& readOnly )
{
    qDebug() << "createShare:" << shareName << admin << readOnly;
    std::set<std::string> admin_set, ro_set;

    foreach( const QString& s, admin )
    {
        admin_set.insert( s.toStdString() );
    }

    foreach( const QString& s, readOnly )
    {
        ro_set.insert( s.toStdString() );
    }

    int n = maidsafe::ClientController::getInstance()->
                                    CreateNewShare( shareName.toStdString(),
                                                    admin_set,
                                                    ro_set );
    printf("Add share result: %i\n", n);

    if ( n == 0 ) // ||      // success
         // n == -30006 || // message error
         // n == -30007 )  // message error
    {
        return true;
    }

    return false;
}

ShareList ClientController::shares() const
{
    ShareList rv;
    std::list<maidsafe::PrivateShare> ps_list;
    const int n = maidsafe::ClientController::getInstance()
                    ->GetShareList( &ps_list, "" );
    qDebug() << ps_list.size();
    if ( n == 0 )
    {
        while ( !ps_list.empty() )
        {
            maidsafe::PrivateShare ps = ps_list.front();
            ps_list.pop_front();

            QString shareName = QString::fromStdString( ps.Name() );
            Share share( shareName );

            std::list<maidsafe::ShareParticipants> participants =
                                                            ps.Participants();
            std::list<maidsafe::ShareParticipants>::const_iterator I =
                                                        participants.begin();
            std::list<maidsafe::ShareParticipants>::const_iterator E =
                                                        participants.end();
            for ( ; I!=E; ++I )
            {
                const QString name = QString::fromStdString( I->id );
                const char role = I->role;
                Share::Permissions permissions = Share::NONE;
                if ( role == 'A' ) {
                    permissions = Share::Permissions(Share::READ | Share::WRITE);
                } else if ( role == 'R' ) {
                    permissions = Share::READ;
                }
                share.addParticipant( name, permissions );

            }
            rv.push_back( share );
        }
    }

    return rv;
}


QDir ClientController::shareDirRoot( const QString& name ) const
{
    qDebug() << "ClientController::shareDirRoot:" << name;
    QString pathInMaidsafe = QString( "Shares%1Private%2%3" )
                            .arg( QDir::separator() )
                            .arg( QDir::separator() )
                            .arg( name );

#ifdef MAIDSAFE_WIN32
    QString maidsafeRoot = QString( "%1:\\" ).arg( maidsafe::SessionSingleton::getInstance()->WinDrive() );
#else
    file_system::FileSystem fs;
    // Path comes back without that last slash
    QString maidsafeRoot = QString::fromStdString( fs.MaidsafeFuseDir() + "/" );
#endif

    QString path = maidsafeRoot + pathInMaidsafe;

    QDir dir( path );
    if ( !dir.exists() )
    {
        qWarning() << "share directory doesn't exist:" << path;
    }

    return dir;
}

QDir ClientController::myFilesDirRoot( const QString& name ) const
{
    qDebug() << "ClientController::myFilesDirRoot:" << name;
    QString pathInMaidsafe = QString( "My Files%1%2" )
                            .arg( QDir::separator() )
                            .arg( name );

#ifdef MAIDSAFE_WIN32
    QString maidsafeRoot = QString( "%1:\\" ).arg( maidsafe::SessionSingleton::getInstance()->WinDrive() );
#else
    file_system::FileSystem fs;
    // Path comes back without that last slash
    QString maidsafeRoot = QString::fromStdString( fs.MaidsafeFuseDir() + "/" );
#endif

    QString path = maidsafeRoot + pathInMaidsafe;

    QDir dir( path );
    if ( !dir.exists() )
    {
        qWarning() << "share directory doesn't exist:" << path;
    }

    return dir;
}


QStringList ClientController::contactsNames() const
{
    std::vector<maidsafe::Contacts> contact_list;
    const int n =
        maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
    if ( n != 0 )
    {
#ifdef DEBUG
        qDebug() << "ClientController::contactNames(): failed to get contacts. Err:"
                 << n;
#endif
        return QStringList();
    }

    QStringList rv;
    for ( int i = 0; i < contact_list.size(); ++i )
    {
        rv.push_back( QString::fromStdString( contact_list[i].PublicName() ) );
    }

    return rv;
}

ContactList ClientController::contacts() const
{
    std::vector<maidsafe::Contacts> contact_list;
    const int n =
        maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
    if ( n != 0 )
    {
#ifdef DEBUG
        qDebug() << "ClientController::contacts(): failed to get contacts. Err:"
                 << n;
#endif
        return ContactList();
    }

    ContactList rv;
    for ( unsigned int i = 0; i < contact_list.size(); ++i )
    {
        // accessors on maidsafe::Contacts are non-const so can't pass in const&
        /*const*/ maidsafe::Contacts mcontact = contact_list[i];
        Contact* contact = Contact::fromContact( mcontact );

        rv.push_back( contact );
    }

    qSort( rv.begin(), rv.end(), contactSortLessThan );

    return rv;
}

bool ClientController::addContact( const QString& name )
{
    qDebug() << "ClientController::addContact:" << name;

    const int n = maidsafe::ClientController::getInstance()->
                                                AddContact( name.toStdString() );
    qDebug() << "Addition result:" << n;
    switch (n)
    {
    case 0:
    {
        return true;
    }
    case -221:
    {
        qDebug() << "Error adding contact. Username doesn't exist.";
        break;
    }
    default:
    {
        // unknown error
        break;
    }
    }

    return false;
}

bool ClientController::removeContact( const QString& name )
{
    qDebug() << "ClientController::removeContact:" << name;

    const int n = maidsafe::ClientController::getInstance()->
                                            DeleteContact( name.toStdString() );

    return (n==0);
}


bool ClientController::sendInstantMessage( const QString& txt,
                                           const QString& to )
{
    qDebug() << "ClientController::sendInstantMessage:" << txt << to;

    const int n = maidsafe::ClientController::getInstance()->
                                        SendInstantMessage( txt.toStdString(),
                                                            to.toStdString() );

    return (n==0);
}

bool ClientController::sendInstantFile( const QString& filePath,
                                        const QString& txt,
                                        const QString& to )
{
    qDebug() << "ClientController::sendInstantFile:" << filePath << txt << to;

    file_system::FileSystem fsys;
    std::string rel_filename( fsys.MakeRelativeMSPath( filePath.toStdString() ) );

#ifdef MAIDSAFE_WIN32
    // trim e.g. C:
    rel_filename.erase( 0, 2 );
#endif
    qDebug() << "Before Tidy Path:" << rel_filename.c_str();

    rel_filename = base::TidyPath( rel_filename );
    qDebug() << "Tidied Path:" << rel_filename.c_str();

    const int n = maidsafe::ClientController::getInstance()->
                                        SendInstantFile( &rel_filename,
                                                         txt.toStdString(),
                                                         to.toStdString() );

    return (n==0);
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


void ClientController::checkForMessages()
{
    qDebug() << "ClientController::checkForMessages()";

    // Check for messages only when public username is set
    if ( publicUsername().isEmpty() )
      return;

    maidsafe::ClientController::getInstance()->GetMessages();
    std::list<packethandler::InstantMessage> msgs;
    const int n = maidsafe::ClientController::getInstance()
                    ->GetInstantMessages( &msgs );

    if ( n != 0 )
      return;

    qDebug() << "found" << msgs.size() << "instant messages";

    std::list<packethandler::InstantMessage> temp = msgs;
    while ( !temp.empty() )
    {
        const packethandler::InstantMessage& im = temp.front();

        const QDateTime time = QDateTime::currentDateTime();
        QString sender;
        QString message;
        analyseMessage(im, &sender, &message);

        emit messageReceived( time, sender, message );

        temp.pop_front();
    }
}

int ClientController::analyseMessage( const packethandler::InstantMessage& im,
                                      QString *sender,
                                      QString *message)
{
  int n = 0;
  if (im.has_contact_notification())
  {
    qDebug() << "HANDLING Cntact Notification";
    packethandler::ContactNotification cn = im.contact_notification();
    packethandler::ContactInfo ci;
    if ( cn.has_contact() )
      ci = cn.contact();

    switch (cn.action())
    {
      // ADD REQUEST
      case 0:
      {
          n = maidsafe::ClientController::getInstance()->
                  HandleAddContactRequest(ci, im.sender());
          if (n == 0)
          {
            QString qs = QString::fromStdString( im.sender() );
            emit addedContact(qs);
          }
          break;
      }
      // ADD RESPONSE
      case 1:
      {
          qDebug() << "HANDLING AddContactResponse";
          n = maidsafe::ClientController::getInstance()->
              HandleAddContactResponse(ci, im.sender());
          break;
      }
    }
  }
  else if (im.has_instantfile_notification())
  {
    n = maidsafe::ClientController::getInstance()->
        AddInstantFile(im.instantfile_notification(), "");
  }
  else if (im.has_privateshare_notification())
  {
    n = maidsafe::ClientController::getInstance()->
        HandleReceivedShare(im.privateshare_notification(), "");
    packethandler::PrivateShareNotification psn =
      im.privateshare_notification();
    if (n == 0)
    {
        QString qs = QString::fromStdString( psn.name() );
        emit addedPrivateShare( qs );
    }
  }

  *message = QString::fromStdString( im.message() );
  *sender = QString::fromStdString( im.sender() );

  return n;
}
