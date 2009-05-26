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
 *  Created on: Apr 12, 2009
 *      Author: Team
 */

#include "shares.h"

// qt
#include <QMessageBox>
#include <QUrl>
#include <QDesktopServices>
#include <QProcess>
#include <QDebug>

// local
#include "qt/widgets/share_participants.h"
#include "qt/client/client_controller.h"


Shares::Shares( QWidget* parent )
    : Panel( parent )
    , init_( false )
{
    ui_.setupUi( this );

    connect( ui_.create, SIGNAL( clicked(bool) ),
             this,       SLOT( onCreateShareClicked() ) );

    connect( ui_.listWidget, SIGNAL( itemDoubleClicked( QListWidgetItem* ) ),
             this,           SLOT( onItemDoubleClicked( QListWidgetItem* ) ) );

    connect( ClientController::instance(),
                   SIGNAL( addedPrivateShare( const QString& ) ),
             this, SLOT( onAddedPrivateShare( const QString& ) ) );
}

Shares::~Shares()
{
}


void Shares::setActive( bool b )
{
    if ( b && !init_ )
    {
        init();
    }
}

void Shares::reset()
{
    // clear the list of share
    /*QList<QLabel*> shares = ui_.sharesScrollArea->findChildren<QLabel*>();
    while( !shares.isEmpty() )
    {
        delete shares.takeLast();
    }*/

    ui_.listWidget->clear();

    ui_.shareNameLineEdit->setText( tr( "Enter share name" ) );

    init_ = false;
}

void Shares::onCreateShareClicked()
{
    // 1 - choose share name
    // 2 - choose admin contacts
    // 3 - choose ro contacts
    // 4 - submit
    if ( ui_.shareNameLineEdit->text().isEmpty() ||
        ui_.shareNameLineEdit->text() == tr( "Enter share name" ) )
    {
        QMessageBox::warning( this,
                              tr( "Problem!" ),
                              tr( "Please type a valid name for the share." )
                            );
        return;
    }
    const QString share_name = ui_.shareNameLineEdit->text().trimmed();

    QStringList admin_set;
    ShareParticipantsChoice spc_admin(this, tr("Administrators"), &admin_set);
    int n = spc_admin.exec();

    QStringList db_contacts = ClientController::instance()->contactsNames();
    foreach ( const QString& s, admin_set )
    {
        db_contacts.removeAll( s );
    }


    QStringList ro_set(admin_set);
    if ( db_contacts.size() > 0 ) {
      ShareParticipantsChoice spc_ro(this, tr("Read Onlys"), &ro_set);
      n = spc_ro.exec();
    } else {
      ro_set.clear();
    }

    if ( ro_set.size() > 0 || admin_set.size() > 0 )
    {
        if ( ClientController::instance()->
                                createShare( share_name,
                                             admin_set,
                                             ro_set ) )
        {
            addShare( share_name );
            ui_.shareNameLineEdit->clear();
        } else {
            QMessageBox::warning( this,
                              tr( "Problem!" ),
                              tr( "There was an issue creating this share." )
                            );
        }
    } else {
        QMessageBox::warning( this,
                              tr( "Problem!" ),
                              tr( "Please select some contacts for the share." )
                            );
    }
}

void Shares::onItemDoubleClicked( QListWidgetItem* item )
{
    qDebug() << "Shares::onItemDoubleClicked:" << item->text();
    QDir dir = ClientController::instance()->shareDirRoot( item->text() );

    //QDesktopServices::openUrl( QUrl( dir.absolutePath() ) );

#ifdef MAIDSAFE_WIN32
    // %SystemRoot%\explorer.exe /e /root,M:\Shares\Private\Share 1

    // TODO: doesn't like spaces in the name
    QString app( "explorer.exe" );
    QStringList args;
    args <<  "/e" << QString( "/root,%1" ).arg( dir.absolutePath().replace( "/", "\\" ) );

    qDebug() << "explore:" << app << args;

    if ( !QProcess::startDetached( app, args ) )
    {
        qWarning() << "PerpetualData::failed to start"
                   << app
                   << "with args"
                   << args;
    }

#else
    // nautilus FuseHomeDir()/Shares/Private/"name"
    QString app( "nautilus" );
    QStringList args;
    args <<  QString( "%1" ).arg( dir.absolutePath() );

    qDebug() << "explore:" << app << args;

    if ( !QProcess::startDetached( app, args ) )
    {
        qWarning() << "PerpetualData::failed to start"
                   << app
                   << "with args"
                   << args;
    }

#endif

}

void Shares::init()
{
    if ( init_ )
        return;

    const QString username = ClientController::instance()->publicUsername();
    if ( !username.isEmpty() )
    {
        Share share1( "1" );
        Share share2( "2" );
        share2 = share1;

        const ShareList shares = ClientController::instance()->shares();
        foreach( const Share& share, shares )
        {
            addShare( share.name() );
        }

        // only init if had public name
        init_ = true;
    }
}

void Shares::addShare( const QString& shareName )
{
    ui_.listWidget->addItem( shareName );
}

void Shares::onAddedPrivateShare(const QString &name) {
  qDebug() << "Shares::onAddedPrivateShare()";
  addShare( name );
}

