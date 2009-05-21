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
 *  Created on: Apr 09, 2009
 *      Author: Team
 */

#include "user_panels.h"

// qt
#include <QDebug>
#include <QLabel>
#include <QValidator>


// local
#include "panel.h"
#include "messages.h"
#include "shares.h"
#include "contacts.h"
#include "public_username.h"
#include "qt/client/client_controller.h"

namespace
{


}

UserPanels::UserPanels( QWidget* parent )
    : QWidget( parent )
    , messages_( NULL )
    , shares_( NULL )
    , contacts_( NULL )
    , panel_( -1 )
{
    ui_.setupUi( this );

    connect( ui_.listWidget, SIGNAL( currentRowChanged(int) ),
             this,           SLOT( onCurrentRowChanged(int) ) );

    ui_.stackedWidget->addWidget( contacts_ = new Contacts );
    ui_.stackedWidget->addWidget( shares_   = new Shares );
    ui_.stackedWidget->addWidget( messages_ = new Messages );
    ui_.stackedWidget->addWidget( new QLabel( "settings" ) );
    ui_.stackedWidget->addWidget( new QLabel( "activities" ) );
    ui_.stackedWidget->addWidget( new QLabel( "help" ) );
    ui_.stackedWidget->addWidget( public_username_ = new PublicUsername );


    Q_ASSERT( messages_ );
    Q_ASSERT( shares_ );
    Q_ASSERT( contacts_ );

    connect( messages_, SIGNAL( messageReceived() ),
             this,      SLOT( onMessageReceived() ) );

    connect( public_username_, SIGNAL( complete() ),
             this,      SLOT( onPublicUsernameChosen() ) );
}

UserPanels::~UserPanels()
{}

void UserPanels::onMessageReceived()
{
    // TODO set message in the status bar
}

void UserPanels::onPublicUsernameChosen()
{
    ui_.listWidget->setEnabled( true );
    onCurrentRowChanged( ui_.stackedWidget->indexOf( contacts_ ) );
}

void UserPanels::onCurrentRowChanged( int i )
{
    // change the active panel
#ifdef DEBUG
    printf("Current: %i -- Next: %i\n", panel_, i);
#endif
    activatePanel( panel_, false );
    panel_ = i;
    activatePanel( panel_, true );

    ui_.stackedWidget->setCurrentIndex( i );
}

void UserPanels::activatePanel( int i, bool active )
{
    if ( i == -1 )
        return;

    if ( Panel* panel = dynamic_cast<Panel*>( ui_.stackedWidget->widget( i ) ) )
    {
        panel->setActive( active );
    }
}

void UserPanels::setActive( bool active )
{
    if ( active )
    {
        const QString username = ClientController::instance()->publicUsername();

        qDebug() << "UserPanels::setActive - public name:" << username;

        if ( username.isEmpty() )
        {
            ui_.listWidget->setEnabled( false );
            onCurrentRowChanged( ui_.stackedWidget->indexOf( public_username_ ) );
        }
        else
        {
            onPublicUsernameChosen();
        }
    }
    else
    {
        QList<Panel*> panels = findChildren<Panel*>();
        foreach( Panel* panel, panels )
        {
            panel->reset();
        }
    }
}

