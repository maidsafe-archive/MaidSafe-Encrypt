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
 *  Created on: May 19, 2009
 *      Author: Team
 */

#include "perpetual_data.h"

// qt
#include <QDebug>
#include <QMessageBox>
#include <QProcess>


// local
#include "widgets/login.h"
#include "widgets/create_user.h"
#include "widgets/progress.h"
#include "widgets/user_panels.h"

#include "client/client_controller.h"
#include "client/mount_thread.h"
#include "client/create_user_thread.h"

// generated
#include "ui_about.h"


PerpetualData::PerpetualData( QWidget* parent )
    : QMainWindow( parent )
    , login_( NULL )
    , create_( NULL )
    , state_( LOGIN )
    , quitting_( false )
{
    setAttribute( Qt::WA_DeleteOnClose, false );
    setWindowIcon( QPixmap( ":/icons/16/globe" ) );

    ui_.setupUi( this );

    statusBar()->show();
    //statusBar()->showMessage( "Status" );

    createActions();

    createMenus();

    // create the main screens
    login_ = new Login;
    create_ = new CreateUser;
    progressPage_ = new Progress;
    userPanels_ = new UserPanels;

    ui_.stackedWidget->addWidget( login_ );
    ui_.stackedWidget->addWidget( create_ );
    ui_.stackedWidget->addWidget( progressPage_ );
    ui_.stackedWidget->addWidget( userPanels_ );

    setCentralWidget( ui_.stackedWidget );

    setState( LOGIN );
}

PerpetualData::~PerpetualData()
{
    onLogout();
}


void PerpetualData::createActions()
{
    // most of the actions have already been created for the menubar
    actions_[ QUIT ] = ui_.actionQuit;
    actions_[ LOGOUT ] = ui_.actionLogout;
    actions_[ FULLSCREEN ] = ui_.actionFullScreen;
    actions_[ ABOUT ] = ui_.actionAbout;

    actions_[ QUIT ]->setShortcut( Qt::ALT + Qt::Key_F4 );
    actions_[ FULLSCREEN ]->setShortcut( Qt::Key_F11 );

    connect( actions_[ QUIT ],   SIGNAL( triggered() ),
             this,               SLOT( onQuit() ) );
    connect( actions_[ LOGOUT ], SIGNAL( triggered() ),
             this,               SLOT( onLogout() ) );
    connect( actions_[ FULLSCREEN ], SIGNAL( toggled( bool ) ),
             this,              SLOT( onToggleFullScreen( bool ) ) );
    connect( actions_[ ABOUT ], SIGNAL( triggered() ),
             this,              SLOT( onAbout() ) );

}

void PerpetualData::createMenus()
{
#if defined(MAIDSAFE_WIN32)
    // an example of launching an extrernal application
    // path to application is stored in the action

    QAction* actionNotepad = new QAction( this );
    actionNotepad->setText( tr( "Notepad" ) );
    actionNotepad->setData( QVariant( "C:/Windows/System32/notepad.exe" ) );
    connect( actionNotepad, SIGNAL( triggered() ),
             this,          SLOT( onApplicationActionTriggered() ) );

    ui_.menuApplications->addAction( actionNotepad );
#endif
}

void PerpetualData::setState( State state )
{
    disconnect( login_, NULL, this, NULL );
    disconnect( create_, NULL, this, NULL );
    disconnect( progressPage_, NULL, this, NULL );
    disconnect( userPanels_, NULL, this, NULL );

    userPanels_->setActive( false );
    create_->reset();

    state_ = state;

    switch ( state_ )
    {
    case LOGIN:
    {
        ui_.stackedWidget->setCurrentWidget( login_ );
        login_->clearFields();
        connect( login_, SIGNAL( newUser() ),
                 this,   SLOT( onLoginNewUser() ) );
        connect( login_, SIGNAL( existingUser() ),
                 this,   SLOT( onLoginExistingUser() ) );
        break;
    }
    case SETUP_USER:
    {
        ui_.stackedWidget->setCurrentWidget( create_ );
        connect( create_, SIGNAL( complete() ),
                 this,    SLOT( onSetupNewUserComplete() ) );
        connect( create_, SIGNAL( cancelled() ),
                 this,    SLOT( onSetupNewUserCancelled() ) );
        break;
    }
    case CREATE_USER:
    {
        ui_.stackedWidget->setCurrentWidget( progressPage_ );
        progressPage_->setTitle( tr( "Creating User" ) );
        progressPage_->setProgressMessage(
                    tr( "Creating a user.  This may take some time..." ) );
        progressPage_->setError( false );
        progressPage_->setCanCancel( false ); // can't cancel it yet
        //connect( create_, SIGNAL( cancel() ),
        //         this,    SLOT( onCreateCancelled() ) );
        break;
    }
    case MOUNT_USER:
    {
        ui_.stackedWidget->setCurrentWidget( progressPage_ );
        progressPage_->setTitle( tr( "Mounting User" ) );
        progressPage_->setProgressMessage(
                                    tr( "Mounting user file system..." ) );
        progressPage_->setError( false );
        progressPage_->setCanCancel( false ); // can't cancel it yet
        //connect( create_, SIGNAL( cancel() ),
        //         this, SLOT( onMountCancelled() ) );
        break;
    }
    case LOGGED_IN:
    {
        ui_.stackedWidget->setCurrentWidget( userPanels_ );
        userPanels_->setActive( true );
        break;
    }
    case LOGGING_OUT:
    {
        ui_.stackedWidget->setCurrentWidget( progressPage_ );
        progressPage_->setTitle( tr( "Logging out" ) );
        progressPage_->setProgressMessage(
            tr( "Logging out. Removing all traces of you from the system." ) );
        progressPage_->setError( false );
        progressPage_->setCanCancel( false );
        break;
    }
    case FAILURE:
    {
        ui_.stackedWidget->setCurrentWidget( progressPage_ );
        progressPage_->setError( true );
        progressPage_->setCanCancel( false );
        connect( progressPage_, SIGNAL( ok() ),
                this,           SLOT( onFailureAcknowledged() ) );
        break;
    }
    default:
    {
        break;
    }
    }
}

void PerpetualData::onLoginExistingUser()
{
    qDebug() << "onLoginExistingUser";
    // existing user whose credentials have been verified
    // mount the file system..

#ifdef DEBUG
    qDebug() << "public name:" << ClientController::instance()->publicUsername();
#endif
    setState( MOUNT_USER );
    asyncMount();
}

void PerpetualData::onLoginNewUser()
{
    setState( SETUP_USER );
}

void PerpetualData::onSetupNewUserComplete()
{
    qDebug() << "onSetupNewUserComplete";
    // user has been successfully setup. can go ahead and create them

    setState( CREATE_USER );
    asyncCreateUser();
}

void PerpetualData::onSetupNewUserCancelled()
{
    // process was cancelled.  back to login.
    setState( LOGIN );
}

void PerpetualData::asyncMount()
{
    MountThread* mt = new MountThread( MountThread::MOUNT, this );
    connect( mt, SIGNAL( completed( bool ) ),
             this, SLOT( onMountCompleted( bool ) ) );

    mt->start();
}

void PerpetualData::asyncUnmount()
{
    MountThread* mt = new MountThread( MountThread::UNMOUNT, this );
    connect( mt, SIGNAL( completed( bool ) ),
             this, SLOT( onUnmountCompleted( bool ) ) );

    mt->start();
}

void PerpetualData::asyncCreateUser()
{
    CreateUserThread* cut = new CreateUserThread( login_->username(),
                                                  login_->pin(),
                                                  login_->password(),
                                                  this );

    connect( cut,  SIGNAL( completed( bool ) ),
             this, SLOT( onUserCreationCompleted( bool ) ) );

    cut->start();
}

void PerpetualData::onUserCreationCompleted( bool success )
{
    qDebug() << "PerpetualData::onUserCreationCompleted:" << success;

    if ( success )
    {
        asyncMount();
        setState( MOUNT_USER );
    }
    else
    {
        // \TODO more detail about the failure
        progressPage_->setProgressMessage( tr( "User creation failed" ) );
        setState( FAILURE );
    }
}

void PerpetualData::onMountCompleted( bool success )
{
    qDebug() << "PerpetualData::onMountCompleted:" << success;

    //
    if ( success )
    {
        statusBar()->showMessage( tr( "Logged in" ) );
        setState( LOGGED_IN );
    }
    else
    {
        // \TODO more detail about the failure
        progressPage_->setProgressMessage( tr( "Mount failed" ) );
        setState( FAILURE );
    }
}

void PerpetualData::onUnmountCompleted( bool success )
{
    qDebug() << "PerpetualData::onUnMountCompleted:" << success;

    if ( success )
    {
        // TODO disable the logout action
        statusBar()->showMessage( tr( "Logged out" ) );

        if ( !quitting_ )
            setState( LOGIN );
    }
    else
    {
        // \TODO more detail about the failure
        progressPage_->setProgressMessage( tr( "Unmount failed" ) );
        setState( FAILURE );
    }

    if ( quitting_ )
    {
        // \TODO what to do (or can we do) if logout failed but we're closing
        // the application?
        qApp->quit();
    }
}

void PerpetualData::onFailureAcknowledged()
{
    setState( LOGIN );
}

void PerpetualData::onLogout()
{
    if ( state_ != LOGGED_IN )
    {
        // if we're still to login we can't logout
        return;
    }

    asyncUnmount();
    setState( LOGGING_OUT );
}

void PerpetualData::onQuit()
{
    // \TODO: confirm quit if something in progress - chats etc
    if ( state_ != LOGGED_IN )
    {
        qApp->quit();
    }
    else
    {
        quitting_ = true;
        onLogout();
    }
}

void PerpetualData::onAbout()
{
    QDialog about;
    Ui::About ui;
    ui.setupUi( &about );

    about.exec();
}

void PerpetualData::onToggleFullScreen( bool b )
{
    if ( b )
    {
        showFullScreen();
    }
    else
    {
        showNormal();
    }
}

void PerpetualData::onApplicationActionTriggered()
{
    QAction* action = qobject_cast<QAction*>( sender() );
    if ( !action )
    {
        return;
    }

    const QString appPath = action->data().toString();
    if ( appPath.isEmpty() )
    {
        qWarning() << "PerpetualData::onApplicationActionTriggered: action"
                   << action->text()
                   << "did not specify app path";
    }

    if ( !QProcess::startDetached( appPath ) )
    {
        qWarning() << "PerpetualData::onApplicationActionTriggered: failed to start"
                   << appPath
                   << "for action"
                   << action->text();
    }
}

