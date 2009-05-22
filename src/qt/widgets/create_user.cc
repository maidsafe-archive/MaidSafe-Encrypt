/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#include "create_user.h"

// qt
#include <QDebug>
#include <QValidator>
#include <QMessageBox>

// core
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/maidsafe-dht.h"
#include "protobuf/maidsafe_service_messages.pb.h"

// local


// generated
#include "create_page_welcome.h"
#include "create_page_license.h"
#include "create_page_options.h"
#include "create_page_complete.h"


CreateUser::CreateUser( QWidget* parent )
    : QWidget( parent )
{
    ui_.setupUi( this );

    connect( ui_.back, SIGNAL( clicked( bool ) ), this, SLOT( onBack() ) );
    connect( ui_.next, SIGNAL( clicked( bool ) ), this, SLOT( onNext() ) );
    connect( ui_.cancel, SIGNAL( clicked( bool ) ), this, SIGNAL( cancelled() ) );

    pages_ << new CreateWelcomePage;
    pages_ << new CreateLicensePage;
    pages_ << new CreateOptionsPage;
    pages_ << new CreateCompletePage;

    while ( ui_.stack->count() > 0 )
    {
        ui_.stack->removeWidget( ui_.stack->widget(0) );
    }

    foreach( QWizardPage* p, pages_ )
    {
        ui_.stack->addWidget( p );
    }

    reset();
}

CreateUser::~CreateUser()
{}


void CreateUser::reset()
{
    setCurrentPage( 0, 0 );
    foreach( QWizardPage* p, pages_ )
    {
        p->cleanupPage();
    }
}

void CreateUser::onBack()
{
    int index = ui_.stack->currentIndex();
    if ( index == 0 )
    {
        return;
    }

    setCurrentPage( --index, -1 );
}

void CreateUser::onNext()
{
    int index = ui_.stack->currentIndex();
    if ( index == pages_.size()-1 )
    {
        // go off and create the user...
        emit complete();
        return;
    }

    ++index;

    setCurrentPage( index, 1 );
}

void CreateUser::setCurrentPage( int index, int dir )
{
    disconnect( ui_.stack->currentWidget(), NULL,
                this, NULL );

    QWizardPage* page = pages_.at( ui_.stack->currentIndex() );
    if ( dir < 0 )
    {
        page->cleanupPage();
    }

    ui_.stack->setCurrentIndex( index );

    connect( ui_.stack->currentWidget(), SIGNAL( completeChanged() ),
             this,                       SLOT( onCompleteChanged() ) );

    page = pages_.at( ui_.stack->currentIndex() );

    ui_.label->setText( page->title() );
    ui_.back->setEnabled( index > 0 );
    ui_.next->setEnabled( page->isComplete() );
    ui_.next->setText( index == pages_.size()-1 ?
                       tr( "Finish" ) :
                       tr( "Next >" ) );
}

void CreateUser::onCompleteChanged()
{
    QWizardPage* page = pages_.at( ui_.stack->currentIndex() );
    ui_.next->setEnabled( page->isComplete() );
}


