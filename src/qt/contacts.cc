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
 *  Created on: Apr 10, 2009
 *      Author: Team
 */

#include "contacts.h"

// qt
#include <QMessageBox>
#include <QInputDialog>

//
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"
#include "qt/contact_detail.h"


Contacts::Contacts( QWidget* parent )
    : Panel( parent )
    , init_( false )
{
    ui_.setupUi( this );

    connect( ui_.add,    SIGNAL( clicked(bool) ),
             this,       SLOT( onAddContactClicked() ) );

    connect( ui_.clear,  SIGNAL( clicked(bool) ),
             this,       SLOT( onClearSearchClicked() ) );

    connect( ui_.contactLineEdit, SIGNAL(editingFinished()),
             this,       SLOT(onLostFocus()));
}

void Contacts::onLostFocus()
{
    if (ui_.contactLineEdit->text() == "")
    {
        ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
    }
}

void Contacts::setActive( bool b )
{
    if ( b && !init_ )
    {
        const QString username = QString::fromStdString(
            maidsafe::SessionSingleton::getInstance()->PublicUsername() );

        std::vector<maidsafe::Contacts> contact_list;
        const int n = maidsafe::ClientController::getInstance()
                        ->ContactList( &contact_list, "" );
        if ( n == 0)
        {
            for ( unsigned int i = 0; i < contact_list.size(); ++i )
            {
                maidsafe::Contacts c = contact_list[i];
                addContact( QString::fromStdString( c.PublicName() ), c.Confirmed() );
            }
        }

        init_ = true;
    }
}

void Contacts::reset()
{
    // clear the list of contacts
    QList<ContactDetail*> contacts = findChildren<ContactDetail*>();
    while( !contacts.isEmpty() )
    {
        delete contacts.takeLast();
    }

    init_ = false;
}

Contacts::~Contacts()
{
}

void Contacts::onAddContactClicked()
{
    const QString contact_name = ui_.contactLineEdit->text().trimmed();

    // TODO add contact should be disabled if name isn't valid

    if (ui_.contactLineEdit->text() == "Search (or add) contacts") {
      QMessageBox::warning( this,
                          tr( "Problem!" ),
                          tr( "Please enter a valid username." )
                        );
      return;
    }

    const int n = maidsafe::ClientController::getInstance()->
                    AddContact( contact_name.toStdString() );
    printf("Addition result: %i\n", n);
    switch (n)
    {
    case 0:
    {
        addContact( contact_name, 'U' );
        ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
        break;
    }
    case -221:
    {
        QMessageBox::warning( this,
                          tr( "Problem!" ),
                          tr( "Error adding contact. Username doesn't exist." )
                        );
        break;
    }
    default:
    {
        // unknown error
        break;
    }
    }

    // debug...
//    addContact( contact_name );
}

void Contacts::onClearSearchClicked()
{
    ui_.contactLineEdit->clear();
    ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
}

void Contacts::addContact( const QString& contact_name, const char &status )
{
    ContactDetail* detail = new ContactDetail( contact_name, status, NULL );
    ui_.contacts_layout->addWidget( detail );
}

