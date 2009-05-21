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
#include <QDebug>

//
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"
#include "qt/widgets/contact_detail.h"

// local
#include "qt/client/client_controller.h"


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
    if ( ui_.contactLineEdit->text().isEmpty() )
    {
        ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
    }
}

void Contacts::setActive( bool b )
{
    if ( b && !init_ )
    {
        ContactList contact_list = ClientController::instance()->contacts();
        foreach ( Contact* contact, contact_list )
        {
            addContact( contact );
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

    qDeleteAll( contacts_ );
    contacts_.clear();

    init_ = false;
}

Contacts::~Contacts()
{
}

void Contacts::onAddContactClicked()
{
    const QString contact_name = ui_.contactLineEdit->text().trimmed();

    // TODO add contact should be disabled if name isn't valid

    if ( ui_.contactLineEdit->text() == "Search (or add) contacts" )
    {
        QMessageBox::warning( this,
                              tr( "Problem!" ),
                              tr( "Please enter a valid username." )
                            );
        return;
    }


    if ( ClientController::instance()->addContact( contact_name ) )
    {
        addContact( new Contact( contact_name ) );
        ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
    }
    else
    {
        QMessageBox::warning( this,
                          tr( "Problem!" ),
                          tr( "Error adding contact. Username doesn't exist." )
                        );
    }
}

void Contacts::onClearSearchClicked()
{
    ui_.contactLineEdit->clear();
    ui_.contactLineEdit->setText( tr( "Search (or add) contacts" ) );
}

void Contacts::addContact( Contact* contact )
{
    contacts_.push_back( contact );
    ContactDetail* detail = new ContactDetail( contact, NULL );
    ui_.contacts_layout->addWidget( detail );
}

