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
#include <QFileDialog>
#include <QDebug>

//
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"

// local
#include "qt/client/client_controller.h"


Contacts::Contacts( QWidget* parent )
    : Panel( parent )
    , init_( false )
{
    ui_.setupUi( this );
    ui_.add->setAutoDefault(true);
    ui_.clear->setAutoDefault(true);
    ui_.delete_user->setAutoDefault(true);
    ui_.view_profile->setAutoDefault(true);
    ui_.send_message->setAutoDefault(true);
    ui_.share_file->setAutoDefault(true);

    connect( ui_.add,    SIGNAL( clicked(bool) ),
             this,       SLOT( onAddContactClicked() ) );

    // To enable the return event on the textbox
    connect( ui_.contactLineEdit,    SIGNAL( returnPressed() ),
             this,                   SLOT( onAddContactClicked() ) );

    connect( ui_.clear,  SIGNAL( clicked(bool) ),
             this,       SLOT( onClearSearchClicked() ) );

    connect( ui_.contactLineEdit, SIGNAL(editingFinished()),
             this,       SLOT(onLostFocus()));


    // buttons
    connect( ui_.delete_user, SIGNAL( clicked(bool) ),
             this,            SLOT( onDeleteUserClicked() ) );

    connect( ui_.view_profile, SIGNAL( clicked(bool) ),
             this,             SLOT( onViewProfileClicked() ) );

    connect( ui_.send_message, SIGNAL( clicked(bool) ),
             this,             SLOT( onSendMessageClicked() ) );

    connect( ui_.share_file, SIGNAL( clicked(bool) ),
             this,           SLOT( onFileSendClicked() ) );


    connect( ClientController::instance(),
                   SIGNAL( addedContact( const QString& ) ),
             this, SLOT( onAddedContact( const QString& ) ) );

    connect( ui_.listWidget, SIGNAL( itemDoubleClicked( QListWidgetItem* ) ),
             this,           SLOT( onItemDoubleClicked( QListWidgetItem* ) ) );

    connect( ui_.listWidget, SIGNAL( itemSelectionChanged() ),
             this,           SLOT( onItemSelectionChanged() ) );
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
    ui_.listWidget->clear();

    qDeleteAll( contacts_ );
    contacts_.clear();

    init_ = false;

    onItemSelectionChanged();
}

Contacts::~Contacts()
{
}

void Contacts::onItemDoubleClicked( QListWidgetItem* item )
{
    qDebug() << "Contacts::onItemDoubleClicked:" << item->text();

    onSendMessageClicked();
}

void Contacts::onItemSelectionChanged()
{
    const bool enable = currentContact() != NULL;

    ui_.delete_user->setEnabled( enable );
    ui_.view_profile->setEnabled( enable );
    ui_.send_message->setEnabled( enable );
    ui_.share_file->setEnabled( enable );
}


void Contacts::onAddContactClicked()
{
    const QString contact_name = ui_.contactLineEdit->text().trimmed();

    if (ui_.contactLineEdit->text().trimmed().toStdString() ==
        maidsafe::SessionSingleton::getInstance()->PublicUsername())
    {
      QMessageBox::warning( this,
                            tr( "Recommendation" ),
                            tr( "Try not to add yourself as a contact." )
                          );
      return;
    }

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

    QPixmap pixmap;
    if ( contact->presence() == Presence::INVALID )
    {
        pixmap = QPixmap(":/icons/16/question");
    }
    else
    {
        pixmap = QPixmap(":/icons/16/tick");
    }

    QListWidgetItem* item = new QListWidgetItem;
    item->setText( contact->publicName() );
    item->setIcon( pixmap );

    ui_.listWidget->addItem( item );
}

void Contacts::onViewProfileClicked()
{
    Contact* contact_ = currentContact();
    if ( !contact_ )
        return;

    // \TODO QString/html/%1,%2 etc - inline view of details?
    QString details("Public Username: ");
    details += contact_->publicName() + "\n";
    details += "Full Name: " +    contact_->profile().full_name + "\n";
    details += "Office Phone: " + contact_->profile().office_phone + "\n";
    details += "Birthday: " +     contact_->profile().birthday.toString() + "\n";
    details += "Gender: " +       QString(contact_->profile().gender == Profile::MALE ? "M" : "F") + "\n";
    details += "Language: " +     QLocale::languageToString( contact_->profile().language ) + "\n";
    details += "City: " +         contact_->profile().city + "\n";
    details += "Country: " +      QLocale::countryToString( contact_->profile().country ) + "\n";

    QMessageBox::information( this,
                              tr( "Contact Details" ),
                              details
                            );
}

void Contacts::onDeleteUserClicked()
{
    Contact* contact_ = currentContact();
    if ( !contact_ )
        return;

    if ( ClientController::instance()->removeContact( contact_->publicName() ) )
    {
        QList<QListWidgetItem*> items =
            ui_.listWidget->findItems( contact_->publicName(), Qt::MatchCaseSensitive );

        contacts_.removeAll( contact_ );
        delete contact_;

        foreach( QListWidgetItem* item, items )
        {
            ui_.listWidget->removeItemWidget( item );
        }

    }
    else
    {
        QMessageBox::warning( this,
                              tr( "Error" ),
                              QString( tr( "Error removing user: %1" ) )
                             .arg( contact_->publicName() )
                            );
    }
}


void Contacts::onSendMessageClicked()
{
    Contact* contact_ = currentContact();
    if ( !contact_ )
        return;

    bool ok;
    QString text = QInputDialog::getText( this,
                                          tr( "Messsage entry" ),
                                          tr( "Please enter a quick message:" ),
                                          QLineEdit::Normal,
                                          QString(),
                                          &ok);
    if ( !ok || text.isEmpty() )
    {
        return;
    }

    if ( ClientController::instance()->sendInstantMessage( text, contact_->publicName() ) )
    {
        QMessageBox::information( this,
                                  tr( "Success!"),
                                  tr( "Message sent to: %1" ).arg( contact_->publicName() )
                                );
    }
    else
    {
        const QString msg = tr( "Error sending a message to: %1")
                                .arg( contact_->publicName() );

        QMessageBox::warning( this,
                              tr( "Error" ),
                              msg
                             );
     }
}

void Contacts::onFileSendClicked()
{
    Contact* contact_ = currentContact();
    if ( !contact_ )
        return;

    // choose a file
    QFileDialog dialog( this, tr( "Select file" ) );
    dialog.setFileMode( QFileDialog::ExistingFile );
    dialog.setViewMode( QFileDialog::Detail );
    // starting directoty should be the maidafe one.
    // TODO: restrict file dialog to maidsafe directories
#ifdef __WIN32__
    // TODO(richard): Change to make sure the correct letter is passed.
    dialog.setDirectory( "M:\\" );
#else
    file_system::FileSystem fs;
    dialog.setDirectory( QString::fromStdString( fs.MaidsafeFuseDir() ) );
#endif
    dialog.setNameFilter( tr( "Any file (*)" ) );

    if ( !dialog.exec() )
    {
        return;
    }

    const QStringList fileNames = dialog.selectedFiles();
    if ( fileNames.isEmpty() )
    {
        return;
    }

    const QString filename = fileNames.at(0);

    // accompanying message
    bool ok;
    QString text = QInputDialog::getText( this,
                                         tr( "Messsage entry" ),
                                         tr( "Please Enter a message if you "
                                             "wish to accompany the file(s)" ),
                                         QLineEdit::Normal,
                                         QString(),
                                         &ok );
    if ( !ok || text.isEmpty() )
    {
        // TODO default message?
        return;
    }

    if ( ClientController::instance()->sendInstantFile( filename,
                                                        text,
                                                        contact_->publicName() ) )
    {
        QMessageBox::information( this,
                                  tr( "File Sent"),
                                  tr( "Success sending file: %1" )
                                  .arg( filename )
                                );
    }
    else
    {
        const QString msg = tr( "There was an error sending the file: %1")
                           .arg( filename );

        QMessageBox::warning( this,
                              tr( "File Not Sent" ),
                              msg
                            );
    }
}


Contact* Contacts::currentContact()
{
    if ( !ui_.listWidget->currentItem() )
        return NULL;

    const QString name = ui_.listWidget->currentItem()->text();

    foreach( Contact* contact, contacts_ )
    {
        if ( contact->publicName() == name )
            return contact;
    }

    return NULL;
}

void Contacts::onAddedContact(const QString &name) {
  qDebug() << "Contacts::onAddedContact()";
  addContact( new Contact( name ) );
}
