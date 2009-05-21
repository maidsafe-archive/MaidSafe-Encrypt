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

#include "contact_detail.h"

// qt
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QPicture>


// local
#include "qt/client/client_controller.h"
#include "qt/client/contact.h"


ContactDetail::ContactDetail( Contact* contact,
    QWidget* parent )
    : QWidget( parent )
    , contact_( contact )
{
    ui_.setupUi( this );

    ui_.user_name->setText( contact_->publicName() );

    if ( contact_->presence() == Presence::INVALID )
    {
        ui_.user_status->setPixmap( QPixmap(":/icons/16/question") );
    }
    else
    {
        ui_.user_status->setPixmap( QPixmap(":/icons/16/tick") );
    }

//    QPicture  pic;
//    if (status_ == 'C') {
//      pic.load( "/home/Smer/svn/working/trunk/build/Linux/tick.png" );
//    } else if (status == 'U') {
//      pic.load( "/home/Smer/svn/working/trunk/build/Linux/question.png" );
//    }
//
//    ui_.user_status->setPicture(pic);
//    std::string s("");
//    s[0] = status_;
//    QString qstatus(s);
//    ui_.user_status->setText(qstatus);

    // \TODO check status and update status icon tick|question

    connect( ui_.user_actions, SIGNAL( clicked(bool) ),
             this,             SLOT( onUserActionsClicked() ) );

    connect( ui_.delete_user, SIGNAL( clicked(bool) ),
             this,            SLOT( onDeleteUserClicked() ) );

    connect( ui_.view_profile, SIGNAL( clicked(bool) ),
             this,             SLOT( onViewProfileClicked() ) );

    connect( ui_.send_message, SIGNAL( clicked(bool) ),
             this,             SLOT( onSendMessageClicked() ) );

    connect( ui_.share_file, SIGNAL( clicked(bool) ),
             this,           SLOT( onFileSendClicked() ) );
}

ContactDetail::~ContactDetail()
{
}

QString ContactDetail::getUser() const
{
    return contact_->publicName();
}

void ContactDetail::onUserActionsClicked()
{
    // \TODO find out what should be here
}

void ContactDetail::onViewProfileClicked()
{
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

void ContactDetail::onDeleteUserClicked()
{
    if ( ClientController::instance()->removeContact( contact_->publicName() ) )
    {
        // delete ourselves.  delayed delete as deleting yourself inside
        // a slot makes bad things happen
        deleteLater();
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


void ContactDetail::onSendMessageClicked()
{
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

void ContactDetail::onFileSendClicked()
{
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


