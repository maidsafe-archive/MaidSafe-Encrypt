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

//
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"


ContactDetail::ContactDetail( const QString& user_name, const char &status,
    QWidget* parent )
    : QWidget( parent )
    , user_name_( user_name ), status_(status)
{
    ui_.setupUi( this );

    ui_.user_name->setText( user_name_ );

    if (status_ == 'C') {
      ui_.user_status->setPixmap(QPixmap(":/icons/16/tick"));
    } else {
      ui_.user_status->setPixmap(QPixmap(":/icons/16/question"));
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
    return user_name_;
}

void ContactDetail::onUserActionsClicked()
{
    // \TODO find out what should be here
}

void ContactDetail::onViewProfileClicked()
{
    const std::string pub_name = user_name_.toStdString();
    std::vector<maidsafe::Contacts> c_list;
    const int n = maidsafe::ClientController::getInstance()->
                    ContactList( &c_list, pub_name );
    if ( n == 0 )
    {
        maidsafe::Contacts c = c_list[0];

        // \TODO QString/html/%1,%2 etc - inline view of details?
        std::string details("Public Username: ");
        details += pub_name + "\n";
        details += "Full Name: " + c.FullName() + "\n";
        details += "Office Phone: " + c.OfficePhone() + "\n";
        details += "Birthday: " + c.Birthday() + "\n";
        std::string gender;
        gender.resize(1, c.Gender());
        details += "Gender: " + gender + "\n";
        details += "Language: " + base::itos(c.Language()) + "\n";
        details += "City: " + c.City() + "\n";
        details += "Country: " + base::itos(c.Country()) + "\n";

        QMessageBox::information( this,
                                  tr( "Contact Details" ),
                                  QString::fromStdString( details )
                                );
    }
    else
    {
        QMessageBox::warning( this,
                              tr( "Error" ),
                              QString( tr( "Error finding details of user: %1" ) )
                             .arg( user_name_ )
                            );
    }
}

void ContactDetail::onDeleteUserClicked()
{
    const std::string pub_name = user_name_.toStdString();
    const int n = maidsafe::ClientController::getInstance()->
                    DeleteContact( pub_name );
    //  std::cout << "Deletion result: " << n << std::endl;
    if ( n == 0 )
    {
        // delete ourselves.  delayed delete as deleting yourself inside
        // a slot makes bad things happen
        deleteLater();
    }

    // debug...
//    deleteLater();
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

    const std::string pub_name = user_name_.toStdString();
    const std::string msg = text.toStdString();
    const int n = maidsafe::ClientController::getInstance()->
                    SendInstantMessage( msg, pub_name );
    if ( n == 0 )
    {
        QMessageBox::information( this,
                                  tr( "Success!"),
                                  tr( "Message sent to: %1" ).arg( user_name_ )
                                );
    }
    else
    {
        const QString msg = tr( "Error sending a message to: %1\n"
                                "Error code: %2")
                                .arg( user_name_ )
                                .arg( n );

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
    const std::string msg = text.toStdString();
    file_system::FileSystem fsys;
    std::string rel_filename( fsys.MakeRelativeMSPath( filename.toStdString() ) );
    const std::string pub_name = user_name_.toStdString();

#ifdef __WIN32__
    rel_filename.erase( 0, 2 );
#endif
    printf( "Before Tidy Path: %s\n", rel_filename.c_str() );
    rel_filename = base::TidyPath( rel_filename );
    printf( "Tidy Path: %s\n", rel_filename.c_str() );
    const int n = maidsafe::ClientController::getInstance()->
                    SendInstantFile( &rel_filename, msg, pub_name );

    if ( n == 0 )
    {
        QMessageBox::information( this,
                                  tr( "File Sent"),
                                  tr( "Success sending file: %1" )
                                  .arg( filename )
                                );
    }
    else
    {
        const QString msg = tr( "There was an error sending the file: %1\n"
                                "Error code: %2")
                           .arg( filename )
                           .arg( n );

        QMessageBox::warning( this,
                              tr( "File Not Sent" ),
                              msg
                            );
    }
}


