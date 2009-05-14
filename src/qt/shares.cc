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
#include <QLabel>

//
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/clientcontroller.h"
#include "qt/share_participants.h"


Shares::Shares( QWidget* parent )
    : Panel( parent )
    , init_( false )
{
    ui_.setupUi( this );

    connect( ui_.create, SIGNAL( clicked(bool) ),
             this,       SLOT( onCreateShareClicked() ) );
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
    QList<QLabel*> shares = ui_.sharesScrollArea->findChildren<QLabel*>();
    while( !shares.isEmpty() )
    {
        delete shares.takeLast();
    }

    init_ = false;
}

void Shares::onCreateShareClicked()
{
  if (ui_.shareNameLineEdit->text() == tr("")) {
    QMessageBox::warning( this,
                          tr( "Problem!" ),
                          tr( "Please type a valid name for the share." )
                        );
    return;
  }

  std::string share_name = ui_.shareNameLineEdit->text().toStdString();

  std::set<std::string> admin_set;
  ShareParticipantsChoice spc_admin(this, "Administrators", &admin_set);
  int n = spc_admin.exec();

  std::set<std::string> ro_set(admin_set);
  ShareParticipantsChoice spc_ro(this, "Read Onlys", &ro_set);
  n = spc_ro.exec();

  if (ro_set.size() > 0 || admin_set.size() > 0) {
    n = maidsafe::ClientController::getInstance()->CreateNewShare(share_name,
      admin_set, ro_set);
    printf("Add share result: %i\n", n);
  }
    // 1 - choose share name
    // 2 - choose admin contacts
    // 3 - choose ro contacts
    // 4 - submit
/*
  // Share name
  boost::shared_ptr<std::set<std::string> > share_name_set;
  share_name_set.reset(new std::set<std::string>());
  ShareDialog share_name_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
    wxDefaultPosition, wxDefaultSize,
    wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 1, share_name_set.get());
  std::string share_name;
  std::set<std::string>::iterator it;
  if (share_name_dlg.ShowModal() == wxID_OK && share_name_set->size() == 1) {
    it = share_name_set->begin();
    share_name = *it;
#ifdef DEBUG
    printf("Share name: size(%i) value(%s)\n",
      share_name_set->size(), share_name.c_str());
#endif
  } else {
    return;
  }

  std::vector<maidsafe::Contacts> contact_list;
  int n =
    maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
  if (n != 0)
    return;
  // Admin Contacts
  // boost::shared_ptr<std::set<std::string> > admin_contact_set;
  std::set<std::string> admin_contact_set;
  // admin_contact_set.reset(new std::set<std::string>());
  for (unsigned int n = 0; n < contact_list.size(); n++) {
    admin_contact_set.insert(contact_list[n].PublicName());
  }
  ShareDialog admin_contact_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
    wxDefaultPosition, wxDefaultSize,
    wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 2, &admin_contact_set);
  if (admin_contact_dlg.ShowModal() == wxID_OK)
    printf("Share name size: %i\n", admin_contact_set.size());
  else
    return;

  // RO Contacts
  // boost::shared_ptr<std::set<std::string> > ro_contact_set;
  std::set<std::string> ro_contact_set;
  // ro_contact_set.reset(new std::set<std::string>());
  for (unsigned int n = 0; n < contact_list.size(); n++) {
    ro_contact_set.insert(contact_list[n].PublicName());
  }
  for (it = admin_contact_set.begin(); it != admin_contact_set.end(); it++)
    ro_contact_set.erase(*it);

  if (ro_contact_set.size() > 0) {
    ShareDialog ro_contact_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
      wxDefaultPosition, wxDefaultSize,
      wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 3, &ro_contact_set);
    if (ro_contact_dlg.ShowModal() == wxID_OK)
      printf("Share name size: %i\n", ro_contact_set.size());
    else
      return;
  }

  // Send to ClientController
  if (ro_contact_set.size() > 0 || admin_contact_set.size() > 0) {
    n = maidsafe::ClientController::getInstance()->CreateNewShare(share_name,
      admin_contact_set, ro_contact_set);
    printf("Add share result: %i\n", n);
    CreateControls();
  }
}
  */
}

void Shares::init()
{
    if ( init_ )
        return;

    if ( maidsafe::SessionSingleton::getInstance()->PublicUsername() != "" )
    {
        std::list<maidsafe::PrivateShare> ps_list;
        const int n = maidsafe::ClientController::getInstance()
                        ->GetShareList( &ps_list, "" );
        if ( n == 0 )
        {
            if ( ps_list.empty() )
            {
                // TODO message about there being no shares
            }
            while ( !ps_list.empty() )
            {
                maidsafe::PrivateShare ps = ps_list.front();
                ps_list.pop_front();
                QString shareName = QString::fromStdString( ps.Name() );
                addShare( shareName );
            }
        }

        // only init if had public name
        init_ = true;
    }
}

void Shares::addShare( const QString& shareName )
{
    //ShareDetail* detail = new ShareDetail( contact_name, NULL );
    ui_.shares_layout->addWidget( new QLabel( shareName ) );
}
