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
 *  Created on: Mar 26, 2009
 *      Author: Team
 */

#include <QListWidget>
#include <QListWidgetItem>
#include <Qt>

#include "share_participants.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"
#include "fs/filesystem.h"

ShareParticipantsChoice::ShareParticipantsChoice(QWidget* parent,
    const std::string &title, std::set<std::string> *usernames)
    : usernames_(usernames) {
  ui_.setupUi(this);

  std::set<std::string> db_contacts;
  getDbContacts(&db_contacts);

  std::set<std::string>::iterator it;
  for (it = usernames->begin(); it != usernames->end(); ++it) {
    std::string s(*it);
    db_contacts.erase(s);
  }

  ui_.listWidget->setSelectionMode(QAbstractItemView::MultiSelection);

  int row = 1;
  for (it = db_contacts.begin(); it != db_contacts.end(); ++it) {
    QListWidgetItem* item = new QListWidgetItem(ui_.listWidget,
      QListWidgetItem::UserType);
    std::string s(*it);
    item->setText(s.c_str());
    item->setCheckState(Qt::Unchecked);
    ui_.listWidget->insertItem(row, item);
    row++;
  }

  ui_.label->setText(tr(title.c_str()));
}

ShareParticipantsChoice::~ShareParticipantsChoice() { }

void ShareParticipantsChoice::accept()
{
    usernames_->clear();
    for ( int i=0; i<ui_.listWidget->count(); ++i )
    {
        QListWidgetItem* item = ui_.listWidget->item( i );
        if ( item->checkState() == Qt::Checked )
        {
            usernames_->insert( item->text().toStdString() );
        }
    }
    done(0);
}

int ShareParticipantsChoice::getDbContacts(std::set<std::string> *db_contacts) {
  std::vector<maidsafe::Contacts> contact_list;
  int n =
    maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
  if (n != 0) {
#ifdef DEBUG
    printf("No contact list in ShareParticipantsChoice::getDbContacts %i.\n",
      n);
#endif
    return n;
  }

  for (int g = 0; g < contact_list.size(); g++) {
    db_contacts->insert(contact_list[g].PublicName());
  }

  return 0;
}
