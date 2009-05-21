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

#ifndef QT_CONTACTS_H_
#define QT_CONTACTS_H_

// local
#include "panel.h"
#include "qt/client/contact.h"

// generated
#include "ui_user_contacts_panel.h"

//! Custom widget that displays contacts
/*!
    Displays a list of contacts and lets you add them.
*/
class Contacts : public Panel
{
    Q_OBJECT
public:
    Contacts( QWidget* parent = 0 );
    virtual ~Contacts();

    virtual void setActive( bool );
    virtual void reset();

private slots:
    void onAddContactClicked();
    void onClearSearchClicked();
    void onLostFocus();

    void onItemDoubleClicked( QListWidgetItem* );
    void onItemSelectionChanged();

    void onDeleteUserClicked();
    void onViewProfileClicked();
    void onSendMessageClicked();
    void onFileSendClicked();

private:
    //! Add a new entry in the listing of contacts
    void addContact( Contact* );
    Ui::ContactsPage ui_;
    bool init_;
    ContactList contacts_;

    Contact* currentContact();
};

#endif // QT_CONTACTS_H_
