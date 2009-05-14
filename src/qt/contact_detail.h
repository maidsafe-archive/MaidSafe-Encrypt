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

#ifndef QT_CONTACT_DETAIL_H_
#define QT_CONTACT_DETAIL_H_

// qt
#include <QWidget>

// generated
#include "ui_user_contacts_item.h"

//! Custom widget that displays a user's contact details
/*!
    Displays:
     - status
     - user name

    Allows you to:
     - view profile
     - delete contact
     - send message
     - share files
*/
class ContactDetail : public QWidget
{
    Q_OBJECT

public:
    /*!
        \param user public name of user
    */
    ContactDetail( const QString& user_name,
      const char &status, QWidget* parent = 0 );
    virtual ~ContactDetail();

    //! Get public name of this user.
    QString getUser() const;

private slots:
    void onUserActionsClicked();
    //! If delete is successful this widget will delete itself
    void onDeleteUserClicked();
    void onViewProfileClicked();
    void onSendMessageClicked();
    void onFileSendClicked();

private:
    Ui::ContactsItem ui_;
    QString user_name_;
    char status_;
};

#endif // QT_CONTACT_DETAIL_H_

