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
 *  Created on: Mar 19, 2009
 *      Author: Team
 */

#ifndef QT_WIDGETS_CONTACT_LIST_WIDGET_H_
#define QT_WIDGETS_CONTACT_LIST_WIDGET_H_

// qt
#include <QWidget>

// generated


//! Custom widget that displays a list of contacts
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
class ContactListWidget : public QWidget
{
    Q_OBJECT

public:
    /*!
        \param user public name of user
    */
    ContactListWidget( QWidget* parent = 0 );
    virtual ~ContactListWidget();



private slots:


private:

};

#endif // QT_WIDGETS_CONTACT_LIST_WIDGET_H_

