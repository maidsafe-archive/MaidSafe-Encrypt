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
 *  Created on: May 18, 2009
 *      Author: Team
 */

#ifndef QT_CLIENT_CONTACT_H_
#define QT_CLIENT_CONTACT_H_

// qt
#include <QObject>
#include <QList>

// local
#include "presence.h"
#include "profile.h"


class Contact : public QObject
{
    Q_OBJECT
public:
    Contact( const QString& publicName, QObject* parent = NULL );
    virtual ~Contact();

    QString publicName() const;

    const Presence& presence() const;
    void setPresence( const Presence& );

    const Profile& profile() const;
    void setProfile( const Profile& );

    // \TODO make accessors on maidsafe::Contacts const
    static Contact* fromContact( /*const */maidsafe::Contact& mc );

signals:
    //! This user's presence has changed.
    void presenceChanged();
    //! The user's information has changed
    void profileChanged();

private:
    QString publicName_;
    Presence presence_;
    Profile profile_;
};

typedef QList<Contact*> ContactList;

#endif // QT_CLIENT_CONTACT_H_
