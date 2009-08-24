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
 *  Created on: May 21, 2009
 *      Author: Team
 */

#ifndef QT_CLIENT_PROFILE_H_
#define QT_CLIENT_PROFILE_H_

// core
#include "maidsafe/client/contacts.h"

// qt
#include <QString>
#include <QDateTime>
#include <QLocale>

//! A Contact's profile
/*!

*/
class Profile
{
public:
    enum Gender
    {
        UNSPECIFIED,
        MALE,
        FEMALE
    };

    Profile();
    ~Profile();

    QString pub_key;
    QString full_name;
    QString office_phone;
    QDate birthday;
    Gender gender;
    QLocale::Language language;
    QLocale::Country country;
    QString city;
    //! waht is
    char confirmed;
    //! ?
    int rank;
    //! Last time contact was seen online (?)
    QDateTime last_contact;

    // \TODO make accessors on maidsafe::Contacts const
    static Profile fromContact( /*const */ maidsafe::Contact& mc );
};


#endif // QT_CLIENT_PROFILE_H_
