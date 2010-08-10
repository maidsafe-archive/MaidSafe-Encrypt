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

#include "qt/client/profile.h"

// qt
#include <QApplication>
#include <QDebug>

Profile::Profile()
    : gender(UNSPECIFIED), language(QLocale::English),
      country(QLocale::AnyCountry) { }

Profile::~Profile() { }

// static
Profile Profile::fromContact(const QString &pubName) {
  return Profile();
}
