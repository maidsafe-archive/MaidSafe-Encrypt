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

#include "qt/client/contact.h"

Contact::Contact(const QString& publicName, QObject* parent)
    : QObject(parent), publicName_(publicName), presence_(), profile_() { }

Contact::~Contact() { }

QString Contact::publicName() const {
  return publicName_;
}

const Presence& Contact::presence() const {
  return presence_;
}

void Contact::setPresence(const Presence& p) {
  if (p != presence_) {
    presence_ = p;
    emit presenceChanged();
  }
}

const Profile& Contact::profile() const {
  return profile_;
}

void Contact::setProfile(const Profile& p) {
//  if (p != profile_)
//  {
      profile_ = p;
      emit profileChanged();
//  }
}

// static
Contact* Contact::fromContact(const QString &pubName) {
  Contact* contact = new Contact(pubName);
  contact->setPresence(Presence::fromContact(pubName));
  contact->setProfile(Profile::fromContact(pubName));

  return contact;
}
