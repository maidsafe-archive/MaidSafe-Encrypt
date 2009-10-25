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
 *  Created on: May 20, 2009
 *      Author: Team
 */

#include "qt/client/share.h"

Share::Share(const QString& name)
    : name_(name) { }

Share::~Share() { }

QString Share::name() const {
  return name_;
}

QStringList Share::participants(Permissions permission_flags) const {
  QStringList rv;
  UserPermissionMap::const_iterator I = participants_.constBegin();
  while (I != participants_.constEnd()) {
    if (I.value() == permission_flags) {
      rv.push_back(I.key());
    }
    ++I;
  }
  return rv;
}

Share::Permissions Share::permissions(const QString& user) const {
  if (!participants_.contains(user))
    return NONE;

  return participants_[user];
}

void Share::addParticipant(const QString& user, Permissions permissions) {
  participants_[user] = permissions;
}

