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

#ifndef QT_CLIENT_SHARE_H_
#define QT_CLIENT_SHARE_H_

// qt
#include <QObject>
#include <QMap>
#include <QList>
#include <QFlags>
#include <QStringList>

#include "maidsafe/lifestuff/client/contact.h"

// Representation of a Share
/*!
    Holds information about a Share:
     - name
     - who's in it (public usernames)
     - what their permissions are (READ and/or WRITE)
*/
class Share {
 public:
  explicit Share(const QString& name);
  virtual ~Share();

  // The share name.
  QString name() const;

  enum Permission {
    NONE   =      0,
    READ   = 1 << 0,
    WRITE  = 1 << 1
  };

  Q_DECLARE_FLAGS(Permissions, Permission)

  // returns participants whose permissions exactly match
  QStringList participants(Permissions permission_flags) const;

  // returns permissions of \a user
  Permissions permissions(const QString& publicUsername) const;

  // add (or modify) a user's permissions
  void addParticipant(const QString& publicUsername,
                      Permissions permissions);

 private:
  QString name_;
  typedef QMap<QString, Permissions> UserPermissionMap;
  UserPermissionMap participants_;
};

typedef QList<Share> ShareList;


#endif  // QT_CLIENT_SHARE_H_
