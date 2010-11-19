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

#ifndef MAIDSAFE_LIFESTUFF_CLIENT_PRESENCE_H_
#define MAIDSAFE_LIFESTUFF_CLIENT_PRESENCE_H_

// qt
#include <QString>

// core

// Represents a Contact's online presence
/*!
    Presence is a combination of enumerated state and an
    optional message set by the contact.
*/
class Presence {
 public:
  enum State {
    INVALID,
    AVAILABLE,
    IDLE,
    BUSY,
    UNAVAILABLE
  };

  Presence();
  Presence(State, QString message = QString());
  ~Presence();

  State state() const;

  // Returns string representation of state or custom message (if set)
  QString message() const;

  // Returns the custom message.
  QString customMessage() const;

  bool isNull() const;

  bool operator==(const Presence& other) const;
  bool operator!=(const Presence& other) const;

  static Presence fromContact(const QString &pubName);

 private:
  State state_;
  QString message_;
};


#endif  //  MAIDSAFE_LIFESTUFF_CLIENT_PRESENCE_H_
