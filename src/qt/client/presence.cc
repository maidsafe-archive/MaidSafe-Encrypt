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

#include "qt/client/presence.h"

// qt
#include <QApplication>
#include <QDebug>

Presence::Presence() : state_(INVALID), message_() { }

Presence::Presence(State state, QString message)
    : state_(state), message_(message) {
  if (!message_.isEmpty()) {
    if (state_ != AVAILABLE && state_ != IDLE && state_ != BUSY) {
      qWarning() << "ignoring presence message for state"
                 << static_cast<int>(state);
      message_ = QString();
    }
  }
}

Presence::~Presence() { }

Presence::State Presence::state() const {
  return state_;
}

QString Presence::message() const {
  if (!message_.isEmpty()) {
    return message_;
  }

  switch (state_) {
    case INVALID:     return QApplication::translate("Presence", "Unknown");
    case AVAILABLE:   return QApplication::translate("Presence", "Available");
    case IDLE:        return QApplication::translate("Presence", "Idle");
    case BUSY:        return QApplication::translate("Presence", "Busy");
    case UNAVAILABLE: return QApplication::translate("Presence", "Unavailable");
    default:          qWarning() << "bad presence" << static_cast<int>(state_);
                      return QApplication::translate("Presence", "Unknown");
  }
}

QString Presence::customMessage() const {
  return message_;
}

bool Presence::isNull() const {
  return state_ == NULL;
}

bool Presence::operator==(const Presence& other) const {
  return other.state_ == state_ && other.message_ == message_;
}

bool Presence::operator!=(const Presence& other) const {
  return !(*this == other);
}

// static
Presence Presence::fromContact(const QString &pubName) {
  return Presence();
}
