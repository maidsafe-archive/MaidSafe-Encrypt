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

#ifndef QT_WIDGETS_MESSAGES_H_
#define QT_WIDGETS_MESSAGES_H_

// qt
#include <QDateTime>
#include <QTimer>

// core
#include "protobuf/packet.pb.h"

// local
#include "qt/client/client_controller.h"
#include "qt/widgets/panel.h"

// generated
#include "ui_user_messages_panel.h"

// Custom widget that displays messages
/*!
    Displays a list of received messages.

    Notifies when messages are received.

    TODO skype like messaging
    TODO currently use polling to check for messages.  need something better..
*/
class Messages : public Panel {
  Q_OBJECT

 public:
  explicit Messages(QWidget* parent = 0);
  virtual ~Messages();

  // Total number of unread messages.
  /*!
      A message is deemed to be unread if it is received whilst this Panel
      is not active.
  */
  int unreadMessages() const;

  // Total of all recevied messages (since logging in)
  int totalMessages() const;

  // Panel interface
  virtual void setActive(bool);
  // Clears received messages
  virtual void reset();

  signals:
    // Notify when a message(s) is received.
    void messageReceived();

  private slots:
    void onMessageReceived(ClientController::MessageType,
                           const QDateTime& time,
                           const QString& sender,
                           const QString& message,
                           const QString& conversation);

 private:
  void addMessage(const QDateTime& time,
                  const QString& sender,
                  const QString& message,
                  const QString& conversation);

  void updateHtml();

  Ui::MessagesPage ui_;
  bool active_;
  bool init_;

  // Hold basic message info
  struct Message {
    QDateTime time;
    QString from;
    QString text;
  };

  typedef QList<Message> MessageList;
  // All received messages
  MessageList messages_;

  // Count of unread messages
  int unread_;
};

#endif  // QT_WIDGETS_MESSAGES_H_
