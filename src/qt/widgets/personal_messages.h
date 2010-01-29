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
 *  Created on: Jan 06, 2010
 *      Author: Stephen Alexander
 */

#ifndef QT_WIDGETS_PERSONAL_MESSAGES_H
#define QT_WIDGETS_PERSONAL_MESSAGES_H

#include <QWidget>
#include <QString>

// local
#include "qt/client/client_controller.h"

#include "ui_user_personal_message.h"

class UserPanels;

class PersonalMessages : public QMainWindow {
    Q_OBJECT
  public:
    explicit PersonalMessages(QWidget* parent = 0);
    explicit PersonalMessages(QString name = "");
    virtual ~PersonalMessages();

    void setName(QString name);
    void setMessage(QString mess);
    QString getName();

  // Panel interface
  virtual void setActive(bool);
  // Closes received messages window
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

    void onSendMessageClicked();

    void onSendInvite();

    void onSendFile();

private:
  void sendMessage(const QDateTime& time,
                  const QString& sender,
                  const QString& message);


  Ui::PersonalMessagePage ui_;
  bool active_;
  bool init_;
  QString convName_;
  UserPanels* userPanels_;

  // Hold basic message info
  struct Message {
    QDateTime time;
    QString from;
    QString text;
  };

  typedef QList<Message> MessageList;
  // All received messages
  MessageList messages_;

};

#endif // PERSONAL_MESSAGES_H_INCLUDED
