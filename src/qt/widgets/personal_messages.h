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

#ifndef QT_WIDGETS_PERSONAL_MESSAGES_H_
#define QT_WIDGETS_PERSONAL_MESSAGES_H_

#include <QWidget>
#include <QString>
#include <QStringList>

// local
#include "qt/client/client_controller.h"
#include "qt/widgets/smily.h"

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
  void onTextClicked();
  void onColorClicked();
  void onSmilyClicked();
  void formatHtml();
  void onSmilyChosen(int row, int column);
  void onSendMessageComplete(bool success, const QString& text);
  void onMessageTextEdit();

 protected:
  bool eventFilter(QObject *obj, QEvent *ev);
  void closeEvent(QCloseEvent *event);
  void changeEvent(QEvent *event);

 private:
  void loadConversation();
  void sendMessage(const QDateTime& time,
                  const QString& sender,
                  const QString& message);
  Ui::PersonalMessagePage ui_;
  bool active_;
  bool init_;
  QString convName_;
  UserPanels* userPanels_;
  QFont font_;
  QColor color_;
  Smily* smilies_;
  QString dir_;

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

#endif  // QT_WIDGETS_PERSONAL_MESSAGES_H_
