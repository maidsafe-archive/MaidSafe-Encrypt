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
 *  Created on: June 09, 2010
 *      Author: Team
 */

#ifndef QT_WIDGETS_USER_MESSAGE_LOGS_H_
#define QT_WIDGETS_USER_MESSAGE_LOGS_H_

#include <QWidget>
#include <QString>

// local
#include "qt/widgets/panel.h"

// generated
#include "ui_user_message_logs.h"

class UserPanels;

// Custom widget that displays Message Logs
/*!
    Displays a list of Messages
*/
class MessageLogs : public Panel {
    Q_OBJECT
 public:
  explicit MessageLogs(QWidget* parent = 0);
  virtual ~MessageLogs();

  virtual void setActive(bool);
  virtual void reset();

  void addMessage(QString message);

  int sortType_;

 private:
  // Add a new entry in the listing of Messages
  Ui::MessageLogs ui_;
  bool init_;
  UserPanels* userPanels_;

  private slots:    
    void onMessageReceived(int,
                           const QDateTime& time,
                           const QString& sender,
                           const QString& message,
                           const QString& conversation);
   
  protected:
    void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_USER_MESSAGE_LOGS_H_
