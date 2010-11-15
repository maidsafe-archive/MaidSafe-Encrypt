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
 *  Created on: May 19, 2010
 *      Author: Stephen Alexander
 */


#ifndef QT_WIDGETS_USER_MAIL_H_
#define QT_WIDGETS_USER_MAIL_H_

#include <QWidget>
#include <QString>

// local
#include "maidsafe/lifestuff/client/client_controller.h"
#include "maidsafe/lifestuff/widgets/user_inbox.h"
#include "maidsafe/lifestuff/widgets/user_send_mail.h"

#include "ui_user_mail.h"

class UserMail : public QDialog {
    Q_OBJECT

 public:
  explicit UserMail(QWidget* parent = 0);
  virtual ~UserMail();

  private slots:
    void onCurrentRowChanged(int);

 private:
  Ui::UserMail ui_;
	UserInbox* userInbox_;
  UserSendMail* userSendMail_;

  void createSettingsMenu();

  enum State {
    SENT,
    INBOX
	};

  void setState(State state);
  State state_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_USER_MAIL_H_
