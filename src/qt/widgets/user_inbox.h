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


#ifndef QT_WIDGETS_USER_INBOX_H_
#define QT_WIDGETS_USER_INBOX_H_

#include <QWidget>
#include <QString>

// local
#include "qt/client/client_controller.h" 

#include "ui_user_inbox.h"

class UserInbox : public QDialog {
    Q_OBJECT

 public:
  explicit UserInbox(QWidget* parent = 0);
  virtual ~UserInbox();	

 private:
  Ui::UserInbox ui_; 

 private slots:
	void onReplyClicked();
	void onEmailClicked(QListWidgetItem*);

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_USER_INBOX_H_
