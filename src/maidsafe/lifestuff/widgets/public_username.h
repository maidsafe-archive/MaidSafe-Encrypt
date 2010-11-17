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
 *  Created on: May 8, 2009
 *      Author: Team
 */

#ifndef MAIDSAFE_LIFESTUFF_WIDGETS_PUBLIC_USERNAME_H_
#define MAIDSAFE_LIFESTUFF_WIDGETS_PUBLIC_USERNAME_H_

// local
#include "maidsafe/lifestuff/widgets/panel.h"

// generated
#include "ui_user_public_username_panel.h"

// Custom widget that prompts user for a public username
/*!
    When a public username has been successfully set the complete()
    signal is emitted
*/
class PublicUsername : public Panel {
  Q_OBJECT
 public:
  explicit PublicUsername(QWidget* parent = 0);
  virtual ~PublicUsername();

  virtual void setActive(bool);
  virtual void reset();
  void clearPubUsername();

 signals:
  void complete();

  private slots:
    void onCreateUsernameClicked();

    void onCreateUsernameCompleted(bool);

 private:
  Ui::PublicUsernamePage ui_;
  bool init_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  //  MAIDSAFE_LIFESTUFF_WIDGETS_PUBLIC_USERNAME_H_
