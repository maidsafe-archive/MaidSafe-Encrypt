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

#ifndef QT_WIDGETS_SHARE_PARTICIPANTS_H_
#define QT_WIDGETS_SHARE_PARTICIPANTS_H_

// qt
#include <QDialog>

// generated
#include "ui_share_participants.h"

// Custom widget that displays contacts to be chosen as participants in a share
class ShareParticipantsChoice : public QDialog {
  Q_OBJECT
 public:
  ShareParticipantsChoice(QWidget* parent = 0, const QString& title = "",
                          QStringList *usernames = 0);
  virtual ~ShareParticipantsChoice();
  private slots:
    void accept();
 private:
  Ui::Dialog ui_;
  QStringList* usernames_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_SHARE_PARTICIPANTS_H_
