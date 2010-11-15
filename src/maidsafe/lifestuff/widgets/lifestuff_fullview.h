/*
 * copyright maidsafe.net limited 2008
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

#ifndef QT_WIDGETS_LIFESTUFF_FULLVIEW_H_
#define QT_WIDGETS_LIFESTUFF_FULLVIEW_H_

// qt
#include <QWidget>

//local
#include "qt/client/read_file_thread.h"
#include "qt/client/save_file_thread.h"
#include "qt/client/contact.h"

// generated
#include "ui_lifestuff_fullview.h"

class LifeStuffFull : public QWidget {
  Q_OBJECT

 public:
  explicit LifeStuffFull(QWidget* parent = 0);
  virtual ~LifeStuffFull();

  bool isActive();

 private:
  Ui::LifeStuffFull ui_;
  void addContact(Contact*);
  void setVariables();
  void saveConversation(QString &);
  void loadConversation(QString &);
  ContactList contacts_;
  QString currentContact_;
  QString chatRootPath_;
  QString rootPath_;
  bool active_;
  QList<QListWidgetItem *> currentContact();

  private slots:
   void onSendMessageClicked();
   void onContactDoubleClicked(QListWidgetItem*);
   void onReadFileCompleted(int, const QString&);
   void onSaveFileCompleted(int, const QString&);
   void onSendMessageComplete(bool, const QString&);
   void onMessageReceived(int,
                          const QDateTime& time,
                          const QString& sender,
                          const QString& message,
                          const QString& conversation);

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_LIFESTUFF_FULLVIEW_H_

