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
 *  Created on: Apr 09, 2009
 *      Author: Team
 */

#ifndef QT_WIDGETS_USER_PANELS_H_
#define QT_WIDGETS_USER_PANELS_H_

// qt
#include <QWidget>
#include <QString>

// std
#include <string>

// generated
#include "ui_user_panels.h"

class Messages;
class Shares;
class Contacts;
class VaultInfo;
class PublicUsername;
class PersonalMessages;
#ifdef PD_LIGHT
  class FileBrowser;
#endif


// Main User Panel for Perpetual Data
/*!
    Has (or will have) panels for:

      Messages
      Shares
      Settings
      Contacts
      Activities
      Help

    The following panels are also available but can not be explicitly
    seen by the user:
      Public Username

    As you switch between panels the previous panel is made inactive and
    the new panel is made active

    \sa Panel::setActive
*/
class UserPanels : public QWidget {
    Q_OBJECT

 public:
  explicit UserPanels(QWidget* parent = 0);
  virtual ~UserPanels();

  QList<QString> openConvList_;

  void addConvToList(QString name);
  QList<QString> getConvList();
  void setConvList(QList<QString> theList);

  // Enable disable user panels
  /*!
      If becoming active it initialises the user panels for the current user.
      If becoming incative it slears all state ready for a new user logging in.
  */
  void setActive(bool active);

  signals:
    // Notify a change in the number of unread messages
    void unreadMessages(int messages);

  private slots:

    // menu bar pop-up on tabBar
    void customContentsMenu(const QPoint &pos);
    void onSortAlphaClicked();
    void onSortContactedClicked();
    void onSortRecentClicked();

    void onSortShareAlphaClicked();
    void onSortShareUsedClicked();
    void onSortShareRecentClicked();

    // Notification from the Messages panel that a message was received
    void onMessageReceived();

    // Notification from the Public Username panel that a username was set
    void onPublicUsernameChosen();

    // 'My Files' button has been clicked
    void onMyFilesClicked();

    void onCurrentChanged(int i);

 private:

  QMenu *menuContacts;
  QAction *sortAlpha;
  QAction *sortContacted;
  QAction *sortRecent;

  QMenu *menuShares;
  QAction *sortShareAlpha;
  QAction *sortShareUsed;
  QAction *sortShareRecent;

  void activatePanel(bool b);

  Ui::UserPanels ui_;

  Messages* messages_;
  Shares* shares_;
  Contacts* contacts_;
//  VaultInfo* vaultinfo_;

  PublicUsername* public_username_;
#ifdef PD_LIGHT
  FileBrowser* browser_;
#endif
  // track the active panel
  int panel_;

  protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_USER_PANELS_H_

