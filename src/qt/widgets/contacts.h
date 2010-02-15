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

#ifndef QT_WIDGETS_CONTACTS_H_
#define QT_WIDGETS_CONTACTS_H_

#include <QWidget>
#include <QMenu>
#include <QAction>
#include <QFileDialog>

// local
#include "qt/widgets/panel.h"
#include "qt/client/contact.h"
#include "qt/widgets/personal_messages.h"

// generated
#include "ui_user_contacts_panel.h"

class PersonalMessages;
class UserPanels;

// Custom widget that displays contacts
/*!
    Displays a list of contacts and lets you add them.
*/
class Contacts : public Panel {
    Q_OBJECT
 public:
  explicit Contacts(QWidget* parent = 0);
  virtual ~Contacts();

  virtual void setActive(bool);
  virtual void reset();

  int sortType_;

 private:
  // Add a new entry in the listing of contacts
  void addContact(Contact*);
  Ui::ContactsPage ui_;
  bool init_;
  QFileDialog* qfd;
  ContactList contacts_;
  UserPanels* userPanels_;
  PersonalMessages* messages_;

  QList<QListWidgetItem *> currentContact();

  QMenu *menu;
  QAction *viewProfile;
  QAction *sendFile;
  QAction *sendMessage;
  QAction *deleteContact;

  QMenu *menuContacts;
  QAction *sortAlpha;
  QAction *sortContacted;
  QAction *sortRecent;

  private slots:
    void onAddContactClicked();
    void onClearSearchClicked();
    void onContactsBoxLostFocus();

    void onItemDoubleClicked(QListWidgetItem*);
    void onItemSelectionChanged();

    void onDeleteUserClicked();
    void onViewProfileClicked();
    void onSendMessageClicked();
    void onFileSendClicked();

    void onDirectoryEntered(const QString&);
    void onContactsBoxTextEdited(const QString &value);
    void onAddedContact(const QString &name,
                        const maidsafe::InstantMessage& im);
    void onConfirmedContact(const QString &name);
    void onDeletedContact(const QString &name);
    void customContentsMenu(const QPoint &pos);
    void DoneAddingContact(int result, QString contact);

    protected:
    bool eventFilter(QObject *obj, QEvent *ev);
};

#endif  // QT_WIDGETS_CONTACTS_H_
