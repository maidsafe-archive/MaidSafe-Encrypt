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
#include "qt/widgets/share_participants.h"

// qt
#include <QListWidget>
#include <QListWidgetItem>

// local
#include "qt/client/client_controller.h"


ShareParticipantsChoice::ShareParticipantsChoice(QWidget* parent,
                                                 const QString &title,
                                                 QStringList *usernames)
                                                 : QDialog(parent),
                                                   usernames_(usernames) {
  ui_.setupUi(this);

  QStringList db_contacts = ClientController::instance()->contactsNames();

  foreach(const QString& s, *usernames) {
    db_contacts.removeAll(s);
  }

  ui_.listWidget->setSelectionMode(QAbstractItemView::MultiSelection);

  int row = 1;
  foreach(const QString& s, db_contacts) {
    QListWidgetItem* item = new QListWidgetItem(ui_.listWidget,
                                                QListWidgetItem::UserType);

    item->setText(s);
    item->setCheckState(Qt::Unchecked);
    ui_.listWidget->insertItem(row, item);
    row++;
  }

  ui_.label->setText(title);
}

ShareParticipantsChoice::~ShareParticipantsChoice() { }

void ShareParticipantsChoice::accept() {
  usernames_->clear();
  for (int i = 0; i < ui_.listWidget->count(); ++i) {
    QListWidgetItem* item = ui_.listWidget->item(i);
    if (item->checkState() == Qt::Checked) {
      usernames_->push_back(item->text());
    }
  }
  done(0);
}

void ShareParticipantsChoice::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    // TODO Get lang from ClientController and Update as Neccesary
    //ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}

