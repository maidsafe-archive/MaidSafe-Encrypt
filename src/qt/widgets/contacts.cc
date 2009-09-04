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
 *  Created on: Apr 10, 2009
 *      Author: Team
 */

#include "qt/widgets/contacts.h"

// boost
#include <boost/progress.hpp>

// qt
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QDebug>

//
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"

// local
#include "qt/client/client_controller.h"


Contacts::Contacts(QWidget* parent)
    : Panel(parent)
    , init_(false) {
  ui_.setupUi(this);
  ui_.add->setAutoDefault(true);
  ui_.clear->setAutoDefault(true);
  ui_.delete_user->setAutoDefault(true);
  ui_.view_profile->setAutoDefault(true);
  ui_.send_message->setAutoDefault(true);
  ui_.share_file->setAutoDefault(true);
  ui_.listWidget->setSelectionMode(QAbstractItemView::MultiSelection);

  connect(ui_.add, SIGNAL(clicked(bool)),
          this, SLOT(onAddContactClicked()));

  // To enable the return event on the textbox
  connect(ui_.contactLineEdit,    SIGNAL(returnPressed()),
          this,                   SLOT(onAddContactClicked()));

  connect(ui_.clear,  SIGNAL(clicked(bool)),
          this,       SLOT(onClearSearchClicked()));

  // buttons
  connect(ui_.delete_user, SIGNAL(clicked(bool)),
          this,            SLOT(onDeleteUserClicked()));

  connect(ui_.view_profile, SIGNAL(clicked(bool)),
          this,             SLOT(onViewProfileClicked()));

  connect(ui_.send_message, SIGNAL(clicked(bool)),
           this,             SLOT(onSendMessageClicked()));

  connect(ui_.share_file, SIGNAL(clicked(bool)),
          this,           SLOT(onFileSendClicked()));


  connect(ClientController::instance(), SIGNAL(addedContact(const QString&)),
          this,                         SLOT(onAddedContact(const QString&)));

  connect(ClientController::instance(),
          SIGNAL(confirmedContact(const QString&)),
          this, SLOT(onConfirmedContact(const QString&)));

  connect(ClientController::instance(),
          SIGNAL(deletedContact(const QString&)),
          this, SLOT(onDeletedContact(const QString&)));

  connect(ui_.listWidget, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
          this,           SLOT(onItemDoubleClicked(QListWidgetItem*)));

  connect(ui_.listWidget, SIGNAL(itemSelectionChanged()),
          this,           SLOT(onItemSelectionChanged()));
}


void Contacts::setActive(bool b) {
  if (b && !init_) {
    ContactList contact_list = ClientController::instance()->contacts();
    foreach(Contact* contact, contact_list) {
      addContact(contact);
    }
    init_ = true;
  }
}

void Contacts::reset() {
  // clear the list of contacts
  ui_.listWidget->clear();

  qDeleteAll(contacts_);
  contacts_.clear();

  init_ = false;

  onItemSelectionChanged();
}

Contacts::~Contacts() { }

void Contacts::onItemDoubleClicked(QListWidgetItem* item) {
  qDebug() << "Contacts::onItemDoubleClicked:" << item->text();

  onSendMessageClicked();
}

void Contacts::onItemSelectionChanged() {
  bool singles = false;
  bool doubles = false;
  if (currentContact().size() > 0) {
    if (currentContact().size() == 1)
      singles = true;
    doubles = true;
  }

  ui_.delete_user->setEnabled(singles);
  ui_.view_profile->setEnabled(singles);
  ui_.send_message->setEnabled(doubles);
  ui_.share_file->setEnabled(doubles);
}

void Contacts::onAddContactClicked() {
  const QString contact_name = ui_.contactLineEdit->text().trimmed();

  if (contact_name == ClientController::instance()->publicUsername()) {
    QMessageBox::warning(this, tr("Recommendation"),
                         tr("Try not to add yourself as a contact."));
    return;
  }

  if (ui_.contactLineEdit->text() == "") {
    QMessageBox::warning(this, tr("Problem!"),
                         tr("Please enter a valid username."));
    return;
  }


  const int n = ClientController::instance()->addContact(contact_name);
  switch (n) {
    case 0: addContact(new Contact(contact_name));
            ui_.contactLineEdit->setText(tr(""));
            break;
    case -221:  QMessageBox::warning(this, tr("Problem!"),
                    tr("Error adding contact. Username doesn't exist."));
                break;
    case -7:  QMessageBox::warning(this, tr("Notification"),
                  tr("User already exists in your list."));
              break;
  }
}

void Contacts::onClearSearchClicked() {
    ui_.contactLineEdit->clear();
}

void Contacts::addContact(Contact* contact) {
  contacts_.push_back(contact);

  QPixmap pixmap;
  if (contact->presence() == Presence::INVALID) {
      pixmap = QPixmap(":/icons/16/question");
  } else {
      pixmap = QPixmap(":/icons/16/tick");
  }

  QListWidgetItem* item = new QListWidgetItem;
  item->setText(contact->publicName());
  item->setIcon(pixmap);

  ui_.listWidget->addItem(item);
}

void Contacts::onViewProfileClicked() {
  QList<QListWidgetItem *> contacts = currentContact();
  if (contacts.size() == 0)
      return;

  if (contacts.size() > 1) {
    QMessageBox::warning(this, tr("Error"),
                         QString(tr("Please select only one user.")));
    return;
  }

  QListWidgetItem *contact = contacts.front();
  maidsafe::mi_contact mic;
  int n = maidsafe::SessionSingleton::getInstance()->GetContactInfo(
          contact->text().toStdString(), &mic);

  if (n != 0) {
    QMessageBox::warning(this, tr("Error"),
                         QString(tr("contact doesn't exist.")));
    return;
  }

  // \TODO QString/html/%1,%2 etc - inline view of details?
  QString details("Public Username: ");
  details += QString(mic.pub_name_.c_str()) + "\n";
  details += "Full Name: " + QString(mic.full_name_.c_str()) + "\n";
  details += "Office Phone: " + QString(mic.office_phone_.c_str()) + "\n";
  details += "Birthday: " + QString(mic.birthday_.c_str()) + "\n";
  details += "Gender: " + QString(1, QChar(mic.gender_)) + "\n";
  details += "Language: English\n";
  details += "City: " + QString(mic.city_.c_str()) + "\n";
  details += "Country: UK\n";

  QMessageBox::information(this, tr("Contact Details"), details);
}

void Contacts::onDeleteUserClicked() {
  QList<QListWidgetItem *> contacts = currentContact();
  if (contacts.size() == 0)
    return;

  if (contacts.size() > 1) {
    QMessageBox::warning(this, tr("Error"),
                         QString(tr("Please select only one user.")));
    return;
  }

  Contact* contact_ = reinterpret_cast<Contact*>(contacts.front());

  if (ClientController::instance()->removeContact(contact_->publicName())) {
    QList<QListWidgetItem*> items = ui_.listWidget->findItems(
                                    contact_->publicName(),
                                    Qt::MatchCaseSensitive);

    int n = contacts_.removeAll(contact_);
    delete contact_;

    foreach(QListWidgetItem* item, items) {
      ui_.listWidget->removeItemWidget(item);
      delete item;
    }
  } else {
    QMessageBox::warning(this, tr("Error"),
                         QString(tr("Error removing user: %1"))
                         .arg(contact_->publicName()));
  }
}

void Contacts::onSendMessageClicked() {
  QList<QListWidgetItem *> contacts = currentContact();
  if (contacts.size() == 0)
    return;

  QList<QString> conts;
  if (contacts.size() > 1) {
    foreach(QListWidgetItem *item, contacts) {
      qDebug() << "Contacts::onSendMessageClicked()";
      conts.push_back(item->text());
    }
  } else {
    conts.push_back(contacts.front()->text());
  }

  bool ok;
  QString text = QInputDialog::getText(this,
                                       tr("Messsage entry"),
                                       tr("Please enter a quick message:"),
                                       QLineEdit::Normal,
                                       QString(),
                                       &ok);
  if (!ok || text.isEmpty()) {
      return;
  }

  if (ClientController::instance()->sendInstantMessage(text, conts)) {
    qDebug() << "Message sent to " << conts.size() << " contacts.";
  } else {
    const QString msg = tr("Error sending message.");
    QMessageBox::warning(this, tr("Error"), msg);
  }
}

void Contacts::onFileSendClicked() {
  QList<QListWidgetItem *> contacts = currentContact();
  if (contacts.size() == 0)
    return;

  QList<QString> conts;
  if (contacts.size() > 1) {
    foreach(QListWidgetItem *item, contacts) {
      qDebug() << "Contacts::onSendMessageClicked()";
      conts.push_back(item->text());
    }
  } else {
    conts.push_back(contacts.front()->text());
  }

  // choose a file
  // starting directoty should be the maidafe one.
  // TODO(Team#5#): 2009-07-28 - restrict file dialog to maidsafe directories
  QString root;
#ifdef __WIN32__
  root = QString("%1:\\My Files").
         arg(maidsafe::SessionSingleton::getInstance()->WinDrive());
//   dialog.setDirectory(root);
#else
  file_system::FileSystem fs;
  root = QString::fromStdString(fs.MaidsafeFuseDir());
#endif
#ifdef DEBUG
  printf("Contacts::onFileSendClicked: opening the \"conversation\".\n");
#endif
  maidsafe::ClientController::getInstance()->open("\\My Files");
  boost::progress_timer t;
  QFileDialog *qfd = new QFileDialog(this,
                     tr("File to share..."),
                     root, tr("Any file (*)"));
  qfd->exec();
  QStringList fileNames = qfd->selectedFiles();
#ifdef DEBUG
  printf("\n\nDialog time: %f\n\n", t.elapsed());
#endif
  if (fileNames.isEmpty()) {
      return;
  }

  const QString filename = fileNames.at(0);

  // accompanying message
  bool ok;
  QString text = QInputDialog::getText(this,
                                       tr("Messsage entry"),
                                       tr("Please Enter a message if you "
                                          "wish to accompany the file(s)"),
                                       QLineEdit::Normal,
                                       QString(),
                                       &ok);
  if (!ok) {
      return;
  }

  if (ClientController::instance()->sendInstantFile(filename, text, conts)) {
    QMessageBox::information(this, tr("File Sent"),
                              tr("Success sending file: %1").arg(filename));
  } else {
    const QString msg = tr("There was an error sending the file: %1")
                       .arg(filename);
    QMessageBox::warning(this, tr("File Not Sent"), msg);
  }
}

QList<QListWidgetItem *> Contacts::currentContact() {
//  if (!ui_.listWidget->currentItem())
//    return NULL;

  const QList<QListWidgetItem *> names = ui_.listWidget->selectedItems();

//  foreach(Contact* contact, contacts_) {
//    if (contact->publicName() == name)
//      return contact;
//  }

  return names;
}

void Contacts::onAddedContact(const QString &name) {
  qDebug() << "Contacts::onAddedContact()";
  QList<QListWidgetItem*> items = ui_.listWidget->findItems(name,
                                  Qt::MatchCaseSensitive);
  if (items.size() == 1) {  // Contact had changed confirmed status only
    onConfirmedContact(name);
  } else {  // Contact wasn't present
    Contact *c = new Contact(name);
    c->setPresence(Presence::AVAILABLE);
    addContact(c);
  }
}

void Contacts::onConfirmedContact(const QString &name) {
  qDebug() << "Contacts::onConfirmedContact()";
  QList<QListWidgetItem*> items = ui_.listWidget->findItems(name,
                                  Qt::MatchCaseSensitive);

  foreach(QListWidgetItem* item, items) {
    if (item->text() == name) {
      QPixmap pixmap(":/icons/16/tick");
      item->setIcon(pixmap);
    }
  }
}

void Contacts::onDeletedContact(const QString &name) {
  qDebug() << "Contacts::onConfirmedContact()";
  QList<QListWidgetItem*> items = ui_.listWidget->findItems(name,
                                  Qt::MatchCaseSensitive);

  foreach(QListWidgetItem* item, items) {
    if (item->text() == name) {
      QPixmap pixmap(":/icons/16/question");
      item->setIcon(pixmap);
    }
  }
}
