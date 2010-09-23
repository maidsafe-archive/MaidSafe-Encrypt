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

#include "qt/widgets/lifestuff_fullview.h"

// boost
#include <boost/progress.hpp>

#include "qt/client/send_instant_message_thread.h"
#include "qt/client/client_controller.h"

// qt
#include <QDebug>
#include <QMessageBox>


LifeStuffFull::LifeStuffFull(QWidget* parent)
    : QWidget(parent) {
  ui_.setupUi(this);

  ContactList contact_list =
                     ClientController::instance()->contacts(0);
  foreach(Contact* contact, contact_list) {
    addContact(contact);
  }

  setVariables();
  active_ = true;

  connect(ui_.contactListWidget, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
        this,           SLOT(onContactDoubleClicked(QListWidgetItem*)));

  connect(ui_.sndMessageBtn, SIGNAL(clicked()),
          this,            SLOT(onSendMessageClicked()));  

  connect(ClientController::instance(),
          SIGNAL(messageReceived(int,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)),
          this,
          SLOT(onMessageReceived(int,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)));
}

LifeStuffFull::~LifeStuffFull() {}

void LifeStuffFull::saveConversation(QString &conv) {
  QString convFilePath;
  convFilePath = chatRootPath_ + conv + ".html";

  std::ofstream myfile;
  myfile.open(convFilePath.toStdString().c_str(), std::ios::app | std::ios::out);
    // SAVE AS XML
  QString htmlMessage = ui_.messageTextEdit->toHtml();
  myfile << htmlMessage.toStdString();
  myfile.close();

  SaveFileThread* sft = new SaveFileThread("/chat/" + conv + ".html", this);
  connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
          this, SLOT(onSaveFileCompleted(int, const QString&)));
  sft->start();
}

void LifeStuffFull::loadConversation(QString &conv) {
  std::string tidyRelPathStr = ClientController::instance()->TidyPath(chatRootPath_.toStdString()
                                                 + conv.toStdString() + ".html");
  QString openFilePath = QString::fromStdString(tidyRelPathStr);
  qDebug() << "upload File" << openFilePath;

  ReadFileThread* rft = new ReadFileThread("/chat/" + conv + ".html",
                                               this);

  connect(rft,  SIGNAL(readFileCompleted(int, const QString&)),
          this, SLOT(onReadFileCompleted(int, const QString&)));

  rft->start();
}

void LifeStuffFull::onReadFileCompleted(int success, const QString& filepath){
  //if (success == 0) {
  QString path = rootPath_ + filepath;
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    return;
  QTextStream in(&file);
  QString line = in.readAll();
  ui_.messageTextEdit->setHtml(line);
  file.close();
  ui_.messageTextEdit->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
  //}
}

void LifeStuffFull::onSaveFileCompleted(int success, const QString& filepath){
  std::string fullFilePath(rootPath_.toStdString() + filepath.toStdString());  
  
  try {
      if (fs::exists(fullFilePath)) {
        fs::remove(fullFilePath);
        qDebug() << "Remove File Success:"
                 << QString::fromStdString(fullFilePath);
      }
    }
    catch(const std::exception&) {
        qDebug() << "Remove File failure:"
                 << QString::fromStdString(fullFilePath);
    }
}

void LifeStuffFull::setVariables() {
 rootPath_ = QString::fromStdString(
                              file_system::MaidsafeHomeDir(
                              ClientController::instance()->SessionName())
                                  .string());
                          
 chatRootPath_ = rootPath_ + "/chat/";

  try {
    if (!boost::filesystem::exists(chatRootPath_.toStdString()))
      boost::filesystem::create_directories(chatRootPath_.toStdString());
  }
  catch(const std::exception &e) {
    qDebug() << "UserInbox::UserInbox - Failed to create " << chatRootPath_;
  }
  QString folder = "/chat/";
  QString lastModified;
  QString fileSize;
  int n = ClientController::instance()->getattr(folder, lastModified, fileSize);
  if (n != 0)
    qDebug() << "UserInbox::UserInbox - getattr failed";
}

bool LifeStuffFull::isActive(){
  return active_;
}

QList<QListWidgetItem *> LifeStuffFull::currentContact() {
  const QList<QListWidgetItem *> names = ui_.contactListWidget->selectedItems();

  return names;
}

void LifeStuffFull::onContactDoubleClicked(QListWidgetItem* item) {
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

    std::list<std::string> theList;
    ClientController::instance()->ConversationList(&theList);

    QList<QString> messageList;
    foreach(std::string theConv, theList) {
        messageList.append(QString::fromStdString(theConv));
    }

  foreach(QString contact, conts) {
    if (!messageList.contains(contact)) {
      // no prior conversation so new tab
      // ui_.convListWidget->addItem(contact);
      ui_.messageTextEdit->clear();
      ui_.msgEntryEdit->clear();
      ui_.msgEntryEdit->setFocus(Qt::OtherFocusReason);
      ui_.sndMessageBtn->setVisible(true);

    } else {
      if (contact == currentContact_)
      {
        // do nothing
      } else {
       // load prev conv into text edit and show
       // type new message label
        loadConversation(contact);
      }
    }
  }
  currentContact_ = item->text();

}

void LifeStuffFull::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

void LifeStuffFull::addContact(Contact* contact) {
  contacts_.push_back(contact);

  QPixmap pixmap;
  if (contact->presence() == Presence::INVALID) {
      pixmap = QPixmap(":/contact_icons/contact_offline.png");
  } else if (contact->presence() == Presence::AVAILABLE) {
      pixmap = QPixmap(":/contact_icons/contact_online.png");
  } else if (contact->presence() == Presence::BUSY) {
      // TODO(Team#5#) Correct symbol
  } else if (contact->presence() == Presence::IDLE) {
      // TODO(Team#5#) Correct symbol
  } else {
      pixmap = QPixmap(":/contact_icons/contact_online.png");
  }

  QListWidgetItem* item = new QListWidgetItem;
  item->setText(contact->publicName());
  item->setIcon(pixmap);

  ui_.contactListWidget->addItem(item);
}

void LifeStuffFull::onSendMessageClicked(){
  if (currentContact_ != "" && ui_.msgEntryEdit->toPlainText() != "") {
    QList<QString> conts;
    conts.push_back(currentContact_);

    QString text = ui_.msgEntryEdit->toHtml();

    SendInstantMessageThread* simt = new SendInstantMessageThread(text,
                                     currentContact_, conts, this);

    connect(simt, SIGNAL(sendMessageCompleted(bool, const QString&)),
            this, SLOT(onSendMessageComplete(bool, const QString&)));

    simt->start();
  }
}

void LifeStuffFull::onSendMessageComplete(bool success,
                                             const QString& text) {
  if (success) {
    QDateTime theDate = QDateTime::currentDateTime();
    // TODO(Team#) use date format from the user's locale
    QString date = theDate.toString("dd/MM/yyyy hh:mm:ss");
    ui_.messageTextEdit->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
    ui_.messageTextEdit->insertHtml(tr("%2 you said: %1")
        .prepend("<span style=\"background-color:#E0FFFF\"><br />")
        .arg(text).arg(date)
        .append("</span>"));
    ui_.messageTextEdit->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
  } else {
    const QString msg = tr("Error sending message.");
    QMessageBox::warning(this, tr("Error"), msg);
  }
  ui_.msgEntryEdit->clear();
  ui_.convListWidget->addItem(currentContact_);
  
  int n = ClientController::instance()->AddConversation(
          currentContact_.toStdString());

  if (n != 0) {
    // There's no registry of the conversation, what do we do?
  }

  saveConversation(currentContact_);
}

void LifeStuffFull::onMessageReceived(int,
                                      const QDateTime&,
                                      const QString& sender,
                                      const QString& message,
                                      const QString&) {
  QList<QListWidgetItem *> items = ui_.convListWidget->findItems(sender, Qt::MatchExactly);

  if (sender == currentContact_) {
    //currently talking to sender 
    ui_.messageTextEdit->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
    QDateTime theDate = QDateTime::currentDateTime();
    // TODO(Team#) use date format from the user's locale
    QString date = theDate.toString("dd/MM/yyyy hh:mm:ss");

    ui_.messageTextEdit->insertHtml(tr("%3 %1 said: %2")
        .prepend("<span style=\"background-color:#CCFF99\"><br />")
        .arg(sender).arg(message).arg(date)
        .append("</span>"));

    ui_.messageTextEdit->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
  } else if (items.empty()) {
    // not talking to sender so new tab create, notify contacts.textedit also
    QListWidgetItem* item = new QListWidgetItem(sender);
    item->setBackgroundColor(QColor("lightblue"));
    ui_.convListWidget->addItem(item);
    QList<QListWidgetItem *> contactItems = 
                    ui_.contactListWidget->findItems(sender, Qt::MatchExactly);
    contactItems[0]->setBackgroundColor(QColor("lightblue"));
  } else {
    // already have conv with person before but not current
    items[0]->setBackgroundColor(QColor("lightblue"));
    QList<QListWidgetItem *> contactItems = 
                    ui_.contactListWidget->findItems(sender, Qt::MatchExactly);
    contactItems[0]->setBackgroundColor(QColor("lightblue"));
  }

}


