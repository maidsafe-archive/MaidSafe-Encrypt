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
 *  Created on: Jan 06, 2010
 *      Author: Stephen Alexander
 */

#include "maidsafe/client/sessionsingleton.h"

#include "qt/widgets/personal_messages.h"

#include <QMessageBox>
#include <QList>

#include "qt/client/client_controller.h"
#include "qt/widgets/user_panels.h"

PersonalMessages::PersonalMessages(QWidget* parent)
    :active_(false), init_(false) {
    ui_.setupUi(this);

    name_ = "";

    connect(ClientController::instance(),
          SIGNAL(messageReceived(ClientController::MessageType,
                                 const QDateTime&,
                                 const QString&,
                                 const QString&)),
          this,
          SLOT(onMessageReceived(ClientController::MessageType,
                                 const QDateTime&,
                                 const QString&,
                                 const QString&)));

        connect(ui_.send_message_btn, SIGNAL(clicked(bool)),
          this,                SLOT(onSendMessageClicked()));
}

PersonalMessages::PersonalMessages(QString name)
    :active_(false), init_(false) {
    ui_.setupUi(this);

    name_ = name;
    ui_.username_lbl->setText(name_);

    maidsafe::SessionSingleton::getInstance()->AddConversation(name.toStdString());

    this->setWindowTitle(this->windowTitle() + " " + name);

    connect(ClientController::instance(),
          SIGNAL(messageReceived(ClientController::MessageType,
                                 const QDateTime&,
                                 const QString&,
                                 const QString&)),
          this,
          SLOT(onMessageReceived(ClientController::MessageType,
                                 const QDateTime&,
                                 const QString&,
                                 const QString&)));

        connect(ui_.send_message_btn, SIGNAL(clicked(bool)),
          this,                SLOT(onSendMessageClicked()));
}

PersonalMessages::~PersonalMessages() {
  maidsafe::SessionSingleton::getInstance()->RemoveConversation(name_.toStdString());
  }

void PersonalMessages::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
  }

  active_ = b;

  if (active_) {

    emit messageReceived();
  }
}

void PersonalMessages::reset() {
  messages_.clear();

  // debug...
//  QTime start = QTime::currentTime();
//  addMessage(start, "adam", "hello");
//  addMessage(start.addSecs(10), "eve", "hello");
//  addMessage(start.addSecs(15), "adam", "is i > j if j < k and i < j?");
//  addMessage(start.addSecs(20), "eve",
//                                  "don't ask me, ask http://www.google.com");
//  addMessage(start.addSecs(25), "adam",
//                                "just send the answer to adam@maidsafe.net");

  init_ = false;

}

void PersonalMessages::onMessageReceived(ClientController::MessageType,
                                 const QDateTime& time,
                                 const QString& sender,
                                 const QString& message,
                                 const QString& conversation) {
  if (sender == name_){

  ui_.message_window->append(tr("'%1' said: %2").arg(sender).arg(message));

  //emit messageReceived();
  }
}

void PersonalMessages::sendMessage(const QDateTime& time,
                          const QString& sender,
                          const QString& message) {

 }

 void PersonalMessages::setName(QString name){
   name_ = name;
   ui_.username_lbl->setText(name_);
 }

QString PersonalMessages::getName(){
  return name_;
 }

void PersonalMessages::setMessage(QString mess){
  ui_.message_window->append(mess);
 }

void PersonalMessages::onSendMessageClicked(){
  if (name_ != "" && ui_.message_text_edit->toPlainText() != ""){

    QList<QString> conts;
    conts.push_back(name_);

    QString text = ui_.message_text_edit->toPlainText();

    if (ClientController::instance()->sendInstantMessage(text, conts, tr(""))) {
      ui_.message_window->append(tr("You said: %1").arg(text));
    } else {
      const QString msg = tr("Error sending message.");
      QMessageBox::warning(this, tr("Error"), msg);
    }

  }
}

