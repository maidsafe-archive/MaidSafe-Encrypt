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

#include "qt/widgets/personal_messages.h"

// boost
#include <boost/progress.hpp>

#include <QMessageBox>
#include <QList>
#include <QFileDialog>
#include <QInputDialog>

#include "maidsafe/client/sessionsingleton.h"
#include "qt/client/client_controller.h"
#include "qt/widgets/user_panels.h"

PersonalMessages::PersonalMessages(QWidget* parent)
    :active_(false), init_(false) {
  ui_.setupUi(this);

  convName_ = "";

  connect(ClientController::instance(),
          SIGNAL(messageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)),
          this,
          SLOT(onMessageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)));

          connect(ui_.send_message_btn, SIGNAL(clicked(bool)),
                  this,                 SLOT(onSendMessageClicked()));
}

PersonalMessages::PersonalMessages(QString name)
    :active_(false), init_(false) {
  ui_.setupUi(this);

  // const QString pu = ClientController::instance()->publicUsername();
  convName_ = name;

  ui_.partListWidget->addItem(name);

  int n = maidsafe::SessionSingleton::getInstance()->AddConversation(
          convName_.toStdString());

  this->setWindowTitle(this->windowTitle() + " " + name);

  connect(ClientController::instance(),
          SIGNAL(messageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)),
          this,
          SLOT(onMessageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)));

  connect(ui_.send_message_btn, SIGNAL(clicked(bool)),
          this,                 SLOT(onSendMessageClicked()));

  connect(ui_.actionInvite, SIGNAL(triggered()),
          this,             SLOT(onInvite()));

  connect(ui_.actionSend_File, SIGNAL(triggered()),
          this,                SLOT(onSendFile()));

}

PersonalMessages::~PersonalMessages() {
  int n = maidsafe::SessionSingleton::getInstance()->RemoveConversation(
          convName_.toStdString());
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

  init_ = false;
}

void PersonalMessages::onMessageReceived(ClientController::MessageType,
                                 const QDateTime& time,
                                 const QString& sender,
                                 const QString& message,
                                 const QString& conversation) {
  if (sender == convName_) {
    ui_.message_window->append(tr("'%1' said: %2").arg(sender).arg(message));
  }
}

void PersonalMessages::sendMessage(const QDateTime& time,
                                   const QString& sender,
                                   const QString& message) {
}

void PersonalMessages::setName(QString name) {
  /*convName_ = name;
  ui_.username_lbl->setText(name_);*/
}

QString PersonalMessages::getName() {
  return convName_;
}

void PersonalMessages::setMessage(QString mess) {
  ui_.message_window->append(mess);
}

void PersonalMessages::onSendMessageClicked() {
  if (convName_ != "" && ui_.message_text_edit->toPlainText() != "") {
    QList<QString> conts;
    conts.push_back(convName_);

    QString text = ui_.message_text_edit->toPlainText();

    if (ClientController::instance()->sendInstantMessage(text, conts,
        convName_)) {
      ui_.message_window->append(tr("You said: %1").arg(text));
    } else {
      const QString msg = tr("Error sending message.");
      QMessageBox::warning(this, tr("Error"), msg);
    }
    ui_.message_text_edit->clear();
  }
}

void PersonalMessages::onSendInvite() {
}

void PersonalMessages::onSendFile(){
  QList<QString> conts;
  conts.push_back(convName_);

  // choose a file
  // starting directory should be the maidafe one.
  // TODO(Team#5#): 2009-07-28 - restrict file dialog to maidsafe directories
  //Possible to do by using Directory Entered Signal
  QString root;
#ifdef DEBUG
  printf("PersonalMessages::onFileSendClicked: opening the \"conversation\".\n");
  boost::progress_timer t;
#endif

#ifdef __WIN32__
  root = QString("%1:\\My Files").
         arg(maidsafe::SessionSingleton::getInstance()->WinDrive());
  QFileDialog *qfd = new QFileDialog(this,
                     tr("File to share..."),
                     root, tr("Any file (*)"));
  int result = qfd->exec();
  if (result == QDialog::Rejected) {
    return;
  }
  QStringList fileNames = qfd->selectedFiles();
#else
  file_system::FileSystem fs;
  root = QString::fromStdString(fs.MaidsafeFuseDir() + "/My Files");
  QStringList fileNames = QFileDialog::getOpenFileNames(
                                this,
                                "Select one to send",
                                root,
                                tr("Any file (*)"));
#endif

#ifdef DEBUG
  printf("PersonalMessages::onFileSendClicked: time - %f.\n", t.elapsed());
#endif
  if (fileNames.isEmpty()) {
#ifdef DEBUG
    printf("PersonalMessages::onFileSendClicked: no file selected.\n");
#endif
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

  if (ClientController::instance()->sendInstantFile(filename, text, conts,
      tr(""))) {
    QMessageBox::information(this, tr("File Sent"),
                             tr("Success sending file: %1").arg(filename));
  } else {
    const QString msg = tr("There was an error sending the file: %1")
                       .arg(filename);
    QMessageBox::warning(this, tr("File Not Sent"), msg);
  }
}

