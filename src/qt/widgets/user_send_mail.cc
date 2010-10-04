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
 *  Created on: May 18, 2010
 *      Author: Stephen Alexander
 */
#include "qt/widgets/user_send_mail.h"

#include <QMessageBox>
#include <QDebug>
#include <QXmlStreamWriter>

#include <fstream>
#include <string>

#include "qt/client/client_controller.h"

UserSendMail::UserSendMail(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  setWindowIcon(QPixmap(":/icons/32/Triangle"));

  connect(ui_.sendButton, SIGNAL(clicked(bool)),
          this,             SLOT(onSendClicked(bool)));
}

UserSendMail::~UserSendMail() {}

void UserSendMail::addToRecipients(const QList<QString>& to) {
  foreach(QString recipient, to) {
    ui_.toTextEdit->setText(recipient + "," +
                                 ui_.toTextEdit->text());
  }
}

void UserSendMail::addSingleRecipient(const QString& to) {
  ui_.toTextEdit->setText(to + "," + ui_.toTextEdit->text());
}

void UserSendMail::onSendClicked(bool) {
  QString subject = ui_.subjectTextEdit->text();
  QString message = ui_.messageTextEdit->toHtml();
  QString to = ui_.toTextEdit->text();
  QString cc = ui_.ccTextEdit->text();
  QString bcc = ui_.bccTextEdit->text();
  QList<QString> toList = to.split(",", QString::SkipEmptyParts);
  QList<QString> ccList = cc.split(",", QString::SkipEmptyParts);
  QList<QString> bccList = bcc.split(",", QString::SkipEmptyParts);

  // remove non confirmed contacts

  QStringList contacts = ClientController::instance()->contactsNames();
  int count =0;
  foreach(QString contact, toList) {
    if (!contacts.contains(contact)) {
      toList.removeAt(count);
      count++;
    }
  }
  count = 0;
  foreach(QString contact, ccList) {
    if (!contacts.contains(contact)) {
      ccList.removeAt(count);
      count++;
    }
  }
  count =0;
  foreach(QString contact, bccList) {
    if (!contacts.contains(contact)) {
      bccList.removeAt(count);
      count++;
    }
  }
  // generate random conv id
  // QString conv = QString::fromStdString(base::RandomAlphaNumericString(5));
  QString conv = ClientController::instance()->publicUsername();

  SendEmailThread* set = new SendEmailThread(subject, message, toList, ccList,
                                             bccList, conv, this);

  connect(set,  SIGNAL(sendEmailCompleted(int, const QString&)),
          this, SLOT(onSendEmailCompleted(int, const QString&)));

  set->start();

  try {
    QString emailRootPath = QString::fromStdString(
                                file_system::MaidsafeHomeDir(
                                    ClientController::instance()->SessionName())
                                    .string())
                                .append("/Emails/");
    try {
      if (!boost::filesystem::exists(emailRootPath.toStdString()))
        boost::filesystem::create_directories(emailRootPath.toStdString());
    }
    catch(const std::exception &e) {
      qDebug() << "UserSendMail::onSendClicked - Failed to create "
               << emailRootPath;
    }

    QString emailFullPath = QString("%1%2.pdmail").arg(emailRootPath)
                                                     .arg(conv);

    qDebug() << "upload File" << emailFullPath;

    QString emailFolder("/Emails/");
    QString emailMaidsafePath = QString("%1%2.pdmail").arg(emailFolder)
                                                         .arg(conv);
    QDateTime theDate = QDateTime::currentDateTime();
    QString date = theDate.toString("dd/MM/yyyy hh:mm:ss");

    QDomDocument doc( "EmailML" );
    QDomElement root = doc.createElement( "email" );
    doc.appendChild( root );

    ClientController::Email e;
    e.to = to;
    e.from = ClientController::instance()->publicUsername();
    e.cc = cc;
    e.bcc = bcc;
    e.body = message;
    e.subject = subject;

    root.appendChild(ClientController::instance()->EmailToNode(doc, e));

    QFile file( emailFullPath );
    if( !file.open( QIODevice::Append ) )
    return;

    QTextStream ts( &file );
    ts << doc.toString();

    file.close();

    SaveFileThread* sft = new SaveFileThread(emailMaidsafePath, this);
    connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
            this, SLOT(onSaveFileCompleted(int, const QString&)));
    sft->start();
  }
  catch(const std::exception&) {
    qDebug() << "Create File Failed";
  }
}



void UserSendMail::onSaveFileCompleted(int success, const QString& filepath) {
  qDebug() << "onSaveFileCompleted: " << filepath;
  if (success != 0) {
    qDebug() << "onSaveFileCompleted: Failed to send email";
  }
}

void UserSendMail::onSendEmailCompleted(int success, const QString& subject) {
  QMessageBox msgBox;
  msgBox.setText(tr("Email: %1 sent!").arg(subject));
  msgBox.exec();
  emit sendEmailCompleted(success, subject);
  this->close();
}

void UserSendMail::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}
