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
#include "qt/widgets/user_inbox.h"

#include <QMessageBox>
#include <QDebug>

#include <fstream>
#include <map>
#include <string>

#include "maidsafe/utils.h"
#include "qt/client/client_controller.h"


UserInbox::UserInbox(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
              ClientController::instance()->SessionName()).string());
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
    qDebug() << "UserInbox::UserInbox - Failed to create " << emailRootPath;
  }

  folder_ = "/Emails/";

  std::string s;
  QString emails(folder_);
  emails.append("a");
  int n = ClientController::instance()->getattr(emails, &s);
  if (n != 0)
    qDebug() << "UserInbox::UserInbox - getattr failed";

  populateEmails();

  connect(ui_.replyButton, SIGNAL(clicked()),
          this,            SLOT(onReplyClicked()));

  connect(ui_.messageListWidget, SIGNAL(itemClicked(QListWidgetItem*)),
          this,                   SLOT(onEmailClicked(QListWidgetItem*)));

  ui_.replyGroupBox->setVisible(false);
}

UserInbox::~UserInbox() {}

int UserInbox::populateEmails() {
  ui_.messageListWidget->clear();

  int rowCount = 0;
//  std::string relPathStr = folder_.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
//  std::string tidyRelPathStr = maidsafe::TidyPath(relPathStr);
  int n = ClientController::instance()->readdir(folder_, &children);
  if (n != 0) {
    qDebug() << "Couldn't read directory contents";
    return -1;
  }

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
//    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path(folder_.toStdString());
    path /= s;
    QString str(path.string().c_str());
    if (ClientController::instance()->getattr(str, &ser_mdm)) {
      qDebug() << "drawIconView failed at getattr()";
      return -1;
    }

    QString filename = QString::fromStdString(s);
    if (filename.endsWith(".pdmail")) {
      mdm.ParseFromString(ser_mdm);
      QDateTime *lastModified = new QDateTime;
      int linuxtime = mdm.last_modified();
      lastModified->setTime_t(linuxtime);

      QListWidgetItem *newItem = new QListWidgetItem;
      newItem->setText(filename.section("_", 1, 1).remove(".pdmail")
                                + ":" + filename.section('_', 0, 0));
      ui_.messageListWidget->addItem(newItem);
    }

    children.erase(children.begin());
    ++rowCount;
  }
  return 0;
}

void UserInbox::onReplyClicked() {
  QListWidgetItem* item = ui_.messageListWidget->currentItem();
  QList<QString> toList, ccList, bccList;
  QString sender = item->text().section(":", 0, 0);
  QString subject = item->text().section(":", 1, 1);
  toList.push_front(sender);

  QString htmlMessage = tr("%1")
        .prepend("<span style=\"background-color:#CCFF99\"><br />")
        .arg(ui_.textEdit_2->toHtml())
        .append("</span>");


  SendEmailThread* set = new SendEmailThread(subject, htmlMessage, toList,
                                             ccList, bccList, sender, this);

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
    qDebug() << "UserInbox::onReplyClicked - Failed to create "
             << emailRootPath;
  }

    QString emailFullPath = QString("%1%2_%3.pdmail").arg(emailRootPath)
                            .arg(subject).arg(sender);

    QString emailFolder("/Emails/");
    QString emailMaidsafePath = QString("%1%2_%3.pdmail").arg(emailFolder)
                                    .arg(subject).arg(sender);

    qDebug() << "upload File" << emailMaidsafePath;

    QDateTime theDate = QDateTime::currentDateTime();
    QString date = theDate.toString("dd/MM/yyyy hh:mm:ss");

    std::ofstream myfile;
    myfile.open(emailFullPath.toStdString().c_str(), std::ios::app);
      // SAVE AS XML
    QString htmlMessage = tr("From : me to %1 at %2 <br /> %3 <br /> %4")
          .prepend("<span style=\"background-color:#CCFF99\"><br />")
          .arg(sender).arg(date).arg(subject).arg(ui_.textEdit_2->toHtml())
          .append("</span>");
    myfile << htmlMessage.toStdString();
    myfile.close();

    SaveFileThread* sft = new SaveFileThread(emailMaidsafePath, this);
    connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
            this, SLOT(onSaveFileCompleted(int, const QString&)));
    sft->start();
  }
  catch(const std::exception&) {
    qDebug() << "Create File Failed";
  }
}

void UserInbox::onSaveFileCompleted(int success, const QString& filepath) {
  QListWidgetItem* item = ui_.messageListWidget->currentItem();

  qDebug() << "onSaveFileCompleted: " << filepath << " - " << success;
//  if (success == 0) {
//    std::string dir = filepath.toStdString();
//    dir.erase(0, 1);
//    QString rootPath = QString::fromStdString(file_system::MaidsafeHomeDir(
//                       ClientController::instance()->SessionName()).string());
//
//    std::string fullFilePath(rootPath.toStdString() + filepath.toStdString());
//
//    if (fs::exists(fullFilePath)) {
//      try {
//        fs::remove(fullFilePath);
//        qDebug() << "Remove File Success:"
//                 << QString::fromStdString(fullFilePath);
//      }
//      catch(const std::exception&) {
//        qDebug() << "Remove File failure:"
//                 << QString::fromStdString(fullFilePath);
//      }
//    }
//  }
  onEmailClicked(item);
}

void UserInbox::onSendEmailCompleted(int, const QString&) {
  ui_.replyGroupBox->setVisible(false);
}

void UserInbox::onEmailClicked(QListWidgetItem* item) {
  QString email = item->text();

  ReadFileThread* rft = new ReadFileThread(folder_ +
                        item->text().section(":", 1, 1)
                        + "_" +  item->text().section(":", 0, 0)
                        + ".pdmail", this);

  connect(rft,  SIGNAL(readFileCompleted(int, const QString&)),
          this, SLOT(onEmailFileCompleted(int, const QString&)));

  rft->start();
}

void UserInbox::onEmailFileCompleted(int success, const QString& filepath) {
  if (success == 0) {
    QString path = rootPath_ + filepath;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
      return;
    QTextStream in(&file);
    QString line = in.readAll();
    ui_.emailDisplayEdit->setHtml(line);
//    file.remove();
    ui_.replyGroupBox->setVisible(true);
  }
}

void UserInbox::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

