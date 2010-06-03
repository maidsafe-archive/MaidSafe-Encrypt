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

#include "maidsafe/utils.h"
#include "qt/client/client_controller.h"


UserInbox::UserInbox(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);
  rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                    ClientController::instance()->SessionName()).string()+"/");
	folder_ = "/Emails/";
									
	populateEmails();

	connect(ui_.replyButton, SIGNAL(clicked()),
          this,             SLOT(onReplyClicked()));

	connect(ui_.messageListWidget, SIGNAL(itemClicked(QListWidgetItem*)),
					this,								SLOT(onEmailClicked(QListWidgetItem*)));

	ui_.replyGroupBox->setVisible(false);
}

UserInbox::~UserInbox() {}

int UserInbox::populateEmails() {
	ui_.messageListWidget->clear();

	int rowCount = 0;
  std::string relPathStr = folder_.toStdString();
  std::map<std::string, maidsafe::ItemType> children;
	std::string tidyRelPathStr = maidsafe::TidyPath(relPathStr);
  ClientController::instance()->readdir(tidyRelPathStr, children);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path_(relPathStr);
    path_ /= s;
    std::string str = maidsafe::TidyPath(path_.string());
    if (ClientController::instance()->getattr(str, ser_mdm)) {
      qDebug() << "drawIconView failed at getattr()";
      return -1;
    }
		
		QString filename = QString::fromStdString(s);
		if (filename.endsWith(".pdmail")){
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

  QString htmlMessage = tr("From : me to %1 at %2 <br /> %3 <br /> %4")
        .prepend("<span style=\"background-color:#CCFF99\"><br />")
        .arg(sender).arg("date").arg(subject).arg(ui_.textEdit_2->toHtml())
        .append("</span>"); 


  SendEmailThread* set = new SendEmailThread(subject, htmlMessage, toList,
                                            ccList, bccList, sender, this);

  connect(set,  SIGNAL(sendEmailCompleted(int, const QString&)),
              this, SLOT(onSendEmailCompleted(int, const QString&)));	

  set->start();

  try {
  QString emailRootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                  ClientController::instance()->SessionName()).string()+"/")
								.append("/Emails/");

  QString emailFullPath = QString("%1%2_%3.pdmail").arg(emailRootPath_)
													.arg(subject).arg(sender);

    QString emailFolder = "/Emails/";
    QString emailMaidsafePath = QString("%1%2_%3.pdmail").arg(emailFolder)
                                          .arg(subject).arg(sender);

  std::string tidyRelPathStr = maidsafe::TidyPath(emailMaidsafePath.toStdString());
  QString emailFolderPath = QString::fromStdString(tidyRelPathStr);
  qDebug() << "upload File" << emailFolderPath;

		std::ofstream myfile;
    myfile.open(emailFullPath.toStdString().c_str());
    // SAVE AS XML
  QString htmlMessage = tr("From : me to %1 at %2 <br /> %3 <br /> %4")
        .prepend("<span style=\"background-color:#CCFF99\"><br />")
        .arg(sender).arg("date").arg(subject).arg(ui_.textEdit_2->toHtml())
        .append("</span>"); 
    myfile << htmlMessage.toStdString();
    myfile.close();

    SaveFileThread* sft = new SaveFileThread(emailFolderPath, this);
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

  qDebug() << "onSaveFileCompleted : " << filepath;
  if (success != -1) {
    std::string dir = filepath.toStdString();
    dir.erase(0, 1);
    QString rootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                  ClientController::instance()->SessionName()).string()+"/");

    std::string fullFilePath(rootPath_.toStdString() + filepath.toStdString());

    if (fs::exists(fullFilePath)) {
      try {
        fs::remove(fullFilePath);
        qDebug() << "Remove File Success:"
                 << QString::fromStdString(fullFilePath);
      }
      catch(const std::exception&) {
        qDebug() << "Remove File failure:"
                 << QString::fromStdString(fullFilePath);
      }
    }
  }
  onEmailClicked(item);
}

void UserInbox::onSendEmailCompleted(int, const QString&) {
  ui_.replyGroupBox->setVisible(false);
}

void UserInbox::onEmailClicked(QListWidgetItem* item) {
	QString email = item->text();

	ReadFileThread* rft = new ReadFileThread(folder_ + 
												item->text().section(":", 1, 1) 
												+ "_" +	item->text().section(":", 0, 0)
												+ ".pdmail", this);

  connect(rft,  SIGNAL(readFileCompleted(int, const QString&)),
          this, SLOT(onEmailFileCompleted(int, const QString&)));

  rft->start();
}

void UserInbox::onEmailFileCompleted(int success, const QString& filepath) {
  if (success != -1) {
		QString path = rootPath_ + filepath;
		QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
     return;
  QTextStream in(&file);
  QString line = in.readAll();
  ui_.emailDisplayEdit->setHtml(line);
  file.remove();
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

