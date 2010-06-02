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
  ClientController::instance()->readdir(relPathStr, children);

  while (!children.empty()) {
    std::string s = children.begin()->first;
    qDebug() << "children not empty";
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path_(relPathStr);
    path_ /= s;
    if (ClientController::instance()->getattr(path_.string(), ser_mdm)) {
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


	//TODO: Send update email message

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

