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

#include "qt/client/client_controller.h"

UserSendMail::UserSendMail(QWidget* parent) : QDialog(parent) {
  ui_.setupUi(this);

	connect(ui_.sendButton, SIGNAL(clicked(bool)),
          this,             SLOT(onSendClicked(bool)));
}

UserSendMail::~UserSendMail() {}

void UserSendMail::addToRecipients(const QList<QString>& to) {
	foreach(QString recipient, to) {
		ui_.toTextEdit->setPlainText(recipient + "," + ui_.toTextEdit->toPlainText());
	}
}

void UserSendMail::addSingleRecipient(const QString& to) {
	ui_.toTextEdit->setPlainText(to + "," + ui_.toTextEdit->toPlainText());
}

void UserSendMail::onSendClicked(bool) {
	QString subject = ui_.subjectTextEdit->text();
	QString message = ui_.messageTextEdit->toHtml();
	QString to = ui_.toTextEdit->toPlainText();
	QString cc = ui_.ccTextEdit->toPlainText();
	QString bcc = ui_.bccTextEdit->toPlainText();
	QList<QString> toList = to.split(",", QString::SkipEmptyParts);
	QList<QString> ccList = cc.split(",", QString::SkipEmptyParts);
	QList<QString> bccList = bcc.split(",", QString::SkipEmptyParts);

	// remove non confirmed contacts

	QStringList contacts = ClientController::instance()->contactsNames();
	int count =0;
	foreach(QString contact, toList) {
		if(!contacts.contains(contact)) {
			toList.removeAt(count);
			count++;
		}
	}
	count = 0;
	foreach(QString contact, ccList) {
		if(!contacts.contains(contact)) {
			ccList.removeAt(count);
			count++;
		}
	}
	count =0;
	foreach(QString contact, bccList) {
		if(!contacts.contains(contact)) {
			bccList.removeAt(count);
			count++;
		}
	}
	 //generate random conv id
	QString conv = QString::fromStdString(base::RandomString(5));

	SendEmailThread* set = new SendEmailThread(subject, message, toList, ccList,
																						 bccList, conv, this);

  connect(set,  SIGNAL(sendEmailCompleted(int, const QString&)),
              this, SLOT(onSendEmailCompleted(int, const QString&)));	

  set->start();

	try {
	QString emailRootPath_ = QString::fromStdString(file_system::MaidsafeHomeDir(
                  ClientController::instance()->SessionName()).string()+"/")
								.append("/Emails/");

	QString emailFullPath = QString("%1%2_%3.pdmail").arg(emailRootPath_)
													.arg(subject).arg(conv); 

		std::ofstream myfile;
    myfile.open(emailFullPath.toStdString().c_str());
		// SAVE AS XML
		QString htmlMessage = QString("<table style=\"width: 100%;\">"
  "<tbody>"
    "<tr>"
      "<td style=\"vertical-align: top;\">me to %1<br />"
        "</td>"
      "<td style=\"vertical-align: top;\"> </td>"
      "<td style=\"vertical-align: top;\"> %2 <br />"
        "</td>"
    "</tr>"
    "<tr>"
      "<td style=\"vertical-align: top;\" colspan=\"3\"> %3</td>"
    "</tr>"
    "<tr>"
      "<td style=\"vertical-align: top;\" colspan=\"3\"> %4</td>"
    "</tr>"
  "</tbody>"
	"</table>").arg(to).arg("")
						.arg(subject).arg(message); 
    myfile << htmlMessage.toStdString();
    myfile.close();

		SaveFileThread* sft = new SaveFileThread(emailFullPath, this);
		connect(sft,  SIGNAL(saveFileCompleted(int, const QString&)),
          this, SLOT(onSaveFileCompleted(int, const QString&)));
		sft->start();
  }
  catch(const std::exception&) {
    qDebug() << "Create File Failed";
	}
}

void UserSendMail::onSendEmailCompleted(int success, const QString& subject) {
	QMessageBox msgBox;
	msgBox.setText(tr("Email : %1 sent!").arg(subject));
	msgBox.exec();	
}

void UserSendMail::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}