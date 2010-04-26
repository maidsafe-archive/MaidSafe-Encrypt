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

#include "qt/widgets/messages.h"

// qt
#include <QMessageBox>
#include <QInputDialog>
#include <QScrollBar>
#include <QDebug>

// std
#include <list>

//
#include "maidsafe/client/contacts.h"

namespace {

QString messageToRichText(QString s) {
  s = s.replace("&", "&amp;");
  s = s.replace("<", "&lt;");
  s = s.replace(">", "&gt;");

  s = s.replace("\n", "<br/>");

  QRegExp urlRegexp("((http://|https://|ftp:/)[^\"\\s]+)");
  s = s.replace(urlRegexp, "<a href=\"\\1\">\\1</a>");

  QRegExp emailRegexp("([^\\s@\"]+@([-a-zA-Z0-9]+)(\\.[-a-zA-Z0-9]+)+)");
  s = s.replace(emailRegexp, "<a href=\"mailto:\\1\">\\1</a>");

  // TODO(Team#5#): 2009-08-17 - should be able to mark up files so they can
  //                             be clicked/opened

  return s;
}

}  // namespace

Messages::Messages(QWidget* parent)
    : Panel(parent), active_(false), init_(false), unread_(0) {
  ui_.setupUi(this);

  ui_.textBrowser->document()->setDefaultStyleSheet(
          "span.time { font-style: italic; color: #443300; }"
          "span.username { font-weight: bold; }"
          "span.message { font-weight: normal; }"
          "span.system-message { font-weight: normal; color: #ff0000; }");
  ui_.textBrowser->setOpenExternalLinks(true);

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
}

Messages::~Messages() { }

void Messages::setActive(bool b) {
  if (b && !init_) {
    init_ = true;
  }

  active_ = b;

  if (active_) {
    unread_ = 0;
    updateHtml();
    emit messageReceived();
  }
}

void Messages::reset() {
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
  unread_ = 0;
  updateHtml();
}

int Messages::unreadMessages() const {
  return unread_;
}

int Messages::totalMessages() const {
  return messages_.size();
}


void Messages::onMessageReceived(ClientController::MessageType,
                                 const QDateTime& time,
                                 const QString& sender,
                                 const QString& message,
                                 const QString& conversation) {
  if (!active_) {
    ++unread_;
  }

  qDebug() << "Messages::onMessageReceived:" << sender << message
           << "Unread:" << unread_;

  addMessage(time, sender, message, conversation);

  emit messageReceived();
}

void Messages::addMessage(const QDateTime& time,
                          const QString& sender,
                          const QString& message,
                          const QString&) {
  Message msg;
  msg.time = time;
  msg.from = sender;
  msg.text = message;

  messages_.push_back(msg);

  updateHtml();
}

void Messages::updateHtml() {
  if (!active_) {
      return;
  }

  QString html;
  foreach(const Message& msg, messages_) {
    html += QString("<p>"
                 "  <span class='time'>[%1] </span>"
                 "  <span class='username'>%2: </span>"
                 "  <span class='message'>%3</span>"
                 "  </p>")
            .arg(msg.time.toString("h:mm:ss ap"))
            .arg(msg.from)
            .arg(messageToRichText(msg.text));
  }

  if (messages_.isEmpty()) {
    html = tr("There are no new messages.");
  }

  ui_.textBrowser->setHtml(html);
  ui_.textBrowser->verticalScrollBar()->setValue(
                   ui_.textBrowser->verticalScrollBar()->maximum());
}

void Messages::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else
    QWidget::changeEvent(event);
}


