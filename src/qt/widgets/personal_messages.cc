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
#include <QFontDialog>
#include <QColorDialog>
#include <QKeyEvent>
#include <QFile>
#include <QTextStream>
#include <QRegExp>
#include <QDateTime>
#include <QDebug>

#include <string>

#include "qt/client/client_controller.h"
#include "qt/client/send_instant_message_thread.h"
#include "qt/widgets/user_panels.h"

PersonalMessages::PersonalMessages(QWidget* parent)
    : active_(false), init_(false), convName_("") {
  ui_.setupUi(this);

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
    : active_(false), init_(false) {
  setAttribute(Qt::WA_DeleteOnClose, true);
  setWindowIcon(QPixmap(":/icons/16/globe"));
  ui_.setupUi(this);

  ui_.message_text_edit->installEventFilter(this);
  statusBar()->hide();

  smilies_ = new Smily;
  convName_ = name;
  font_ = QFont("Arial", 10);
  color_ = QColor("Black");
  ui_.partListWidget->addItem(name);
  dir_ = "" + convName_ + ".html";

  int n = ClientController::instance()->AddConversation(
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

  connect(ui_.textButton, SIGNAL(clicked(bool)),
          this,           SLOT(onTextClicked()));

  connect(ui_.actionInvite, SIGNAL(triggered()),
          this,             SLOT(onSendInvite()));

  connect(ui_.actionSend_File, SIGNAL(triggered()),
          this,                SLOT(onSendFile()));

  connect(ui_.colorButton, SIGNAL(clicked(bool)),
          this,             SLOT(onColorClicked()));

  connect(ui_.smilyButton, SIGNAL(clicked(bool)),
          this,             SLOT(onSmilyClicked()));

  connect(ui_.message_text_edit, SIGNAL(textChanged()),
          this,           SLOT(onMessageTextEdit()));

  loadConversation();
}

PersonalMessages::~PersonalMessages() {
  int n = ClientController::instance()->RemoveConversation(
          convName_.toStdString());
  dir_ = "" + convName_ + ".html";
  QFile f(dir_);
  f.open(QIODevice::WriteOnly);
  QTextStream out(&f);
  out << ui_.message_window->toHtml();
  f.close();
  qDebug() << "Destroy Finished";
}

void PersonalMessages::closeEvent(QCloseEvent *event) { }

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

void PersonalMessages::loadConversation() {
  QFile file(dir_);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    return;
  QTextStream in(&file);
  QString line = in.readAll();
  ui_.message_window->setHtml(line);
  file.close();
  ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
}

void PersonalMessages::onMessageReceived(ClientController::MessageType,
                                         const QDateTime& time,
                                         const QString& sender,
                                         const QString& message,
                                         const QString& conversation) {
  boost::progress_timer t;
  if (sender == convName_) {
    ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
    QDateTime theDate = QDateTime::currentDateTime();
    QString date = theDate.toString("dd.MM.yyyy hh:mm:ss");

    ui_.message_window->insertHtml(
        tr("<span style=\"background-color:#CCFF99\">"
           "<br />%3 %1 said: %2</span>").arg(sender).arg(message).arg(date));
  }
    printf("Personal Messages.cc %f", t.elapsed());
    ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
}

void PersonalMessages::sendMessage(const QDateTime& time,
                                   const QString& sender,
                                   const QString& message) {
}

void PersonalMessages::setName(QString name) {
//  convName_ = name;
//  ui_.username_lbl->setText(name_);
}

QString PersonalMessages::getName() {
  return convName_;
}

void PersonalMessages::setMessage(QString mess) {
  ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
  QDateTime theDate = QDateTime::currentDateTime();
  QString date = theDate.toString("dd.MM.yyyy hh:mm:ss");

  ui_.message_window->insertHtml(
      tr("<span style=\"background-color:#CCFF99\">"
         "<br />%3 %1 said: %2</span>").arg(convName_).arg(mess).arg(date));
  ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
}

void PersonalMessages::onSendMessageClicked() {
  if (convName_ != "" && ui_.message_text_edit->toPlainText() != "") {
    QList<QString> conts;
    conts.push_back(convName_);

    QString text = ui_.message_text_edit->toHtml();

    SendInstantMessageThread* simt = new SendInstantMessageThread(text,
                                     convName_, conts, this);

    connect(simt, SIGNAL(sendMessageCompleted(bool, const QString&)),
          this, SLOT(onSendMessageComplete(bool, const QString&)));

    simt->start();
  }
}

void PersonalMessages::onSendMessageComplete(bool success,
                                             const QString& text) {
  if (success) {
    QDateTime theDate = QDateTime::currentDateTime();
    QString date = theDate.toString("dd.MM.yyyy hh:mm:ss");
    ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
    ui_.message_window->insertHtml(
        tr("<span style=\"background-color:#E0FFFF\">"
           "<br />%1 you said: %2 </span>").arg(date).arg(text));
    ui_.message_window->moveCursor(QTextCursor::End, QTextCursor::MoveAnchor);
  } else {
    const QString msg = tr("Error sending message.");
    QMessageBox::warning(this, tr("Error"), msg);
  }
  ui_.message_text_edit->clear();
}

void PersonalMessages::onSendInvite() {
  QString filename = QFileDialog::getSaveFileName(this, "Save file", "",
                                                  ".html");
  QFile f(filename);
  f.open(QIODevice::WriteOnly);
  QTextStream out(&f);
  out << ui_.message_window->toHtml();
  f.close();
}

void PersonalMessages::onSendFile() {
  QList<QString> conts;
  conts.push_back(convName_);

  // choose a file
  // starting directory should be the maidafe one.
  // TODO(Team#5#): 2009-07-28 - restrict file dialog to maidsafe directories
  // Possible to do by using Directory Entered Signal
  QString root;
#ifdef DEBUG
  printf("PersonalMessages::onFileSendClicked: opening the 'conversation'.\n");
  boost::progress_timer t;
#endif

#ifdef __WIN32__
  root = QString("%1:\\My Files").
         arg(ClientController::instance()->WinDrive());
  QFileDialog *qfd = new QFileDialog(this,
                     tr("File to share..."),
                     root, tr("Any file (*)"));
  int result = qfd->exec();
  if (result == QDialog::Rejected) {
    return;
  }
  QStringList fileNames = qfd->selectedFiles();
#else
  root = QString::fromStdString(file_system::MaidsafeFuseDir(
  ClientController::instance()->SessionName()).string() +
         "/My Files");
  QStringList fileNames = QFileDialog::getOpenFileNames(this,
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

void PersonalMessages::onTextClicked() {
  bool ok;
  QString startTags;
  font_ = QFontDialog::getFont(&ok, QFont("Arial", 10), this);
  if (ok) {
    formatHtml();
  } else {
     // the user canceled the dialog; font is set to the initial
     // value, in this case Helvetica [Cronyx], 10
  }
}

void PersonalMessages::onColorClicked() {
  bool ok;
  color_ = QColorDialog::getColor(QColor("black"), this);
  formatHtml();
}

bool PersonalMessages::eventFilter(QObject *obj, QEvent *event) {
  if (event->type() == QEvent::KeyPress) {
    QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
    if (keyEvent->key() == Qt::Key_Return) {
      onSendMessageClicked();
      return true;
    } else {
      return QObject::eventFilter(obj, event);
    }
  } else {
    return QObject::eventFilter(obj, event);
  }
}

void PersonalMessages::formatHtml() {
  QString currentHtml = ui_.message_text_edit->toHtml();
  ui_.message_text_edit->setFont(font_);
  ui_.message_text_edit->setTextColor(color_);
//  ui_.message_window->setPlainText(currentHtml);
}

void PersonalMessages::onSmilyClicked() {
  smilies_ = new Smily();

  connect(smilies_, SIGNAL(smilyChosen(int, int)),
          this,     SLOT(onSmilyChosen(int, int)));

  smilies_->show();
  QPoint globalPos = ui_.smilyButton->mapToGlobal(QPoint(0, 0));
  smilies_->move(globalPos);
}

void PersonalMessages::onSmilyChosen(int row, int column) {
  if (column == 0) {
    if (row == 0) {
      ui_.message_text_edit->insertHtml(
          "<img src=\"://smilies//smily_blue//sbiggrin.gif\";");
    }
    if (row == 1) {
      ui_.message_text_edit->insertHtml(
          "<img src=\"://smilies//smily_blue//scry.gif\";");
    }
    if (row == 2) {
      ui_.message_text_edit->insertHtml(
          "<img src=\"://smilies//smily_blue//smad.gif\";");
    }
    if (row == 3) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//ssmile.gif\";");
    }
  } else if (column == 1) {
    if (row == 0) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//sconfused.gif\";");
    }
    if (row == 1) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//sdrool.gif\";");
    }
    if (row == 2) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//ssad.gif\";");
    }
    if (row == 3) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//ssuprised.gif\";");
    }
  } else if (column == 2) {
    if (row == 0) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//scool.gif\";");
    }
    if (row == 1) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//shappy.gif\";");
    }
    if (row == 2) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//ssleepy.gif\";");
    }
    if (row == 3) {
      ui_.message_text_edit->insertHtml(
        "<img src=\"://smilies//smily_blue//stongue.gif\";");
    }
  }
}

void PersonalMessages::onMessageTextEdit() {
  QString text = ui_.message_text_edit->toHtml();

  if (text.contains(":-D")) {
    text.replace(":-D", "<img src=\"://smilies//smily_blue//sbiggrin.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-)")) {
    text.replace(":-)", "<img src=\"://smilies//smily_blue//ssmile.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-O")) {
    text.replace(":-O", "<img src=\"://smilies//smily_blue//ssuprised.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-P")) {
    text.replace(":-P", "<img src=\"://smilies//smily_blue//stongue.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-\\")) {
    text.replace(":-\\", "<img src=\"://smilies//smily_blue//sconfused.gif\";");  // NOLINT
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":)~")) {
    text.replace(":)~", "<img src=\"://smilies//smily_blue//sdrool.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(">:)")) {
    text.replace(">:)", "<img src=\"://smilies//smily_blue//smad.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains("8-)")) {
    text.replace("8-)", "<img src=\"://smilies//smily_blue//scool.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":')")) {
    text.replace(":')", "<img src=\"://smilies//smily_blue//scry.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-(")) {
    text.replace(":-(", "<img src=\"://smilies//smily_blue//ssad.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  } else if (text.contains(":-Z")) {
    text.replace(":-Z", "<img src=\"://smilies//smily_blue//ssleepy.gif\";");
    ui_.message_text_edit->setHtml(text);
    ui_.message_text_edit->moveCursor(QTextCursor::End,
                                      QTextCursor::MoveAnchor);
  }
}



