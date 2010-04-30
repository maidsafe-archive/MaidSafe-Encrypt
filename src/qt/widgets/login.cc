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

#include "qt/widgets/login.h"

// qt
#include <QDebug>
#include <QValidator>
#include <QMessageBox>
#include <maidsafe/maidsafe-dht.h>

// std
#include <limits.h>

// core
#include "protobuf/maidsafe_service_messages.pb.h"
#include "qt/client/check_user_thread.h"
#include "qt/client/validate_user_thread.h"

// local
namespace {

class ThreadSafeUpdateEvent : public QEvent {
 public:
  enum { EventNumber = QEvent::User+7 };

  explicit ThreadSafeUpdateEvent()
      : QEvent(static_cast<QEvent::Type>(EventNumber)) {}
};

//  bool isCorrectPassword(const QString& password) {
//    return maidsafe::ClientController::getInstance()->ValidateUser(
//           password.toStdString());
//  }

// switch focus and enable fields
void advance(QLineEdit* from, QLineEdit* to,
             Qt::FocusReason reason = Qt::OtherFocusReason,
             bool clearPrevious = false) {
  if (clearPrevious) {
    from->blockSignals(true);
    from->clear();
    from->blockSignals(false);
  }
  from->setDisabled(true);
  to->setEnabled(true);
  to->setFocus(reason);
}

// validate the text in an edit against its validator
bool validate(QLineEdit* edit) {
  if (!edit->validator())
    return true;

  QString text = edit->text();
  int pos = 0;
  return edit->validator()->validate(text, pos) ==
         QValidator::Acceptable;
}

// Must be at least a 4 digit number
class PinValidator : public QIntValidator {
 public:
  explicit PinValidator(QObject* parent) : QIntValidator(0, INT_MAX, parent) { }

  virtual State validate(QString& input, int& pos) const {
    State s = QIntValidator::validate(input, pos);
    if (s == Acceptable && input.length() < 4)
        return Intermediate;
    return s;
  }

  virtual void fixup(QString& input) {
      QIntValidator::fixup(input);
  }
};

// Must be > 4 characters, no spaces
class PasswordValidator : public QValidator {
 public:
  explicit PasswordValidator(QObject* parent) : QValidator(parent) { }

  virtual State validate(QString& input, int&) const {
    if (input.contains(" "))
        return Invalid;
    if (input.length() < 4)
        return Intermediate;
    return Acceptable;
  }

  virtual void fixup(QString& input) {
    input.remove(" ");
    QValidator::fixup(input);
  }
};

}  // namespace

Login::Login(QWidget* parent)
    : QWidget(parent),
      got_enc_data_(false),
      user_exists_(false),
      state_(EDIT_USER) {
  ui_.setupUi(this);

  ui_.pin->setValidator(new PinValidator(this));
  ui_.password->setValidator(new PasswordValidator(this));
  ui_.login->setAutoDefault(true);
  ui_.create->setAutoDefault(true);

  reset();

  connect(ui_.username, SIGNAL(textEdited(const QString&)),
          this,         SLOT(onUsernameEdited(const QString&)));

  connect(ui_.pin, SIGNAL(textEdited(const QString&)),
          this,    SLOT(onPinEdited(const QString&)));

  connect(ui_.password, SIGNAL(textEdited(const QString&)),
          this,         SLOT(onPasswordEdited(const QString&)));

  connect(ui_.username, SIGNAL(returnPressed()),
          this,         SLOT(onUsernameDone()));

  connect(ui_.pin, SIGNAL(returnPressed()),
          this,    SLOT(onPinDone()));

  connect(ui_.password, SIGNAL(returnPressed()),
          this,         SLOT(onPasswordDone()));

  connect(ui_.clear, SIGNAL(clicked(bool)),
          this,      SLOT(onClearClicked()));

  connect(ui_.create, SIGNAL(clicked(bool)),
          this,       SLOT(onCreateClicked()));

  connect(ui_.login, SIGNAL(clicked(bool)),
          this,      SLOT(onLoginClicked()));

  updateUI();
}

Login::~Login() {}

void Login::StartProgressBar() {
  ui_.label->setVisible(false);
  ui_.label_2->setVisible(false);
  ui_.label_3->setVisible(false);
  ui_.username->setVisible(false);
  ui_.pin->setVisible(false);
  ui_.password->setVisible(false);
  ui_.clear->setVisible(false);
  ui_.create->setVisible(false);
  ui_.login->setVisible(false);
  ui_.progress_bar->setVisible(true);
  ui_.progress_label->setVisible(true);
  ui_.progress_label->setText(tr("Joining the network..."));
}

void Login::onUsernameEdited(const QString&) {
  updateUI();
}

void Login::onPinEdited(const QString&) {
  updateUI();
}

void Login::onPasswordEdited(const QString&) {
  // TODO(Team#5#): 2009-08-27 - indicate password strength?
  if (!user_exists_) {
  }

  updateUI();
}

void Login::updateUI() {
  switch (state_) {
    case EDIT_USER:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.password->setEnabled(false);
        break;
      }
    case EDIT_PIN:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.password->setEnabled(false);
        break;
      }
    case WAITING_ON_USER_CHECK:
      {
        ui_.progress_label->setVisible(true);
        ui_.progress_bar->setVisible(true);
        ui_.password->setEnabled(false);

        ui_.progress_label->setText(tr("Checking user details..."));
        break;
      }
    case EDIT_PASSWORD:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.password->setEnabled(true);
        ui_.password->setFocus(Qt::OtherFocusReason);
        break;
      }
    case LOGGING_IN:
      {
          ui_.progress_label->setVisible(true);
          ui_.progress_bar->setVisible(true);
          ui_.password->setEnabled(false);

          ui_.progress_label->setText(tr("Validating password..."));
          break;
      }
  }

  ui_.login->setVisible(user_exists_);
  ui_.login->setEnabled((state_ == EDIT_PASSWORD) && validate(ui_.password));

  ui_.create->setVisible(!user_exists_ && !username().isEmpty());
  ui_.create->setEnabled((state_ == EDIT_PASSWORD) && validate(ui_.password));
}

void Login::onUsernameDone() {
  if (!validate(ui_.username))
    return;

  advance(ui_.username, ui_.pin);

  state_ = EDIT_PIN;
}

void Login::onPinDone() {
  qDebug() << "Login::onPinDone()";
  if (!validate(ui_.pin))
      return;

  advance(ui_.pin, ui_.password);

  // checkPin();

  // (password is disabled until callback completes)
  updateUI();
}

void Login::checkPin() {
  state_ = WAITING_ON_USER_CHECK;
  CheckUserThread *cut = new CheckUserThread(username(), pin());
  connect(cut,  SIGNAL(completed(bool)),
          this, SLOT(UserExists_Callback(bool)));
  cut->start();
}

void Login::onPasswordDone() {
  if (!validate(ui_.password))
    return;

  if (user_exists_) {
      ui_.login->animateClick();
  } else {
    ui_.create->animateClick();
  }
}

void Login::onClearClicked() {
  reset();
}

void Login::onCreateClicked() {
  Q_ASSERT(!user_exists_);
  Q_ASSERT(validate(ui_.password));

  emit newUser();
}

void Login::onLoginClicked() {
  Q_ASSERT(user_exists_);
  Q_ASSERT(validate(ui_.password));

  ValidateUserThread *vut = new ValidateUserThread(password());
  connect(vut,  SIGNAL(completed(bool)),
          this, SLOT(UserValidated(bool)));
  vut->start();

  state_ = LOGGING_IN;

  updateUI();
  // verify the password
//  if (!isCorrectPassword(password())) {
//    QMessageBox::warning(this, tr("Error!"),
//                         tr("Please verify your credentials."));
//    return;
//  }

//  emit existingUser();
}

void Login::reset() {
  ui_.label->setVisible(true);
  ui_.label_2->setVisible(true);
  ui_.label_3->setVisible(true);
  ui_.username->setVisible(true);
  ui_.pin->setVisible(true);
  ui_.password->setVisible(true);
  ui_.clear->setVisible(true);
  ui_.create->setVisible(true);
  ui_.login->setVisible(true);
  ui_.progress_bar->setVisible(false);
  ui_.progress_label->setVisible(false);

  ui_.username->clear();
  ui_.username->setEnabled(true);
  ui_.username->setFocus(Qt::OtherFocusReason);

  ui_.pin->clear();
  ui_.pin->setEnabled(false);

  ui_.password->clear();
  ui_.password->setEnabled(false);

  ui_.create->hide();
  ui_.login->hide();

  got_enc_data_ = false;
  user_exists_ = false;

  state_ = EDIT_USER;

  updateUI();
}

QString Login::username() const {
  return ui_.username->text();
}

QString Login::password() const {
  return ui_.password->text();
}

QString Login::pin() const {
  return ui_.pin->text();
}

void Login::UserExists_Callback(bool b) {
  got_enc_data_ = b;
  user_exists_ = b;

  state_ = EDIT_PASSWORD;

  // can't poke UI here as it's not thread safe...
  // updateUI();

  QApplication::postEvent(this, new ThreadSafeUpdateEvent,
                          Qt::HighEventPriority);
}

void Login::UserValidated(bool b) {
  if (b) {
    emit existingUser();
  } else {
    QMessageBox::warning(this, tr("Error"),
                         tr("Please verify your credentials."));
    reset();
  }
}

bool Login::event(QEvent* event) {
  if (event->type() ==
      static_cast<QEvent::Type>(ThreadSafeUpdateEvent::EventNumber)) {
    updateUI();
    return true;
  }
  return QWidget::event(event);
}

bool Login::focusNextPrevChild(bool next) {
  QLineEdit* c = static_cast<QLineEdit*>(focusWidget());
  if (c == ui_.password || c == ui_.pin || c == ui_.username) {
    bool clear = false;
    QLineEdit* f = NULL;
    if (next) {
      if ((c == ui_.username) && validate(ui_.username)) {
          f = ui_.pin;
          state_ = EDIT_PIN;
      } else if ((c == ui_.pin) && validate(ui_.pin)) {
          f = ui_.password;
          if (state_ != WAITING_ON_USER_CHECK)
            checkPin();
      }
    } else {
      if (c == ui_.password) {
        f = ui_.pin;
        clear = true;
        state_ = EDIT_PIN;
      } else if (c == ui_.pin) {
        f = ui_.username;
        clear = true;
        state_ = EDIT_USER;
      }
    }

    if (f) {
      advance(c, f, next ? Qt::TabFocusReason : Qt::BacktabFocusReason, clear);
      updateUI();
      return true;
    }
  }

  return QWidget::focusNextPrevChild(next);
}

void Login::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

