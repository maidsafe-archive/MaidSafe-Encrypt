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

#include "maidsafe/lifestuff/widgets/lifestuff_login.h"

// qt
#include <QDebug>
#include <QValidator>
#include <QMessageBox>
#include <maidsafe/maidsafe-dht.h>

// std
#include <limits>

// core
#include "maidsafe/common/maidsafe_service_messages.pb.h"
#include "maidsafe/lifestuff/client/check_user_thread.h"
#include "maidsafe/lifestuff/client/validate_user_thread.h"

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

LifeStuffLogin::LifeStuffLogin(QWidget* parent)
    : QWidget(parent),
      got_enc_data_(false),
      user_exists_(false),
      state_(EDIT_USER) {
  ui_.setupUi(this);

  setAttribute(Qt::WA_DeleteOnClose);

  ui_.PinEdit->setValidator(new PinValidator(this));
  ui_.PassEdit->setValidator(new PasswordValidator(this));
  ui_.createBtn->setAutoDefault(true);
  ui_.loginBtn->setAutoDefault(true);

  ui_.PassEdit->installEventFilter(this);
  ui_.PinEdit->installEventFilter(this);
  ui_.UserEdit->installEventFilter(this);
  reset();

  connect(ui_.UserEdit, SIGNAL(textEdited(const QString&)),
          this,         SLOT(onUsernameEdited(const QString&)));

  connect(ui_.PinEdit, SIGNAL(textEdited(const QString&)),
          this,    SLOT(onPinEdited(const QString&)));

  connect(ui_.PassEdit, SIGNAL(textEdited(const QString&)),
          this,         SLOT(onPasswordEdited(const QString&)));

  connect(ui_.UserEdit, SIGNAL(returnPressed()),
          this,         SLOT(onUsernameDone()));

  connect(ui_.PinEdit, SIGNAL(returnPressed()),
          this,    SLOT(onPinDone()));

  connect(ui_.PassEdit, SIGNAL(returnPressed()),
          this,         SLOT(onPasswordDone()));

  connect(ui_.clearBtn, SIGNAL(clicked(bool)),
          this,      SLOT(onClearClicked()));

  connect(ui_.createBtn, SIGNAL(clicked(bool)),
          this,       SLOT(onCreateClicked()));

  connect(ui_.loginBtn, SIGNAL(clicked(bool)),
          this,      SLOT(onLoginClicked()));

  updateUI();
}

LifeStuffLogin::~LifeStuffLogin() {}

void LifeStuffLogin::StartProgressBar() {
  ui_.UserEdit->setVisible(false);
  ui_.PinEdit->setVisible(false);
  ui_.PassEdit->setVisible(false);
  ui_.clearBtn->setVisible(false);
  ui_.createBtn->setVisible(false);
  ui_.loginBtn->setVisible(false);
  ui_.progress_bar->setVisible(true);
  ui_.progress_label->setVisible(true);
  ui_.progress_label->setText(tr("Joining the network..."));
}

void LifeStuffLogin::onUsernameEdited(const QString&) {
  updateUI();
}

void LifeStuffLogin::onPinEdited(const QString&) {
  updateUI();
}

void LifeStuffLogin::onPasswordEdited(const QString&) {
  // TODO(Team#5#): 2009-08-27 - indicate password strength?
  if (!user_exists_) {
  }

  updateUI();
}

void LifeStuffLogin::updateUI() {
  switch (state_) {
    case EDIT_USER:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.PassEdit->setEnabled(false);
        break;
      }
    case EDIT_PIN:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.PassEdit->setEnabled(false);
        break;
      }
    case WAITING_ON_USER_CHECK:
      {
        ui_.progress_label->setVisible(true);
        ui_.progress_bar->setVisible(true);
        ui_.PassEdit->setEnabled(false);

        ui_.progress_label->setText(tr("Checking user details..."));
        break;
      }
    case EDIT_PASSWORD:
      {
        ui_.progress_label->setVisible(false);
        ui_.progress_bar->setVisible(false);
        ui_.PassEdit->setEnabled(true);
        ui_.PassEdit->setFocus(Qt::OtherFocusReason);
        break;
      }
    case LOGGING_IN:
      {
          ui_.progress_label->setVisible(true);
          ui_.progress_bar->setVisible(true);
          ui_.PassEdit->setEnabled(false);

          ui_.progress_label->setText(tr("Validating password..."));
          break;
      }
  }

  ui_.loginBtn->setVisible(user_exists_);
  ui_.loginBtn->setEnabled((state_ == EDIT_PASSWORD) && validate(ui_.PassEdit));

  ui_.createBtn->setVisible(!user_exists_ && !username().isEmpty());
  ui_.createBtn->setEnabled((state_ == EDIT_PASSWORD) && validate(ui_.PassEdit));
}

void LifeStuffLogin::onUsernameDone() {
  if (!validate(ui_.UserEdit))
    return;

  advance(ui_.UserEdit, ui_.PinEdit);

  state_ = EDIT_PIN;
}

void LifeStuffLogin::onPinDone() {
  qDebug() << "LifeStuffLogin::onPinDone()";
  if (!validate(ui_.PinEdit))
      return;

  advance(ui_.PinEdit, ui_.PassEdit);

  // checkPin();

  // (password is disabled until callback completes)
  updateUI();
}

void LifeStuffLogin::checkPin() {
  state_ = WAITING_ON_USER_CHECK;
  CheckUserThread *cut = new CheckUserThread(username(), pin());
  connect(cut,  SIGNAL(completed(bool)),
          this, SLOT(UserExists_Callback(bool)));
  cut->start();
}

void LifeStuffLogin::onPasswordDone() {
  if (!validate(ui_.PassEdit))
    return;

  if (user_exists_) {
      ui_.loginBtn->animateClick();
  } else {
    ui_.createBtn->animateClick();
  }
}

void LifeStuffLogin::onClearClicked() {
  reset();
}

void LifeStuffLogin::onCreateClicked() {
  Q_ASSERT(!user_exists_);
  Q_ASSERT(validate(ui_.PassEdit));

  emit newUser(ui_.UserEdit->text(), ui_.PinEdit->text(),
                ui_.PassEdit->text());
  this->hide();
}

void LifeStuffLogin::onLoginClicked() {
  Q_ASSERT(user_exists_);
  Q_ASSERT(validate(ui_.PassEdit));

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

void LifeStuffLogin::reset() {
  ui_.UserEdit->setVisible(true);
  ui_.PinEdit->setVisible(true);
  ui_.PassEdit->setVisible(true);
  ui_.clearBtn->setVisible(true);
  ui_.createBtn->setVisible(true);
  ui_.loginBtn->setVisible(true);
  ui_.progress_bar->setVisible(false);
  ui_.progress_label->setVisible(false);

  ui_.PinEdit->clear();
  ui_.PinEdit->setEnabled(false);

  ui_.PassEdit->clear();
  ui_.PassEdit->setEnabled(false);

  ui_.createBtn->hide();
  ui_.loginBtn->hide();

  got_enc_data_ = false;
  user_exists_ = false;

  state_ = EDIT_USER;

  ui_.PassEdit->setEchoMode(QLineEdit::Normal);
  ui_.PassEdit->setText("Password");

  ui_.UserEdit->setEchoMode(QLineEdit::Normal);
  ui_.UserEdit->setText("Username");

  ui_.PinEdit->setEchoMode(QLineEdit::Normal);
  ui_.PinEdit->setText("PIN");

  ui_.UserEdit->clear();
  ui_.UserEdit->setEnabled(true);
  ui_.UserEdit->setFocus(Qt::OtherFocusReason);

  updateUI();
}

QString LifeStuffLogin::username() const {
  return ui_.UserEdit->text();
}

QString LifeStuffLogin::password() const {
  return ui_.PassEdit->text();
}

QString LifeStuffLogin::pin() const {
  return ui_.PinEdit->text();
}

void LifeStuffLogin::UserExists_Callback(bool b) {
  got_enc_data_ = b;
  user_exists_ = b;

  state_ = EDIT_PASSWORD;

  // can't poke UI here as it's not thread safe...
  // updateUI();

  QApplication::postEvent(this, new ThreadSafeUpdateEvent,
                          Qt::HighEventPriority);
}

void LifeStuffLogin::UserValidated(bool b) {
  if (b) {
    emit existingUser();
    this->hide();
  } else {
    QMessageBox::warning(this, tr("Error"),
                         tr("Please verify your credentials."));
    reset();
  }
}

bool LifeStuffLogin::event(QEvent* event) {
  if (event->type() ==
      static_cast<QEvent::Type>(ThreadSafeUpdateEvent::EventNumber)) {
    updateUI();
    return true;
  }
  return QWidget::event(event);
}

bool LifeStuffLogin::focusNextPrevChild(bool next) {
  QLineEdit* c = static_cast<QLineEdit*>(focusWidget());
  if (c == ui_.PassEdit || c == ui_.PinEdit || c == ui_.UserEdit) {
    bool clear = false;
    QLineEdit* f = NULL;
    if (next) {
      if ((c == ui_.UserEdit) && validate(ui_.UserEdit)) {
          f = ui_.PinEdit;
          state_ = EDIT_PIN;
      } else if ((c == ui_.PinEdit) && validate(ui_.PinEdit)) {
          f = ui_.PassEdit;
          if (state_ != WAITING_ON_USER_CHECK)
            checkPin();
      }
    } else {
      if (c == ui_.PassEdit) {
        f = ui_.PinEdit;
        clear = true;
        state_ = EDIT_PIN;
      } else if (c == ui_.PinEdit) {
        f = ui_.UserEdit;
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

void LifeStuffLogin::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

bool LifeStuffLogin::eventFilter(QObject *obj, QEvent *event) {
   if (obj == ui_.UserEdit) {
       if (event->type() == QEvent::FocusIn) {
           if (ui_.UserEdit->text() == tr("Username")) {
              ui_.UserEdit->clear();
              QPalette pal;
              pal.setColor(QPalette::Text, Qt::black);
              ui_.UserEdit->setPalette(pal);
           }
           return true;
       } else {
           return false;
       }
   } else if (obj == ui_.PinEdit) {
      if (event->type() == QEvent::FocusIn) {
        if (ui_.PinEdit->text() == tr("PIN")) {
              ui_.PinEdit->clear();
                 ui_.PinEdit->setEchoMode(QLineEdit::Password);
           }
           return true;
      } else {
      return false;
      }          
   } else if (obj == ui_.PassEdit) {
     if (event->type() == QEvent::FocusIn) {
        if (ui_.PassEdit->text() == tr("Password")) {
              ui_.PassEdit->clear();
              ui_.PassEdit->setEchoMode(QLineEdit::Password);
           }
           return true;
      } else {
      return false;
      }          
   } else {
     return LifeStuffLogin::eventFilter(obj, event);
   }
}


