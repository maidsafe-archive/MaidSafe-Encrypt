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

#ifndef QT_WIDGETS_LOGIN_H_
#define QT_WIDGETS_LOGIN_H_

// qt
#include <QWidget>

// std
#include <string>

// generated
#include "ui_login.h"

// Main Login screen for Perpetual Data
/*!
    Has fields for:

      Username
      Pin
      Password

    Only one field is enabled at a time.  To advance to the next field
    valid text must have been entered.

    As usernames and pins are entered we will check to see if they
    are new or existing users.
*/
class Login : public QWidget {
  Q_OBJECT

 public:
  explicit Login(QWidget* parent = 0);
  virtual ~Login();

  QString username() const;
  QString pin() const;
  QString password() const;

  void clearFields() { reset(); }
  void StartProgressBar();
  // Clear all fields, puts focus back to username
  void reset();

 protected:
  // handle custom events (for thread safe ui updates)
  virtual bool event(QEvent* event);
  // custom tab focus behaviour lets us advance to disabled widgets
  /*!
      can tab forward from username and pin
      can tab bcakwards from pin and password.
  */
  virtual bool focusNextPrevChild(bool next);

  signals:
    // Details of an existing user have been entered and 'Login' clicked
    /*!
        emitted when a valid username, pin and verified password have been
        correctly entered
    */
    void existingUser();

    // Details of a new user have been entered and 'Create' clicked.
    void newUser();

  private slots:
    void onUsernameEdited(const QString& text);
    void onPinEdited(const QString& text);
    void onPasswordEdited(const QString& text);

    void onUsernameDone();
    void onPinDone();
    void onPasswordDone();

    void onClearClicked();
    void onCreateClicked();
    void onLoginClicked();
    void UserExists_Callback(bool b);

  private:
    Ui::LoginScreen ui_;


    // Update field enabled ness as usernames and pins are changed
    void updateUI();

    // valid/known combination of username and pin
    bool got_enc_data_;
    // waiting on the username/pin check
    bool waiting_on_callback_;
    // user exists
    bool user_exists_;

    void checkPin();

    typedef enum State {
      EDIT_USER,
      EDIT_PIN,
      WAITING_ON_USER_CHECK,
      EDIT_PASSWORD
    };

    State state_;
};

#endif  // QT_WIDGETS_LOGIN_H_

