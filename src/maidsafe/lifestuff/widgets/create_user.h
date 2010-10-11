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

#ifndef QT_WIDGETS_CREATE_USER_H_
#define QT_WIDGETS_CREATE_USER_H_

// std

// qt
#include <QWidget>

// generated
#include "ui_create.h"

class QWizardPage;

// Main User creation screen for Perpetual Data
/*!
    Takes the user through a series of pages:
     - welcome
     - license agreement
     - vault options
        - local
        - buy space
        - friend's space
     - set up public name
     - congratulation

     Creation process is split into pages which are responsible for
     each stage.
*/
class CreateUser : public QWidget {
  Q_OBJECT

 public:
  explicit CreateUser(QWidget* parent = 0);
  virtual ~CreateUser();

  // Reset the wizard in preparation for use
  void reset();
  int VaultType();
  QString SpaceOffered() const;
  QString PortChosen() const;
  QString DirectoryChosen() const;

  signals:
    // Process is complete
    void complete();

    // ! Process has been cancelled
    void cancelled();

  private slots:
    void onBack();
    void onNext();
    void onCompleteChanged();

 private:
  Ui::CreateScreen ui_;
  QList<QWizardPage*> pages_;
  int vault_type_;
  QString space_;
  QString port_;
  QString directory_;

  // Switches to the page at given index
  /*!
      Updates buttons, titles and cleanrs pages if going backwards.

      \param dir direction of page navigation
  */
  void setCurrentPage(int index, int dir);

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_CREATE_USER_H_

