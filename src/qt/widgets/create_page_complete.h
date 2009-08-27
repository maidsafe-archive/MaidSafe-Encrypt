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

#ifndef QT_WIDGETS_CREATE_PAGE_COMPLETE_H_
#define QT_WIDGETS_CREATE_PAGE_COMPLETE_H_

// qt
#include <QWizardPage>

// generated
#include "ui_create_page_complete.h"

class QWizardPage;

class CreateCompletePage : public QWizardPage {
  Q_OBJECT

 public:
  explicit CreateCompletePage(QWidget* parent = 0);
  virtual ~CreateCompletePage();

  void showCreationProgress(bool show);

  // Set a message for the main mody of the page
  void setMessage(const QString& msg);

  // Set a message to be displayed above the progress bar
  void setProgressMessage(const QString& msg);

  // Implementaion of QWizardPage interface
  virtual void cleanupPage();

 private:
  Ui::complete ui_;
};

#endif  // QT_WIDGETS_CREATE_PAGE_COMPLETE_H_

