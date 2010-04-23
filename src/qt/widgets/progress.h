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
 *  Created on: May 6, 2009
 *      Author: Team
 */

#ifndef QT_WIDGETS_PROGRESS_H_
#define QT_WIDGETS_PROGRESS_H_

// qt
#include <QWidget>

// generated
#include "ui_progress.h"


// General purpose page for showing feedback during long lived operations
class Progress : public QWidget {
    Q_OBJECT

 public:
  explicit Progress(QWidget* parent = 0);
  virtual ~Progress();

  // Set the title for the page
  void setTitle(const QString& msg);

  // Set a message for the main mody of the page
  void setMessage(const QString& msg);

  // Set a message to be displayed above the progress bar
  void setProgressMessage(const QString& msg);

  // Indicate that an error has occured
  /*!
      If \param error is true the 'OK' button will be shown rather than
      'Cancel'
  */
  void setError(bool error);

  // Specify whether the current operation is cancellable
  void setCanCancel(bool);

  signals:
    // User has acknowledged the error
    void ok();
    // User wishes to cancel the current operation
    void cancel();

 private:
  Ui::Progress ui_;

 protected:
  void changeEvent(QEvent *event);
};

#endif  // QT_WIDGETS_PROGRESS_H_

