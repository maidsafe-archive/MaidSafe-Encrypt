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
 *  Created on: May 19, 2010
 *      Author: Stephen
 */

#ifndef QT_CLIENT_SEND_EMAIL_THREAD_H_
#define QT_CLIENT_SEND_EMAIL_THREAD_H_

#include "qt/client/worker_thread.h"

// Worker thread for sending an email message
/*!
    sending a message is blocking and can take a while so we
    use a worker thread to ensure that it doesn't block the main gui.

    Currently intended for single use.
*/
class SendEmailThread : public WorkerThread {
  Q_OBJECT
 public:
  SendEmailThread(const QString& subject, const QString& message,
									const QList<QString>& to, const QList<QString>& cc,
									const QList<QString>& bcc, const QString& conversation,
									QObject* parent = 0);
  virtual ~SendEmailThread();

  virtual void run();

 private:
  QString subject_;
  QString message_;
  QList<QString> to_;
  QList<QString> cc_;
  QList<QString> bcc_;
  QString conversation_;

  signals:
  void sendEmailCompleted(int, const QString&);
};

#endif  // QT_CLIENT_SEND_EMAIL_THREAD_H_
