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

#include "qt/client/send_email_thread.h"

// qt
#include <QDebug>

// core
#include "qt/client/client_controller.h"


SendEmailThread::SendEmailThread(const QString& subject,
																const QString& message,
																const QList<QString>& to,
																const QList<QString>& cc,
																const QList<QString>& bcc,
																const QString& conversation,
                                 QObject* parent) :
                                 WorkerThread(parent),
                                 subject_(subject), message_(message),
                                 to_(to), cc_(cc), bcc_(bcc),
																 conversation_(conversation){																 
}

SendEmailThread::~SendEmailThread() { }

void SendEmailThread::run() {
  qDebug() << "SendEmailThread::run" << message_;

  bool success = ClientController::instance()->sendEmail(subject_,
															message_, to_, cc_, bcc_, conversation_);

  emit sendEmailCompleted(success, subject_);
}

