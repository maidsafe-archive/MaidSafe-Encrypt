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


SendEmailThread::SendEmailThread(const QString& text,
                                 const QString& convName,
                                 QList<QString> conts,
                                 QObject* parent) :
                                 WorkerThread(parent),
                                 text_(text), conts_(conts),
                                 convName_(convName) { }

SendEmailThread::~SendEmailThread() { }

void SendEmailThread::run() {
  qDebug() << "SendEmailThread::run" << text_;

  //int success = ClientController::instance()->newEmailSendMessage();

  //emit sendEmailCompleted(success, text_);
}

