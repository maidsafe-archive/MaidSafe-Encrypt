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

#include "qt/widgets/system_tray_icon.h"

// qt
#include <QDebug>
#include <QMenu>
#include <QAction>

// static
SystemTrayIcon* SystemTrayIcon::instance() {
  static SystemTrayIcon icon;
  return &icon;
}

SystemTrayIcon::SystemTrayIcon()
  : menu_(NULL), action_open_(NULL), action_close_(NULL),
    action_quit_(NULL) {
  if (!QSystemTrayIcon::isSystemTrayAvailable()) {
    qWarning() << "System tray icon not available";
    return;
  }

  if (!QSystemTrayIcon::supportsMessages()) {
    qWarning() << "System tray messages not available";
  }

  setIcon(QPixmap(":/icons/16/globe"));

  {
    action_open_ = new QAction(tr("&Restore window"), this);
    connect(action_open_, SIGNAL(triggered()), this, SIGNAL(open()));

    action_close_ = new QAction(tr("&Close"), this);
    connect(action_close_, SIGNAL(triggered()), this, SIGNAL(close()));

    action_quit_ = new QAction(tr("&Exit"), this);
    connect(action_quit_, SIGNAL(triggered()), this, SIGNAL(quit()));

    action_data_share_ = new QAction(tr("&Data"), this);
    connect(action_data_share_, SIGNAL(triggered()), this, SIGNAL(dataShare()));

    action_send_file_ = new QAction(tr("&Send a file"), this);
    connect(action_send_file_, SIGNAL(triggered()), this, SIGNAL(sendFile()));
  }

  {
    menu_ = new QMenu;
    menu_->addAction(action_open_);

    QMenu* share_menu = menu_->addMenu(tr("&Create a share"));
    share_menu->addAction(action_data_share_);
    share_menu->addAction(action_send_file_);

    // menu_->addAction(action_close_);
    menu_->addSeparator();
    menu_->addAction(action_quit_);

    setContextMenu(menu_);
  }

  connect(this, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
          this, SLOT(onActivated(QSystemTrayIcon::ActivationReason)));

  setVisible(true);
}

SystemTrayIcon::~SystemTrayIcon() {
  setVisible(false);
  delete menu_;
  menu_ = NULL;
}

void SystemTrayIcon::onActivated(QSystemTrayIcon::ActivationReason reason) {
  qDebug() << "Activated:" << reason;

  QString message;
  switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
      {
        emit open();
      }
    default:
        message = "unknown";
  }
}

void SystemTrayIcon::ChangeStatus(int status) {
  switch (status) {
    case 0: setIcon(QPixmap(":/icons/16/globe")); break;
    case 1: setIcon(QPixmap(":/icons/16/offline")); break;
    default: break;
  }
}

void SystemTrayIcon::changeEvent(QEvent*) {
  // TODO(Team): Implement for QObject
//  if (event->type() == QEvent::LanguageChange) {
//    // TODO(Team): Get lang from ClientController and Update as Neccesary
//    ui_.retranslateUi(this);
//  } else {
//    QWidget::changeEvent(event);
//  }
}

