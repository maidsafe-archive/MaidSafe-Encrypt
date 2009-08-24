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

#ifndef QT_SYSTEM_TRAY_H_
#define QT_SYSTEM_TRAY_H_

#include <QObject>
#include <QSystemTrayIcon>

class QMenu;
class QAction;

//! Wrapper round the system tray icon functionality
class SystemTrayIcon : public QSystemTrayIcon
{
    Q_OBJECT
public:
    static SystemTrayIcon* instance();
    virtual ~SystemTrayIcon();
    void ChangeStatus(int status);

signals:
    void open();
    void close();
    void quit();

    void dataShare();
    void sendFile();

protected:
    explicit SystemTrayIcon();

private slots:
    void onActivated( QSystemTrayIcon::ActivationReason reason );

private:
    QMenu* menu_;
    QAction* action_open_;
    QAction* action_close_;
    QAction* action_quit_;

    QAction* action_data_share_;
    QAction* action_send_file_;
};

#endif // QT_SYSTEM_TRAY_H_
