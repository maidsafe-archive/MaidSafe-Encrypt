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
 *  Created on: May 19, 2009
 *      Author: Team
 */

#include "qt/perpetual_data.h"

// qt
#include <QDebug>
#include <QTranslator>
#include <QMessageBox>
#include <QProcess>
#include <QList>
#include <QFileDialog>
#include <QInputDialog>
#include <boost/progress.hpp>
#include <QLibraryInfo>

#include <list>
#include <string>

// core
#include "qt/client/client_controller.h"

// local
#include "qt/widgets/login.h"
#include "qt/widgets/create_user.h"
#include "qt/widgets/progress.h"
#include "qt/widgets/user_panels.h"
#include "qt/widgets/system_tray_icon.h"
#include "qt/widgets/user_settings.h"

#include "qt/client/create_user_thread.h"
#include "qt/client/join_kademlia_thread.h"
#include "qt/client/mount_thread.h"
#include "qt/client/save_session_thread.h"
#include "qt/client/user_space_filesystem.h"

// generated
#include "ui_about.h"

PerpetualData::PerpetualData(QWidget* parent)
    : QMainWindow(parent), quitting_(false), login_(NULL), create_(NULL),
      message_status_(NULL), state_(LOGIN) {
  setAttribute(Qt::WA_DeleteOnClose, false);
  setWindowIcon(QPixmap(":/icons/16/globe"));
  ui_.setupUi(this);

  statusBar()->show();
  statusBar()->addPermanentWidget(message_status_ = new QLabel);

  createActions();
  createMenus();
  showLoggedOutMenu();
  // create the main screens
  login_ = new Login;
  create_ = new CreateUser;
  progressPage_ = new Progress;
  userPanels_ = new UserPanels;

  ui_.stackedWidget->addWidget(login_);
  ui_.stackedWidget->addWidget(create_);
  ui_.stackedWidget->addWidget(progressPage_);
  ui_.stackedWidget->addWidget(userPanels_);

  setCentralWidget(ui_.stackedWidget);
  ui_.stackedWidget->setCurrentWidget(login_);

  JoinKademliaThread *jkt = new JoinKademliaThread(this);
  connect(jkt,  SIGNAL(completed(bool)),
          this, SLOT(onJoinKademliaCompleted(bool)));
  jkt->start();

  login_->StartProgressBar();

  qtTranslator = new QTranslator;
  myAppTranslator = new QTranslator;
  QString locale = QLocale::system().name().left(2);
  qtTranslator->load("qt_" + locale,
            QLibraryInfo::location(QLibraryInfo::TranslationsPath));
  qApp->installTranslator(qtTranslator);

  bool res = myAppTranslator->load(":/translations/pd_translation_" + locale);
  if (res) {
    qApp->installTranslator(myAppTranslator);
    ui_.retranslateUi(this);
  }
}

void PerpetualData::onJoinKademliaCompleted(bool b) {
  if (!b) {
    qDebug() << "U didn't join kademlia, so fuck U!";
    return;
  }
  login_->reset();
  qDebug() << "PerpetualData::onJoinKademliaCompleted";
  setState(LOGIN);

  connect(ClientController::instance(),
          SIGNAL(messageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)),
          this,
          SLOT(onMessageReceived(ClientController::MessageType,
                                    const QDateTime&,
                                    const QString&,
                                    const QString&,
                                    const QString&)));

  connect(ClientController::instance(),
                SIGNAL(shareReceived(const QString&, const QString&)),
          this, SLOT(onShareReceived(const QString&, const QString&)));

  connect(ClientController::instance(),
                SIGNAL(fileReceived(const maidsafe::InstantMessage&)),
          this, SLOT(onFileReceived(const maidsafe::InstantMessage&)));

  connect(ClientController::instance(),
                SIGNAL(connectionStatusChanged(int)),
          this, SLOT(onConnectionStatusChanged(int)));
}

PerpetualData::~PerpetualData() {
//  onLogout();
}

void PerpetualData::createActions() {
// most of the actions have already been created for the menubar
  actions_[ QUIT ] = ui_.actionQuit;
  actions_[ LOGOUT ] = ui_.actionLogout;
  actions_[ FULLSCREEN ] = ui_.actionFullScreen;
  actions_[ ABOUT ] = ui_.actionAbout;
  actions_[ MY_FILES ] = ui_.actionMy_Files;
  actions_[ PRIVATE_SHARES ] = ui_.actionPrivate_Shares;
  actions_[ GO_OFFLINE ] = ui_.actionOffline;
  actions_[ SETTINGS ] = ui_.actionSettings_2;
  actions_[ ONLINE ] = ui_.actionAvailable;
  actions_[ AWAY ] = ui_.actionAway;
  actions_[ BUSY ] = ui_.actionBusy;
  actions_[ OFFLINE_2 ] = ui_.actionOffline_2;
// actions_[ SAVE_SESSION ] = ui_.actionSave_Session;

// Remove Status Menu until implemented
  ui_.menuStatus->setVisible(false);
  actions_[ ONLINE ]->setVisible(false);
  actions_[ AWAY ]->setVisible(false);
  actions_[ BUSY ]->setVisible(false);
  actions_[ OFFLINE_2 ]->setVisible(false);
  actions_[ QUIT ]->setShortcut(Qt::ALT + Qt::Key_F4);
  actions_[ FULLSCREEN ]->setShortcut(Qt::Key_F11);

  connect(actions_[ QUIT ], SIGNAL(triggered()),
          this,             SLOT(onQuit()));
  connect(actions_[ LOGOUT ], SIGNAL(triggered()),
          this,               SLOT(onLogout()));
  connect(actions_[ FULLSCREEN ], SIGNAL(toggled(bool)),
          this,              SLOT(onToggleFullScreen(bool)));
  connect(actions_[ ABOUT ], SIGNAL(triggered()),
          this,              SLOT(onAbout()));
  connect(actions_[ MY_FILES ], SIGNAL(triggered()),
          this,                 SLOT(onMyFiles()));
  connect(actions_[ PRIVATE_SHARES ], SIGNAL(triggered()),
          this,                       SLOT(onPrivateShares()));
  connect(actions_[ GO_OFFLINE ], SIGNAL(toggled(bool)),
          this,                   SLOT(onGoOffline(bool)));
  connect(actions_[ SETTINGS ], SIGNAL(triggered()),
          this,                 SLOT(onSettingsTriggered()));
  connect(actions_[ ONLINE ], SIGNAL(triggered()),
          this,                 SLOT(onOnlineTriggered()));
  connect(actions_[ AWAY ], SIGNAL(triggered()),
          this,                 SLOT(onAwayTriggered()));
  connect(actions_[ BUSY ], SIGNAL(triggered()),
          this,                 SLOT(onBusyTriggered()));
  connect(actions_[ OFFLINE_2 ], SIGNAL(triggered()),
          this,                 SLOT(onOffline_2Triggered()));
// connect(actions_[ SAVE_SESSION ], SIGNAL(triggered()),
//         this,                     SLOT(onSaveSession()));
}

void PerpetualData::createMenus() {
#if defined(MAIDSAFE_WIN32)
  // an example of launching an extrernal application
  // path to application is stored in the action

  QAction* actionNotepad = new QAction(this);
  actionNotepad->setText(tr("Notepad"));
  actionNotepad->setData(QVariant("C:/Windows/System32/notepad.exe"));
  connect(actionNotepad, SIGNAL(triggered()),
           this,          SLOT(onApplicationActionTriggered()));

  ui_.menuApplications->addAction(actionNotepad);
#endif
}

void PerpetualData::setState(State state) {
  disconnect(login_, NULL, this, NULL);
  disconnect(create_, NULL, this, NULL);
  disconnect(progressPage_, NULL, this, NULL);
  disconnect(userPanels_, NULL, this, NULL);

  userPanels_->setActive(false);

  state_ = state;

  switch (state_) {
    case LOGIN:
    {
        ui_.stackedWidget->setCurrentWidget(login_);
        login_->clearFields();
        connect(login_, SIGNAL(newUser()),
                this,   SLOT(onLoginNewUser()));
        connect(login_, SIGNAL(existingUser()),
                this,   SLOT(onLoginExistingUser()));
        break;
    }
    case SETUP_USER:
    {
        create_->reset();
        ui_.stackedWidget->setCurrentWidget(create_);
        connect(create_, SIGNAL(complete()),
                this,    SLOT(onSetupNewUserComplete()));
        connect(create_, SIGNAL(cancelled()),
                this,    SLOT(onSetupNewUserCancelled()));
        break;
    }
    case CREATE_USER:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Creating User Account"));
        progressPage_->setProgressMessage(
            tr("A user account is being created. This may take some time..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);  // can't cancel it yet
        // connect(create_, SIGNAL(cancel()),
        //         this,    SLOT(onCreateCancelled()));
        break;
    }
    case MOUNT_USER:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Mounting User File System"));
        progressPage_->setProgressMessage(
            tr("Your file system is being set up..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);  // can't cancel it yet
        // connect(create_, SIGNAL(cancel()),
        //         this, SLOT(onMountCancelled()));
        break;
    }
    case LOGGED_IN:
    {
        showLoggedInMenu();
        ui_.stackedWidget->setCurrentWidget(userPanels_);
        connect(userPanels_, SIGNAL(unreadMessages(int)),
                this,        SLOT(onUnreadMessagesChanged(int)));
        userPanels_->setActive(true);
        break;
    }
    case LOGGING_OUT:
    {
        showLoggedOutMenu();
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setTitle(tr("Logging out"));
        progressPage_->setProgressMessage(
            tr("Logging out and removing all traces of you from the "
               "system..."));
        progressPage_->setError(false);
        progressPage_->setCanCancel(false);
        break;
    }
    case FAILURE:
    {
        ui_.stackedWidget->setCurrentWidget(progressPage_);
        progressPage_->setError(true);
        progressPage_->setCanCancel(false);
        connect(progressPage_, SIGNAL(ok()),
                this,          SLOT(onFailureAcknowledged()));
        break;
    }
    default:
    {
        break;
    }
  }

  if (state != LOGGED_IN) {
      message_status_->clear();
  }
}

void PerpetualData::onLoginExistingUser() {
  qDebug() << "onLoginExistingUser";
  // existing user whose credentials have been verified
  // mount the file system..

  qDebug() << "public name:" << ClientController::instance()->publicUsername();

#ifdef PD_LIGHT
  onMountCompleted(true);
#else
  setState(MOUNT_USER);
  asyncMount();
#endif
}

void PerpetualData::onLoginNewUser() {
  setState(SETUP_USER);
}

void PerpetualData::onSetupNewUserComplete() {
  qDebug() << "onSetupNewUserComplete";
  // user has been successfully setup. can go ahead and create them

  setState(CREATE_USER);
  asyncCreateUser();
}

void PerpetualData::onSetupNewUserCancelled() {
  // process was cancelled. back to login.
  setState(LOGIN);
}

void PerpetualData::asyncMount() {
  MountThread* mt = new MountThread(MountThread::MOUNT, this);
  connect(mt,   SIGNAL(completed(bool)),
          this, SLOT(onMountCompleted(bool)));

  mt->start();
}

void PerpetualData::asyncUnmount() {
  MountThread* mt = new MountThread(MountThread::UNMOUNT, this);
  connect(mt,   SIGNAL(completed(bool)),
          this, SLOT(onUnmountCompleted(bool)));

  mt->start();
}

//  void PerpetualData::asyncLogout() {
//    LogoutUserThread* lut = new LogoutUserThread();
//    connect(lut,   SIGNAL(logoutUserCompleted(bool)),
//           this, SLOT(onLogoutUserCompleted(bool)));
//
//    lut->start();
//  }

void PerpetualData::asyncCreateUser() {
  CreateUserThread* cut = new CreateUserThread(login_->username(),
                                               login_->pin(),
                                               login_->password(),
                                               create_->VaultType(),
                                               create_->SpaceOffered(),
                                               create_->PortChosen(),
                                               create_->DirectoryChosen(),
                                               this);
  create_->reset();
  connect(cut,  SIGNAL(completed(bool)),
          this, SLOT(onUserCreationCompleted(bool)));

  create_->reset();

  cut->start();
}

void PerpetualData::onUserCreationCompleted(bool success) {
  qDebug() << "PerpetualData::onUserCreationCompleted:" << success;

  if (success) {
#ifdef PD_LIGHT
  ClientController::instance()->SetMounted(0);
  onMountCompleted(true);
#else
  setState(MOUNT_USER);
  asyncMount();
#endif
  } else {
    progressPage_->setProgressMessage(tr("Failed creating a user account."));
    setState(FAILURE);
  }
}

void PerpetualData::onMountCompleted(bool success) {
  qDebug() << "PerpetualData::onMountCompleted: " << success;

  if (success) {
    const QString pu = ClientController::instance()->publicUsername();
    if (!pu.isEmpty()) {
      statusBar()->showMessage(tr("Logged in: %1").arg(pu));
    } else {
      statusBar()->showMessage(tr("Logged in"));
    }
    setState(LOGGED_IN);
    qDebug() << QString("Logged in: %1").arg(pu);
  } else {
    // TODO(Team#5#): 2009-08-18 - more detail about the failure
    progressPage_->setProgressMessage(
        tr("The file system could not be mounted."));
    setState(FAILURE);
  }
  if (!ClientController::instance()->publicUsername().isEmpty())
    ClientController::instance()->StartCheckingMessages();
}

void PerpetualData::onUnmountCompleted(bool success) {
  qDebug() << "PerpetualData::onUnMountCompleted: " << success;

  if (success) {
    // TODO(Team#5#): 2009-08-18 - disable the logout action
    statusBar()->showMessage(tr("Logged out"));

    if (!quitting_)
      setState(LOGIN);
  } else {
    // TODO(Team#5#): 2009-08-18 - more detail about the failure
    progressPage_->setProgressMessage(
        tr("The file system could not be unmounted."));
    setState(FAILURE);
  }

  if (quitting_) {
    // TODO(Team#5#): 2009-08-18 - what to do (or can we do)
    //                             if logout failed but we're closing
    //                             the application?
    ClientController::instance()->shutdown();
    qApp->quit();
  }
}

void PerpetualData::onSaveSessionCompleted(int result) {
  QString saveSessionMsg(tr("Your session could not be saved."));
  if (result == 0)
    saveSessionMsg = tr("Your session was successfully saved.");
  qDebug() << "PerpetualData::onSaveSessionCompleted - Result: " << result;

//  QMessageBox::warning(this, tr("Notification!"), saveSessionMsg);
  SystemTrayIcon::instance()->showMessage(tr("Alert"), saveSessionMsg);
}

void PerpetualData::onFailureAcknowledged() {
  setState(LOGIN);
}

void PerpetualData::onLogout() {
  if (state_ != LOGGED_IN) {
    // if we're still to login we can't logout
    return;
  }
  if (!ClientController::instance()->publicUsername().isEmpty())
    ClientController::instance()->StopCheckingMessages();
  asyncUnmount();
  setState(LOGGING_OUT);
}

void PerpetualData::quit() {
  showNormal();
  onQuit();
}

void PerpetualData::onQuit() {
  // TODO(Team#5#): 2009-08-18 - confirm quit if something in progress
  if (state_ != LOGGED_IN) {
    ClientController::instance()->shutdown();
    qApp->quit();
  } else {
    quitting_ = true;
    onLogout();
  }
}

void PerpetualData::onAbout() {
  QDialog about;
  Ui::About ui;
  ui.setupUi(&about);

  about.exec();
}

void PerpetualData::onMyFiles() {
  if (ClientController::instance()->SessionName().empty())
    return;

  qDebug() << "PerpetualData::onMyFiles()";

  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::MY_FILES);
}

void PerpetualData::onPrivateShares() {
  if (ClientController::instance()->SessionName().empty())
    return;

  qDebug() << "PerpetualData::onPrivateShares()";

  UserSpaceFileSystem::instance()->explore(UserSpaceFileSystem::PRIVATE_SHARES);
}

void PerpetualData::onGoOffline(bool b) {
  if (b) {
    SystemTrayIcon::instance()->ChangeStatus(1);
    ClientController::instance()->SetConnectionStatus(1);
  } else {
    SystemTrayIcon::instance()->ChangeStatus(0);
    ClientController::instance()->SetConnectionStatus(0);
  }
}

void PerpetualData::onSaveSession() {
  SaveSessionThread *sst = new SaveSessionThread();
  connect(sst,  SIGNAL(completed(int)),
          this, SLOT(onSaveSessionCompleted(int)));

  sst->start();
}

void PerpetualData::onToggleFullScreen(bool b) {
  if (b) {
    showFullScreen();
  } else {
    showNormal();
  }
}

void PerpetualData::onApplicationActionTriggered() {
  QAction* action = qobject_cast<QAction*>(sender());
  if (!action) {
      return;
  }

  const QString appPath = action->data().toString();
  if (appPath.isEmpty()) {
      qWarning() << "PerpetualData::onApplicationActionTriggered: action"
                 << action->text()
                 << "did not specify app path";
  }

  if (!QProcess::startDetached(appPath)) {
      qWarning() << "PerpetualData::onApplicationActionTriggered: failed to "
                    "start" << appPath << "for action" << action->text();
  }
}

void PerpetualData::onMessageReceived(ClientController::MessageType type,
                                      const QDateTime&,
                                      const QString& sender,
                                      const QString& detail,
                                      const QString&) {
  boost::progress_timer t;
  if (type == ClientController::TEXT) {
    std::list<std::string> theList;
    ClientController::instance()->ConversationList(&theList);

    QList<QString> messageList;
    foreach(std::string theConv, theList) {
        messageList.append(QString::fromStdString(theConv));
    }

    if (!messageList.contains(sender)) {
      PersonalMessages* mess_ = new PersonalMessages(this, sender);

      QFile file(":/qss/defaultWithWhite1.qss");
      file.open(QFile::ReadOnly);
      QString styleSheet = QLatin1String(file.readAll());

      mess_->setStyleSheet(styleSheet);
      mess_->setMessage(tr("%1 said: %2").arg(sender).arg(detail));
      mess_->show();
    }
  } else if (type == ClientController::INVITE) {
    // TODO(Team#5#): 2010-01-13 - handle Invite
  }
}

void PerpetualData::onShareReceived(const QString& from,
                                    const QString& share_name) {
  QString title = tr("Share received");
  QString message = tr("'%1' has shared '%2' with you")
                    .arg(from).arg(share_name);

  SystemTrayIcon::instance()->showMessage(title, message);
}

void PerpetualData::onFileReceived(const maidsafe::InstantMessage& im) {
  maidsafe::InstantFileNotification ifn = im.instantfile_notification();

  QMessageBox msgBox;
  msgBox.setText(tr("%1 is sending you: %2")
                 .arg(QString::fromStdString(im.sender()))
                 .arg(QString::fromStdString(ifn.filename())));
  msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);
  msgBox.setDefaultButton(QMessageBox::Save);
  int ret = msgBox.exec();

  int n;
  QString directory;
  QString root;

  switch (ret) {
    case QMessageBox::Save: {
      // Save
#ifdef PD_LIGHT
    bool ok;
    QString text = QInputDialog::getText(this, tr("Save File As"),
                                      tr("Filename"),
                                      QLineEdit::Normal, "", &ok);
    if (ok && !text.isEmpty()) {
      QString s = QString("My Files\\%1").arg(text);
      n = maidsafe::ClientController::getInstance()->
          AddInstantFile(im.instantfile_notification(), s.toStdString());
    }
#else

#ifdef __WIN32__
      root = QString("%1:\\My Files").
             arg(ClientController::instance()->WinDrive());
#else
      root = QString::fromStdString(file_system::MaidsafeFuseDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()).string() +
          "/My Files");
#endif
      root += "/" + QString::fromStdString(ifn.filename());
      qfd_ = new QFileDialog(this, tr("Save File As..."), root);
      connect(qfd_, SIGNAL(directoryEntered(const QString&)),
              this, SLOT(onDirectoryEntered(const QString&)));
      qfd_->setFileMode(QFileDialog::AnyFile);
      qfd_->setAcceptMode(QFileDialog::AcceptSave);

      int result = qfd_->exec();
      if (result == QDialog::Rejected) {
        return;
      }
      QStringList fileNames = qfd_->selectedFiles();
      directory = fileNames.at(0);
#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Dir chosen: %s\n",
             directory.toStdString().c_str());
#endif

#ifdef __WIN32__
      std::string s = directory.toStdString();
      s = s.substr(2, s.length()-1);
#else
      std::string s(file_system::MakeRelativeMSPath(directory.toStdString(),
          maidsafe::SessionSingleton::getInstance()->SessionName()).string());
#endif

#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Dir chosen: -%s-\n", s.c_str());
#endif
      n = maidsafe::ClientController::getInstance()->
          AddInstantFile(im.instantfile_notification(), s);

#ifdef DEBUG
      printf("PerpetualData::onFileReceived - Res: %i\n", n);
#endif
#endif  // end of elseif PD_LIGHT
      if (n == 0) {
        QString title = tr("File received");
        QString message = tr("'%1' has shared the file '%2' with you")
                          .arg(QString::fromStdString(im.sender()))
                          .arg(QString::fromStdString(ifn.filename()));

        SystemTrayIcon::instance()->showMessage(title, message);
      }
      break;
    }
    case QMessageBox::Cancel:
      // Cancel
      break;
    default:
      // Default
      break;
  }
}

void PerpetualData::onUnreadMessagesChanged(int count) {
  qDebug() << "PerpetualData::onUnreadMessagesChanged:" << count;
  QString text;
  if (state_ == LOGGED_IN) {
    text = tr("%n unread message(s)", "", count);
  }
  message_status_->setText(text);
}

void PerpetualData::onConnectionStatusChanged(int status) {
  SystemTrayIcon::instance()->ChangeStatus(status);
  QString title(tr("Connection status"));
  QString message;
  switch (status) {
    case 0: message = tr("You are connected!"); break;
    case 1: message = tr("You are off-line!"); break;
  }
  SystemTrayIcon::instance()->showMessage(title, message);
}

void PerpetualData::onDirectoryEntered(const QString& dir) {
  QString root;

#ifdef __WIN32__
  root = QString(ClientController::instance()->WinDrive());

  if (!dir.startsWith(root, Qt::CaseInsensitive)) {
    root = QString("%1:\\My Files").
         arg(ClientController::instance()->WinDrive());
    qfd_->setDirectory(root);
  }
#else
  root = QString::fromStdString(file_system::MaidsafeFuseDir(
      ClientController::instance()->SessionName()).string());

  if (!dir.startsWith(root, Qt::CaseInsensitive)) {
    root = QString::fromStdString(file_system::MaidsafeFuseDir(
        ClientController::instance()->SessionName()).string() +
        "/My Files");
    qfd_->setDirectory(root);
  }
#endif
}

void PerpetualData::onSettingsTriggered() {
  qDebug() << "in onSettingsTriggered()";
    settings_ = new UserSettings;

    connect(settings_, SIGNAL(langChanged(const QString&)),
          this,                 SLOT(onLangChanged(const QString&)));

    QFile file(":/qss/defaultWithWhite1.qss");
    file.open(QFile::ReadOnly);
    QString styleSheet = QLatin1String(file.readAll());

    settings_->setStyleSheet(styleSheet);

    settings_->exec();
}

void PerpetualData::onOnlineTriggered() {
}

void PerpetualData::onAwayTriggered() {
}

void PerpetualData::onBusyTriggered() {
}

void PerpetualData::onOffline_2Triggered() {
}

void PerpetualData::onLogoutUserCompleted(bool success) {
  onUnmountCompleted(success);
}

void PerpetualData::showLoggedInMenu() {
  actions_[LOGOUT]->setEnabled(true);
  // actions_[MY_FILES]->setEnabled(true);
  actions_[PRIVATE_SHARES]->setEnabled(true);
  actions_[GO_OFFLINE]->setEnabled(true);
  actions_[SETTINGS]->setEnabled(true);
}

void PerpetualData::showLoggedOutMenu() {
  actions_[LOGOUT]->setEnabled(false);
  // ui_.menuStatus->setEnabled(false);
  actions_[MY_FILES]->setEnabled(false);
  actions_[PRIVATE_SHARES]->setEnabled(false);
  actions_[GO_OFFLINE]->setEnabled(false);
  actions_[SETTINGS]->setEnabled(false);
}

void PerpetualData::changeEvent(QEvent *event) {
  if (event->type() == QEvent::LanguageChange) {
    ui_.retranslateUi(this);
  } else {
    QWidget::changeEvent(event);
  }
}

void PerpetualData::onLangChanged(const QString &lang) {
  qtTranslator->load("qt_" + lang,
           QLibraryInfo::location(QLibraryInfo::TranslationsPath));
  qApp->installTranslator(qtTranslator);

  bool res = myAppTranslator->load(":/translations/pd_translation_" + lang);
  if (res) {
    qApp->installTranslator(myAppTranslator);
    ui_.retranslateUi(this);
  }
}
