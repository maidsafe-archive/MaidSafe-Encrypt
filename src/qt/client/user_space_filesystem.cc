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

#include "qt/client/user_space_filesystem.h"

// qt
#include <QObject>
#include <QDebug>
#include <QProcess>

// dht
#include <maidsafe/maidsafe-dht_config.h>

// os
#ifdef MAIDSAFE_WIN32
  #include <shellapi.h>
#endif

// core
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"

// 3rd party
#if defined(MAIDSAFE_WIN32)
#include "fs/w_fuse/fswin.h"
#elif defined(MAIDSAFE_POSIX)
#include "fs/l_fuse/fslinux.h"
//  #elif defined(MAIDSAFE_APPLE)
//  #include "fs/l_fuse/fslinux.h"
#endif

// local
#include "qt/client/client_controller.h"

class UserSpaceFileSystem::UserSpaceFileSystemImpl {
 public:
  UserSpaceFileSystemImpl() { }

  file_system::FileSystem fsys_;
#ifdef MAIDSAFE_WIN32
  // none needed
#elif defined(MAIDSAFE_POSIX)
  fs_l_fuse::FSLinux fsl_;
#elif defined(MAIDSAFE_APPLE)
  fs_l_fuse::FSLinux fsl_;
  // fs_m_fuse::FSMac fsm_;
#endif
};

UserSpaceFileSystem* UserSpaceFileSystem::instance() {
  static UserSpaceFileSystem usfp;
  return &usfp;
}

UserSpaceFileSystem::UserSpaceFileSystem(QObject* parent)
    : QObject(parent)
    , impl_(new UserSpaceFileSystemImpl) { }

UserSpaceFileSystem::~UserSpaceFileSystem() {
  delete impl_;
  impl_ = NULL;
}

bool UserSpaceFileSystem::mount() {
  maidsafe::SessionSingleton::getInstance()->SetMounted(0);

  std::string debug_mode("-d");
#ifdef MAIDSAFE_WIN32
  char drive = maidsafe::ClientController::getInstance()->DriveLetter();
  fs_w_fuse::Mount(drive);
  maidsafe::SessionSingleton::getInstance()->SetWinDrive(drive);
#elif defined(MAIDSAFE_POSIX)
  std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
  impl_->fsl_.Mount(mount_point, debug_mode);
#elif defined(MAIDSAFE_APPLE)
  std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
  impl_->fsl_.Mount(mount_point, debug_mode);
#endif
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  if (maidsafe::SessionSingleton::getInstance()->Mounted() != 0) {
      return false;
  }
  return true;
}

bool UserSpaceFileSystem::unmount() {
  // unmount drive
  qDebug() << "UserSpaceFileSystem::unmount() -";
  bool success = false;
  qDebug() << "UserSpaceFileSystem::unmount() - -";
  std::string ms_dir = impl_->fsys_.MaidsafeDir();
  qDebug() << "UserSpaceFileSystem::unmount() - - -";
  std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
  qDebug() << "UserSpaceFileSystem::unmount() - - - -";
#ifdef MAIDSAFE_WIN32
  std::locale loc;
  wchar_t drive_letter = std::use_facet< std::ctype<wchar_t> >
      (loc).widen(maidsafe::SessionSingleton::getInstance()->WinDrive());
  success = fs_w_fuse::DokanUnmount(drive_letter);

/*
  // %SystemRoot%\explorer.exe /e /root,M:\Shares\Private\Share 1
  // invoking using QProcess doesn't work if the path has spaces in the name
  // so we need to go old skool...
  QString operation("open");
  QString command("dokanctl");
  QString parameters(" /u ");
  parameters.append(maidsafe::SessionSingleton::getInstance()->WinDrive());
  quintptr returnValue;
  QT_WA(
      {
          returnValue = (quintptr)ShellExecute(0,
                                  (TCHAR *)operation.utf16(),
                                  (TCHAR *)command.utf16(),
                                  (TCHAR *)parameters.utf16(),
                                  0,
                                  SW_HIDE);
      } ,
      {
          returnValue = (quintptr)ShellExecuteA(0,
                                  operation.toLocal8Bit().constData(),
                                  command.toLocal8Bit().constData(),
                                  parameters.toLocal8Bit().constData(),
                                  0,
                                  SW_HIDE);
      }
 );
*/

  if (!success)
    qWarning() << "UserSpaceFileSystem::unmount: failed to unmount dokan"
               << success;
#else
  // un-mount fuse
  impl_->fsl_.UnMount();
  success = true;
#endif

  // logout from client controller
  const int n = maidsafe::ClientController::getInstance()->Logout();
  if (n != 0) {
      // TODO(Dan#5#): 2009-06-25 - verify n!=0 means failure
  }

  return success;
}


void UserSpaceFileSystem::explore(Location l, QString subDir) {
  QDir dir;
  if (l == MY_FILES) {
    dir = ClientController::instance()->myFilesDirRoot(subDir);
  } else {  // PRIVATE_SHARES
    dir = ClientController::instance()->shareDirRoot(subDir);
  }

#ifdef MAIDSAFE_WIN32
  // %SystemRoot%\explorer.exe /e /root,M:\Shares\Private\Share 1
  // invoking using QProcess doesn't work if the path has spaces in the name
  // so we need to go old skool...
  QString operation("explore");
  quintptr returnValue;
  QT_WA({
        returnValue = (quintptr)ShellExecute(0,
                          (TCHAR *)(operation.utf16()),
                          (TCHAR *)(dir.absolutePath().utf16()),
                          0,
                          0,
                          SW_SHOWNORMAL);
      } , {
        returnValue = (quintptr)ShellExecuteA(0,
                                  operation.toLocal8Bit().constData(),
                                  dir.absolutePath().toLocal8Bit().constData(),
                                  0,
                                  0,
                                  SW_SHOWNORMAL);
      });

  if (returnValue <= 32) {
    qWarning() << "UserSpaceFileSystem::explore: failed to open"
               << dir.absolutePath();
  }

#else
  // nautilus FuseHomeDir()/Shares/Private/"name"
  QString app("nautilus");
  QStringList args;
  args <<  QString("%1").arg(dir.absolutePath());

  qDebug() << "explore:" << app << args;

  if (!QProcess::startDetached(app, args)) {
    qWarning() << "UserSpaceFileSystem::explore: failed to start"
               << app
               << "with args"
               << args;
  }

#endif
}

