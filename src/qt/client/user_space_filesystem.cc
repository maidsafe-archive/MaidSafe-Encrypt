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

#include "user_space_filesystem.h"

// qt
#include <QObject>
#include <QDebug>
#include <QProcess>

// core
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"

// 3rd party
#if defined(MAIDSAFE_WIN32)
#include "fs/w_fuse/fswin.h"
#elif defined(MAIDSAFE_POSIX)
#include "fs/l_fuse/fslinux.h"
#elif defined(MAIDSAFE_APPLE)
#include "fs/m_fuse/fsmac.h"
#endif

// os
#ifdef MAIDSAFE_WIN32
  #include <shellapi.h>
#endif

// local
#include "qt/client/client_controller.h"

class UserSpaceFileSystem::UserSpaceFileSystemImpl
{

public:
    UserSpaceFileSystemImpl()
    {
    }

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

UserSpaceFileSystem* UserSpaceFileSystem::instance()
{
    static UserSpaceFileSystem usfp;
    return &usfp;
}

UserSpaceFileSystem::UserSpaceFileSystem( QObject* parent )
    : QObject( parent )
    , impl_( new UserSpaceFileSystemImpl )
{

}

UserSpaceFileSystem::~UserSpaceFileSystem()
{
    delete impl_;
    impl_ = NULL;
}

bool UserSpaceFileSystem::mount()
{
    maidsafe::SessionSingleton::getInstance()->SetMounted(0);

    std::string debug_mode("-d");
#ifdef MAIDSAFE_WIN32
    char drive = maidsafe::ClientController::getInstance()->DriveLetter();
    fs_w_fuse::Mount(drive);
    maidsafe::SessionSingleton::getInstance()->SetWinDrive(drive);
#elif defined(MAIDSAFE_POSIX)
    // std::string mount_point = fsys->MaidsafeFuseDir();
    std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
    impl_->fsl_.Mount(mount_point, debug_mode);
#elif defined(MAIDSAFE_APPLE)
    std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
    impl_->fsl_.Mount(mount_point, debug_mode);
#endif
    boost::this_thread::sleep(boost::posix_time::seconds(1));

    if ( maidsafe::SessionSingleton::getInstance()->Mounted() != 0 )
    {
        return false;
    }

    //
    const QString username = ClientController::instance()->publicUsername();
    if ( !username.isEmpty() )
    {
        std::string newDb("/.contacts");
        maidsafe::ClientController::getInstance()->read(newDb);
        newDb = std::string("/.shares");
        maidsafe::ClientController::getInstance()->read(newDb);
    }

    return true;
}

bool UserSpaceFileSystem::unmount()
{
    // backup databases
    const QString username = ClientController::instance()->publicUsername();
    if ( !username.isEmpty() )
    {
        std::string newDb("/.contacts");
        int res_ = maidsafe::ClientController::getInstance()->write(newDb);
        printf("Backed up contacts db with result %i\n", res_);
        newDb = std::string("/.shares");
        res_ = maidsafe::ClientController::getInstance()->write(newDb);
        printf("Backed up shares db with result %i\n", res_);
    }

    // unmount drive
    bool success = false;
    std::string ms_dir = impl_->fsys_.MaidsafeDir();
    std::string mount_point = impl_->fsys_.MaidsafeFuseDir();
#ifdef MAIDSAFE_WIN32
    // unload dokan
    SHELLEXECUTEINFO shell_info;
    memset(&shell_info, 0, sizeof(shell_info));
    shell_info.cbSize = sizeof(shell_info);
    shell_info.hwnd = NULL;
    shell_info.lpVerb = L"open";
    shell_info.lpFile = L"dokanctl";
    shell_info.lpParameters = L" /u ";
    shell_info.lpParameters +=
    maidsafe::SessionSingleton::getInstance()->WinDrive();
    shell_info.nShow = SW_HIDE;
    shell_info.fMask = SEE_MASK_NOCLOSEPROCESS;
    success = ShellExecuteEx(&shell_info);

    WaitForSingleObject(shell_info.hProcess, INFINITE);
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
#else
    // un-mount fuse
    impl_->fsl_.UnMount();
    success = true;
#endif

    // logout from client controller
    const int n = maidsafe::ClientController::getInstance()->Logout();
    if ( n != 0 )
    {
        // TODO verify n!=0 means failure
    }

    return success;
}


void UserSpaceFileSystem::explore( Location l, QString subDir )
{
    QDir dir;
    if ( l == MY_FILES )
    {
        dir = ClientController::instance()->myFilesDirRoot( subDir );
    }
    else // PRIVATE_SHARES
    {
        dir = ClientController::instance()->shareDirRoot( subDir );
    }

    //QDesktopServices::openUrl( QUrl( dir.absolutePath() ) );

#ifdef MAIDSAFE_WIN32
    // %SystemRoot%\explorer.exe /e /root,M:\Shares\Private\Share 1

    // TODO: doesn't like spaces in the name
    QString app( "explorer.exe" );
    QStringList args;
    args <<  "/e" << QString( "/root,%1" ).arg( dir.absolutePath().replace( "/", "\\" ) );

    qDebug() << "explore:" << app << args;

    if ( !QProcess::startDetached( app, args ) )
    {
        qWarning() << "PerpetualData::failed to start"
                   << app
                   << "with args"
                   << args;
    }

#else
    // nautilus FuseHomeDir()/Shares/Private/"name"
    QString app( "nautilus" );
    QStringList args;
    args <<  QString( "%1" ).arg( dir.absolutePath() );

    qDebug() << "explore:" << app << args;

    if ( !QProcess::startDetached( app, args ) )
    {
        qWarning() << "PerpetualData::failed to start"
                   << app
                   << "with args"
                   << args;
    }

#endif

}

