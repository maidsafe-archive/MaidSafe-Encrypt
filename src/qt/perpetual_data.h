#pragma once

#include <QMainWindow>

// core
#include "fs/filesystem.h"
#include "base/config.h"

#if defined(MAIDSAFE_WIN32)
  //  #include "fs/w_fuse/fswin.h"
#elif defined(MAIDSAFE_POSIX)
  #include "fs/l_fuse/fslinux.h"
#elif defined(MAIDSAFE_APPLE)
  #include "fs/m_fuse/fsmac.h"
#endif

// generated
#include "ui_pd.h"

class Login;
class CreateUser;
class UserPanels;
class MountThread;
class Progress;

//! Main Window for Perpetual Data
/*!
    Structure is:

    Menu Bar
    --------------
    GUI Area


    --------------
    Status Bar

    The GUI area is a stacked widget that swtiches between different panels
    based on the current state.  There are 3 main states (at the moment)
     - logging in       (username, pin, password etc)
     - creating a user  (naming, paying etc)
     - being a user     (messaging, sharing, contacts)
*/
class PerpetualData : public QMainWindow
{
    Q_OBJECT

public:
    PerpetualData( QWidget* parent = 0 );
    virtual ~PerpetualData();

private slots:
    //! Existing user logging in.
    void onLoginExistingUser();

    //! New user needs creating
    void onLoginNewUser();

    void onSetupNewUserComplete();
    void onSetupNewUserCancelled();

    //! asyncCreate has completed
    void onUserCreationCompleted( bool success );

    //! asyncMount has completed
    void onMountCompleted( bool success );
    void onUnmountCompleted( bool success );

    //!
    void onFailureAcknowledged();

    void onLogout();
    void onAbout();
    void onToggleFullScreen( bool );
    void onApplicationActionTriggered();
    void onQuit();

protected:
    friend class MountThread;
    //! Mount the user space filesystem
    /*!
        This is blocking and takes a while.  Should normally only ever be
        called by MountThread
    */
    bool mount();

    //! Unmount the user space filesystem
    /*!
        This is blocking and takes a while.  Should normally only ever be
        called by MountThread
    */
    bool unmount();

private:
    Ui::PerpetualData ui_;

    //! Actions
    void createActions();
    enum Action {
        LOGOUT,
        FULLSCREEN,
        QUIT,
        ABOUT
    };
    typedef QMap<Action, QAction*> ActionMap;
    ActionMap actions_;

    //! Adds any dyncamic actions to the application menu
    void createMenus();

    //! Application state
    /*!
        Typical progression:
        LOGIN -> (SETUP -> CREATE ->) MOUNT -> LOGGED_IN

        SETUP/CREATE are only required for new users

    */
    enum State {
        LOGIN,          //!< Gathering user credentials
        SETUP_USER,     //!< Setup a new user
        CREATE_USER,    //!< Create a new user
        MOUNT_USER,     //!< Mount user space file system
        LOGGED_IN,      //!< User logged in
        LOGGING_OUT,    //!< Logging user out
        FAILURE         //!< Something critical failed.  Showing message before
                        //!< returning to login
    };

    //! flag set to true when application is quitting
    bool quitting_;

    //! Login screen
    Login* login_;

    //! Create user wizard
    CreateUser* create_;

    //! General purpose progress page
    /*!
        Used to show progress of:
         - creating user
         - mounting user
         - logging users out
    */
    Progress* progressPage_;

    //! User level pages - shown once logged in
    UserPanels* userPanels_;

    //! Switch between different application states
    void setState( State state );
    State state_;

    //! Uses MountThread to perform a non-blocking mount
    /*!
        Success or failure is indicated via onMountComplete
    */
    void asyncMount();
    void asyncCreateUser();
    void asyncUnmount();

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
