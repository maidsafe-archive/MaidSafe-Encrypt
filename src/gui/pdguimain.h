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
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#ifndef GUI_PDGUIMAIN_H_
#define GUI_PDGUIMAIN_H_

#include <wx/dialup.h>
#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/taskbar.h>
#include <wx/listbook.h>
#include <wx/imaglist.h>

#include <boost/progress.hpp>

#include <string>
#include <vector>

#include "maidsafe/utils.h"
#include "gui/general_login.h"
#include "gui/logged_in.h"
#include "gui/message_panel.h"
#include "gui/share_panel.h"
#include "gui/cyber_cash.h"
#include "gui/voting.h"
#include "gui/contacts.h"
#include "maidsafe/client/clientcontroller.h"
#include "fs/filesystem.h"
#include "maidsafe/config.h"

#if defined(MAIDSAFE_WIN32)
  //  #include "fs/w_fuse/fswin.h"
#elif defined(MAIDSAFE_POSIX)
  #include "fs/l_fuse/fslinux.h"
#elif defined(MAIDSAFE_APPLE)
  #include "fs/m_fuse/fsmac.h"
#endif

enum {
  PU_RESTORE = 10001,
  PU_NEW_ICON,
  PU_OLD_ICON,
  PU_EXIT,
  PU_CHECKMARK,
  PU_SUB1,
  PU_SUB2,
  PU_SUBMAIN
};

class TaskBar: public wxTaskBarIcon {
  public:
    #if defined(__WXCOCOA__)
      explicit TaskBar(wxTaskBarIconType iconType = DEFAULT_TYPE)
      : wxTaskBarIcon(iconType)
    #else
       TaskBar()
    #endif
      {}

    void OnLeftButtonDClick(wxTaskBarIconEvent&);
    void OnMenuRestore(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnMenuExit(wxCommandEvent&);  // NOLINT
    virtual wxMenu *CreatePopupMenu();
};

class pdguiFrame: public wxFrame {
  public:
    explicit pdguiFrame(wxWindow* parent);
    virtual ~pdguiFrame();
    void OnIconize(wxIconizeEvent& WXUNUSED(event));  // NOLINT
    void OnRestore(wxTaskBarIconEvent& WXUNUSED(event));  // NOLINT
    void OnExit(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnQuit(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnAbout(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnClose(wxCloseEvent& WXUNUSED(event));  // NOLINT
    void Onbutton_createCLICK(wxWizardEvent& WXUNUSED(event));  // NOLINT
    void Onbutton_loginClick(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Onbutton_logoutClick(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnPageChanged(wxListbookEvent& WXUNUSED(event));  // NOLINT
    void OnFullSCreen(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_passwordText(wxCommandEvent& WXUNUSED(event));  // NOLINT
    #ifdef __WIN32__
      void OnNet_Con_Off(wxDialUpEvent& WXUNUSED(event));  // NOLINT
      void OnNet_Con_On(wxDialUpEvent& WXUNUSED(event));  // NOLINT
    #endif
    void PeriodicMessageSearch(wxTimerEvent &event);  // NOLINT
    void AddLoggedInPanels(unsigned int const &shown_panel);
    void RemoveLoggedInPanels();
    wxBitmap image_ok;
  private:
    pdguiFrame(const pdguiFrame&);
    pdguiFrame& operator=(const pdguiFrame&);
    static const int32_t ID_STATICBITMAPPD;
    static const int32_t ID_PANEL_LOGIN;
    static const int32_t ID_PANEL_MAIN;
    static const int32_t ID_PANEL_CONTACTS;
    static const int32_t ID_PANEL_MESSAGES;
    static const int32_t ID_PANEL_SHARES;
    static const int32_t ID_PANEL_CYBERCASH;
    static const int32_t ID_PANEL_VOTING;
    static const int32_t ID_PANEL_SETTINGS;
    static const int32_t ID_LISTBOOK_MAIN;
    static const int32_t idMenuQuit;
    static const int32_t IDMENULOGOUT;
    static const int32_t idMenuAbout;
    static const int32_t IDHelp;
    static const int32_t ID_MENU_FULLSCREEN;
    static const int32_t id_tool_menu_1;
    static const int32_t id_tool_menu_2;
    static const int32_t id_tool_menu_3;
    static const int32_t id_tool_menu_4;
    static const int32_t id_tool_menu_5;
    static const int32_t id_tool_menu_6;

    TaskBar *m_taskBarIcon;
    wxImageList *listbook_images;
    wxTimer *m_timer;
    bool got_enc_data;
    bool user_exists;
    void UserExists_Callback(const std::string& result);


    file_system::FileSystem fsys_;
    #ifdef MAIDSAFE_WIN32

    #elif defined(MAIDSAFE_POSIX)
      fs_l_fuse::FSLinux fsl_;
    #elif defined(MAIDSAFE_APPLE)
      fs_l_fuse::FSLinux fsl_;
      // fs_m_fuse::FSMac fsm_;
    #endif

    SharePanel* panel_shares;
    wxListbook* listbook_main;
    wxMenuItem* MenuItem11;
    wxMenuItem* MenuItem12;
    wxMenuItem* MenuItem31;
    wxMenuItem* MenuItem32;
    wxMenuItem* MenuItem61;
    wxMenuItem* MenuItem62;
    wxMenuItem* tool_menu_1;
    wxMenuItem* tool_menu_2;
    wxMenuItem* tool_menu_3;
    wxMenuItem* tool_menu_4;
    wxMenuItem* tool_menu_5;
    wxMenuItem* tool_menu_6;
    wxPanel* panel_general;
    wxMenuBar *MenuBar1;
    wxMenu *Menu1;
    wxMenu *tool_menu;
    general_login *login_panel;
    logged_in *panel_logged_in;
    general_login *panel_login;
    MessagePanel* panel_messages;
    wxPanel* panel_settings;
    cyber_cash* panel_cybercash;
    Voting* panel_voting;
    contacts *panel_contacts;
    wxBoxSizer *frame_sizer;
    wxPanel* m_panel_;
    wxPanel *l_panel_;
    #ifdef __WIN32__
      wxDialUpManager *net_connect_;
    #endif
    std::vector<packethandler::InstantMessage> all_messages_;
    std::vector<packethandler::InstantMessage> new_messages_;

  DECLARE_EVENT_TABLE()
};

#endif  // GUI_PDGUIMAIN_H_
