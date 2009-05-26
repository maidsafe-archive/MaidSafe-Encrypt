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

#ifdef __WXMSW__
  #undef CreateDialog
  #include <wx/msw/winundef.h>
#endif

// #ifdef MAIDSAFE_WIN32
//  #include <wxprec_monolib.pch"
// #else
#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/hyperlink.h>
#include <wx/splash.h>
#include <wx/aboutdlg.h>
#include <wx/xrc/xmlres.h>
// #endif
#ifdef MAIDSAFE_WIN32
  #include <shellapi.h>
#endif


#include <gtest/gtest.h>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/progress.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/filesystem/fstream.hpp>

#include <signal.h>
// #include <iostream>
// #include <fstream>
#include <list>
#include <vector>
#include <map>
#include <string>

#include "maidsafe/utils.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/selfencryption.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "fs/filesystem.h"
#include "gui/maidsafe_logo_small.xpm"
#include "gui/maidsafe_logo1.xpm"
#include "gui/logged_in.h"
#include "gui/pdguimain.h"
#include "gui/general_login.h"
#include "gui/contacts.h"

namespace fs = boost::filesystem;

pdguiFrame *main_frame = NULL;


const int32_t pdguiFrame::ID_PANEL_LOGIN = wxNewId();
const int32_t pdguiFrame::ID_PANEL_MAIN = wxNewId();
const int32_t pdguiFrame::ID_PANEL_MESSAGES = wxNewId();
const int32_t pdguiFrame::ID_PANEL_CONTACTS = 77;
const int32_t pdguiFrame::ID_PANEL_SHARES = wxNewId();
const int32_t pdguiFrame::ID_PANEL_CYBERCASH = wxNewId();
const int32_t pdguiFrame::ID_PANEL_VOTING = wxNewId();
const int32_t pdguiFrame::ID_PANEL_SETTINGS = wxNewId();
const int32_t pdguiFrame::ID_LISTBOOK_MAIN = wxNewId();
const int32_t pdguiFrame::idMenuQuit = wxNewId();
const int32_t pdguiFrame::IDMENULOGOUT = wxNewId();
const int32_t pdguiFrame::idMenuAbout = wxNewId();
const int32_t pdguiFrame::IDHelp = wxNewId();
const int32_t pdguiFrame::ID_MENU_FULLSCREEN = wxNewId();
const int32_t pdguiFrame::id_tool_menu_1 = wxNewId();
const int32_t pdguiFrame::id_tool_menu_2 = wxNewId();
const int32_t pdguiFrame::id_tool_menu_3 = wxNewId();
const int32_t pdguiFrame::id_tool_menu_4 = wxNewId();
const int32_t pdguiFrame::id_tool_menu_5 = wxNewId();
const int32_t pdguiFrame::id_tool_menu_6 = wxNewId();

enum events {
  TIMER_ID = 1
};

BEGIN_EVENT_TABLE(pdguiFrame, wxFrame)
  EVT_TIMER(TIMER_ID, pdguiFrame::PeriodicMessageSearch)
END_EVENT_TABLE()

pdguiFrame::pdguiFrame(wxWindow* parent)
  : wxFrame(parent, -1,  _("Perpetual Data")),
  image_ok(NULL), m_taskBarIcon(NULL), listbook_images(NULL),
  m_timer(NULL), got_enc_data(false), user_exists(false),
  fsys_(),
  #ifdef MAIDSAFE_WIN32
  #else
    fsl_(),
  #endif
  panel_shares(NULL), listbook_main(NULL),
  MenuItem11(NULL), MenuItem12(NULL), MenuItem31(NULL),
  MenuItem32(NULL), MenuItem61(NULL), MenuItem62(NULL),
  tool_menu_1(NULL), tool_menu_2(NULL), tool_menu_3(NULL),
  tool_menu_4(NULL), tool_menu_5(NULL), tool_menu_6(NULL),
  panel_general(NULL), MenuBar1(NULL), Menu1(NULL),
  tool_menu(NULL), login_panel(NULL), panel_logged_in(NULL),
  panel_login(NULL), panel_messages(NULL), panel_settings(NULL),
  panel_cybercash(NULL), panel_voting(NULL), panel_contacts(NULL),
  frame_sizer(NULL), m_panel_(NULL), l_panel_(NULL),
  all_messages_(), new_messages_() {
  // Frame setup
  // SetClientSize(wxSize(500,300));

  CreateStatusBar(3);
  SetStatusText(wxT("On line"), 0);
  // the wxICON macro makes this cross platform
  wxIcon icon(wxICON(maidsafe_logo1));
  #ifdef MAIDSAFE_WIN32
    // TODO(dan): this does not work on linux at least
    net_connect_ = wxDialUpManager::Create();
    // need to use an IDLE time WXUNUSED(event) to test linux and set manually
    net_connect_->SetWellKnownHost(_("www.google.com"));
    if (!net_connect_->EnableAutoCheckOnlineStatus(2))
      std::cout << "could not connect to network " << std::endl;
    std::cout << "Net OK" <<std::endl;
  #endif
  wxIcon iconok;
  wxIcon iconnotok;
  wxBitmap image_animation = wxXmlResource::Get()->LoadBitmap(wxT("icon"));
  #ifdef DEBUG
    if (image_ok.IsOk())
      std::cout << "it is an animation" << std::endl;
  #endif
  wxBitmap image_pd = wxXmlResource::Get()->LoadBitmap(wxT("pd"));
  wxBitmap image_splash = wxXmlResource::Get()->LoadBitmap(wxT("splash"));
  wxBitmap image_ok = wxXmlResource::Get()->LoadBitmap(wxT("ok"));
  iconok.CopyFromBitmap(image_ok);
  wxBitmap image_notok = wxXmlResource::Get()->LoadBitmap(wxT("notok"));
  iconnotok.CopyFromBitmap(image_notok);

  // Frame icon
  SetIcon(iconok);
  // Taskbar icon

  #if defined(__WXCOCOA__)
    m_taskBarIcon = new TaskBar(wxTaskBarIcon::DOCK);
  #else
    m_taskBarIcon = new TaskBar();
  #endif
  // , wxT("Perpetual data - On Line"); // We change this when offline to grey
  m_taskBarIcon->SetIcon(iconok);

  // cc = maidsafe::ClientController::getInstance();
  //   wxSplashScreen* splash ;
  //   splash = new wxSplashScreen(image_splash,
  //     wxSPLASH_CENTRE_ON_SCREEN|wxSPLASH_TIMEOUT,
  //     3000, NULL, -1, wxDefaultPosition, wxDefaultSize,
  //     wxSIMPLE_BORDER|wxSTAY_ON_TOP);

  // maybe show a splash screen here
  maidsafe::ClientController::getInstance()->JoinKademlia();
  printf("AFTER JoinKademlia\n");
  maidsafe::ClientController::getInstance()->Init();
  printf("AFTER Init\n");

  // MENUS
  wxMenu* Menu3;
  wxMenu* Menu6;

  // FRAME SIZE STUFF
  frame_sizer = new wxBoxSizer(wxVERTICAL);
  panel_login = new general_login(this,
    ID_PANEL_LOGIN, wxDefaultPosition, wxDefaultSize);
  // TODO(dan): FIXME *********************
  panel_login->Hide();
  // listbook_main = NULL;
  listbook_main = new wxListbook(this, ID_LISTBOOK_MAIN, wxPoint(0, 0),
    wxSize(500, 400), wxEXPAND|wxTAB_TRAVERSAL|wxLB_LEFT|wxNO_BORDER,
    _T("ID_LISTBOOK_MAIN"));
  listbook_main->Show();

  panel_login->SetToolTip(_("Login and account creation"));
  panel_login->SetHelpText(_("General login screen"));

  // MENU's
  MenuBar1 = new wxMenuBar();
  Menu1 = new wxMenu();
  MenuItem11 = new wxMenuItem(Menu1, idMenuQuit,
    _("&Quit\tAlt-F4"), _("Quit the application"), wxITEM_NORMAL);
  MenuItem11->SetBitmap(maidsafe_logo_small_xpm);
  MenuItem12 = new wxMenuItem(Menu1, IDMENULOGOUT,
    _("&Logout\tF2"), _("Logout current maidsafe user"), wxITEM_NORMAL);
  MenuItem12->SetBitmap(maidsafe_logo_small_xpm);

  Menu1->Append(MenuItem12);
  Menu1->Append(MenuItem11);
  MenuBar1->Append(Menu1, _("&File"));
  MenuItem12->Enable(false);
  // TODO(dan): We need to grey out menu items when there not allowed
  // this works enabling again is a prob !! MenuItem12->Enable(false);
  // View Menu
  Menu3 = new wxMenu();
  MenuItem31 = new wxMenuItem(Menu3, ID_MENU_FULLSCREEN,
    _("&FullScreen\tF11"), _("Fullscreen mode"), wxITEM_NORMAL);
  MenuItem31->SetBitmap(maidsafe_logo_small_xpm);
  // MenuItem32 = new wxMenuItem(Menu3, IDMENULOGOUT,
  //  _("Logout"), _("Logout current maidsafe user"), wxITEM_NORMAL);
  // MenuItem32->SetBitmap(maidsafe_logo_small_xpm);
  Menu3->Append(MenuItem31);
  // Menu3->Append(MenuItem32);
  MenuBar1->Append(Menu3, _("&View"));
  tool_menu = new wxMenu();

  tool_menu_1 = new wxMenuItem(tool_menu, id_tool_menu_1,
    _T("&Word Processor"), _("Open Office"), wxITEM_NORMAL);
  tool_menu_2 = new wxMenuItem(tool_menu, id_tool_menu_2,
    _T("&Spread Sheet"), _("Open Office"), wxITEM_NORMAL);
  tool_menu_3 = new wxMenuItem(tool_menu, id_tool_menu_3,
    _T("&Presentation"), _("Open Office"), wxITEM_NORMAL);
  tool_menu_4 = new wxMenuItem(tool_menu, id_tool_menu_4,
    _T("&Web Browser"), _("Firefox"), wxITEM_NORMAL);
  tool_menu_5 = new wxMenuItem(tool_menu, id_tool_menu_5,
    _T("&Drawing Tool"), _("Gimp"), wxITEM_NORMAL);
  tool_menu->Append(tool_menu_1);
  tool_menu->Append(tool_menu_2);
  tool_menu->Append(tool_menu_3);
  tool_menu->Append(tool_menu_4);
  tool_menu->Append(tool_menu_5);

  MenuBar1->Append(tool_menu, _("&Applications"));
  // Help Menu
  Menu6 = new wxMenu();
  MenuItem61 = new wxMenuItem(Menu6, idMenuAbout, _("&About\tF1"),
    _("Show info about this application"), wxITEM_NORMAL);
  Menu6->Append(MenuItem61);
  MenuItem62 = new wxMenuItem(Menu6, IDHelp, _("&Manual"),
    _("maidsafe Perpetual Data help manual"), wxITEM_NORMAL);
  Menu6->Append(MenuItem62);
  MenuBar1->Append(Menu6, _("&Help"));
  SetMenuBar(MenuBar1);

  Connect(idMenuQuit, wxEVT_COMMAND_MENU_SELECTED,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnQuit));
  Connect(IDMENULOGOUT, wxEVT_COMMAND_MENU_SELECTED,
    reinterpret_cast<wxObjectEventFunction>
    (&pdguiFrame::Onbutton_logoutClick));
  Connect(ID_MENU_FULLSCREEN, wxEVT_COMMAND_MENU_SELECTED,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnFullSCreen));
  Connect(idMenuAbout, wxEVT_COMMAND_MENU_SELECTED,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnAbout));
  Connect(wxID_ANY, wxEVT_ICONIZE,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnIconize));
  Connect(ID_LISTBOOK_MAIN, wxEVT_COMMAND_LISTBOOK_PAGE_CHANGED,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnPageChanged));
#ifdef MAIDSAFE_WIN32
  Connect(wxID_ANY, wxEVT_DIALUP_CONNECTED,
    wxDialUpEventHandler(pdguiFrame::OnNet_Con_Off));
  Connect(wxID_ANY, wxEVT_DIALUP_CONNECTED,
    wxDialUpEventHandler(pdguiFrame::OnNet_Con_On));
#endif
  panel_login->Connect(general_login::ID_WIZARD, wxEVT_WIZARD_FINISHED,
      wxObjectEventFunction(&pdguiFrame::Onbutton_createCLICK), NULL, this);

  panel_login->Connect(general_login::ID_TEXTCTRLPASSWORD,
    wxEVT_COMMAND_TEXT_UPDATED, reinterpret_cast<wxObjectEventFunction>
    (&pdguiFrame::Ontxt_passwordText), NULL, this);

  // TASKBAR
  m_taskBarIcon->Connect(wxID_ANY, wxEVT_TASKBAR_LEFT_DOWN,
    wxObjectEventFunction(&pdguiFrame::OnRestore), NULL, this);
  m_taskBarIcon->Connect(PU_RESTORE, wxEVT_COMMAND_MENU_SELECTED,
    wxObjectEventFunction(&pdguiFrame::OnRestore), NULL, this);
  m_taskBarIcon->Connect(PU_EXIT, wxEVT_COMMAND_MENU_SELECTED,
    wxObjectEventFunction(&pdguiFrame::OnQuit), NULL, this);
  Connect(wxID_ANY, wxEVT_CLOSE_WINDOW,
    reinterpret_cast<wxObjectEventFunction>(&pdguiFrame::OnExit));

  // frame_sizer->Insert(0, listbook_main, wxSizerFlags(5).Expand().Border());

  frame_sizer->Add(listbook_main, 1,
    wxALL|wxALIGN_LEFT|wxEXPAND|wxALIGN_CENTER_VERTICAL, 5);
  frame_sizer->Add(panel_login, 1,
    wxALL|wxALIGN_LEFT|wxEXPAND|wxALIGN_CENTER_VERTICAL, 5);
  //   # ifdef MAIDSAFE_WIN32
  // remove the ifdef endif when fuse works
  listbook_main->Hide();
  frame_sizer->Show(panel_login);
  //   #endif
  frame_sizer->Layout();
  SetSizer(frame_sizer);
  frame_sizer->Fit(this);
  frame_sizer->SetSizeHints(this);
  // delete splash;
}

pdguiFrame::~pdguiFrame() {
  // maidsafe::ClientController::getInstance()->CloseConnection();
  if (m_taskBarIcon)
    delete m_taskBarIcon;
}

void pdguiFrame::OnFullSCreen(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  if (IsFullScreen()) {
    ShowFullScreen(false);
    SetFocus();
  } else {
    ShowFullScreen(true);
    SetFocus();
  }
}

#if defined(MAIDSAFE_WIN32)
void pdguiFrame::OnNet_Con_On(wxDialUpEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  wxIcon iconok;
  wxIcon iconnotok;
  wxBitmap image_animation = wxXmlResource::Get()->LoadBitmap(wxT("icon"));
  #ifdef DEBUG
    if (image_ok.IsOk()) std::cout << "it is an animation" << std::endl;
    std::cout << "Network connected" << std::endl;
  #endif
  wxBitmap image_pd = wxXmlResource::Get()->LoadBitmap(wxT("pd"));
  wxBitmap image_splash = wxXmlResource::Get()->LoadBitmap(wxT("splash"));
  wxBitmap image_ok = wxXmlResource::Get()->LoadBitmap(wxT("ok"));
  iconok.CopyFromBitmap(image_ok);
  wxBitmap image_notok = wxXmlResource::Get()->LoadBitmap(wxT("notok"));
  iconnotok.CopyFromBitmap(image_notok);
  // Frame icon
  SetIcon(iconok);
}

void pdguiFrame::OnNet_Con_Off(wxDialUpEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  wxIcon iconok;
  wxIcon iconnotok;
  wxBitmap image_animation = wxXmlResource::Get()->LoadBitmap(wxT("icon"));
  #ifdef DEBUG
    if (image_ok.IsOk()) std::cout << "it is an animation" << std::endl;
    std::cout << "Network connected" << std::endl;
  #endif
  wxBitmap image_pd = wxXmlResource::Get()->LoadBitmap(wxT("pd"));
  wxBitmap image_splash = wxXmlResource::Get()->LoadBitmap(wxT("splash"));
  wxBitmap image_ok = wxXmlResource::Get()->LoadBitmap(wxT("ok"));
  iconok.CopyFromBitmap(image_ok);
  wxBitmap image_notok = wxXmlResource::Get()->LoadBitmap(wxT("notok"));
  iconnotok.CopyFromBitmap(image_notok);
  // Frame icon
  SetIcon(iconnotok);
  SetLabel(_("Perpetual Data Off Line"));
}
#endif

void pdguiFrame::Ontxt_passwordText(wxCommandEvent& event) {  // NOLINT
  /*
   * Here we will work out if the user is logging in and do this
   * automatically by downloading the MID and TMID and try decrypting
   * after 4 chars are typed from the password screen.
   * Otherwise we enable the create user button - which will bring up the
   * wizard. Also we confirm *FIRST* the username and pin fields are
   * correctly entered.
  */
  printf("Event id: %i\n", event.GetId());
  std::string pwd = panel_login->GetPassword();
  if (pwd.size() == 0)
    return;
  std::string username = panel_login->GetUsername();
  std::string pin = panel_login->GetPin();

  if (username == "" || pin == "") {
    panel_login->ClearData();
    return;
  }

  if (pwd.size() == 1) {
    maidsafe::exitcode result =
      maidsafe::ClientController::getInstance()->CheckUserExists(username,
      pin, boost::bind(&pdguiFrame::UserExists_Callback, this, _1),
      maidsafe::DEFCON2);
    if (result == maidsafe::USER_EXISTS)
      user_exists = true;
    else if (result == maidsafe::NON_EXISTING_USER) {
      user_exists = false;
    } else {
      wxMessageDialog info(NULL, _("Invalid combination of username & PIN"),
        _("Perpetual Data"), wxICON_ERROR);
      info.ShowModal();
      user_exists = false;
    }
    return;
  }
  if (pwd.size() < 4)
    return;
  if (!user_exists) {
    panel_login->button_create_user->Enable();
    panel_login->GridSizer1->Show(panel_login->BoxSizer4, false);
    panel_login->GridSizer1->Show(panel_login->BoxSizer2, true);
    panel_login->GridSizer1->Layout();
    SetStatusText(wxT("New !"), 1);
    SetStatusText(wxT("Welcome"), 2);
  } else {
    if (got_enc_data) {
      // panel_login->ShowProgress("User Exists");
      SetStatusText(wxT("Exists"), 1);
      std::list<std::string> msgs;
      if (maidsafe::ClientController::getInstance()->ValidateUser(
          pwd, &msgs)) {
#ifdef DEBUG
          std::cout << "Pub_name: " <<
            maidsafe::SessionSingleton::getInstance()->PublicUsername() <<
            std::endl;
#endif
        maidsafe::SessionSingleton::getInstance()->SetMounted(0);
#ifdef MAIDSAFE_WIN32
          char drive = maidsafe::ClientController::getInstance()->DriveLetter();
          fs_w_fuse::Mount(drive);
          maidsafe::SessionSingleton::getInstance()->SetWinDrive(drive);
#elif defined(MAIDSAFE_POSIX)
          // std::string mount_point = fsys->MaidsafeFuseDir();
          std::string mount_point = fsys_.MaidsafeFuseDir();
          std::string debug_mode("-d");
          fsl_.Mount(mount_point, debug_mode);
#elif defined(MAIDSAFE_APPLE)
          std::string mount_point = fsys_.MaidsafeFuseDir();
          std::string debug_mode("-d");
          fsl_.Mount(mount_point, debug_mode);
#endif
        boost::this_thread::sleep(boost::posix_time::seconds(1));
        if (maidsafe::SessionSingleton::
            getInstance()->PublicUsername() != "") {
          std::string newDb("/.contacts");
          maidsafe::ClientController::getInstance()->read(newDb);
          newDb = std::string("/.shares");
          maidsafe::ClientController::getInstance()->read(newDb);
        }

        if (maidsafe::SessionSingleton::getInstance()->Mounted() == 0) {
          int n =
            maidsafe::ClientController::getInstance()->HandleMessages(&msgs);
//          n = maidsafe::ClientController::getInstance()->InstantMessageCount();
          n = 22;
          std::string message_cnt("New messages: " + base::itos(n));
          SetStatusText(wxString::FromAscii(message_cnt.c_str()), 2);
          AddLoggedInPanels(1);
          SetStatusText(wxT("Logged In"), 1);
          got_enc_data = false;
          user_exists = false;
          m_timer = new wxTimer(this, TIMER_ID);
          m_timer->Start(6000);
        }
      } else {
        printf("pdguiFrame::Ontxt_passwordText pinche password the mierda\n");
      }
    }
  }
}

void pdguiFrame::OnPageChanged(wxListbookEvent& event) {  // NOLINT
#ifdef DEBUG
    std::cout << "Caught page changed: " << event.GetSelection() << std::endl;
#endif
  if (event.GetSelection() == 0) {
    if (new_messages_.size() > 0) {
      for (unsigned int i = 0; i < new_messages_.size(); i++)
        all_messages_.push_back(new_messages_[i]);
      new_messages_.clear();
      RemoveLoggedInPanels();
      AddLoggedInPanels(0);
      SetStatusText(wxString::FromAscii("New messages: 0"), 2);
    }
  } else if (event.GetSelection() == 1 &&
        maidsafe::ClientController::getInstance()->BufferPacketMessages()) {
#ifdef DEBUG
    std::cout << "Page activated: " <<
      event.GetSelection() << " -- " <<
      maidsafe::ClientController::getInstance()->BufferPacketMessages() <<
      std::endl;
#endif
    maidsafe::ClientController::getInstance()->SetBufferPacketMessages(false);
    RemoveLoggedInPanels();
    AddLoggedInPanels(1);
  }
  listbook_main->SetFitToCurrentPage(true);
  frame_sizer->ComputeFittingClientSize(this);
  frame_sizer->ComputeFittingWindowSize(this);
  frame_sizer->RecalcSizes();
  frame_sizer->Fit(this);
  event.Skip();
}

void pdguiFrame::OnIconize(wxIconizeEvent& event) {  // NOLINT
  #ifdef DEBUG
    std::cout << "Caught iconised " << std::endl;
  #endif
  if (event.Iconized()) {
    this->Show(FALSE);
    SetFocus();
  } else {
    this->Show(TRUE);
    SetFocus();
  }
}

void pdguiFrame::Onbutton_logoutClick(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
#ifdef DEBUG
  std::cout << "log out clicked " << std::endl;
#endif
  bool logout = false;
  if (maidsafe::SessionSingleton::getInstance()->PublicUsername() != "") {
    std::string newDb("/.contacts");
    int res_ = maidsafe::ClientController::getInstance()->write(newDb);
    printf("Backed up contacts db with result %i\n", res_);
    newDb = std::string("/.shares");
    res_ = maidsafe::ClientController::getInstance()->write(newDb);
    printf("Backed up shares db with result %i\n", res_);
  }
  std::string ms_dir = fsys_.MaidsafeDir();
  std::string mount_point = fsys_.MaidsafeFuseDir();
#ifdef MAIDSAFE_WIN32
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
  logout = ShellExecuteEx(&shell_info);

  if (logout)
    WaitForSingleObject(shell_info.hProcess, INFINITE);
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
#else
  // un-mount fuse
  fsl_.UnMount();
  logout = true;
#endif

  if (logout) {
    printf("damn the devil to hell.\n");
    int n = maidsafe::ClientController::getInstance()->Logout();
    n = n * 1;
    // TODO(dan): verify that n == 0 for success.
    MenuBar1->Enable(IDMENULOGOUT, false);
    // TODO(dan): sort out menus in this way (method though).
    // MenuBar1->Enable(id_tool_menu_1,false);
    RemoveLoggedInPanels();
    listbook_main->Hide();
    panel_login->ClearData();
    panel_login->Show();
    panel_login->GridSizer1->Show(panel_login->BoxSizer4, true);
    panel_login->GridSizer1->Show(panel_login->BoxSizer2, false);
    panel_login->GridSizer1->Layout();
    frame_sizer->ComputeFittingClientSize(this);
    frame_sizer->ComputeFittingWindowSize(this);
    frame_sizer->RecalcSizes();
    frame_sizer->Fit(this);
    SetStatusText(wxT("Logged Out"), 1);
    SetStatusText(wxT(""), 2);
    Layout();
  }
}

void pdguiFrame::OnQuit(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  if (maidsafe::SessionSingleton::getInstance()->SessionName() != "") {
    bool logout = false;
    if (maidsafe::SessionSingleton::getInstance()->PublicUsername() != "") {
      std::string newDb(".contacts");
      int res_ = maidsafe::ClientController::getInstance()->write(newDb);
      printf("Backed up contacts db with result %i\n", res_);
      newDb = std::string("/.shares");
      res_ = maidsafe::ClientController::getInstance()->write(newDb);
      printf("Backed up shares db with result %i\n", res_);
    }
    std::string ms_dir = fsys_.MaidsafeDir();
    std::string mount_point = fsys_.MaidsafeFuseDir();
#ifdef MAIDSAFE_WIN32
//    std::string drive(" /u ");
//    drive += maidsafe::ClientController::getInstance()->DriveLetter();
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
    logout = ShellExecuteEx(&shell_info);
    if (logout)
      WaitForSingleObject(shell_info.hProcess, INFINITE);
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
#else
    // un-mount fuse
    fsl_.UnMount();
    logout = true;
#endif
    if (logout) {
      std::cout << "OnQuit" << std::endl;
      printf("damn the devil to hell.\n");
      bool b = maidsafe::ClientController::getInstance()->Logout();
      printf("damn the devil to hell %i.\n", b);
      if (!b)
        printf("Te la pelaaaaaaaste con el Logout de CC\n");

      // n = n * 1;
      boost::this_thread::sleep(boost::posix_time::seconds(5));
      maidsafe::ClientController::getInstance()->CloseConnection();
      Destroy();
    }
  } else {
    maidsafe::ClientController::getInstance()->CloseConnection();
    Destroy();
  }
}

void pdguiFrame::OnAbout(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  wxAboutDialogInfo info;
  info.SetName(_("Perpetual Data"));
  info.SetVersion(_("0.6 Alpha"));
  info.SetDescription(_T("This program provides: \n")
  _T("secure data \n")
  _T("secure messages \n")
  _T("secure voting \n")
  _T("secure digital ID management \n")
  _T("secure sharing of data \n")
  _T("Instant huge file transfers \n")
  _T("All anonymously and free."));
  info.AddDeveloper(_("Jose Cisneros"));
  info.AddDeveloper(_("Fraser Hutchison"));
  info.AddDeveloper(_("Haiyang Ma"));
  info.AddDeveloper(_("Dan Schmidt"));
  info.AddDeveloper(_("David Irvine"));
  info.AddDocWriter(_("Richard Johnstone"));
  info.AddArtist(_("Claire Roney <claire@activ8multimedia.co.uk>"));
  info.SetWebSite(_("www.maidsafe.net"));
  info.SetCopyright(_T("(C) 2008 maidsafe.net limited <info@maidsafe.net>"));
  wxAboutBox(info);
}

void pdguiFrame::OnClose(wxCloseEvent& event) {  // NOLINT
  // we add our own close actions here (cc->leave(); etc.
  printf("Event id: %i\n", event.GetId());
  Show(false);
}

void pdguiFrame::Onbutton_createCLICK(wxWizardEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  std::string username = panel_login->GetUsername();
  std::string pin = panel_login->GetPin();
  std::string password = panel_login->GetPassword();

  #ifdef DEBUG
    std::cout << "user " << username << " pin " <<
      pin << " password " << password << std::endl;
  #endif
  std::string debug_mode("-d");

  if (maidsafe::ClientController::getInstance()->
    CreateUser(username, pin, password)) {
    maidsafe::SessionSingleton::getInstance()->SetMounted(0);
    // label = "User Created OK \n mounting filesystem";
    //  panel_login->ShowProgress(label);
    // panel_login->gauge_login->Show(true);
#ifdef MAIDSAFE_WIN32
      char drive = maidsafe::ClientController::getInstance()->DriveLetter();
      fs_w_fuse::Mount(drive);
      maidsafe::SessionSingleton::getInstance()->SetWinDrive(drive);
#elif defined(MAIDSAFE_POSIX)
      std::string mount_point = fsys_.MaidsafeFuseDir();
      std::string debug_mode("-d");
      fsl_.Mount(mount_point, debug_mode);
#elif defined(MAIDSAFE_APPLE)
      std::string mount_point = fsys_.MaidsafeFuseDir();
      std::string debug_mode("-d");
      fsm_.Mount(mount_point, debug_mode);
#endif
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    if (maidsafe::SessionSingleton::getInstance()->Mounted() == 0) {
      AddLoggedInPanels(1);
      SetStatusText(wxT("Logged In"), 1);
      SetStatusText(wxT("New messages: 0"), 2);
      m_timer = new wxTimer(this, TIMER_ID);
      m_timer->Start(30000);
    } else {
      std::string label("Drive Failure");
      panel_login->ShowProgress(label);
    }
  } else {
    wxString msg = wxT("Cannot create \n Those details");
    wxMessageBox(msg, wxT("Warning"));
    std::string label("Account");
    panel_login->ShowProgress(label);
  }
}

void pdguiFrame::OnRestore(wxTaskBarIconEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  if (IsShown())
    Show(false);
  else
    Show(true);
}

void pdguiFrame::OnExit(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  Show(false);
}

void pdguiFrame::PeriodicMessageSearch(wxTimerEvent &event) { // NOLINT
  printf("Event id: %i\n", event.GetId());
  if (maidsafe::ClientController::getInstance()->GetMessages()) {
    std::list<packethandler::InstantMessage> list;
    maidsafe::ClientController::getInstance()->GetInstantMessages(
      &list);
    int n = list.size();
    while (!list.empty()) {
      new_messages_.push_back(list.front());
      list.pop_front();
    }

    n = new_messages_.size();
    printf("PeriodicMessageSearch n: %i\n", n);
    if (n > 0) {
      std::string message_cnt("New messages: " + base::itos(n));
      SetStatusText(wxString::FromAscii(message_cnt.c_str()), 2);
    } else {
      std::string message_cnt("New messages: 0");
      SetStatusText(wxString::FromAscii(message_cnt.c_str()), 2);
    }
  }
}

wxMenu *TaskBar::CreatePopupMenu() {
  // Try creating menus different ways
  // TODO(dan): Probably try calling SetBitmap with some XPMs here
  wxMenu *menu = new wxMenu;
  menu->Append(PU_RESTORE, _T("&Restore Window"));
  menu->AppendSeparator();
  wxMenu *submenu = new wxMenu;
  submenu->Append(PU_SUB1, _T("Data"));
  submenu->AppendSeparator();
  submenu->Append(PU_SUB2, _T("Send a file"));
  menu->Append(PU_SUBMAIN, _T("Create a share"), submenu);
  // #ifndef __WXMAC_OSX__ /*Mac has built-in quit menu*/
  menu->AppendSeparator();
  menu->Append(PU_EXIT, _T("E&xit"));
  // #endif
  return menu;
}

void pdguiFrame::AddLoggedInPanels(unsigned int const &shown_panel) {
  panel_shares = new SharePanel(listbook_main, ID_PANEL_SHARES,
    wxDefaultPosition, wxSize(500, 400));
  std::list<packethandler::InstantMessage> m_list;
  int n =
    maidsafe::ClientController::getInstance()->GetInstantMessages(&m_list);
  while (!m_list.empty()) {
    all_messages_.push_back(m_list.front());
    m_list.pop_front();
  }

  if (n == 0) {
    panel_messages = new MessagePanel(listbook_main, ID_PANEL_MESSAGES,
      wxDefaultPosition, wxSize(500, 400), &all_messages_);
  } else {
    panel_messages = new MessagePanel(listbook_main, ID_PANEL_MESSAGES,
      wxDefaultPosition, wxSize(500, 400));
  }
  panel_contacts = new contacts(listbook_main, ID_PANEL_CONTACTS,
    wxDefaultPosition, wxSize(500, 400));

  listbook_images = new wxImageList(32, 32);
  listbook_images->Add(wxXmlResource::Get()->LoadBitmap(wxT("messages")));
  listbook_images->Add(wxXmlResource::Get()->LoadBitmap(wxT("contacts")));
  listbook_images->Add(wxXmlResource::Get()->LoadBitmap(wxT("shares")));
  listbook_main->SetImageList(listbook_images);

  switch (shown_panel) {
    case 0: listbook_main->AddPage(panel_messages, _("Messages"), true, 0);
            listbook_main->AddPage(panel_contacts, _("Contacts"), false, 1);
            listbook_main->AddPage(panel_shares, _("Shares"), false, 2);
            break;
    case 1: listbook_main->AddPage(panel_messages, _("Messages"), false, 0);
            listbook_main->AddPage(panel_contacts, _("Contacts"), true, 1);
            listbook_main->AddPage(panel_shares, _("Shares"), false, 2);
            break;
    case 2: listbook_main->AddPage(panel_messages, _("Messages"), false, 0);
            listbook_main->AddPage(panel_contacts, _("Contacts"), false, 1);
            listbook_main->AddPage(panel_shares, _("Shares"), true, 2);
            break;
  }

  panel_login->Hide();
  listbook_main->Show();
  frame_sizer->ComputeFittingClientSize(this);
  frame_sizer->ComputeFittingWindowSize(this);
  frame_sizer->RecalcSizes();
  frame_sizer->Fit(this);
  MenuBar1->Enable(IDMENULOGOUT, true);
  Layout();
}

void pdguiFrame::RemoveLoggedInPanels() {
  unsigned int panel_cnt = listbook_main->GetPageCount();
  while (panel_cnt > 0) {
    listbook_main->DeletePage(panel_cnt - 1);
    panel_cnt = listbook_main->GetPageCount();
  }
}

void pdguiFrame::UserExists_Callback(const std::string &result) {
  maidsafe::GetResponse res;
  printf("pdguiFrame::UserExists_Callback\n");
  if ((!res.ParseFromString(result)) || (res.result() != kCallbackSuccess)) {
    got_enc_data = false;
  } else {
    got_enc_data = true;
  }
}
