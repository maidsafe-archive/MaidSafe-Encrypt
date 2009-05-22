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
 *    Author: Team
 */

#include "gui/general_login.h"
#ifdef MAIDSAFE_WIN32
  // TODO(dan): MINGW #include "wx/msw/winundef.h".
#endif

#include <wx/wx.h>
#include <wx/msgdlg.h>
#include <wx/app.h>
#include <wx/xrc/xmlres.h>
#include <wx/wizard.h>
#include <wx/popupwin.h>
#include <wx/frame.h>
#include <wx/stattext.h>
#include <wx/log.h>
#include <wx/checkbox.h>
#include <wx/checklst.h>
#include <wx/radiobox.h>
#include <wx/menu.h>
#include <wx/sizer.h>

#include <boost/thread/thread.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/progress.hpp>
#include <boost/scoped_ptr.hpp>

#include <string>

#include "gui/pdguiapp.h"
#include "gui/pdguimain.h"
#include "maidsafe/client/clientcontroller.h"

const int32_t general_login::ID_GAUGE_LOGIN = wxNewId();
const int32_t general_login::ID_STATICTEXT_LOGIN = wxNewId();
const int32_t general_login::ID_CHECKBOX_SAVE_USER_AND_PIN = wxNewId();
const int32_t general_login::ID_STATICTEXTUSERNAME = wxNewId();
const int32_t general_login::ID_TEXTCTRLUSERNAME = wxNewId();
const int32_t general_login::ID_STATICTEXTPIN = wxNewId();
const int32_t general_login::ID_TEXTCTRLPIN = wxNewId();
const int32_t general_login::ID_STATICTEXTPASSWORD = wxNewId();
const int32_t general_login::ID_TEXTCTRLPASSWORD = wxNewId();
const int32_t general_login::ID_STATICTEXT1 = wxNewId();
const int32_t general_login::ID_NEWUSER = wxNewId();
const int32_t general_login::ID_LOGIN = wxNewId();
const int32_t general_login::ID_STATICBITMAPPD = wxNewId();
const int32_t general_login::ID_WIZARD = wxNewId();

general_login::general_login(wxWindow* parent,
  wxWindowID id, const wxPoint& pos, const wxSize& size)
  : wxPanel(parent, id, pos, size), StaticTextCREATEUSER(NULL),
  button_create_user(NULL), GridSizer1(NULL),
  BoxSizer2(NULL), BoxSizer4(NULL), fsys(NULL),
  #ifdef MAIDSAFE_WIN32
  #else
    fsl_(),
  #endif
  BoxSizer5(NULL), BoxSizer3(NULL), BoxSizer1(NULL),
  static_username(NULL), button_login(NULL),
  txt_password(NULL), StaticBitmapPD(NULL),
  txt_pin(NULL), button_cancel_clear1(NULL),
  button_cancel_clear(NULL), gauge_login(NULL),
  static_password(NULL), txt_username(NULL),
  static_txt_progress(NULL), static_pin(NULL),
  check_box_save_user_and_pin(NULL),
  wizard(NULL), m_parent(NULL) {
  fsys = new file_system::FileSystem;
  m_parent = parent;
  GridSizer1 = new wxFlexGridSizer(9, 1, 0, 0);
  GridSizer1->AddGrowableCol(0);
  GridSizer1->AddGrowableRow(1);
  GridSizer1->AddGrowableRow(2);
  GridSizer1->AddGrowableRow(3);
  GridSizer1->AddGrowableRow(4);
  GridSizer1->AddGrowableRow(5);
  GridSizer1->AddGrowableRow(6);
  GridSizer1->AddGrowableRow(7);
  GridSizer1->AddGrowableRow(8);

  wxBitmap image_pd = wxXmlResource::Get()->LoadBitmap(wxT("pd"));
  StaticBitmapPD = new wxStaticBitmap(this,
    ID_STATICBITMAPPD, image_pd, wxDefaultPosition,
    wxDefaultSize, 0, _T("ID_STATICBITMAPPD"));
  GridSizer1->Add(StaticBitmapPD, 1, wxALL|wxALPHA_TRANSPARENT|
    wxALIGN_CENTER_HORIZONTAL|wxEXPAND|wxALIGN_CENTER_VERTICAL, 5);
  static_username = new wxStaticText(this, ID_STATICTEXTUSERNAME,
    _("Enter &username"), wxDefaultPosition,
    wxDefaultSize, 0, _T("ID_STATICTEXTUSERNAME"));
  GridSizer1->Add(static_username, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
  txt_username = new wxTextCtrl(this, ID_TEXTCTRLUSERNAME, wxEmptyString,
    wxDefaultPosition, wxSize(200, 20), wxPROCESS_ENTER,
    wxDefaultValidator, _T("ID_TEXTCTRLUSERNAME"));
  // txt_username->SetMaxLength(25);
  txt_username->SetFocus();
  txt_username->SetToolTip(_T("Enter a username. ")
    _T("Do not use dictionary words or names."));
  txt_username->SetHelpText(_T("Your username is private ")
    _T("to you. It should be between 4 and 25 characters."));
  GridSizer1->Add(txt_username, 1,
    wxALL|wxEXPAND|wxALIGN_TOP|wxALIGN_LEFT, 5);

  static_pin = new wxStaticText(this, ID_STATICTEXTPIN, _("Enter pi&n"),
    wxDefaultPosition, wxDefaultSize, 0, _T("ID_STATICTEXTPIN"));
  GridSizer1->Add(static_pin, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_BOTTOM, 5);
  txt_pin = new wxTextCtrl(this, ID_TEXTCTRLPIN,
    wxEmptyString, wxDefaultPosition, wxSize(200, 20),
    wxTE_PASSWORD|wxPROCESS_ENTER,
    wxTextValidator(wxFILTER_NUMERIC), _T("ID_TEXTCTRLPIN"));
  txt_pin->Disable();
  // txt_pin->SetMaxLength(4);
  txt_pin->SetToolTip(_T("Enter a pin (numbers only). Note this ")
    _T("pin is private to you, do not divulge this to anyone."));
  txt_pin->SetHelpText(_T("You need to enter a 4 digit ")
    _T("private identification number here."));
  GridSizer1->Add(txt_pin, 1, wxALL|wxEXPAND|wxALIGN_TOP|wxALIGN_BOTTOM, 5);

  static_password = new wxStaticText(this,
    ID_STATICTEXTPASSWORD, _("Enter &password"),
    wxDefaultPosition, wxDefaultSize, 0, _T("ID_STATICTEXTPASSWORD"));
  GridSizer1->Add(static_password, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_BOTTOM, 5);
  txt_password = new wxTextCtrl(this, ID_TEXTCTRLPASSWORD, wxEmptyString,
    wxDefaultPosition, wxSize(200, 20), wxPROCESS_ENTER|wxTE_PASSWORD,
    wxDefaultValidator, _T("ID_TEXTCTRLPASSWORD"));
  txt_password->Disable();
  // txt_password->SetMaxLength(25);
  txt_password->SetToolTip(_("type a password here"));
  txt_password->SetHelpText(_T("Enter a password, please use ")
    _T("numbers and characters to increase security. \n"));
  txt_password->Disable();
  GridSizer1->Add(txt_password, 1,
    wxALL|wxEXPAND|wxALIGN_TOP|wxALIGN_LEFT, 5);

  BoxSizer2 = new wxBoxSizer(wxHORIZONTAL);
  button_cancel_clear = new wxButton(this, wxID_CLEAR, wxEmptyString,
  wxDefaultPosition, wxDefaultSize, 0,
    wxDefaultValidator, _T("wxID_CLEAR"));
  button_create_user = new wxButton(this,
    ID_NEWUSER, _("C&reate"), wxDefaultPosition, wxDefaultSize,
    0, wxDefaultValidator, _T("ID_NEWUSER"));
  BoxSizer2->Add(button_cancel_clear, 1, wxTOP|wxLEFT|wxRIGHT|
    wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 2);
  BoxSizer2->Add(button_create_user, 1,
    wxTOP|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);
  StaticTextCREATEUSER = new wxStaticText(this, ID_STATICTEXT1,
    _(" "), wxDefaultPosition, wxDefaultSize, 0, _T("ID_STATICTEXT1"));
  // StaticTextCREATEUSER->Hide();
  // BoxSizer2->Add(StaticTextCREATEUSER, 1,
  // wxTOP|wxRIGHT|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);

  // button_create_user->Disable();
  // button_create_user->Hide();
  button_create_user->SetToolTip(_T("If you do not have an account type ")
    _T("in your requested details and click here."));
  button_create_user->SetHelpText(_T("To create a user you will be required ")
    _T("to either purchase tokens by selecting the purchase page, or set up ")
    _T("a local vault which will act as your payment to the network. ")
    _T("None of your data will be stored here."));
  // BoxSizer2->Add(button_create_user, 1,
  // wxTOP|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);
  // BoxSizer2->Show(false);

  BoxSizer1 = new wxBoxSizer(wxHORIZONTAL);
  button_cancel_clear1 = new wxButton(this, wxID_CLEAR, wxEmptyString,
    wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, _T("wxID_CLEAR"));

//   button_cancel_clear->Hide();


  button_login = new wxButton(this, ID_LOGIN, _("&Login"),
    wxPoint(-1, -1), wxSize(-1, -1), 0, wxDefaultValidator, _T("ID_LOGIN"));
  // button_login->Disable();
  // button_login->Hide();
  BoxSizer1->Add(button_login, 1,
    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);
  // add these to the grid

  BoxSizer4 = new wxBoxSizer(wxHORIZONTAL);

  BoxSizer4->Add(button_cancel_clear1, 1, wxRIGHT, 2);
  BoxSizer4->Add(StaticTextCREATEUSER, 1,
    wxTOP|wxRIGHT|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);
  button_cancel_clear1->Enable(false);
  GridSizer1->Add(BoxSizer4, 1,
    wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 0);
  GridSizer1->Add(BoxSizer1, 1,
    wxEXPAND|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 0);
  GridSizer1->Add(BoxSizer2, 1,
    wxEXPAND|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 1);
  GridSizer1->Show(BoxSizer1, false);
  GridSizer1->Show(BoxSizer2, false);

  SetSizer(GridSizer1);

  GridSizer1->Fit(this);
  GridSizer1->SetSizeHints(this);
  // GridSizer1->Show(BoxSizer4, false);
  // GridSizer1->Layout();

  Connect(ID_CHECKBOX_SAVE_USER_AND_PIN, wxEVT_COMMAND_CHECKBOX_CLICKED,
    (wxObjectEventFunction)&general_login::Oncheck_box_save_user_and_pinClick);

  // Connect(ID_TEXTCTRLPIN,wxEVT_COMMAND_TEXT_UPDATED,
  // (wxObjectEventFunction)&general_login::Ontxt_pinText);
  Connect(ID_TEXTCTRLUSERNAME, wxEVT_COMMAND_TEXT_ENTER,
    reinterpret_cast<wxObjectEventFunction>
    (&general_login::Ontxt_username_enter));
  Connect(ID_TEXTCTRLPIN, wxEVT_COMMAND_TEXT_ENTER,
    reinterpret_cast<wxObjectEventFunction>(&general_login::Ontxt_pin_enter));
  Connect(ID_TEXTCTRLPASSWORD, wxEVT_COMMAND_TEXT_ENTER,
    reinterpret_cast<wxObjectEventFunction>
    (&general_login::Ontxt_password_enter));
  //  txt_username->Connect(ID_TEXTCTRLUSERNAME,wxEVT_COMMAND_KILL_FOCUS,
  //  wxFocusEventHandler(general_login::Ontxt_username_foc));

  Connect(wxID_CLEAR, wxEVT_COMMAND_BUTTON_CLICKED,
    reinterpret_cast<wxObjectEventFunction>
    (&general_login::Onbutton_cancel_clearClick));
  Connect(ID_NEWUSER, wxEVT_COMMAND_BUTTON_CLICKED,
    reinterpret_cast<wxObjectEventFunction>
    (&general_login::Onbutton_createCLICK));
  Connect(ID_WIZARD, wxEVT_WIZARD_CANCEL,
    reinterpret_cast<wxObjectEventFunction>
    (&general_login::Onbutton_cancel_clearClick));
  // Here we a re catching tab keys - cause using PROCESS_ENTER stops this and
  // the control we want to tab to is dead so we need to enable it first
  txt_username->GetEventHandler()->Connect(
    wxEVT_KEY_DOWN, wxKeyEventHandler(general_login::OnKey_username));
  txt_pin->GetEventHandler()->Connect(
    wxEVT_KEY_DOWN, wxKeyEventHandler(general_login::OnKey_pin));
}

general_login::~general_login() {}

void general_login::Onbutton_createCLICK(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  wxBitmap world = wxXmlResource::Get()->LoadBitmap(wxT("world"));

  wizard = new wxWizard(this, ID_WIZARD,
              wxT("Perpetualdata private account setup."),
              world,
              wxDefaultPosition,
              wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
  //  PAGE 1
  wxWizardPageSimple *page1 = new wxWizardPageSimple(wizard);
  wxWizardPageSimple *page2 = new wxWizardPageSimple(wizard);
  wxWizardPageSimple *page3 = new wxWizardPageSimple(wizard);
  // wxWizardPageSimple *page4 = new wxWizardPageSimple(wizard);
  // wxWizardPageSimple *page5 = new wxWizardPageSimple(wizard);
  // wxWizardPageSimple *page6 = new wxWizardPageSimple(wizard);
  // wxWizardPageSimple *page7 = new wxWizardPageSimple(wizard);
  //  wxStaticText *text1 = new wxStaticText(page1, wxID_ANY,
  //    wxT("Welcome to perpetualdata, if you expected to login sorry\n")
  //    wxT("you must have mistyped your details. click cancel to try again.")
  //    wxT("\n For new people on the network - there only a few questions\n")
  //    wxT("that will set up your account and provide you all the services\n")
  //    wxT("Free of charge, please click next"),
  //    wxPoint(5, 5));
  //  wxStaticText *text2 = new wxStaticText(page2, wxID_ANY,
  //    wxT("Ok first we ensure you typed the correct details\n")
  //    wxT("so we show the pin and password textctrls here again.")
  //    wxT("\nWe will have already stored the tmid etc. with a 1 hour IOU\n"),
  //    wxPoint(5, 5));
  //  wxStaticText *text3 = new wxStaticText(page3, wxID_ANY,
  //    wxT("Now a radiobox page (i.e. extend simple page)\n")
  //    wxT("To use perpetual data you need some disk space.")
  //    wxT("\n choice 1 - This is my computer, its on \nmost of the time\n")
  //    wxT("\n So set up loval vault store 0's and create IOU's\n")
  //    wxT("choice 2 - I will enter the name of somebody
  //    \n who will provide me\n")
  //    wxT("with some space (here ask user to set up public
  //    \n name to tell their pal.\n)")
  //    wxT("\n So we add pub_name get pal's name and use buffer messages\n")
  //    wxT("choice 3 - I will buy some IOU's from maidsafe ! \n")
  //    wxT("\nSo here we direct them to maidsafe website \n")
  //    wxT("\nby create a tmp id go to our buy page with the id in the link\n")
  //    wxT("\npurchase means tehir browser downloads a miadsafe file\n")
  //    wxT("\nor similar (we may be able to
  //    use html page in the app direct)\n"),
  //    wxPoint(5, 5));
  wxWizardPageSimple::Chain(page1, page2);
  wxWizardPageSimple::Chain(page2, page3);
  wizard->GetPageAreaSizer()->Add(page1);
  wizard->GetPageAreaSizer()->Add(page2);
  wizard->GetPageAreaSizer()->Add(page3);
  wizard->RunWizard(page1);
  // if finished ctrl passed to pdguimain::onCREATE
  // else clear details (Clear function grabs the event)
}

void general_login::OnKey_username(wxKeyEvent& event) {  // NOLINT
  if (event.GetKeyCode() == WXK_TAB) {
    wxTextCtrl* user = reinterpret_cast<wxTextCtrl*>(event.GetEventObject());
    user->Disable();
    wxWindow *panel = reinterpret_cast<wxWindow*>(user->GetParent());
    wxWindow * win = panel->FindWindow(ID_TEXTCTRLPIN);
    win->Enable();
    win->SetFocus();
    Navigate(wxNavigationKeyEvent::IsForward);
  } else {
    event.Skip();
  }
}

void general_login::OnKey_pin(wxKeyEvent& event) {  // NOLINT
  if (event.GetKeyCode() == WXK_TAB) {
    wxTextCtrl* pin = reinterpret_cast<wxTextCtrl*>(event.GetEventObject());
    pin->Disable();
    wxWindow *panel = reinterpret_cast<wxWindow*>(pin->GetParent());
    wxWindow * pas = panel->FindWindow(ID_TEXTCTRLPASSWORD);
    pas->Enable();
    pas->SetFocus();
    Navigate(wxNavigationKeyEvent::IsForward);
  } else {
    event.Skip();
  }
}

void general_login::Ontxt_username_enter(wxCommandEvent& event) {  // NOLINT
  txt_username->Disable();
  txt_pin->Enable();
  txt_pin->SetFocus();
  button_cancel_clear1->Enable();
  // GridSizer1->Show(BoxSizer4, true);
  GridSizer1->Layout();
  event.Skip();
}

void general_login::Ontxt_username_foc(wxFocusEvent& event) {  // NOLINT
  txt_username->Disable();
  txt_pin->Enable();
  txt_pin->SetFocus();
  GridSizer1->Layout();
  event.Skip();
}


void general_login::Ontxt_pin_enter(wxCommandEvent& event) {  // NOLINT
  txt_pin->Disable();
  txt_password->Enable();
  txt_password->SetFocus();
  event.Skip();
}

// void general_login::Ontxt_username_txt(wxCommandEvent& event) {  // NOLINT
// // if (event. == wxT("\t"))
// // {
// //  Ontxt_username_enter();
// // }
// button_cancel_clear1->Enable(true);
// }

void general_login::Ontxt_password_enter(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  txt_pin->Disable();
}



void general_login::Ontxt_passwordText(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  txt_pin->Disable();
  event.Skip();
}

void general_login::Oncheck_box_save_user_and_pinClick(
  wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  if (check_box_save_user_and_pin->GetValue()) {
    wxString msg = wxT("This is not recommended and will \n");
    msg += wxT("potentially cause security breaches.");
    wxMessageBox(msg, wxT("Warning"));
  }
}


void general_login::Onbutton_cancel_clearClick(
  wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  ClearData();
}

std::string general_login::GetUsername() {
  wxString wxusername = txt_username->GetValue();
  std::string username((const char*)wxusername.mb_str());
  return username;
}

std::string general_login::GetPin() {
  wxString wxpin = txt_pin->GetValue();
  std::string pin((const char*)wxpin.mb_str());
  return pin;
}

std::string general_login::GetPassword() {
  wxString wxpasswd = txt_password->GetValue();
  std::string password((const char*)wxpasswd.mb_str());
  return password;
}

void general_login::ShowProgress(std::string value) {
  wxString wxvalue(wxString::FromAscii((const char*) value.c_str()));
  StaticTextCREATEUSER->SetLabel(wxvalue);
  StaticTextCREATEUSER->Show();
}

void general_login::HideProgress() {
  if (static_txt_progress->IsShown())
    static_txt_progress->Hide();
}

void general_login::ClearData() {
  txt_username->Clear();
  txt_pin->Clear();
  txt_password->Clear();
  txt_username->Enable(true);
  txt_pin->Enable(false);
  txt_password->Enable(false);
  txt_username->SetFocus();
}

