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
#include "gui/contact_detail.h"
#include <wx/list.h>
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"
#include "gui/contacts.h"

// #ifdef WIN32
//  #include <wxprec_monolib.pch"
// #endif

const int32_t ContactDetail::id_static_bitmap_user_status = wxNewId();
const int32_t ContactDetail::id_static_text_contact_name = wxNewId();
const int32_t ContactDetail::id_bitmap_button_user_actions = wxNewId();
const int32_t ContactDetail::id_delete_user_button = wxNewId();
const int32_t ContactDetail::id_static_bitmap_user_photo = wxNewId();
const int32_t ContactDetail::id_text_ctrl_user_comment = wxNewId();
const int32_t ContactDetail::id_bitmap_button_user_profile = wxNewId();
const int32_t ContactDetail::id_button_send_message = wxNewId();
const int32_t ContactDetail::id_bitmap_button_send_file = wxNewId();
const int32_t ContactDetail::id_static_text_last_seen = wxNewId();
const int32_t ContactDetail::id_menuitem_send_message1 = wxNewId();
const int32_t ContactDetail::id_menu_item_block_user = wxNewId();
const int32_t ContactDetail::id_menu_item_delete_user = wxNewId();
const int32_t ContactDetail::id_menu_item_add_to_share_ro = wxNewId();
const int32_t ContactDetail::id_menu_item_add_to_share_rw = wxNewId();
const int32_t ContactDetail::id_menu_item_add_to_share_admin = wxNewId();
const int32_t ContactDetail::id_menu_item_remove_from_share = wxNewId();
const int32_t ContactDetail::id_menuitem_share1 = wxNewId();
const int32_t ContactDetail::id_menu_shares = wxNewId();
// const long ContactDetail::id_win_contact_detail = wxNewId();

BEGIN_EVENT_TABLE(ContactDetail, wxPanel)
  // (*EventTable(ContactDetail)
  // *)
END_EVENT_TABLE()

ContactDetail::ContactDetail(wxWindow* parent,
  wxWindowID id_win_contact_detail, const wxPoint& pos, const wxSize& size,
  const wxString& user_name_, const char &status)
  : user_action_menu(), user_name(), flex_grid_small(NULL),
  flex_grid_detail(NULL), flex_grid_main(NULL),
  FileDialog1(NULL), db_key() {
  user_name = user_name_;

  Create(parent, id_win_contact_detail, pos, size,
    wxNO_BORDER|wxTAB_TRAVERSAL, _T("id_win_contact_detail"));


  // Controls below
  wxStaticBitmap* bitmap_user_status = NULL;
  if (status == 'C') {
    bitmap_user_status = new wxStaticBitmap(this, id_static_bitmap_user_status,
      wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(
      _T("wxART_TICK_MARK")), wxART_OTHER), wxDefaultPosition,
      wxDefaultSize, wxNO_BORDER, _T("id_static_bitmap_user_status"));
  } else {
    bitmap_user_status = new wxStaticBitmap(this, id_static_bitmap_user_status,
      wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(
      _T("wxART_QUESTION")), wxART_OTHER), wxDefaultPosition,
      wxDefaultSize, wxNO_BORDER, _T("id_static_bitmap_user_status"));
  }

  wxStaticText* static_text_contact_name = new wxStaticText(this,
    id_static_text_contact_name, user_name_, wxDefaultPosition, wxDefaultSize,
    wxNO_BORDER, _T("id_static_text_contact_name"));

  static_text_contact_name->SetMinSize(wxDLG_UNIT(this, wxSize(50, 10)));

  wxBitmapButton* delete_user_button =
    new wxBitmapButton(this, id_delete_user_button,
    wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(_T("wxART_ERROR")),
    wxART_BUTTON), wxDefaultPosition, wxSize(35, 40),
    wxBU_AUTODRAW|wxNO_BORDER|wxTAB_TRAVERSAL,
    wxDefaultValidator, _T("id_bitmap_button_user_actions"));

//  wxTextCtrl* txt_ctrl_user_comment =
//    new wxTextCtrl(this, id_text_ctrl_user_comment,
//    _("No comment !"), wxDefaultPosition, wxDefaultSize,
//    wxTE_MULTILINE|wxTE_AUTO_URL|wxTC_OWNERDRAW|
//    wxNO_BORDER|wxTEXT_ALIGNMENT_JUSTIFIED,
//    wxDefaultValidator, _T("id_text_ctrl_user_comment"));

  wxBitmapButton* view_profile_button =
    new wxBitmapButton(this, id_bitmap_button_user_profile,
    wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(_T("wxART_HELP_BOOK")),
    wxART_BUTTON), wxDefaultPosition, wxDefaultSize,
    wxBU_AUTODRAW|wxNO_BORDER|wxTAB_TRAVERSAL, wxDefaultValidator,
    _T("id_bitmap_button_user_profile"));

  view_profile_button->SetBitmapDisabled(wxArtProvider::GetBitmap(
    wxART_MAKE_ART_ID_FROM_STR(_T("wxART_UNDO")), wxART_BUTTON));

  view_profile_button->SetBitmapSelected(wxArtProvider::GetBitmap(
    wxART_MAKE_ART_ID_FROM_STR(_T("wxART_FIND")), wxART_BUTTON));

  view_profile_button->SetBitmapFocus(wxArtProvider::GetBitmap(
    wxART_MAKE_ART_ID_FROM_STR(_T("wxART_INFORMATION")), wxART_BUTTON));

  view_profile_button->SetToolTip(_("See this persons profile"));

  wxBitmapButton* button_send_message = new wxBitmapButton(this,
    id_button_send_message, wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR
    (_T("wxART_HELP_PAGE")), wxART_BUTTON), wxDefaultPosition,
    wxDefaultSize, wxBU_AUTODRAW|wxNO_BORDER|wxTAB_TRAVERSAL,
    wxDefaultValidator, _T("id_button_send_message"));

  button_send_message->SetDefault();
  button_send_message->SetToolTip(_("send message to"));

  wxBitmapButton* file_send_button =
    new wxBitmapButton(this, id_bitmap_button_send_file,
    wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(_T("wxART_GO_DIR_UP")),
    wxART_BUTTON), wxDefaultPosition, wxDefaultSize,
    wxBU_AUTODRAW|wxNO_BORDER|wxTAB_TRAVERSAL, wxDefaultValidator,
    _T("id_bitmap_button_send_file"));

  file_send_button->SetBitmapSelected(wxArtProvider::GetBitmap(
    wxART_MAKE_ART_ID_FROM_STR(_T("wxART_FOLDER_OPEN")), wxART_BUTTON));

  file_send_button->SetDefault();
  file_send_button->SetToolTip(_("Send file(s) to "));

//  wxStaticText* static_last_seen =
//    new wxStaticText(this, id_static_text_last_seen,
//    _("Last Seen"), wxDefaultPosition, wxDefaultSize, wxNO_BORDER,
//    _T("id_static_text_last_seen"));
//  static_last_seen->SetForegroundColour(
//    wxSystemSettings::GetColour(wxSYS_COLOUR_GRAYTEXT));
//  static_last_seen->SetToolTip(_("Last seen"));

  // Dialog's below
  file_system::FileSystem fs;
  #ifdef __WIN32__
    // TODO(richard): Change to make sure the correct letter is passed.
    wxString default_dir = wxString::FromAscii("M:\\");
  #else
    wxString default_dir = wxString::FromAscii(fs.MaidsafeFuseDir().c_str());
  #endif
  FileDialog1 = new wxFileDialog(this, _("Select file"),
    default_dir, wxEmptyString, _("*"), wxFD_DEFAULT_STYLE|wxFD_OPEN|
    wxFD_FILE_MUST_EXIST|wxFD_MULTIPLE|wxNO_BORDER|wxTRANSPARENT_WINDOW,
    wxDefaultPosition, wxDefaultSize, _T("wxFileDialog"));

  //  wxString __wxMultiChoiceDialogChoices_1[9] = {
  //    _("Block "),
  //    _("Delete"),
  //    _("Send message"),
  //    _("Send file(s)"),
  //    _("Add to group"),
  //    _("Add to share as admin"),
  //    _("Add to share as read/write"),
  //    _("Add to share as read/only"),
  //    _("Show log")
  //  };

  //  wxMultiChoiceDialog* user_action_dialog =
  //    new wxMultiChoiceDialog(this, _("Actions"),
  //    _("Actions menu"), 9, __wxMultiChoiceDialogChoices_1,
  //    wxCHOICEDLG_STYLE|wxOK|wxCANCEL|wxCENTRE, wxDefaultPosition);

  // Sizers
  wxBoxSizer* BoxSizer2 = new wxBoxSizer(wxHORIZONTAL);
  wxBoxSizer* BoxSizer1 = new wxBoxSizer(wxHORIZONTAL);
  flex_grid_small = new wxFlexGridSizer(1, 6, 0, 0);
  // flex_grid_detail = new wxFlexGridSizer(1, 5, 0, 0);
  flex_grid_main = new wxFlexGridSizer(0, 1, 0, 0);
  flex_grid_main->AddGrowableRow(0, 1);
  flex_grid_main->AddGrowableRow(1, 1);
  flex_grid_main->AddGrowableRow(2, 1);

  // Layout
  flex_grid_small->Add(bitmap_user_status, 1,
    wxTOP|wxBOTTOM|wxLEFT|wxALIGN_CENTER_VERTICAL, 5);

  flex_grid_small->Add(static_text_contact_name, 1,
    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL,
    wxDLG_UNIT(this, wxSize(5, 0)).GetWidth());

//  flex_grid_small->Add(user_actions_button, 1,
//    wxALL|wxSHAPED|wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);

  // R0 C0
  flex_grid_small->Add(delete_user_button, 1,
    wxALL|wxEXPAND|wxSHAPED|wxALIGN_LEFT|wxALIGN_TOP, 5);
  // R0 C1
//  flex_grid_detail->Add(txt_ctrl_user_comment, 1,
//    wxALL|wxEXPAND|wxSHAPED|wxALIGN_LEFT|wxALIGN_TOP, 5);

  BoxSizer1->Add(view_profile_button, 1,
    wxALL|wxSHAPED|wxALIGN_RIGHT|wxALIGN_CENTER_VERTICAL, 5);

  // R0 C2
  flex_grid_small->Add(BoxSizer1, 1,
    wxALL|wxEXPAND|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);

  BoxSizer2->Add(button_send_message, 1,
    wxALL|wxSHAPED|wxALIGN_LEFT|wxALIGN_TOP, 5);

  BoxSizer2->Add(file_send_button, 1,
    wxALL|wxSHAPED|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);

  // R1 C0
  flex_grid_small->Add(BoxSizer2, 1,
    wxALL|wxEXPAND|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);

  // R1 C1
  flex_grid_main->Add(flex_grid_small, 1, wxALL|wxALIGN_LEFT|wxALIGN_TOP, 5);

  Layout();
  SetSizer(flex_grid_main);
  flex_grid_main->Layout();
  flex_grid_main->Fit(this);
  flex_grid_main->SetSizeHints(this);

  Layout();

  Connect(id_bitmap_button_user_actions, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(ContactDetail::Onuser_actions_buttonClick));

  Connect(id_delete_user_button, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(ContactDetail::Ondelete_user_buttonClick));

  // user_actions_button->Connect(id_bitmap_button_user_actions,
  // wxEVT_ENTER_WINDOW, wxMouseEventHandler(ContactDetail::OnMouseEnter));

  // user_actions_button->Connect(id_bitmap_button_user_actions,
  // wxEVT_LEAVE_WINDOW, wxMouseEventHandler(ContactDetail::OnMouseEnter));

  // Connect(id_text_ctrl_user_comment, wxEVT_COMMAND_TEXT_UPDATED,
  //   wxCommandEventHandler(ContactDetail::Ontxt_ctrl_user_commentText));

  Connect(id_bitmap_button_user_profile, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(ContactDetail::Onview_profile_buttonClick));

  Connect(id_button_send_message, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(ContactDetail::Onbutton_send_messageClick));

  Connect(id_bitmap_button_send_file, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(ContactDetail::Onfile_send_buttonClick));

  //   Connect(wxID_ANY,wxEVT_LEAVE_WINDOW,wxMouseEventHandler(
  //    ContactDetail::OnMouseLeave));

  //   Connect(wxID_ANY,wxEVT_LEFT_DOWN,wxMouseEventHandler(
  //    ContactDetail::OnMouseLeave));
}

ContactDetail::~ContactDetail() {
}

void ContactDetail::Onview_profile_buttonClick(
  wxCommandEvent& event) {  // NOLINT
  wxBitmapButton* wxbb =
    reinterpret_cast<wxBitmapButton*>(event.GetEventObject());
  ContactDetail* cd = reinterpret_cast<ContactDetail*>(wxbb->GetParent());
  wxString wx_pub_name = cd->GetUser();
  std::string pub_name((const char*)wx_pub_name.mb_str());
  std::vector<maidsafe::Contacts> c_list;
  int n = maidsafe::ClientController::getInstance()->ContactList(
    &c_list, pub_name);
  if (n == 0) {
    maidsafe::Contacts c = c_list[0];
    std::string details("Public Username: ");
    details += pub_name + "\n";
    details += "Full Name: " + c.FullName() + "\n";
    details += "Office Phone: " + c.OfficePhone() + "\n";
    details += "Birthday: " + c.Birthday() + "\n";
    std::string gender;
    gender.resize(1, c.Gender());
    details += "Gender: " + gender + "\n";
    details += "Language: " + base::itos(c.Language()) + "\n";
    details += "City: " + c.City() + "\n";
    details += "Country: " + base::itos(c.Country()) + "\n";
    wxMessageBox(wxString::FromAscii(details.c_str()),
      _("Contact Details"), wxOK, this);
  } else {
    std::string details("Error finding details of user: " + pub_name);
    wxMessageBox(wxString::FromAscii(details.c_str()),
      _("Error"), wxOK, this);
  }
}

void ContactDetail::Ondelete_user_buttonClick(
  wxCommandEvent& event) {  // NOLINT
  wxBitmapButton* wxbb = reinterpret_cast<wxBitmapButton*>
    (event.GetEventObject());
  ContactDetail* cd = reinterpret_cast<ContactDetail*>(wxbb->GetParent());
  wxString wx_pub_name = cd->GetUser();
  std::string pub_name((const char*)wx_pub_name.mb_str());
  int n = maidsafe::ClientController::getInstance()->DeleteContact(pub_name);
  //  std::cout << "Deletion result: " << n << std::endl;
  if (n == 0) {
    // id_contact_scrolled_window
    wxScrolledWindow *sw =
      reinterpret_cast<wxScrolledWindow*>(cd->GetParent());
    wxFlexGridSizer *cfgs =
      reinterpret_cast<wxFlexGridSizer*>(sw->GetSizer());
    // contacts *cp = reinterpret_cast<contacts*>(sw->GetParent());
    cfgs->Clear();
    std::vector<maidsafe::Contacts> contact_list;
    int get_contact_result =
      maidsafe::ClientController::getInstance()->ContactList(
      &contact_list, "");
    if (get_contact_result == 0) {  //  Success
      for (unsigned int n = 0; n < contact_list.size(); n++) {
        maidsafe::Contacts c = contact_list[n];
        wxString wx_s = wxString::FromAscii(c.PublicName().c_str());
        ContactDetail *i = new ContactDetail(sw, wxID_ANY,
          wxDefaultPosition, wxDefaultSize, wx_s, c.Confirmed());
        cfgs->Add(i, 1, wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
      }
    }
    sw->SetSizer(cfgs);
    cfgs->Fit(sw);
    sw->Layout();
  }
}

void ContactDetail::Onuser_actions_buttonClick(
  wxCommandEvent& event) {  // NOLINT
  std::cout << "In useractions" << std::endl;
  // TODO(david): we can do this much better I think
  // by using on mouse enter - set a flag for this panel
  // and first hide detail from any opened panels
  // this will allow us to move the mouse over
  // a contact to see the detail - easily
  wxWindow * win(reinterpret_cast<wxWindow *>(
    FindWindowByName(_("id_contact_scrolled_window"), NULL)));
  if (flex_grid_main->IsShown(flex_grid_detail)) {
    flex_grid_main->Show(flex_grid_detail, false);
    // win->SetSizer(flex_grid_main);
    // flex_grid_detail->Layout();
    win->GetSizer()->Layout();
    win->Refresh();
  //   flex_grid_main->Fit(win);
  //   flex_grid_main->SetSizeHints(win);
  } else {
    flex_grid_main->Show(flex_grid_detail, true);
  // win->SetSizer(flex_grid_main);
  //  flex_grid_detail->Layout();
  //  flex_grid_main->Layout();
    win->GetSizer()->Layout();
    win->Refresh();
  //   flex_grid_main->Fit(win);
  //   flex_grid_main->SetSizeHints(win);
  }
  // wxWindow * win((wxWindow *)FindWindowByName
  //  (_("id_contact_scrolled_window"),NULL));
  //  wxWindow * win(FindWindowByName(_("id_contact_scrolled_window"),NULL));
  //  if (win->GetSizer())
  //  {

  flex_grid_main->Layout();
  flex_grid_main->Fit(this);

  //  } else {
  //    std::cout << "cannot get sizer" <<std::endl;
  //  }

  event.Skip();   //  catch it in another window if we want / need
}

void ContactDetail::Onbutton_send_messageClick(
  wxCommandEvent& event) {  // NOLINT
  wxTextEntryDialog dialog(this, _T("Please Enter a ") _T("quick message"),
    _T("Messsage entry"), _T(""), wxOK | wxCANCEL);

  if (dialog.ShowModal() == wxID_OK) {
    // TODO(dan): Check if other contacts status == online to do
    //      direct messaging, opposed to bufferpacket

    wxBitmapButton* wxbb =
      reinterpret_cast<wxBitmapButton*>(event.GetEventObject());
    ContactDetail* cd = reinterpret_cast<ContactDetail*>(wxbb->GetParent());
    wxString wx_pub_name = cd->GetUser();
    std::string pub_name((const char*)wx_pub_name.mb_str());
    wxString wx_m = dialog.GetValue();
    std::string m((const char*)wx_m.mb_str());

    int n = maidsafe::ClientController::getInstance()->SendInstantMessage(
      m, pub_name);
    if (n == 0) {
      std::string success("Message sent to: " + pub_name);
      wxString successmessage = wxString::FromAscii(success.c_str());
      wxMessageBox(successmessage, _T("Success!"),
        wxOK | wxICON_INFORMATION, this);
    } else {
      wxString errormessage =
        wxString::FromAscii("Error sending a message to: ");
      errormessage += wx_pub_name;
      errormessage += wxString::FromAscii("\nError code: ");
      errormessage += wxString::FromAscii(base::itos(n).c_str());
      wxMessageBox(errormessage, _T("Error!"),
        wxOK | wxICON_INFORMATION, this);
    }
  }
}

void ContactDetail::Onfile_send_buttonClick(wxCommandEvent& event) {  // NOLINT
  if (FileDialog1->ShowModal() == wxID_OK) {
    std::string filename((const char*)FileDialog1->GetPath().mb_str());
    file_system::FileSystem fsys;
    std::string rel_filename(fsys.MakeRelativeMSPath(filename));
    wxTextEntryDialog dialog(this,
                  _T("Please Enter a \n")
                  _T("message if you wish to accompany the file(s)"),
                  _T("Messsage entry"),
                  _T(""),
                  wxOK | wxCANCEL);
    if (dialog.ShowModal() == wxID_OK) {
      wxBitmapButton* wxbb =
        reinterpret_cast<wxBitmapButton*>(event.GetEventObject());
      ContactDetail* cd = reinterpret_cast<ContactDetail*>(wxbb->GetParent());
      wxString wx_pub_name = cd->GetUser();
      std::string pub_name((const char*)wx_pub_name.mb_str());
      wxString wx_m = dialog.GetValue();
      std::string m((const char*)wx_m.mb_str());
      #ifdef __WIN32__
        rel_filename.erase(0, 2);
      #endif
      printf("Beforeeeeee Tidyyyyyy Pathhhhhh: %s\n", rel_filename.c_str());
      rel_filename = base::TidyPath(rel_filename);
      printf("Tidyyyyyy Pathhhhhh: %s\n", rel_filename.c_str());
      int n =
        maidsafe::ClientController::getInstance()->SendInstantFile(
        &rel_filename, m, pub_name);

      if (n == 0) {
        wxMessageBox(wxString::FromAscii("Success sending file."),
          _T("File Sent"), wxOK | wxICON_INFORMATION, this);
      } else {
        std::string error("There was an error sending the file! Error: " +
          base::itos(n));
        wxMessageBox(wxString::FromAscii(error.c_str()),
          _T("File Not Sent"), wxOK, this);
      }
    }
  }
}

// void ContactDetail::Ontxt_ctrl_user_commentText(
//  wxCommandEvent& event) {  // NOLINT
// }

void ContactDetail::UserActionMenu() {
  wxMenuItem* menu_item_send_message = new wxMenuItem((&user_action_menu),
    id_menuitem_send_message1, _("Send &message"), wxEmptyString,
    wxITEM_NORMAL);

  user_action_menu.Append(menu_item_send_message);

  wxMenuItem* menu_item_block_user = new wxMenuItem((&user_action_menu),
    id_menu_item_block_user, _("&Block user"), wxEmptyString, wxITEM_CHECK);

  user_action_menu.Append(menu_item_block_user);

  wxMenuItem* menu_item_delete_user = new wxMenuItem((&user_action_menu),
    id_menu_item_delete_user, _("&Delete user"), wxEmptyString, wxITEM_NORMAL);

  user_action_menu.Append(menu_item_delete_user);
  user_action_menu.AppendSeparator();
  wxMenu* menu_item_seperator = new wxMenu();
  menu_item_seperator->AppendSeparator();
  wxMenu* menu_item_shares = new wxMenu();
  wxMenuItem* menu_item_add_to_share_add_ro = new wxMenuItem(menu_item_shares,
    id_menu_item_add_to_share_ro, _("Add as r/o"),
    wxEmptyString, wxITEM_RADIO);

  menu_item_shares->Append(menu_item_add_to_share_add_ro);
  wxMenuItem* menu_item_add_to_share_add_rw = new wxMenuItem(menu_item_shares,
    id_menu_item_add_to_share_rw, _("Add as r/w"),
    wxEmptyString, wxITEM_RADIO);

  menu_item_shares->Append(menu_item_add_to_share_add_rw);

  wxMenuItem* menu_item_add_to_share_add_admin =
    new wxMenuItem(menu_item_shares,
    id_menu_item_add_to_share_admin, _("Add as Admin"), wxEmptyString,
    wxITEM_RADIO);

  menu_item_shares->Append(menu_item_add_to_share_add_admin);
  wxMenuItem* menu_item_remove_from_share = new wxMenuItem(menu_item_shares,
    id_menu_item_remove_from_share, _("Remove from share"),
    wxEmptyString, wxITEM_RADIO);

  menu_item_shares->Append(menu_item_remove_from_share);
  menu_item_seperator->Append(id_menuitem_share1, _("Share1"),
    menu_item_shares, wxEmptyString);

  user_action_menu.Append(id_menu_shares, _("&Shares"),
    menu_item_seperator, wxEmptyString);
}

// void ContactDetail::OnMouseEnter(wxMouseEvent& event) {  // NOLINT
  // #ifdef DEBUG
  // std::cout << "In OnMouseEnter- contact details" << std::endl;
  //  if (!flex_grid_main->IsShown(flex_grid_detail))
  //  {
  //    flex_grid_main->Show(flex_grid_detail, true);
  //  }

  // #endif
  //  flex_grid_main->Show(flex_grid_detail, true);
  // //  // flex_grid_detail-Layout();
  //  flex_grid_main->Layout();
  // flex_grid_detail->Layout();
  //  showing this crashes the windows - bugger of jesus
// }

// void ContactDetail::OnMouseLeave(wxMouseEvent& event) {  // NOLINT
//  std::cout << "In mouseleave contact details" << std::endl;
  //  flex_grid_main->Hide(flex_grid_detail, true);
  //  // flex_grid_detail-Layout();
  //  flex_grid_main->Layout();
  // //    flex_grid_detail->Hide(BoxSizer1);
  //   flex_grid_detail->Hide(BoxSizer2);
  //  flex_grid_detail->Layout();
// }

