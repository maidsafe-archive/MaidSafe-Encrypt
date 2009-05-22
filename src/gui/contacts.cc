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
#include "gui/contacts.h"

#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#ifdef MAIDSAFE_WIN32
  #include <wx/msw/winundef.h>
#endif
#include <wx/event.h>
#include <boost/filesystem.hpp>
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/clientcontroller.h"
#include "gui/d_add_publicname.h"
#include "gui/contact_detail.h"

namespace fs = boost::filesystem;

// (*IdInit(contacts)
const int32_t contacts::id_txt_ctrl_search_contacts = wxNewId();
const int32_t contacts::id_stat_txt_pub_name = wxNewId();
const int32_t contacts::id_stat_url_pub_name = wxNewId();
const int32_t contacts::id_stat_txt_space_available = wxNewId();
const int32_t contacts::id_bitmap_button_add_contact = wxNewId();
const int32_t contacts::id_bitmap_button_clear_search = wxNewId();
const int32_t contacts::id_list_box_contacts = wxNewId();
const int32_t contacts::id_contact_scrolled_window = 122;
const int32_t contacts::id_add_public_username = wxNewId();
// *)

BEGIN_EVENT_TABLE(contacts, wxPanel)
  // (*EventTable(contacts)
// EVT_SET_FOCUS (contacts::OnTextCtrl1Text)
  // *)
END_EVENT_TABLE()

contacts::contacts(wxWindow* parent, wxWindowID id,
  const wxPoint& pos, const wxSize& size)
  : bitmap_button_add_contact(NULL), bitmap_button_clear_search(NULL),
  stat_url_pub_name(NULL), stat_txt_pub_name(NULL),
  txt_ctrl_search_contacts(NULL), txt_ctrl_add_contact(NULL),
  list_box_contacts(NULL), stat_txt_space_available(NULL),
  contact_scrolled_window(NULL), flex_grid_my_details(NULL),
  flex_grid_main(NULL), grid_sizer_contact_list(NULL),
  box_sizer_scrolled_window(NULL), flex_sizer_main(NULL),
  addPublicUsername(NULL) {
  Create(parent, id, pos,
    size, wxTAB_TRAVERSAL, _T("id"));
  // create and set all sizers here

  // sizer for contacts page
  flex_grid_main = new wxFlexGridSizer(3, 1, 0, 0);
  flex_grid_main->AddGrowableRow(1);
  flex_grid_main->AddGrowableCol(0);
  flex_grid_main->AddGrowableCol(1);
  // sizer for list of contacts inside scrolled window
  grid_sizer_contact_list = new wxFlexGridSizer(0, 1, 0, 0);
  grid_sizer_contact_list->SetFlexibleDirection(wxHORIZONTAL);
  grid_sizer_contact_list->AddGrowableRow(0, 1);
  grid_sizer_contact_list->AddGrowableRow(1, 1);
  grid_sizer_contact_list->AddGrowableRow(2, 1);
  grid_sizer_contact_list->AddGrowableRow(3, 1);
  grid_sizer_contact_list->AddGrowableRow(4, 1);
  grid_sizer_contact_list->AddGrowableRow(5, 1);
  grid_sizer_contact_list->AddGrowableRow(6, 1);
  // sizer for row 1 (pub name etc.)
  flex_grid_my_details = new wxFlexGridSizer(2, 3, 0, 0);
  flex_grid_my_details->AddGrowableCol(0);

  txt_ctrl_search_contacts = new wxTextCtrl(this,
    id_txt_ctrl_search_contacts, _("Search (or add) contacts")
    , wxDefaultPosition, wxSize(300, 27),
    wxTE_NO_VSCROLL|wxNO_BORDER|wxTE_PROCESS_ENTER|wxTE_PROCESS_TAB|
    wxFULL_REPAINT_ON_RESIZE, wxDefaultValidator,
    _T("id_txt_ctrl_search_contacts"));

  stat_txt_space_available = new wxStaticText(this,
    id_stat_txt_space_available,
    _("Space"), wxDefaultPosition, wxDefaultSize, 0,
    _T("id_stat_txt_space_available"));

  bitmap_button_add_contact = new wxBitmapButton(this,
    id_bitmap_button_add_contact,
    wxXmlResource::Get()->LoadBitmap(wxT("addcontact")),
    wxDefaultPosition, wxDefaultSize, wxBU_AUTODRAW|wxNO_BORDER,
    wxDefaultValidator, _T("id_bitmap_button_add_contact"));

  bitmap_button_clear_search = new wxBitmapButton(this,
    id_bitmap_button_clear_search,
    wxArtProvider::GetBitmap(wxART_MAKE_ART_ID_FROM_STR(_T("wxART_DELETE")),
    wxART_BUTTON), wxDefaultPosition, wxDefaultSize, wxNO_BORDER|wxBU_AUTODRAW,
    wxDefaultValidator, _T("id_bitmap_button_clear_search"));

  bitmap_button_add_contact->SetDefault();
  bitmap_button_add_contact->SetToolTip(_
    ("Click here to add this contact to your list"));
  bitmap_button_clear_search->SetToolTip(_
    ("Clear search"));

  contact_scrolled_window = new wxScrolledWindow(this,
    id_contact_scrolled_window, wxDefaultPosition,
    wxDefaultSize, wxALL|wxEXPAND|wxHSCROLL, _T("id_contact_scrolled_window"));
    contact_scrolled_window->SetScrollbars(10, 10, 1000, 1000);

  // Now layout the window proper
  flex_grid_my_details->Add(bitmap_button_add_contact, 1,
    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxNO_BORDER, 0);
  flex_grid_my_details->Add(txt_ctrl_search_contacts, 1,
    wxALL|wxEXPAND|wxALIGN_CENTER_HORIZONTAL|
    wxALIGN_CENTER_VERTICAL|wxNO_BORDER, 0);
  flex_grid_my_details->Add(bitmap_button_clear_search, 1,
    wxALL|wxALIGN_LEFT|wxNO_BORDER, 0);
  // build a wee grid with three items
  flex_grid_my_details->AddStretchSpacer(1);

  if (maidsafe::SessionSingleton::getInstance()->PublicUsername() != "") {
    wxString wx_s = wxString::FromAscii(
      maidsafe::SessionSingleton::getInstance()->PublicUsername().c_str());
    stat_txt_pub_name = new wxStaticText(this, id_stat_txt_pub_name,
    wx_s, wxDefaultPosition, wxDefaultSize, 0, _T("id_stat_txt_pub_name"));
    flex_grid_my_details->Add(stat_txt_pub_name, 1,
    wxALL|wxALIGN_LEFT|wxALIGN_TOP, 5);
  } else {
    addPublicUsername = new wxButton(this,
      id_add_public_username, wxT("&Create your public username!"),
      wxDefaultPosition, wxDefaultSize, 0);
    flex_grid_my_details->Add(addPublicUsername, 1,
      wxALL|wxALIGN_LEFT|wxALIGN_TOP|wxALL, 5);
  }

  flex_grid_my_details->Add(stat_txt_space_available, 1,
    wxALL|wxALIGN_LEFT|wxALIGN_TOP, 5);

  if (maidsafe::SessionSingleton::getInstance()->PublicUsername() != "") {
    std::vector<maidsafe::Contacts> contact_list;
    int get_contact_result =
      maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
    if (get_contact_result == 0) {  //  Success
      for (unsigned int n = 0; n < contact_list.size(); n++) {
        maidsafe::Contacts c = contact_list[n];
        wxString wx_s = wxString::FromAscii(c.PublicName().c_str());
        ContactDetail *i = new ContactDetail(contact_scrolled_window,
          wxID_ANY, wxDefaultPosition, wxDefaultSize, wx_s, c.Confirmed());
        grid_sizer_contact_list->Add(i, 1,
          wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
      }
    }
  }
  contact_scrolled_window->SetSizer(grid_sizer_contact_list);
  grid_sizer_contact_list->Fit(contact_scrolled_window);
  flex_grid_main->Add(flex_grid_my_details, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
  flex_grid_main->Add(contact_scrolled_window, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);


  SetSizer(flex_grid_main);
  flex_grid_main->SetSizeHints(this);
  flex_grid_main->Fit(this);
  Layout();
  //   Connect(id_txt_ctrl_search_contacts,wxEVT_COMMAND_ENTER
  //    ,(wxObjectEventFunction)&contacts::OnTextCtrl1Text);

  txt_ctrl_search_contacts->Connect(id_txt_ctrl_search_contacts,
    wxEVT_ENTER_WINDOW, wxFocusEventHandler(contacts::OnSearchEnter));

  // works on windows
  txt_ctrl_search_contacts->Connect(id_txt_ctrl_search_contacts,
    wxEVT_LEAVE_WINDOW, wxFocusEventHandler(contacts::OnSearchLeave));

  // best I can do for linux / osx
  txt_ctrl_search_contacts->Connect(id_txt_ctrl_search_contacts,
    wxEVT_KILL_FOCUS, wxFocusEventHandler(contacts::OnSearchLeave));

  // catch characters as typed an update contacts shown
  // Connect(id_bitmap_button_clear_search,
  // wxEVT_ENTER_WINDOW,wxFocusEventHandler(
  // contacts::On_focus_bitmap_button_clear_search));
  Connect(id_bitmap_button_clear_search, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(contacts::Onbitmap_button_clear_search));

  Connect(id_bitmap_button_add_contact, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(contacts::Onbitmap_button_add_contactClick));

  Connect(id_add_public_username, wxEVT_COMMAND_BUTTON_CLICKED,
    wxCommandEventHandler(contacts::OnCreatePublicUsernameClick));
}

contacts::~contacts() {
  // (*Destroy(contacts)
  // *)
}

void contacts::OnCreatePublicUsernameClick(wxCommandEvent& event) { // NOLINT
  printf("Event id: %i\n", event.GetId());
  PublicUsernameDialog dlg(this);
  int n = dlg.ShowModal();

  wxString wx_s = wxString::FromAscii(
    maidsafe::SessionSingleton::getInstance()->PublicUsername().c_str());
  stat_txt_pub_name = new wxStaticText(this, id_stat_txt_pub_name,
    wx_s, wxDefaultPosition, wxDefaultSize, 0, _T("id_stat_txt_pub_name"));
  flex_grid_my_details->Replace(addPublicUsername, stat_txt_pub_name, false);
  addPublicUsername->Hide();

  flex_grid_my_details->Layout();
  std::cout << "En contacts: " << n << std::endl;
}

void contacts::Onbitmap_button_add_contactClick(
  wxCommandEvent& event) {  // NOLINT
  wxString wx_contact_txt = txt_ctrl_search_contacts->GetValue();
  std::string contact_txt((const char*)wx_contact_txt.mb_str());
  if (contact_txt.compare("Search (or add) contacts")) {
    int n = maidsafe::ClientController::getInstance()->AddContact(contact_txt);
    printf("Addition result: %i\n", n);
    if (n == 0) {
      grid_sizer_contact_list->Clear();
      std::vector<maidsafe::Contacts> contact_list;
      int get_contact_result =
        maidsafe::ClientController::getInstance()->ContactList(
        &contact_list, "");
      if (get_contact_result == 0) {  //  Success
        for (unsigned int n = 0; n < contact_list.size(); n++) {
          maidsafe::Contacts c = contact_list[n];
          wxString wx_s = wxString::FromAscii(c.PublicName().c_str());
          ContactDetail *i = new ContactDetail(contact_scrolled_window,
            222222 + n, wxDefaultPosition, wxDefaultSize, wx_s, c.Confirmed());
          grid_sizer_contact_list->Add(i, 1,
            wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
        }
      }
      contact_scrolled_window->SetSizer(grid_sizer_contact_list);
      grid_sizer_contact_list->Fit(contact_scrolled_window);
      Layout();
    } else {
      if (n == -221)
        wxMessageBox(_("Error adding contact. Username doesn't exist."),
          _("Problem!"), wxOK, this);
      event.Skip();
    }
  } else {
    event.Skip();
  }
}

void contacts::Onbitmap_button_clear_search(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  txt_ctrl_search_contacts->Clear();
  txt_ctrl_search_contacts->SetValue(_("Search (or add) contacts"));
#ifdef DEBUG
  std::cout << "in Onbitmap_button_clear_search " << std::endl;
#endif
}

// void contacts::On_focus_bitmap_button_clear_search(
//  wxFocusEvent& event) {  // NOLINT
  //   wxBitmapButton* txt = (wxBitmapButton*)(event.GetEventObject());
  //  txt->Clear();
  //  txt->SetValue(_("Search (or add) contacts"));
  // // //  event.Skip();
  // //  txt_ctrl_search_contacts->Clear();
  // //  txt_ctrl_search_contacts->SetValue(_("Search (or add) contacts"));
  //  event.Skip();
// }

void contacts::OnSearchEnter(wxFocusEvent& event) {  // NOLINT
  // #ifdef DEBUG
  std::cout << "In search control" << std::endl;
  // #endif
  wxTextCtrl* searchtxt =
    reinterpret_cast<wxTextCtrl*>(event.GetEventObject());
  if (searchtxt->GetValue() == _("Search (or add) contacts")) {
    searchtxt->Clear();
  }
  searchtxt->SetFocus();

  // stat_txt_pub_name->SetLabel(_("test"));
  event.Skip();
}

void contacts::OnSearchLeave(wxFocusEvent& event) {  // NOLINT
#ifdef DEBUG
  std::cout << "In search control" << std::endl;
#endif
  wxTextCtrl* searchtxt =
    reinterpret_cast<wxTextCtrl*>(event.GetEventObject());
  if (searchtxt->GetValue() == _("")) {
    searchtxt->SetValue(_("Search (or add) contacts"));
  }
#ifdef DEBUG
  std::cout << searchtxt->GetValue() << "<- search value " << std::endl;
#endif
  // stat_txt_pub_name->SetLabel(_("test"));
  event.Skip();
}
