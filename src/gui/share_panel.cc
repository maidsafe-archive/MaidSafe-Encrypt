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

#include "gui/share_panel.h"

#include <boost/shared_ptr.hpp>
#include <wx/button.h>
#include <wx/string.h>
#include <wx/gbsizer.h>
#include <wx/statline.h>
#include <wx/intl.h>

#include <list>
#include <set>

#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/privateshares.h"
#include "gui/createsharedialog.h"
#include "base/utils.h"

enum share_panel_ids {
  ID_share_name = 1,
  ID_new_share,
  ID_scrolled_share,
  ID_knob_share
};

BEGIN_EVENT_TABLE(SharePanel, wxPanel)
  EVT_BUTTON(ID_new_share, SharePanel::CreateShareClick)
END_EVENT_TABLE()

SharePanel::SharePanel(wxWindow* parent, wxWindowID id,
    const wxPoint& pos, const wxSize& size) {
  Create(parent, id, pos, size);
}

bool SharePanel::Create(wxWindow* parent, wxWindowID id,
    const wxPoint& pos, const wxSize& size) {
  if (!wxPanel::Create(parent, id, pos, size))
    return false;
  CreateControls();
  return true;
}

void SharePanel::CreateControls() {
  wxFlexGridSizer* flex_grid_main = new wxFlexGridSizer(2, 1, 0, 0);
  flex_grid_main->AddGrowableRow(1);
  flex_grid_main->AddGrowableCol(0);
  flex_grid_main->AddGrowableCol(1);

  wxBoxSizer* topLevel = new wxBoxSizer(wxVERTICAL);
  wxStaticBox* staticBox = new wxStaticBox(this,
    wxID_ANY, wxT("New Share"));
  wxStaticBoxSizer* staticSizer = new wxStaticBoxSizer(staticBox,
    wxVERTICAL);
  topLevel->Add(staticSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

//  wxBoxSizer* topLevel2 = new wxBoxSizer(wxVERTICAL);
//  wxStaticBox* staticBox2 = new wxStaticBox(this,
//    wxID_ANY, wxT("Current Shares"));
//  wxStaticBoxSizer* staticSizer2 = new wxStaticBoxSizer(staticBox2,
//    wxVERTICAL);
//  topLevel2->Add(staticSizer2, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

  wxScrolledWindow* shares_scrolled_window = new wxScrolledWindow(this,
    ID_scrolled_share, wxDefaultPosition, wxDefaultSize,
    wxALL|wxEXPAND|wxVSCROLL, _T("id_contact_scrolled_window"));
  shares_scrolled_window->SetScrollbars(10, 10, 1000, 1000);
  wxFlexGridSizer* share_list = new wxFlexGridSizer(0, 1, 0, 0);
  share_list->SetFlexibleDirection(wxHORIZONTAL);
  share_list->AddGrowableRow(0, 1);
  share_list->AddGrowableRow(1, 1);
  share_list->AddGrowableRow(2, 1);
  share_list->AddGrowableRow(3, 1);
  share_list->AddGrowableRow(4, 1);
  share_list->AddGrowableRow(5, 1);
  share_list->AddGrowableRow(6, 1);

  if (maidsafe::SessionSingleton::getInstance()->PublicUsername() != "") {
#ifdef DEBUG
    printf("Hay PublicUsername.\n");
#endif
    std::vector<maidsafe::Contacts> contact_list;
    std::list<maidsafe::PrivateShare> ps_list;
    int n =
      maidsafe::ClientController::getInstance()->GetShareList(
      &ps_list, "");
    if (n == 0) {  //  Success
#ifdef DEBUG
      printf("Hay GetShareList.\n");
#endif
      while (!ps_list.empty()) {
        maidsafe::PrivateShare ps;
        ps = ps_list.front();
        ps_list.pop_front();
        wxString wx_s = wxString::FromAscii(ps.Name().c_str());
        wxStaticText* st = new wxStaticText(shares_scrolled_window, 100 + n,
          wx_s, wxDefaultPosition, wxDefaultSize,
          0, _T("id_stat_txt_pub_name"));
        share_list->Add(st, 1, wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
        n++;
      }
      if (n == 0) {
          wxString wx_s = wxString::FromAscii("No shares, sucker");
          wxStaticText* st = new wxStaticText(shares_scrolled_window, 100 + n,
            wx_s, wxDefaultPosition, wxDefaultSize,
            0, _T("id_stat_txt_pub_name"));
          share_list->Add(st, 1, wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
      }
    }
  }
  shares_scrolled_window->SetSizer(share_list);
  share_list->Fit(shares_scrolled_window);

  wxStaticLine* line = new wxStaticLine(this, wxID_STATIC,
    wxDefaultPosition, wxSize(380, 1), wxLI_HORIZONTAL);
  wxButton* newShare = new wxButton(this, ID_new_share,
    wxT("Create New Share"), wxDefaultPosition, wxDefaultSize);

  staticSizer->Add(newShare, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(line, 0, wxALIGN_LEFT |wxALL, 5);
//  staticSizer2->Add(shares_scrolled_window, 0, wxALIGN_LEFT |wxALL, 5);

  flex_grid_main->Add(topLevel);
  flex_grid_main->Add(shares_scrolled_window, 1,
    wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
//  flex_grid_main->Add(topLevel2);

  SetSizer(flex_grid_main);
  flex_grid_main->SetSizeHints(this);
  flex_grid_main->Fit(this);
  Layout();
}

void SharePanel::CreateShareClick(wxCommandEvent& event) {  // NOLINT
#ifdef DEBUG
  printf("Event id: %i\n", event.GetId());
#endif
  event.GetId();
  // Share name
  boost::shared_ptr<std::set<std::string> > share_name_set;
  share_name_set.reset(new std::set<std::string>());
  ShareDialog share_name_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
    wxDefaultPosition, wxDefaultSize,
    wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 1, share_name_set.get());
  std::string share_name;
  std::set<std::string>::iterator it;
  if (share_name_dlg.ShowModal() == wxID_OK && share_name_set->size() == 1) {
    it = share_name_set->begin();
    share_name = *it;
#ifdef DEBUG
    printf("Share name: size(%i) value(%s)\n",
      share_name_set->size(), share_name.c_str());
#endif
  } else {
    return;
  }

  std::vector<maidsafe::Contacts> contact_list;
  int n =
    maidsafe::ClientController::getInstance()->ContactList(&contact_list, "");
  if (n != 0)
    return;
  // Admin Contacts
  // boost::shared_ptr<std::set<std::string> > admin_contact_set;
  std::set<std::string> admin_contact_set;
  // admin_contact_set.reset(new std::set<std::string>());
  for (unsigned int n = 0; n < contact_list.size(); n++) {
    admin_contact_set.insert(contact_list[n].PublicName());
  }
  ShareDialog admin_contact_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
    wxDefaultPosition, wxDefaultSize,
    wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 2, &admin_contact_set);
  if (admin_contact_dlg.ShowModal() == wxID_OK)
    printf("Share name size: %i\n", admin_contact_set.size());
  else
    return;

  // RO Contacts
  // boost::shared_ptr<std::set<std::string> > ro_contact_set;
  std::set<std::string> ro_contact_set;
  // ro_contact_set.reset(new std::set<std::string>());
  for (unsigned int n = 0; n < contact_list.size(); n++) {
    ro_contact_set.insert(contact_list[n].PublicName());
  }
  for (it = admin_contact_set.begin(); it != admin_contact_set.end(); it++)
    ro_contact_set.erase(*it);

  if (ro_contact_set.size() > 0) {
    ShareDialog ro_contact_dlg(this, wxID_ANY, wxT("Create Share Dialog"),
      wxDefaultPosition, wxDefaultSize,
      wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU, 3, &ro_contact_set);
    if (ro_contact_dlg.ShowModal() == wxID_OK)
      printf("Share name size: %i\n", ro_contact_set.size());
    else
      return;
  }

  // Send to ClientController
  if (ro_contact_set.size() > 0 || admin_contact_set.size() > 0) {
    n = maidsafe::ClientController::getInstance()->CreateNewShare(share_name,
      admin_contact_set, ro_contact_set);
    printf("Add share result: %i\n", n);
    CreateControls();
  }
}

SharePanel::~SharePanel() {
}
